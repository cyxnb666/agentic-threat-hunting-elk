# Threat hunt report — 20261017-104114-converged-demo2

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 5 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003.001 (F01, F08, F15, F21, F28, F32, F43), I03 T1552 (F27), I04 T1552.001 (F24), I05 T1552.004 (F18, F23, F51), I07 T1557.002 (F39)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-17T02:41:15+00:00 / 2026-10-17T02:51:29+00:00 (614.5 s) |
| LLM calls / tokens | 177 / {'prompt': 4511162, 'completion': 127264} |
| MCP tool calls | 1131 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003.001 | yes | malicious/high | F01, F08, F15, F21, F28, F32, F43 | LSASS memory accessed with full-access masks by PowerShell (scranton) and wsmprovhost (nashua) under pbeesly |
| I02 | T1003.002 | yes | suspicious/low | F02 | SAM_SERVER and SamSs registry handles requested by lsass.exe on scranton |
| I03 | T1552 | yes | malicious/high | F27 | Hardcoded plaintext passwords in attacker PowerShell tooling on SCRANTON |
| I04 | T1552.001 | yes | malicious/high | F24 | Recursive user-profile sweep for password/login-named files archived to Draft.Zip on SCRANTON |
| I05 | T1552.004 | yes | malicious/high | F18, F23, F51 | PowerShell Get-PrivateKeys exported LocalMachine certificate private keys to .pfx on SCRANTON |
| I06 | T1557.001 | yes | suspicious/medium | F40 | SMB/RPC/WinRM traffic carried by spoofed MAC and NetBIOS name-service broadcasts |
| I07 | T1557.002 | yes | malicious/high | F39 | ARP cache poisoning: second MAC impersonating 10.0.1.4 |
| I08 | out-of-scope:T1021.002 | no | suspicious/medium | F16 | PsExec reuse of known pbeesly credentials to move to NASHUA |
| I09 | out-of-scope:T1059 | no | suspicious/medium | F09 | Suspicious .scr and python.exe payloads opening full-access handles to conhost/cmd/powershell |

## Findings

### F01 · malicious / high · T1003.001 · LSASS memory accessed with full-access masks by PowerShell and wsmprovhost under user pbeesly

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:05:16Z, C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe (PID 2976, running as pbeesly) opened a handle to C:\windows\system32\lsass.exe with GrantedAccess 0x1fffff and 0x1f3fff — PROCESS_ALL_ACCESS-class rights used for memory dumping, with a short UNKNOWN-module call trace. The same activity repeated on nashua.dmevals.local at 03:09:29Z from C:\windows\system32\wsmprovhost.exe (PID 7720, PowerShell remoting host, user pbeesly) with GrantedAccess 0x1f3fff, call trace through System.ni.dll / Microsoft.PowerShell.Commands.Management.ni.dll. Windows Security corroborates: 4656 handle requests to \Device\HarddiskVolume2\Windows\System32\lsass.exe with AccessMask 0x1fffff and 0x1f3fff by powershell.exe on scranton (SubjectUserName pbeesly) and by wsmprovhost.exe on nashua (SubjectUserName pbeesly), followed by 4663 read (0x10) events. This is not the baseline pattern: the dominant LSASS accessor is svchost.exe with 0x1000 (293 of 326 events), and the only other high-mask accessors are Defender MsMpEng.exe and Azure CollectGuestLogs.exe. The pbeesly session on scranton is independently malicious (Invoke-Exfil script, PsExec64 to \\NASHUA with cleartext password, davclnt.dll WebDAV staging to 192.168.0.4, hidden encoded PowerShell), so the LSASS full-access handles are credential dumping in the course of that intrusion.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-ce7a7de0be | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-ce7a7de0be | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-ce7a7de0be | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-0bfcc4bd43 | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo57 | q-67d9cc39b8 | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo57 | q-67d9cc39b8 | ok |
| 7 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFv53 | q-67d9cc39b8 | ok |
| 8 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFv53 | q-67d9cc39b8 | ok |

### F08 · malicious / high · T1056.004 · pbeesly PowerShell/wsmprovhost requests full-access (0x1F3FFF / 0x1FFFFF) handles to lsass.exe on scranton and nashua

Evidence status: **verified**

On 2020-05-02 at 03:05:16Z (23:05:16 -04:00) the account DMEVALS\pbeesly, running as C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID 0xba0, logon 0x372E81), requested two handles to \Device\HarddiskVolume2\Windows\System32\lsass.exe on scranton.dmevals.local with AccessMask 0x1f3fff and 0x1fffff — including 'Read from process memory', 'Write to process memory', 'Perform virtual memory operation' and 'Duplicate handle into or out of process'. At 03:09:29Z the same account requested a 0x1f3fff handle to lsass.exe on nashua.dmevals.local from C:\Windows\System32\wsmprovhost.exe (PID 0x1e28, logon 0x85AAD2), i.e. over a PowerShell remoting session. These are the only non-system, non-AV LSASS handle requests in the dataset (the other 4656 lsass hits are CollectGuestLogs.exe, MsMpEng.exe and lsass.exe itself under machine accounts). Full-access process handles to LSASS from PowerShell are the classic credential-API-hooking / memory-read pattern used to extract logon credentials. No 4104 script block containing lsass/minidump/sekurlsa/hook strings was found, so the exact tooling is not visible in PowerShell logging.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo4k | q-d5ffdfe032 | ok |
| 2 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo4k | q-d5ffdfe032 | ok |
| 3 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo57 | q-6047f2377e | ok |
| 4 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFv53 | q-431e79d3d6 | ok |
| 5 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFv53 | q-431e79d3d6 | ok |

### F18 · malicious / medium · T1111 · PowerShell steganography loader on scranton exported certificate private keys (PFX) and opened LSASS with full access

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a hidden, execution-policy-bypassing PowerShell (PID 2976, parent control.exe) that decoded a payload from C:\Users\pbeesly\Downloads\monkey.png and IEX'd it. The session then ran discovery, persistence steps, accesschk, and a Get-PrivateKeys function that enumerates cert:\LocalMachine and exports each certificate with a private key to a random .pfx in the user's Downloads folder (password 'saribas'). At 03:04:57 a file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx was created by powershell.exe and at 03:08:51 the same file was deleted (Sysmon 23) by powershell.exe. At 03:05:16 the same PowerShell process (PID 2976) opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff (full access) with an UNKNOWN call trace, i.e. direct credential-store access from the attacker's PowerShell. This is credential material theft (certificate private keys usable for authentication / MFA-bypass via certificate-based logon) rather than interception of an MFA provider; no smart-card/MFA provider tampering was observed. Related: on nashua.dmevals.local wsmprovhost.exe (WinRM PowerShell) opened lsass.exe with 0x1f3fff at 03:09:29, and pbeesly credentials were used explicitly via PSEXESVC.exe (4648, target localhost) at 23:11:40 local, consistent with reuse of the stolen account.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgwo_a | q-59a9b9ede1 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-92fe524248 | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-df4e758aaa | ok |
| 4 | 2020-05-02 03:08:51.489Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkx5I18 | q-df4e758aaa | ok |
| 5 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-de348c1862 | ok |
| 6 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-da4d0cc9ec | ok |
| 7 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-eb78728fa6 | ok |
| 8 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0ff | q-5328dbf2d7 | ok |

### F27 · malicious / high · T1552 · Unsecured credentials: hardcoded plaintext passwords in attacker PowerShell tooling on SCRANTON

Evidence status: **verified**

Across scranton.dmevals.local the pbeesly PowerShell session (2020-05-01 22:56–23:08) contains multiple hardcoded plaintext secrets in script blocks: "saribas" used as the .pfx export password in Get-PrivateKeys, "lolol" as the 7-Zip archive password in Invoke-Exfil, and "MyCozyPassw0rd!" for the cozy account used to mount \\192.168.0.4\webdav. Combined with the recursive *pass*/*login* file sweep and the certificate export, this is credential collection and staging on a compromised host, followed by SMB/PsExec reuse of pbeesly against nashua.dmevals.local.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-e30b443f1c | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-445961774a | ok |
| 3 | 2020-05-02 03:04:03.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Discovery {     $DiscoveryInfo =@()     $CurrentDir = Get-Location      $DiscoveryInfo += [PSCustomObject]@{                 CurrentDirectory = … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSwG | q-7f1e281b52 | ok |

### F24 · malicious / high · T1552.001 · Recursive user-profile sweep for password/login-named files archived to Draft.Zip on SCRANTON

Evidence status: **verified**

At 2020-05-01T22:56:17-04:00 on scranton.dmevals.local, pbeesly's PowerShell session (PID 5944) ran a script block that recursively enumerates $env:USERPROFILE for documents plus wildcard patterns *psw*, *pass*, *login*, *admin*, *sifr*, *sifer*, *vpn and archives the results with Compress-Archive into $env:APPDATA\Draft.Zip — a classic search of user files for stored credentials. The same session then ran Invoke-Discovery (host/user/AV enumeration) and later Invoke-Exfil, which 7-Zips the Downloads folder and copies it to \\192.168.0.4\webdav using hardcoded credentials (cozy / MyCozyPassw0rd!). The 4648 explicit-credential logons by pbeesly to NASHUA over SMB (port 445, source 10.0.1.6) and via PSEXESVC.exe on nashua.dmevals.local show the harvested account being reused for lateral movement.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwHqJZm | q-2f964314c3 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-445961774a | ok |
| 3 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEcw | q-09a4c03fc8 | ok |
| 4 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0ff | q-76318bb8d6 | ok |

### F23 · malicious / high · T1552.004 · PowerShell Get-PrivateKeys exports every LocalMachine certificate to .pfx on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell script block (ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b, Path C:\Program Files\SysinternalsSuite\readme.ps1) at 2020-05-01T23:04:56-04:00 that defines Get-PrivateKeys: it builds a SecureString from the hardcoded plaintext password "saribas", enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint into $env:USERPROFILE\Downloads\<random>.pfx. One second later Sysmon recorded the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe. This is private-key/certificate theft staged for exfiltration (the same host then ran Invoke-Exfil compressing Downloads and copying it to a WebDAV share).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-e30b443f1c | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-e30b443f1c | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-d4dee03f54 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-d4dee03f54 | ok |

### F28 · malicious / high · T1555 · PowerShell on SCRANTON opened LSASS with full-access mask (0x1F3FFF / 0x1FFFFF) including read-process-memory, in the middle of a hands-on-keyboard intrusion

Evidence status: **verified**

On scranton.dmevals.local the user pbeesly ran an interactive PowerShell session that was spawned by a malicious screen-saver (C:\ProgramData\victim\â€®cod.3aka3.scr -> cmd.exe -> powershell.exe). At 2020-05-02T03:05:16Z that PowerShell process (PID 2976 / 0xba0) opened handles to C:\windows\system32\lsass.exe with GrantedAccess 0x1F3FFF and 0x1FFFFF (Sysmon event 10, call trace ending in UNKNOWN module), and Security 4656 recorded the same handle request with AccessMask 0x1F3FFF listing 'Read from process memory' / 'Perform virtual memory operation'. This is the access pattern of an in-memory credential dump of the LSASS password store. The surrounding session shows the same actor staging SysinternalsSuite, running accesschk, Get-PrivateKeys (exporting certs to .pfx), persistence and screen capture, so the LSASS access is attacker credential theft, not a benign tool.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-494ca0a439 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-494ca0a439 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-fb0b32e5b9 | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo4k | q-5b0119e96b | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo4k | q-5b0119e96b | ok |
| 6 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpk1QgV | q-3d960db916 | ok |
| 7 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-5825c3b911 | ok |

### F32 · malicious / high · T1556 · Steganographic PowerShell loader on scranton opened LSASS with full-access mask (0x1FFFFF) — credential access, not auth-process modification

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T02:58:44Z, control.exe spawned a hidden, execution-policy-bypass PowerShell (PID 2976, user DMEVALS\pbeesly, High integrity) that decoded a payload from C:\Users\pbeesly\Downloads\monkey.png via System.Drawing GetPixel and IEX'd it. At 03:05:16Z that same process (SourceProcessGUID {47ab858c-e1e4-5eac-b803-000000000400}) opened lsass.exe (PID 736) twice with GrantedAccess 0x1F3FFF and 0x1FFFFF — full read/write access consistent with in-memory credential dumping. A second full-access LSASS handle came from wsmprovhost.exe (PID 7720) on nashua.dmevals.local at 03:09:29Z with GrantedAccess 0x1F3FFF and a .NET/PowerShell call trace. However, no evidence of authentication-process tampering was found: no 4657 registry changes to LSA/SecurityProviders/Notification Packages/NetworkProvider keys, no 4739, no 5136, no 4657 on NetworkProvider, no lsass image-load of a non-Microsoft module (only lsass.exe loading itself at 03:19:09Z), and no 4688/4104 referencing lsass, procdump, comsvcs, MiniDump or mimikatz. The 289 svchost.exe LSASS accesses (0x1000) and the AntimalwareConfig.exe / WindowsAzureTelemetryService.exe accesses (0x1400) are routine. Assessment: credential theft activity is real, but the T1556 family itself is not observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgwo_a | q-481d5e2e17 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-5d7368eedd | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-5d7368eedd | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-52c8298d8b | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-52c8298d8b | ok |
| 6 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpo7f-g | q-50a35f3fa7 | ok |

### F39 · malicious / high · T1557.002 · Second MAC address (fc:bd:67:e1:a9:c1) impersonating IP 10.0.1.4 in parallel with the legitimate NIC MAC — ARP cache poisoning

Evidence status: **verified**

In the Zeek window (2020-04-30 00:06–00:45Z) host 10.0.1.4 normally sources traffic from MAC 00:0d:3a:4d:42:f2 (134 conn records, 00:06:38–00:45:00). Starting 00:33:26.283Z a second, different MAC fc:bd:67:e1:a9:c1 also appears as zeek.orig_l2_addr for the same source IP 10.0.1.4 (44 conn records through 00:45:00.042Z), interleaved with the legitimate MAC on the same destinations and ports (e.g. 10.0.1.6:5985 at 00:33:26, 10.0.1.6:445 at 00:35:25, 10.0.1.6:55121 from 00:36:17). Two distinct L2 addresses claiming one IP simultaneously is the signature of ARP cache poisoning / an on-path attacker, not of a normal NIC change (which would replace, not interleave with, the original MAC). The attacker MAC's traffic is directed at the peer host 10.0.1.6 (NASHUA) on SMB 445, RPC 135, WinRM 5985, HTTP 80 and high port 55121, consistent with interception of that host's traffic.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:33:26.283Z | bobs.bigwheel.local | zeek | zeek.orig_l2_addr | fc:bd:67:e1:a9:c1 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8u4rk | q-873d9a3f3e | ok |
| 2 | 2020-04-30 00:33:26.283Z | bobs.bigwheel.local | zeek | source.ip | 10.0.1.4 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8u4rk | q-873d9a3f3e | ok |
| 3 | 2020-04-30 00:33:26.283Z | bobs.bigwheel.local | zeek | destination.port | 5985 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8u4rk | q-873d9a3f3e | ok |
| 4 | 2020-04-30 00:06:38.903Z | simplerockbuild.simplerock.lan | zeek | zeek.orig_l2_addr | 00:0d:3a:4d:42:f2 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4ud | q-5bbaeba100 | ok |
| 5 | 2020-04-30 00:06:38.903Z | simplerockbuild.simplerock.lan | zeek | source.ip | 10.0.1.4 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4ud | q-5bbaeba100 | ok |
| 6 | 2020-04-30 00:35:25.606Z | bobs.bigwheel.local | zeek | zeek.orig_l2_addr | fc:bd:67:e1:a9:c1 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8u4rQ | q-cf24d843af | ok |
| 7 | 2020-04-30 00:35:25.606Z | bobs.bigwheel.local | zeek | destination.port | 445 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8u4rQ | q-cf24d843af | ok |
| 8 | 2020-04-30 00:35:25.606Z | bobs.bigwheel.local | zeek | destination.ip | 10.0.1.6 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8u4rQ | q-cf24d843af | ok |

### F43 · malicious / high · T1558 · Steganographic PowerShell loader on SCRANTON opened LSASS with full-access masks (credential/ticket theft precursor)

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T02:57:00Z the dropped binary C:\ProgramData\victim\â€®cod.3aka3.scr wrote C:\Users\pbeesly\Downloads\monkey.png. At 02:58:44Z control.exe (/name Microsoft.BackupAndRestoreCenter) spawned a hidden, execution-policy-bypassing PowerShell (PID 2976, user DMEVALS\pbeesly, IntegrityLevel High) that decoded a payload out of the PNG's pixel data and IEX'd it. At 03:05:16Z that same PID 2976 opened lsass.exe (PID 736) with GrantedAccess 0x1f3fff and 0x1fffff — full LSASS read access, the classic prerequisite for extracting Kerberos tickets/keys. Separately, on nashua.dmevals.local at 03:09:29Z wsmprovhost.exe (PID 7720) opened lsass.exe (PID 728) with 0x1f3fff, immediately after PowerShell ran Get-Process -IncludeUserName to enumerate the user's processes. This is attacker credential access, not normal system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\monkey.png | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpizF2M | q-7888f3a6ae | ok |
| 2 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgwo_a | q-45e8f85162 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-e04d0825ee | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-94c1ae390c | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-891de3b438 | ok |
| 6 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz-ho2U | q-51e048f5e6 | ok |

### F51 · malicious / high · T1649 · PowerShell Get-PrivateKeys exported all LocalMachine certificates to password-protected .pfx files on SCRANTON, then staged and exfiltrated them

Evidence status: **verified**

On scranton.dmevals.local, in the context of user pbeesly (S-1-5-21-1830255721-3727074217-2423397540-1107), a PowerShell script block named Get-PrivateKeys (script block 9d153741-75c3-4062-afe3-aeca0aee611b, loaded from C:\Program Files\SysinternalsSuite\readme.ps1) enumerated the entire cert:\LocalMachine store recursively and called Export-PfxCertificate for every certificate with a thumbprint, writing each to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded password 'saribas'. At 03:04:57.460Z Sysmon recorded the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by powershell.exe (PID 3876) — the same PID that hosted the Get-PrivateKeys script block. The stolen certificates were then staged: Invoke-Exfil (script block b2b03a9c-43f0-4285-837d-f22d4600b2ae) compressed the whole Downloads directory with Compress-7Zip into C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z (created 03:08:35.270Z), copied it to a WebDAV share \\192.168.0.4\webdav using credentials 'cozy', and Invoke-BeachCleanup (script block 31f21f1d-9199-4d21-9ea8-c29b97841202) deleted the *.pfx, *.bmp, *.png and OfficeSupplies.7z artifacts. Sysmon event 23 confirms the .pfx, .bmp and OfficeSupplies.7z were deleted at 03:08:51. This is deliberate theft of authentication certificates/private keys from the host certificate store, followed by anti-forensic cleanup. The single 4657 modification of HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 on nashua.dmevals.local was performed by C:\Windows\Sysmon.exe under SYSTEM (NASHUA$) and is unrelated benign certificate-store maintenance, not attacker activity.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-1c0349b5e8 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-5d81e87ab6 | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-7ee6b42d7c | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-f05fe45a9a | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-ff7d417f39 | ok |
| 6 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-ff7d417f39 | ok |
| 7 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkx5Y3M | q-435ea02448 | ok |
| 8 | 2020-05-02 03:08:51.489Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkx5I18 | q-435ea02448 | ok |
| 9 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCk1N1 | q-9547267d45 | ok |
| 10 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhDM5P | q-71b7682708 | ok |

### F02 · suspicious / low · T1003.002 · SAM_SERVER handle with 0xF003F requested by lsass.exe on scranton during the intrusion

Evidence status: **verified**

On scranton.dmevals.local, Security 4656 events show handles requested to ObjectName 'SAM' (Object Server 'Security Account Manager', Object Type SAM_SERVER) with AccessMask 0xf003f (DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, ConnectToServer, ShutdownServer, InitializeServer, CreateDomain, EnumerateDomains, LookupDomain) at 03:19:21-03:19:22Z and 03:20:46Z, plus handles to \REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\SamSs at 03:19:10Z. The requesting process is C:\Windows\System32\lsass.exe under SubjectUserName SCRANTON$ (S-1-5-18, logon 0x3e7), i.e. the SAM service itself, which is the normal owner of these objects — no non-lsass process was seen reading the SAM hive. No reg save / hive export command lines were found (only dsregcmd.exe and sc.exe start pushtoinstall registration matched the reg/save/SAM/ntds pattern), and no SAM/SECURITY/SYSTEM hive files were created on disk (only Prefetch .pf files matched). The timing inside the pbeesly intrusion window keeps this worth noting, but the actor and access path are the legitimate SAM server, so I cannot attribute SAM dumping.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.ObjectName | SAM | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO1YtA | q-67d9cc39b8 | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0xf003f | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO1YtA | q-e84a1b1b4c | ok |
| 3 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO1YtA | q-e84a1b1b4c | ok |
| 4 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\SamSs | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsc9wP8 | q-67d9cc39b8 | ok |

### F09 · suspicious / medium · T1056 · Suspicious .scr and python.exe payloads on scranton/nashua open full-access (0x1FFFFF) handles to conhost/cmd/powershell

Evidence status: **verified**

On scranton.dmevals.local, C:\ProgramData\victim\â€®cod.3aka3.scr (PID 8524, launched by explorer.exe as DMEVALS\pbeesly at 02:55:56Z, SHA256 0DF38A55D940F498478EB03683C94D4584236E100125B526A67650BA54DF4AE4) opened 0x1FFFFF handles to conhost.exe and cmd.exe at 02:56:04Z and 02:57:12Z; the file was later wiped with sdelete64.exe at 03:02:04Z. On nashua.dmevals.local, C:\Windows\Temp\python.exe (PID 2172, spawned by another C:\Windows\Temp\python.exe, user DMEVALS\pbeesly) opened 0x1FFFFF handles to powershell.exe (03:15:48Z) and cmd.exe (03:16:40Z). Full-access handles to console/shell processes are consistent with input capture / process injection, but no keyboard-hook, GetAsyncKeyState or keylogger registry artifacts were observed, so the capture mechanism itself is not proven.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:04.487Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpk1Agy | q-2d340ae96f | ok |
| 2 | 2020-05-02 02:56:04.487Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpk1Agy | q-2d340ae96f | ok |
| 3 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpk1QgV | q-e0f3ed0e97 | ok |
| 4 | 2020-05-02 03:15:04.235Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItknvJ_4 | q-f542ea1495 | ok |
| 5 | 2020-05-02 03:15:04.228Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItknvJ_5 | q-64b3575842 | ok |

### F15 · suspicious / medium · T1110.002 · No offline cracking tooling or hash-dump artifacts; lsass access by PowerShell/wsmprovhost is credential dumping, not cracking

Evidence status: **verified**

No hashcat/john/cracking binaries appear in the 447 process-create events, and no .pot/.hash/ntds.dit output files appear among 1649 file-create events. However, the lsass process-access stack shows two non-system processes opening lsass with dump-grade access: PowerShell.exe (PID 2976, user DMEVALS\pbeesly, spawned by control.exe /name Microsoft.BackupAndRestoreCenter with a hidden -ep bypass IEX-from-bitmap loader) opened lsass with GrantedAccess 0x1f3fff then 0x1fffff on scranton.dmevals.local at 2020-05-02T03:05:16Z, and wsmprovhost.exe (PID 7720, user pbeesly, PowerShell remoting) opened lsass with 0x1f3fff on nashua.dmevals.local at 2020-05-02T03:09:29Z. Security 4656/4663 corroborate the same handles (0x1f3fff/0x1fffff on \Device\HarddiskVolume2\Windows\System32\lsass.exe). The 10 SAM_SERVER 4656 events are all lsass.exe itself under SCRANTON$ at 23:19-23:20 local, coinciding with a system restart (wininit/csrss re-opening lsass at 03:19:09Z), i.e. benign. The 0x1fffff/0x1f3fff lsass handles are the credential-theft step that would feed offline cracking, but no cracking itself was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-22bb04bbc2 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-22bb04bbc2 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-ee2269bc0e | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-ee2269bc0e | ok |
| 5 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgwo_a | q-1a6b1a19af | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo57 | q-e5a67a9e73 | ok |
| 7 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectType | SAM_SERVER | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsS38Vi | q-6cb0594009 | ok |

### F16 · suspicious / medium · T1110.003 · No password spraying; the only explicit-credential logons are PsExec reuse of the already-known pbeesly password

Evidence status: **verified**

There are no 4625 failures, so no spray pattern exists. The 15 4648 explicit-credential events are: 9 for pbeesly (5 on scranton.dmevals.local targeting NASHUA from 10.0.1.6, 4 on nashua.dmevals.local from C:\Windows\PSEXESVC.exe), plus DWM-1/DWM-2/UMFD-0/UMFD-1/UMFD-2/SCRANTON$ from winlogon/wininit/taskhostw (normal session setup). The pbeesly 4648s pair with PsExec64.exe being run on scranton.dmevals.local at 2020-05-02T03:11:18Z with the cleartext password on the command line (\\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe), followed by python.exe launching on nashua.dmevals.local under PSEXESVC.exe at 03:11:40Z. This is reuse of a single already-obtained credential for lateral movement, not spraying across many accounts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2r93 | q-e4af1ec663 | ok |
| 2 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2b9g | q-e4af1ec663 | ok |
| 3 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0ff | q-5de6ff96e3 | ok |
| 4 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0ff | q-5de6ff96e3 | ok |

### F21 · suspicious / medium · T1212 · LSASS accessed with full-access rights by PowerShell (scranton) and wsmprovhost (nashua) during a pbeesly intrusion — no exploitation of a vulnerable service observed

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976) opened lsass.exe (PID 736) twice within 31 ms at 2020-05-02T03:05:16 (GrantedAccess 0x1f3fff and 0x1fffff, call trace ending in UNKNOWN modules), and on nashua.dmevals.local wsmprovhost.exe (PID 7720) opened lsass.exe (PID 728) with 0x1f3fff at 03:09:29. These are the only high-access LSASS handles in the window; the other 317 LSASS accesses are svchost/Azure agent reads at 0x1000/0x1400. The surrounding activity on scranton is hands-on-keyboard by user pbeesly: accesschk.exe (03:04:34), sdelete64.exe against Draft.Zip and SysinternalsSuite.zip (03:03:14/03:03:33), csc.exe/cvtres.exe compiling from C:\Users\pbeesly\AppData\Local\Temp (03:08:03), PsExec64.exe to \\NASHUA with the cleartext password for dmevals\pbeesly (03:11:18), and hidden encoded PowerShell plus 'Get-ItemPropertyValue HKLM:\SOFTWARE\Javasoft ... \| Invoke-Expression' spawned from hostui.exe (03:21:27). However, nothing retrieved shows exploitation of a vulnerable service/application to obtain these handles: no crash-then-child pattern, no service/app process spawning children (parents are services.exe, svchost.exe, cmd.exe, powershell.exe, Azure agents), no Mimikatz/sekurlsa script blocks (4104 search returned none), and the LSASS call traces point to PowerShell/.NET rather than an exploited process. Credential access is real but the T1212 exploitation vector is unconfirmed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-e3e20d0625 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-e3e20d0625 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-c1a7a93707 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-23b29e49f9 | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-23b29e49f9 | ok |

### F40 · suspicious / medium · T1557.001 · SMB/RPC/WinRM traffic to NASHUA (10.0.1.6) carried by the spoofed MAC; NetBIOS name-service broadcasts on the wire

Evidence status: **verified**

The poisoned L2 path is used for SMB (445), RPC endpoint mapper (135), WinRM (5985) and HTTP (80) sessions toward 10.0.1.6, i.e. the attacker MAC is positioned on the SMB/RPC path where NTLM relay would occur. Zeek also records NetBIOS name-service broadcasts to 10.0.1.255:137 from 10.0.1.4 (00:35:01.874Z) and from 10.0.1.6 (00:34:51.731Z) — the name-resolution traffic that is poisonable for SMB relay. However, no relayed authentication or poisoned name resolution is directly proven: the SMB sessions to 10.0.0.4 are RSTO (reset/timeout) and the 4624 records show only normal machine-account (type 3) and pbeesly logons. The Windows-side DNS client registry keys (Sysmon 13 *DNSClient*) had zero hits, so no host-level name-resolution tampering is visible.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:35:25.606Z | bobs.bigwheel.local | zeek | destination.port | 445 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8u4rQ | q-cf24d843af | ok |
| 2 | 2020-04-30 00:35:25.606Z | bobs.bigwheel.local | zeek | zeek.conn_state | RSTO | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8u4rQ | q-cf24d843af | ok |
| 3 | 2020-04-30 00:35:01.874Z | simplerockbuild.simplerock.lan | zeek | destination.port | 137 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4uM | q-b20af04fa2 | ok |
| 4 | 2020-04-30 00:35:01.874Z | simplerockbuild.simplerock.lan | zeek | source.ip | 10.0.1.4 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4uM | q-b20af04fa2 | ok |
| 5 | 2020-04-30 00:35:01.874Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 10.0.1.255 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4uM | q-b20af04fa2 | ok |
| 6 | 2020-04-30 00:34:51.731Z | bobs.bigwheel.local | zeek | destination.port | 137 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8u4rw | q-f98ba0bbfc | ok |
| 7 | 2020-04-30 00:34:51.731Z | bobs.bigwheel.local | zeek | source.ip | 10.0.1.6 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8u4rw | q-f98ba0bbfc | ok |

### F03 · benign / medium · T1003.003 · No NTDS.dit access or copy observed

Evidence status: **verified**

No evidence of NTDS.dit theft. File-creation events matching ntds/.dit/.dmp returned only two Windows Error Reporting crash dumps (C:\ProgramData\Microsoft\Windows\WER\Temp\WER51F5.tmp.dmp and WER5437.tmp.dmp), and no process command line contained ntds, vssadmin, shadow or procdump. The domain controller newyork.dmevals.local shows only machine-account network logons (NEWYORK$, NASHUA$, WEC$, SCRANTON$ type 3) and no directory-service replication access was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-ce7a7de0be | ok |

### F04 · benign / medium · T1003.004 · LSA secrets not accessed by any non-system process

Evidence status: **verified**

The only LSASS accessors with elevated rights were the malicious PowerShell/wsmprovhost handles (covered under T1003.001); all other LSASS handle sources are baseline (svchost.exe 289 events at 0x1000, Azure AntimalwareConfig.exe 15, WindowsAzureTelemetryService.exe 13, plus wininit/csrss/services). Registry modifications touching SECURITY/LSA paths were limited to HKLM\SECURITY\Cache\NL$1 (5 events) and benign CredentialEnrollmentManagerUserSvc / CredentialGuard service keys; no SECURITY\Policy\Secrets access was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-0bfcc4bd43 | ok |

### F05 · benign / medium · T1003.005 · Cached domain credential store (SECURITY\Cache) not read by attacker tooling

Evidence status: **verified**

Registry writes to HKLM\SECURITY\Cache\NL$1 (5 events) are the only cached-credential-related modifications and are consistent with normal logon cache maintenance; the remaining 'Cache' matches are unrelated (NetworkList NLA cache, TaskCache, AppContainer Internet Settings cache). No process was observed reading the SECURITY\Cache hive, and the LSASS access that could expose DCC2 hashes is the same PowerShell/wsmprovhost activity already reported under T1003.001.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-18b18aa251 | ok |

### F06 · benign / medium · T1003.006 · No DCSync / DRSUAPI replication abuse observed

Evidence status: **verified**

No process command line or PowerShell script block contained drsuapi, lsadump, dcsync or Invoke-Mimikatz. The only PowerShell script blocks on the DC newyork.dmevals.local are DSC resource modules (xDNSServerAddress, xStorage, MSFT_ScriptResourceStrings) and AD cmdlet help text, all running as SYSTEM. Directory replication access was not observed on newyork.dmevals.local.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:32.000Z | newyork.dmevals.local | windows.powershell | host.name | newyork.dmevals.local | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCk1Ol | q-fb84b18f03 | ok |

### F07 · benign / high · T1040 · netsh trace packet capture on scranton.dmevals.local is Azure Network Watcher agent telemetry, not adversary sniffing

Evidence status: **verified**

On 2020-05-02 at 03:19:17 UTC the only packet-capture activity in the whole dataset appeared on scranton.dmevals.local: netsh.exe was launched as NT AUTHORITY\SYSTEM (LogonId 0x3E7) with 'netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl"'. Both Sysmon EID 1 and Security EID 4688 show the parent as C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe (PID 3180, '/service'), and the capture was stopped 7 seconds later by the same parent ('netsh.exe trace stop'). The surrounding activity is the Azure guest-agent/Network Watcher lifecycle: NetworkWatcherAgent.exe /service at 03:19:13, logman.exe stop/create/start of GAEvents and RTEvents writing to C:\WindowsAzure\Logs\*.etl, and NetworkWatcherAgent.exe Test/Install/Start /service /autoStart at 03:20:41-42. No third-party or offensive capture tooling was found: no pktmon, windump, tcpdump, rawcap, dumpcap, Wireshark or promiscuous-mode command lines in Sysmon EID 1 or Security 4688, no capture-related driver/image loads (pktmon/npcap/wpcap/ndiscap) in Sysmon EID 6, and no PowerShell capture scripting (4104 check C047 zero hits). The 7045 service installs in windows.other are javamtsup.exe and repeated PSEXESVC.exe (pbeesly) on nashua, unrelated to packet capture. Zeek data (2020-04-30) does not overlap the Windows window and shows only ordinary conn/ssl/dns/smb/kerberos logs with no capture-specific record type. Conclusion: T1040 is not evidenced as attacker behaviour; the netsh trace is legitimate Azure platform network diagnostics.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkYcTxy | q-cf3871991c | ok |
| 2 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkYcTxy | q-b1d98f56c0 | ok |
| 3 | 2020-05-02 03:19:24.835Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpp7sQg | q-ceab4de430 | ok |
| 4 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | win.ParentProcessName | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsU5KNV | q-90fa4df4a9 | ok |
| 5 | 2020-05-02 03:19:13.877Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe" /service | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchIttyFQdU | q-9ebcff2a4c | ok |
| 6 | 2020-05-02 03:19:29.878Z | scranton.dmevals.local | windows.sysmon | process.command_line | "logman.exe" create trace GAEvents -max 50 -f bincirc -o C:\WindowsAzure\Logs\WaAppAgent.etl -p "{3000b92b-ca8b-4269-90ea-c4185ee09e92}" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpo7P8B | q-9ebcff2a4c | ok |
| 7 | 2020-05-02 03:20:42.017Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe"  Start /service /autoStar… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkORY1E | q-9ebcff2a4c | ok |

### F10 · benign / medium · T1056.001 · No keylogger artifacts: no keyboard-hook registry writes or keylogging script blocks

Evidence status: **verified**

The 17,541 Sysmon registry-value-set (event 13) events are dominated by W32Time, DeliveryOptimization, UserAssist, BAM and ContentDeliveryManager keys; the 1,357 hits for Keyboard/keylog/Services registry paths are ordinary service configuration writes (e.g. svchost.exe writing HKLM\System\CurrentControlSet\Services\W32Time\Config\LastKnownGoodTime). No 4104 script block contained GetAsyncKeyState, keylog or SetWindowsHookEx. No keylogger persistence or configuration key was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:29.635Z | nashua.dmevals.local | windows.sysmon | win.TargetObject | HKLM\System\CurrentControlSet\Services\W32Time\Config\LastKnownGoodTime | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpk1gg4 | q-580691273e | ok |

### F11 · benign / low · T1056.002 · No GUI input capture (credential prompt spoofing) observed

Evidence status: **verified**

No evidence of fake credential dialogs or GUI input capture was found in the retrieved data; the only GUI-adjacent activity is the .scr payload's full-access handles to conhost/cmd, which is reported under T1056 rather than as GUI prompt capture.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:04.487Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | \\?\C:\windows\system32\conhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpk1Agy | q-2d340ae96f | ok |

### F12 · benign / medium · T1056.003 · No web portal capture: no IIS/wwwroot/aspx writes or login-page HTTP activity

Evidence status: **verified**

Checks for file writes to wwwroot/inetpub/.aspx, IIS/appcmd/w3wp command lines, PowerShell referencing wwwroot/inetpub/appcmd, and HTTP URLs containing login/auth/signin all returned zero hits, so no web portal credential-capture activity was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWV3 | q-1d99e790cd | ok |

### F13 · benign / high · T1110 · No brute-force authentication activity observed; credential theft was done by dumping lsass, not by guessing

Evidence status: **verified**

Across the whole windows.security window (2020-05-02T02:55:25Z..03:28:09Z, 4 hosts) there are zero 4625 failed-logon events, zero 4771/4776 failure statuses and zero 4740 lockouts. The only 4776 in the dataset is a successful NTLM validation (Status 0x0) for pbeesly on newyork.dmevals.local at 2020-05-01T23:20:40-04:00. Successful 4624 logons are dominated by machine accounts (NEWYORK$ 123, SCRANTON$ 37, NASHUA$ 25) and pbeesly (20, type 3), consistent with normal service/network logons. No authentication-failure burst exists to support a brute-force hypothesis.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO14sT | q-956ae0b6d3 | ok |
| 2 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | event.code | 4776 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO14sT | q-956ae0b6d3 | ok |

### F14 · benign / high · T1110.001 · No password guessing: zero 4625 events on any host

Evidence status: **verified**

The count of event.code:4625 in windows.security is 0 for the entire collection window, so there is no repeated failed authentication against any account or host that would indicate password guessing. The credential access that did occur on scranton.dmevals.local was memory-based (lsass handle with 0x1fffff), not password guessing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO14sT | q-956ae0b6d3 | ok |

### F17 · benign / high · T1110.004 · No credential stuffing: no failed logons and no multi-account credential list use

Evidence status: **verified**

Credential stuffing requires many failed authentications from a list of stolen credentials; windows.security contains 0 events with event.code:4625 and no 4771/4776 failure statuses, and the 218 type-3 network logons involve only machine accounts plus pbeesly. The single account used with explicit credentials is pbeesly, so there is no evidence of stuffing a credential list against the hosts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO14sT | q-956ae0b6d3 | ok |

### F19 · benign / high · T1111 · Smart-card / crypto registry and service activity is Windows baseline, not MFA interception

Evidence status: **verified**

The only smart-card/crypto-related registry writes were made by core Windows processes during normal boot/startup on scranton.dmevals.local: smss.exe setting Cryptography\Calais symbolic links, taskhostw.exe writing CertificateTemplateCache timestamps, and services.exe writing an MUICache entry for SCardSvr.dll ('Smart Card'). No smart-card or MFA provider DLL was registered, replaced or configured by a non-system process, and no script block referenced smart-card/MFA APIs (the three 4104 hits were unrelated module/help text and an exfiltration function). The 7045 service installs were javamtsup.exe and repeated PSEXESVC.exe (PsExec lateral movement by pbeesly), not MFA-provider tampering. LSASS handle opens with 0x1000/0x1400 by svchost.exe, AntimalwareConfig.exe and WindowsAzureTelemetryService.exe are routine security/telemetry reads.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:49.376Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\.DEFAULT\Software\Classes\Local Settings\MuiCache\4\52C64B7E\@%SystemRoot%\System32\SCardSvr.dll,-1 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkTWMJ0 | q-e341cd588f | ok |
| 2 | 2020-05-02 03:19:09.177Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\smss.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkZdAbb | q-e341cd588f | ok |
| 3 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | process.executable | %SystemRoot%\PSEXESVC.exe | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWV3 | q-ef41b6a081 | ok |

### F20 · benign / medium · T1187 · No forced-authentication (T1187) activity observed; LSASS reads and SMB traffic are benign system/administrative behaviour

Evidence status: **verified**

Hunting for T1187 on 2020-05-02 02:55–03:28Z found no coercion artefacts. The six 4663 events on lsass.exe objects are all AccessMask 0x10 (read) by machine accounts (NEWYORK$, SCRANTON$, NASHUA$, UTICA$) via C:\WindowsAzure\Packages\CollectGuestLogs.exe and MsMpEng.exe, plus one by pbeesly via powershell.exe — routine Azure guest-agent/AV/administrative reads, not credential dumping or forced auth. The three shortcut files created (Sysmon 11) are Explorer 'Recent' .lnk files for pbeesly and a StartUp\hostui.lnk written by powershell.exe on scranton.dmevals.local; the hostui.lnk is part of a local persistence chain (hostui.txt dropped from SysinternalsSuite, Invoke-Persistence -PersistStep 1/2, then hostui.bat -> powershell Start-Process C:\Windows\System32\hostui.exe -verb runas) and points to a local path, not a UNC/WebDAV resource, so it does not force outbound NTLM. SMB (Sysmon 3, port 445) traffic goes only to internal addresses 10.0.0.4, 10.0.1.6 and a link-local IPv6 address, and 5145 IPC$ access shows pbeesly using samr/svcctl/PSEXESVC against newyork and nashua from 10.0.1.4 — lateral PsExec-style administration, not authentication coercion to an attacker host. No WebDAV/NTLM/Responder script blocks were found (C104 zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo54 | q-f91edc9952 | ok |
| 2 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x10 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo54 | q-f91edc9952 | ok |
| 3 | 2020-05-02 03:20:15.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Program Files\Windows Defender\MsMpEng.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsQ2P9A | q-f91edc9952 | ok |
| 4 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpESdr2 | q-a1c51bceaf | ok |
| 5 | 2020-05-02 03:21:19.323Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHoX1uOFchItj59cFt | q-8a8db0f1a5 | ok |
| 6 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.0.4 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpIWWNw | q-4af00a8e3b | ok |
| 7 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.RelativeTargetName | PSEXESVC | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0eh | q-322ae287c2 | ok |

### F22 · benign / high · T1539 · No web session cookie theft observed; browser cookie-store activity on scranton is MicrosoftEdge.exe's own profile I/O

Evidence status: **verified**

Hunting for T1539 across windows.sysmon, windows.security, windows.powershell and windows.other (2020-05-02 02:55–03:28Z) found no evidence of cookie-store theft. The only events touching browser cookie/profile paths are on scranton.dmevals.local under user pbeesly, and every one of them is performed by MicrosoftEdge.exe itself: Sysmon 23 file-delete of Edge AC\Temp ~DF*.TMP files at 03:18:33, Sysmon 11 creation of ...\MicrosoftEdge\User\Default\DataStore\_TempTestAccess.txt at 03:21:05, and Sysmon 11 creation of Edge RecoveryStore .dat and further ~DF*.TMP files at 03:21:05–03:21:06. A query for any non-Edge process touching *microsoftedge*, *google*, *mozilla* or *cookies* paths returned only svchost.exe creating C:\Windows\ServiceProfiles\LocalService\...\AC\INetCookies and Prefetch GOOGLEUPDATE.EXE-B95715F5.pf entries — normal OS/updater behaviour. No Sysmon 10 process-access to chrome/firefox/msedge/iexplore images (check C114, zero hits), no security 4663 object access to Cookies/Login Data/Web Data/Edge/Chrome/Mozilla paths, and no PowerShell 4104 script block referencing cookies, Login Data, sqlite or browser profile paths. The C112 'Cookies/Login Data/Web Data' aggregate hits were false positives from the substring 'DataStore' in GroupPolicy and Edge paths plus lastalive*.dat, not browser credential stores. Separately, the same window does contain clearly malicious activity on scranton.dmevals.local by pbeesly (Invoke-ScreenCapture/Keystroke-Check script block, Invoke-Exfil staging to \\192.168.0.4\webdav, sdelete64 wiping C:\programdata\victim\???cod.3aka3.scr) and PsExec-delivered C:\Windows\Temp\python.exe on nashua.dmevals.local, but none of that activity reads or exfiltrates browser cookie databases, so it is not T1539.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.198Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\DataStore\_TempTestAccess.txt | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkKNpkH | q-3a12824faf | ok |
| 2 | 2020-05-02 03:21:05.198Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkKNpkH | q-3a12824faf | ok |
| 3 | 2020-05-02 03:18:33.063Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\Temp\~DFA8154AA6BD3291F9.TMP | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkfkUhu | q-3481d37317 | ok |
| 4 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkKNZkz | q-a1ad703d63 | ok |
| 5 | 2020-05-02 03:21:15.387Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\Prefetch\GOOGLEUPDATE.EXE-B95715F5.pf | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHoX1uOFchItj59MFD | q-a1ad703d63 | ok |
| 6 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-b2e780d1f4 | ok |
| 7 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2b9g | q-5a5ede2d61 | ok |

### F25 · benign / medium · T1552.002 · Registry credential-key writes are OS components only — no adversary registry credential access

Evidence status: **verified**

The 24 Sysmon registry value-set events touching Password/Credential/Winlogon paths are all attributable to Windows components: services.exe (10), svchost.exe (6), winlogon.exe (6), lsass.exe (1) and wininit.exe (1) on scranton/nashua, covering keys such as CredentialGuard\Enabled, CredentialEnrollmentManagerUserSvc_13619b and Winlogon\PasswordExpiryNotification. No reg query/save/export command lines and no 4663 access to SAM/SECURITY/Password objects were found, so no registry credential harvesting is evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-d4dee03f54 | ok |

### F26 · benign / medium · T1552.006 · SYSVOL/GPO reads are routine machine-account policy refresh, not GPP cpassword harvesting

Evidence status: **verified**

The 38 5145 SMB accesses to \\*\SYSVOL are gpt.ini, Policies, Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf reads performed by computer accounts (NEWYORK$, SCRANTON$, NASHUA$) from their own IPs during normal Group Policy refresh; no Groups.xml, cpassword, gpprefdecrypt or AES-key script/command activity was found in PowerShell, Sysmon process or file events.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.RelativeTargetName | dmevals.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\gpt.ini | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwxXRM1 | q-0550904033 | ok |
| 2 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | win.RelativeTargetName | dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwsQxHO | q-0550904033 | ok |

### F29 · benign / medium · T1555.003 · No browser credential-store access observed

Evidence status: **verified**

Hunting for browser password stores (Chrome 'Login Data'/'Local State', Firefox logins.json/key4.db) found no file creation, no process command line and no object-access audit referencing them on any host. The only file-creation hit was an unrelated INetCookies file written by svchost.exe under the LocalService service profile on scranton.dmevals.local, which is normal Windows behaviour. The actor on scranton did run a recursive file-collection script matching *pass*, *login*, *admin* patterns and compressed the results, but no browser credential database was touched in the retrieved events.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkKNZkz | q-298d525900 | ok |
| 2 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwHqJZm | q-89b1d4c2ef | ok |

### F30 · benign / medium · T1555.004 · No Windows Credential Manager (vault/cmdkey) harvesting observed; LSASS access is covered under T1555

Evidence status: **verified**

No vaultcmd, cmdkey or Credential-Manager command lines appeared in Sysmon process creation or Security 4688, and no process-access events targeted vaultsvc. The only 'vault/credential' text hits were benign: a Credential Guard configuration message (event 14) on scranton.dmevals.local and PowerShell script blocks containing unrelated words ('validate', 'Get-CommonADParameters'). The rare LSASS handle masks (0x1F3FFF/0x1FFFFF by PowerShell.exe as pbeesly on scranton) are reported under T1555; the remaining LSASS accessors (svchost.exe with 0x1000/0x101001 via lsm.dll, wininit.exe/csrss.exe at boot, WindowsAzureTelemetryService.exe and AntimalwareConfig.exe with 0x1400) are normal system/AV behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWX1 | q-c63b262d19 | ok |
| 2 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x101001 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkady05 | q-dc16869130 | ok |
| 3 | 2020-05-02 03:19:42.009Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1400 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkbfEQ2 | q-dc16869130 | ok |

### F31 · benign / medium · T1555.005 · No password-manager (KeePass/1Password/Bitwarden/LastPass) access observed

Evidence status: **verified**

No process creation, process access, file creation (.kdbx/keepass/1password/bitwarden), Security 4688 or PowerShell script block referencing a third-party password manager was found on any of the four hosts. The only credential-adjacent theft in the data is the LSASS handle access on scranton.dmevals.local, which is not a password-manager store.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | host.name | scranton.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpk1QgV | q-3d960db916 | ok |

### F33 · benign / medium · T1556.001 · No domain-controller authentication tampering; 4624/4648 logons are routine machine-account and pbeesly activity

Evidence status: **verified**

297 successful logons (4624) are dominated by machine accounts NEWYORK$ (123), SYSTEM (60), SCRANTON$ (37), NASHUA$ (25) and the user pbeesly (30); the 218 network logons (LogonType 3) are loopback/IPv6 machine-account authentications on newyork.dmevals.local. The 15 explicit-credential logons (4648) are pbeesly re-using its own credentials, including four from C:\Windows\PSEXESVC.exe on nashua.dmevals.local between 23:11:40 and 23:15:03 local time — consistent with lateral movement by the same actor, not with a backdoor authentication mechanism. No 4657 changes to LSA/SecurityProviders keys, no 4739 policy changes, no 5136 directory-service changes, and no lsass image-load of a third-party module were observed, so no DC authentication-process modification is evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0ff | q-756c2923a5 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | user.name | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0ff | q-756c2923a5 | ok |
| 3 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwxYBM5 | q-ee7d116a59 | ok |

### F34 · benign / medium · T1556.002 · No password-filter (Notification Packages) DLL registration observed

Evidence status: **verified**

No 4657 registry-value modification referenced Notification Packages, lsa or Password keys, and no PowerShell 4104 script block mentioned Notification Packages, PasswordFilter or HKLM\...\lsa. The 36 registry-value modifications (4657) that do exist are unrelated: certificate blob writes by C:\Windows\Sysmon.exe on nashua.dmevals.local and WMI Autologger EventLog-Application value changes by wevtutil.exe on scranton.dmevals.local. No password-filter DLL was registered.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhDM5P | q-ae2048ee04 | ok |
| 2 | 2020-05-02 03:08:50.000Z | scranton.dmevals.local | windows.security | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjGP74 | q-ed70f80f7c | ok |

### F35 · benign / medium · T1556.005 · No reversible-encryption or account-control changes; no 4739 policy events

Evidence status: **verified**

Event 4739 (domain policy change) returned zero hits, and no 4688 command line, PowerShell 4103 payload, sysmon process creation or windows.other message referenced Reversible, Set-ADAccountControl, Set-ADUser or dsmod. The only AD-related PowerShell script blocks seen were generic Get-ADUser/New-ADUser helper functions on newyork.dmevals.local, not account-flag changes. No reversible-encryption tampering is evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:32.000Z | newyork.dmevals.local | windows.powershell | host.name | newyork.dmevals.local | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwDlAOq | q-74ad192c78 | ok |

### F36 · benign / medium · T1556.006 · No MFA modification observed

Evidence status: **verified**

No 4739 domain-policy-change events were returned in windows.security, and nothing in the retrieved events touched multi-factor authentication configuration. The observed malicious activity (steganographic PowerShell loader, LSASS handle with 0x1FFFFF, WebDAV exfiltration to 192.168.0.4) does not include MFA tampering.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-4c3f95d0e1 | ok |

### F37 · benign / medium · T1556.007 · No hybrid-identity / directory-service object modification (5136) observed

Evidence status: **verified**

Event 5136 (directory service object modified) returned zero hits in windows.security, so no AD object or hybrid-identity configuration was altered in this window. The AD-related PowerShell on newyork.dmevals.local was read/parameter-helper code, not a federation or sync configuration change.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | host.name | newyork.dmevals.local | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwDl0_c | q-74ad192c78 | ok |

### F38 · benign / medium · T1556.008 · No Network Provider DLL registration observed

Evidence status: **verified**

No sysmon registry-set (event 13) or file-create (event 11) touched a NetworkProvider path, and no 4657 modification referenced NetworkProvider. The 442 registry-set hits matching lsa/NetworkProvider/Notification/WDigest/SecurityProviders were all benign Windows notification and AppContainer/ContentDeliveryManager writes by Explorer.EXE, RuntimeBroker.exe, DllHost.exe, backgroundTaskHost.exe and SearchProtocolHost.exe. No credential-provider DLL was installed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:09.240Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications\Data\418A073AA3BC3475 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItphxmvL | q-fa57115dd9 | ok |
| 2 | 2020-05-02 02:59:17.458Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\DllHost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpeuBtX | q-2df8d448b8 | ok |

### F42 · benign / medium · T1557 · Windows-side hits (4670 token permission changes, 4697 service installs, PsExec to NASHUA) are benign/adjacent, not AiTM

Evidence status: **verified**

The 143 event.code 4670 hits are all 'Object Server: Security / Object Type: Token' permission changes by SYSTEM machine accounts (SCRANTON$, NEWYORK$) from SearchIndexer.exe, svchost.exe and services.exe — routine token DACL churn, not network interception. The 4697/7045 service installs are the Java VM support service (javamtsup) on scranton and repeated PSEXESVC installs on nashua by pbeesly, plus a burst of svchost-based per-user services on scranton. The PsExec64.exe execution on scranton at 2020-05-02T03:11:18Z (parent powershell.exe, user pbeesly) with the command line containing a cleartext password for dmevals\pbeesly and launching C:\Windows\Temp\python.exe on \\NASHUA is lateral movement / credential misuse, not adversary-in-the-middle, and is out of scope for T1557. No Windows event in this window shows ARP, DHCP or name-resolution tampering.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:57:01.000Z | scranton.dmevals.local | windows.security | win.ObjectType | Token | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwxXBPl | q-a3b0497f33 | ok |
| 2 | 2020-05-02 02:57:01.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\SearchIndexer.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwxXBPl | q-a3b0497f33 | ok |
| 3 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.security | win.ServiceName | PSEXESVC | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEck | q-a8b026edd9 | ok |
| 4 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2r93 | q-be48122999 | ok |
| 5 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | host.name | scranton.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2r93 | q-be48122999 | ok |

### F41 · benign / high · T1557.003 · No DHCP spoofing observed — no DHCP traffic, no rogue DHCP server events

Evidence status: **verified**

No DHCP activity exists in any dataset. Zeek conn logs contain no UDP 67/68 flows (UDP destination ports are only 53, 389, 138, 123, 137). Sysmon event.code 3 UDP destinations likewise show no 67/68. windows.other contains no DHCP-server events (1341/1342/1020/1063 returned zero hits) and windows.powershell has no dhcp/rogue references. The only broadcast traffic is normal NetBIOS name service (137/138) and NTP/DNS. Nothing indicates a rogue DHCP server or DHCP option tampering.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:08:43.385Z | bobs.bigwheel.local | zeek | destination.port | 138 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8vYpc | q-82243fc5e4 | ok |
| 2 | 2020-04-30 00:08:43.385Z | bobs.bigwheel.local | zeek | network.transport | udp | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8vYpc | q-82243fc5e4 | ok |

### F44 · benign / medium · T1558.001 · No golden-ticket indicators: krbtgt TGTs are normal pre-authenticated AS exchanges

Evidence status: **verified**

All 14 4768 events on newyork.dmevals.local are ordinary AS-REQ/TGT issuance for krbtgt with PreAuthType 2 (pre-authentication performed), TicketEncryptionType 0x12 (AES256) and Status 0x0, for accounts pbeesly and the machine account SCRANTON$. No forged-TGT hallmarks (RC4 0x17, missing pre-auth, anomalous lifetimes) appear, and no krbtgt/golden/mimikatz strings exist in PowerShell or other Windows logs. The LSASS full-access reads above are the precursor to krbtgt theft, but no golden-ticket use is evidenced in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:45.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO1osm | q-81d6f9242e | ok |
| 2 | 2020-05-02 03:19:34.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsZ8ncx | q-81d6f9242e | ok |

### F45 · benign / medium · T1558.002 · No silver-ticket indicators in TGS requests

Evidence status: **verified**

The 28 4769 events on newyork.dmevals.local are service-ticket requests for machine accounts (NEWYORK$, NASHUA$, SCRANTON$, WEC$) and krbtgt, all with Status 0x0 and AES256 (0x12) encryption, issued to pbeesly and SCRANTON$ from 10.0.1.4/10.0.1.6. No RC4-encrypted service tickets, no anomalous service names, and no silver/service-ticket strings in any log. Nothing indicates forged service tickets.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:14.000Z | newyork.dmevals.local | windows.security | win.ServiceName | WEC$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItse-34r | q-81d6f9242e | ok |
| 2 | 2020-05-02 03:20:46.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO1osw | q-81d6f9242e | ok |

### F46 · benign / medium · T1558.003 · No Kerberoasting: no RC4 TGS bursts or SPN enumeration

Evidence status: **verified**

No 4769 request uses RC4 (0x17) encryption, the signature of Kerberoasting, and no SPN/Kerberoast/Rubeus strings appear in PowerShell or other Windows logs. Zeek kerberos data (2020-04-30, non-overlapping window) shows only 14 AS and 11 TGS requests with a single error type KDC_ERR_PREAUTH_REQUIRED, consistent with normal authentication. The observed TGS volume is low and tied to machine-account service access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjGP6m | q-81d6f9242e | ok |

### F47 · benign / medium · T1558.004 · No AS-REP Roasting indicators

Evidence status: **verified**

Every 4768 in the dataset carries PreAuthType 2, meaning Kerberos pre-authentication was required and performed; AS-REP Roasting depends on accounts with pre-auth disabled. No asreproast/GetNPUsers/DontReqPreAuth strings were found in Sysmon process command lines, PowerShell script blocks, or other Windows logs.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:34.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsZ8ncx | q-81d6f9242e | ok |

### F48 · benign / high · T1606 · No forged web credentials observed; certificate export and WebDAV cookie activity are unrelated to T1606

Evidence status: **verified**

Across windows.security, windows.sysmon and windows.powershell (2020-05-02 02:55–03:28Z) there is no evidence of forged web credential material. The 4624 logon-process stack is dominated by Kerberos (217) and Advapi (76) with only 2 User32, 1 NtLmSsp and 1 '-' entries; the User32/NtLmSsp entries are pbeesly interactive (type 10) and network (type 3) logons from 172.18.39.2 on scranton, and the '-' entry is a SYSTEM type-0 boot logon — all normal. The single PowerShell 4104 hit matching token/cookie keywords is the Sysinternals helper function Get-AttributesMask in C:\Program Files\SysinternalsSuite\readme.ps1 (SE_GROUP_* token attribute constants), not credential forging. The rare Sysmon process-access masks resolve to svchost/consent/wininit/Explorer/service-host interactions with system processes (e.g. wininit.exe -> lsass.exe 0x1000000, services.exe -> svchost.exe 0x18), which are normal Windows behaviour. Separately, the host does show a real intrusion (pbeesly running discovery, persistence, screen capture, keystroke jobs, sdelete and WebDAV exfiltration to 192.168.0.4), but that is credential/certificate theft and exfiltration, not T1606 web credential forging.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkCwA | q-1211f4201d | ok |
| 2 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | NtLmSsp  | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO1ovv | q-479cfa8134 | ok |
| 3 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | - | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsc-QNb | q-479cfa8134 | ok |
| 4 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JAv | q-1ee78a0c11 | ok |

### F49 · benign / high · T1606.001 · WebDAV DavSetCookie invocations are WebClient-service artifacts of the exfiltration script, not forged web cookies

Evidence status: **verified**

Six rundll32.exe executions of 'davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav' ran as DMEVALS\pbeesly on scranton.dmevals.local at 03:08:50 and 03:10:22-23Z (Sysmon 1 and Security 4688). Their parent is svchost.exe -k LocalService -p -s WebClient, i.e. the Windows WebDAV redirector service, and they coincide with the WebClient service start at 03:08:47Z. This is the normal mechanism by which the WebClient service stores WebDAV auth cookies when the PowerShell Invoke-Exfil function maps \\192.168.0.4\webdav via New-PSDrive — the cookie is being set by the OS for the attacker's own WebDAV share, not a forged/stolen web session cookie being injected. No cookie-file writes to browser stores were found; the only cookie-related file creation is a benign INetCookies package path under the LocalService profile. The underlying exfiltration is malicious, but it is not T1606.001.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkv3sHT | q-1b3c3e6ce1 | ok |
| 2 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | C:\windows\system32\svchost.exe -k LocalService -p -s WebClient | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkv3sHT | q-350e0aa658 | ok |
| 3 | 2020-05-02 03:08:47.859Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\svchost.exe -k LocalService -p -s WebClient | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkx5Y2d | q-1863d48ef1 | ok |
| 4 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-5db27242ee | ok |
| 5 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkKNZkz | q-0ee0335e22 | ok |

### F50 · benign / high · T1606.002 · No SAML token forging; certificate export via Get-PrivateKeys is local cert theft, not token-signing abuse

Evidence status: **verified**

No SAML/ADFS token-signing activity exists in the data: no ADFS service, no SAML tooling, no token-signing certificate registry or file artifacts, and no 4624/4648 logons attributable to forged SAML assertions. The 4648 explicit-credential logons are 9 for pbeesly (PSEXESVC.exe on nashua and pbeesly->NASHUA from 10.0.1.6 on scranton) plus DWM/UMFD/SCRANTON$ machine-account entries — PsExec lateral movement, not SAML. The one certificate-related action is PowerShell function Get-PrivateKeys (readme.ps1) run by pbeesly at 03:04:56Z, which enumerates cert:\LocalMachine and exports each certificate to a random .pfx in Downloads with password 'saribas'; this produced C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx at 03:04:57Z. That is local private-key/certificate theft (a Credential Access action) but it is not forging of SAML tokens, so T1606.002 is not observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-500e2c9c65 | ok |
| 2 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-0ee0335e22 | ok |
| 3 | 2020-05-02 03:15:03.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwiDnzA | q-54b35d6a38 | ok |
| 4 | 2020-05-02 03:14:42.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwiDnzL | q-54b35d6a38 | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | not assessed |  |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | not assessed |  |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | not assessed |  |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | not assessed |  |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | not assessed |  |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | not assessed |  |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | not assessed |  |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | not assessed |  |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | not assessed |  |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | not assessed |  |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | not assessed |  |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | not assessed |  |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | not assessed |  |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | not assessed |  |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | not assessed |  |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | not assessed |  |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | not assessed |  |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | not assessed |  |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | not assessed |  |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | not assessed |  |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | not assessed |  |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | not assessed |  |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | not assessed |  |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | 1 | C:\Windows\System32\services.exe | not assessed |  |
| scranton.dmevals.local | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | 1 | C:\Windows\System32\services.exe | not assessed |  |
| scranton.dmevals.local | C:\WindowsAzure\Packages\WaAppAgent.exe | 1 | C:\Windows\System32\services.exe | not assessed |  |
| scranton.dmevals.local | C:\WindowsAzure\SecAgent\WaSecAgentProv.exe | 2 | C:\WindowsAzure\Packages\WaAppAgent.exe | not assessed |  |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\Plugins\VFPl… | 1 | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | not assessed |  |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | 1 | C:\Windows\System32\services.exe | not assessed |  |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | Credential dumping activity confirmed via LSASS full-access handles from PowerShell/wsmprovhost under user pbeesly on scranton and nashua, inside a broader intrusion (Invoke-Exfil, PsExec64 with cleartext password, WebDA… |
| T1003.001 LSASS Memory | malicious | PowerShell.exe (scranton, 03:05:16Z) and wsmprovhost.exe (nashua, 03:09:29Z) opened LSASS with 0x1fffff/0x1f3fff, corroborated by Security 4656/4663 with SubjectUserName pbeesly. |
| T1003.002 Security Account Manager | suspicious | SAM_SERVER handles with 0xf003f and SamSs registry handles on scranton during the intrusion window, but requested by lsass.exe itself (SCRANTON$); no hive export or SAM file creation seen. |
| T1003.003 NTDS | not_observed | No ntds/.dit file creation, no vssadmin/shadow/procdump command lines, no directory replication access on the DC. |
| T1003.004 LSA Secrets | not_observed | No SECURITY\Policy\Secrets access; registry hits limited to HKLM\SECURITY\Cache\NL$1 and benign CredentialEnrollmentManager/CredentialGuard keys. |
| T1003.005 Cached Domain Credentials | not_observed | Only routine HKLM\SECURITY\Cache\NL$1 writes; no process read the cached-credential store. |
| T1003.006 DCSync | not_observed | No drsuapi/lsadump/dcsync strings in process command lines or PowerShell script blocks; DC PowerShell blocks are DSC/AD module content. |
| T1040 Network Sniffing | benign | The only packet-capture activity (netsh.exe trace start capture=yes writing an .etl to C:\windows\TEMP on scranton.dmevals.local, 03:19:17 UTC) was spawned by and stopped by the Microsoft Azure Network Watcher agent (Net… |
| T1056 Input Capture | suspicious | Suspicious .scr (scranton) and C:\Windows\Temp\python.exe (nashua) payloads opened 0x1FFFFF handles to conhost/cmd/powershell, consistent with input capture/injection, but no capture mechanism was directly observed. |
| T1056.001 Keylogging | not_observed | No keyboard-hook registry keys, keylogger services, or GetAsyncKeyState/keylog/SetWindowsHookEx script blocks; registry writes were routine service/system configuration. |
| T1056.002 GUI Input Capture | not_observed | No credential-prompt spoofing or GUI input capture artifacts in the retrieved events. |
| T1056.003 Web Portal Capture | not_observed | Zero hits for wwwroot/inetpub/aspx writes, IIS/appcmd/w3wp command lines, or login/auth/signin HTTP URLs. |
| T1056.004 Credential API Hooking | malicious | DMEVALS\pbeesly PowerShell (scranton) and wsmprovhost (nashua) requested 0x1f3fff/0x1fffff handles to lsass.exe including read/write process memory — credential API hooking/memory access pattern. |
| T1110 Brute Force | not_observed | Zero 4625 failed logons, zero 4771/4776 failures and zero 4740 lockouts in windows.security; the only 4776 is a success (Status 0x0). No brute-force authentication pattern exists. |
| T1110.001 Password Guessing | not_observed | event.code:4625 count is 0 across all four hosts for the entire window; no repeated failed authentication against any account. |
| T1110.002 Password Cracking | suspicious | No cracking tools or hash output files were found, but PowerShell.exe (PID 2976, pbeesly) opened lsass with 0x1f3fff/0x1fffff on scranton and wsmprovhost.exe opened lsass with 0x1f3fff on nashua — dump-grade access that … |
| T1110.003 Password Spraying | suspicious | No spray (no failures), but PsExec64.exe on scranton reused the cleartext pbeesly password against \\NASHUA, producing matching 4648 events and PSEXESVC.exe-spawned python.exe on nashua — single-credential reuse rather t… |
| T1110.004 Credential Stuffing | not_observed | No failed logons and only one account (pbeesly) used with explicit credentials; no evidence of a stolen credential list being replayed across hosts. |
| T1111 Multi-Factor Authentication Interception | suspicious | No MFA/smart-card provider interception was observed (smart-card registry writes were Windows baseline by smss.exe/taskhostw.exe/services.exe). However, on scranton.dmevals.local a hidden steganographic PowerShell loader… |
| T1187 Forced Authentication | not_observed | No forced-authentication artefacts: LSASS 4663 events are 0x10 reads by CollectGuestLogs.exe/MsMpEng.exe/machine accounts; the only StartUp shortcut (hostui.lnk) targets a local path as part of a local persistence chain;… |
| T1212 Exploitation for Credential Access | suspicious | Full-access LSASS handles (0x1fffff/0x1f3fff) were taken by PowerShell on scranton and wsmprovhost on nashua inside a pbeesly intrusion (Sysinternals toolkit, sdelete, PsExec with cleartext password, hidden encoded Power… |
| T1539 Steal Web Session Cookie | not_observed | No process other than MicrosoftEdge.exe itself touched browser cookie/profile stores; no Sysmon 10 access to browser images, no security 4663 access to Cookies/Login Data/Web Data, and no PowerShell script block referenc… |
| T1552 Unsecured Credentials | malicious | Hardcoded plaintext credentials ("saribas", "lolol", "MyCozyPassw0rd!") in attacker PowerShell tooling on scranton.dmevals.local, plus recursive *pass*/*login* file sweep and cert export. |
| T1552.001 Credentials In Files | malicious | PowerShell on scranton recursively collected user-profile files matching *psw*/*pass*/*login*/*admin*/*vpn* into $env:APPDATA\Draft.Zip, then staged Downloads for WebDAV exfiltration. |
| T1552.002 Credentials in Registry | benign | All 24 credential/Winlogon registry value sets came from services.exe, svchost.exe, winlogon.exe, lsass.exe and wininit.exe; no reg query/save/export or SAM/SECURITY object access. |
| T1552.003 Shell History | not_observed | No ConsoleHost_history, history.txt or Get-Content activity in PowerShell, Sysmon process/file or 4663 events. |
| T1552.004 Private Keys | malicious | Get-PrivateKeys exported all LocalMachine certificates with Export-PfxCertificate to C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx on scranton.dmevals.local. |
| T1552.006 Group Policy Preferences | benign | SYSVOL 5145 reads are gpt.ini/GptTmpl.inf policy refresh by machine accounts; no Groups.xml, cpassword or gpprefdecrypt activity. |
| T1555 Credentials from Password Stores | malicious | PowerShell.exe (PID 2976) running as pbeesly on scranton.dmevals.local opened LSASS with 0x1F3FFF and 0x1FFFFF (Sysmon 10) and Security 4656 shows AccessMask 0x1F3FFF including 'Read from process memory', inside a malici… |
| T1555.003 Credentials from Web Browsers | not_observed | No access to Chrome Login Data/Local State or Firefox logins.json/key4.db in file-creation, process-creation or object-access events; only an unrelated svchost INetCookies write. |
| T1555.004 Windows Credential Manager | not_observed | No vaultcmd/cmdkey/Credential Manager activity and no vaultsvc access; LSASS handle access is attributed to T1555, other LSASS accessors are system/AV processes. |
| T1555.005 Password Managers | not_observed | No KeePass/1Password/Bitwarden/LastPass process, file or script activity on any host. |
| T1556 Modify Authentication Process | suspicious | Real credential-access activity is present (hidden steganographic PowerShell on scranton opening lsass.exe with 0x1F3FFF/0x1FFFFF, and wsmprovhost.exe on nashua with 0x1F3FFF), but no authentication-process modification … |
| T1556.001 Domain Controller Authentication | not_observed | 4624/4648 logons are routine machine-account and pbeesly activity (including PSEXESVC lateral movement); no DC authentication tampering, no LSA registry modification, no 4739/5136. |
| T1556.002 Password Filter DLL | not_observed | No 4657 or 4104 activity referencing Notification Packages, PasswordFilter or lsa keys; the 36 registry-value modifications were certificate and WMI Autologger writes. |
| T1556.005 Reversible Encryption | not_observed | Zero 4739 events and no Reversible/Set-ADAccountControl/Set-ADUser/dsmod references in 4688, 4103, sysmon or windows.other. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739 domain-policy-change events and no MFA-related configuration activity in any retrieved event. |
| T1556.007 Hybrid Identity | not_observed | Zero 5136 directory-service object modification events; AD PowerShell seen was generic Get-ADUser/New-ADUser helper code. |
| T1556.008 Network Provider DLL | not_observed | No sysmon registry-set or file-create on NetworkProvider paths and no 4657 NetworkProvider modification; matching registry hits were benign notification/AppContainer writes. |
| T1557 Adversary-in-the-Middle | suspicious | An on-path condition is proven at L2 (duplicate MAC for 10.0.1.4) and the spoofed path carries SMB/RPC/WinRM toward 10.0.1.6, but no Windows-side AiTM artifact (no DNS client registry tampering, no relayed auth) was foun… |
| T1557.001 Name Resolution Poisoning and SMB Relay | suspicious | SMB 445 / RPC 135 / WinRM 5985 sessions to 10.0.1.6 are carried by the spoofed MAC fc:bd:67:e1:a9:c1, and NetBIOS name-service broadcasts are on the wire, but no successful relay or poisoned resolution is directly eviden… |
| T1557.002 ARP Cache Poisoning | malicious | MAC fc:bd:67:e1:a9:c1 claims source IP 10.0.1.4 from 00:33:26Z onward in parallel with the legitimate MAC 00:0d:3a:4d:42:f2, interleaved on the same destinations/ports — classic ARP cache poisoning by an on-path attacker… |
| T1557.003 DHCP Spoofing | not_observed | No DHCP traffic at all: no UDP 67/68 in Zeek conn or Sysmon network events, no DHCP server events (1341/1342/1020/1063 zero hits), no dhcp/rogue strings in PowerShell logs. |
| T1558 Steal or Forge Kerberos Tickets | malicious | Hidden steganographic PowerShell (PID 2976, user pbeesly) on scranton opened lsass.exe with 0x1f3fff/0x1fffff, and wsmprovhost.exe on nashua opened lsass.exe with 0x1f3fff — full LSASS access enabling Kerberos ticket/key… |
| T1558.001 Golden Ticket | not_observed | All 4768 krbtgt TGTs are pre-authenticated (PreAuthType 2) AES256 requests with Status 0x0; no forged-TGT indicators or krbtgt/mimikatz strings. |
| T1558.002 Silver Ticket | not_observed | 4769 service tickets are all AES256 (0x12), Status 0x0, for legitimate machine accounts; no forged service-ticket evidence. |
| T1558.003 Kerberoasting | not_observed | No RC4 (0x17) TGS requests, no SPN enumeration or Kerberoast/Rubeus tooling in any dataset. |
| T1558.004 AS-REP Roasting | not_observed | All AS requests require pre-authentication (PreAuthType 2); no asreproast/GetNPUsers/DontReqPreAuth activity. |
| T1606 Forge Web Credentials | not_observed | No forged web credential material. 4624 logon processes are Kerberos/Advapi dominated with only benign User32/NtLmSsp/'-' entries; the sole token-keyword PowerShell hit is the Sysinternals Get-AttributesMask helper; rare… |
| T1606.001 Web Cookies | not_observed | The six rundll32 davclnt.dll,DavSetCookie 192.168.0.4 invocations are spawned by svchost -k LocalService -s WebClient as the OS WebDAV redirector storing cookies for the attacker's own WebDAV share used by Invoke-Exfil; … |
| T1606.002 SAML Tokens | not_observed | No ADFS/SAML tooling, token-signing certificate artifacts or SAML-derived logons. The only certificate activity is Get-PrivateKeys exporting LocalMachine certs to coyn5igj.3io.pfx (local cert theft), and 4648 logons are … |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | 5 planned checks, all with zero hits |
| T1649 Steal or Forge Authentication Certificates | malicious | On scranton.dmevals.local, PowerShell (user pbeesly) ran Get-PrivateKeys, which recursively enumerated cert:\LocalMachine and used Export-PfxCertificate with hardcoded password 'saribas' to write private-key-bearing .pfx… |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 0 hits | 0 hits | 10977 hits | 773 hits | n/a |
| T1003.001 LSASS Memory | 0 hits | 0 hits | 0 hits | 665 hits | n/a |
| T1003.002 Security Account Manager | 0 hits | 0 hits | 10983 hits | 11331 hits | n/a |
| T1003.003 NTDS | 0 hits | 0 hits | 0 hits | 2 hits | n/a |
| T1003.004 LSA Secrets | 0 hits | 0 hits | 10977 hits | 378 hits | n/a |
| T1003.005 Cached Domain Credentials | 0 hits | 0 hits | 10977 hits | 6951 hits | n/a |
| T1003.006 DCSync | 5 hits | 0 hits | 21 hits | 0 hits | n/a |
| T1040 Network Sniffing | 5 hits | 0 hits | 2 hits | 448 hits | 2140 hits |
| T1056 Input Capture | 5 hits | 0 hits | 10990 hits | 79061 hits | n/a |
| T1056.001 Keylogging | 5 hits | 0 hits | 13 hits | 19368 hits | n/a |
| T1056.002 GUI Input Capture | 5 hits | 5496 hits | 3 hits | 450 hits | n/a |
| T1056.003 Web Portal Capture | 5 hits | 0 hits | 0 hits | 1649 hits | 0 hits |
| T1056.004 Credential API Hooking | n/a | n/a | 5337 hits | 98920 hits | n/a |
| T1110 Brute Force | n/a | n/a | 0 hits | n/a | n/a |
| T1110.001 Password Guessing | n/a | n/a | 0 hits | n/a | n/a |
| T1110.002 Password Cracking | n/a | n/a | 10977 hits | 41379 hits | n/a |
| T1110.003 Password Spraying | n/a | n/a | 15 hits | n/a | n/a |
| T1110.004 Credential Stuffing | n/a | n/a | 0 hits | n/a | n/a |
| T1111 Multi-Factor Authentication Interception | 5 hits | 3 hits | 312 hits | 332 hits | GAP: n/a refused (time window … |
| T1187 Forced Authentication | 4 hits | 0 hits | 169 hits | 69 hits | n/a |
| T1212 Exploitation for Credential Access | 8 hits | 0 hits | 212 hits | 39730 hits | n/a |
| T1539 Steal Web Session Cookie | 4 hits | 13 hits | 460 hits | 371 hits | n/a |
| T1552 Unsecured Credentials | 7 hits | 4 hits | 460 hits | 96 hits | n/a |
| T1552.001 Credentials In Files | 4 hits | 1 hits | 15 hits | 0 hits | n/a |
| T1552.002 Credentials in Registry | 1 hits | 4 hits | 0 hits | 20 hits | n/a |
| T1552.003 Shell History | n/a | 0 hits | 0 hits | 0 hits | n/a |
| T1552.004 Private Keys | n/a | 1 hits | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | n/a | 0 hits | 38 hits | 0 hits | n/a |
| T1555 Credentials from Password Stores | n/a | 0 hits | 6 hits | 653 hits | n/a |
| T1555.003 Credentials from Web Browsers | n/a | 0 hits | 0 hits | 1 hits | n/a |
| T1555.004 Windows Credential Manager | 2 hits | 3 hits | 0 hits | 24641 hits | n/a |
| T1555.005 Password Managers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556 Modify Authentication Process | 4 hits | 0 hits | 0 hits | 744 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | 0 hits | 530 hits | 359 hits | n/a |
| T1556.002 Password Filter DLL | 5 hits | 0 hits | 2 hits | 88 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 1 hits | 0 hits | 0 hits | n/a |
| T1556.006 Multi-Factor Authentication | 0 hits | 0 hits | 41002 hits | 0 hits | n/a |
| T1556.007 Hybrid Identity | 0 hits | 0 hits | 41002 hits | 20259 hits | n/a |
| T1556.008 Network Provider DLL | 0 hits | 0 hits | 0 hits | 39283 hits | n/a |
| T1557 Adversary-in-the-Middle | 0 hits | 0 hits | 11120 hits | 1310 hits | 613 hits |
| T1557.001 Name Resolution Poisoning and SMB Relay | 0 hits | 0 hits | 23 hits | 81 hits | 51 hits |
| T1557.002 ARP Cache Poisoning | 0 hits | 0 hits | 41002 hits | 1310 hits | 613 hits |
| T1557.003 DHCP Spoofing | 216 hits | 0 hits | 0 hits | 308 hits | 62 hits |
| T1558 Steal or Forge Kerberos Tickets | 1 hits | 0 hits | 999 hits | 652 hits | 35 hits |
| T1558.001 Golden Ticket | 0 hits | 0 hits | 240 hits | 326 hits | 35 hits |
| T1558.002 Silver Ticket | 0 hits | 24 hits | 537 hits | 326 hits | 35 hits |
| T1558.003 Kerberoasting | 0 hits | 0 hits | 71 hits | 326 hits | 35 hits |
| T1558.004 AS-REP Roasting | 0 hits | 0 hits | 28 hits | 0 hits | 35 hits |
| T1606 Forge Web Credentials | 0 hits | 1 hits | 312 hits | 39283 hits | n/a |
| T1606.001 Web Cookies | 0 hits | 0 hits | 297 hits | 1649 hits | n/a |
| T1606.002 SAML Tokens | 0 hits | 0 hits | 312 hits | 1649 hits | n/a |
| T1621 Multi-Factor Authentication Request Generatio… | 0 hits | 0 hits | 0 hits | n/a | n/a |
| T1649 Steal or Forge Authentication Certificates | 0 hits | 0 hits | 64 hits | 1649 hits | n/a |

Cells: 265, gaps: 1.

## Queries

Every MCP tool call of this run (1131), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-dc112bc33b | scope | list_data_sources | {} | None |  |
| q-97299447cb | scope | get_registry | {} | None |  |
| q-6b8a9d36dd | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-74961b7021 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-c67bf6ce14 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-bab7aba57d | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-b2888c90bd | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-6fc6f60999 | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-3741776c01 | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*LSASS*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-39f8136331 | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-aa5b1bd333 | check C004 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*comsvcs*\" OR TO_LOWER(win… | ERROR |  |
| q-00e1218e3c | check C004 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*comsvcs*\" OR TO_LOWER(win… | ERROR |  |
| q-bcaa4d21ff | check C005 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*lsass*\" OR TO_LOWER(message) LIKE \"*mimikatz*\" OR TO_LOWER(message) LIKE \"*procdump*\" OR TO_LOWER(message) LIKE \"*ntds*\" OR TO_LOWER(message) LIKE \"*minidump*\" OR TO… | ERROR |  |
| q-f0b3f4c9a7 | check C005 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*lsass*\" OR TO_LOWER(message) LIKE \"*mimikatz*\" OR TO_LOWER(message) LIKE \"*procdump*\" OR TO_LOWER(message) LIKE \"*ntds*\" OR TO_LOWER(message) LIKE \"*minidump*\" OR TO… | ERROR |  |
| q-32f53552a4 | check C006 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*LSASS*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-86c1662259 | check C007 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*LSASS*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-7418c32604 | check C008 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*comsvcs*\" OR TO_LOWER(process.command_line) LIKE \"*minidump*\" OR TO_LOWER(process.command_line) LIKE \"*procdump*\" OR TO_LOWER(proc… | ERROR |  |
| q-6b4e9c8278 | check C008 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*comsvcs*\" OR TO_LOWER(process.command_line) LIKE \"*minidump*\" OR TO_LOWER(process.command_line) LIKE \"*procdump*\" OR TO_LOWER(proc… | ERROR |  |
| q-6fe695fb1a | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*lsass* OR win.TargetFilename:*.dmp)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 2 |  |
| q-5fd1772017 | check C010 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*lsass* OR registry.path:*WDigest* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 11 |  |
| q-5eb79480de | check C011 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4673 AND (win.ObjectName:*lsass* OR win.ObjectName:*LSASS* OR win.ObjectName:*SeDebug*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-54aa56d9dd | check C012 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*comsvcs*\" OR TO_LOWER(win… | ERROR |  |
| q-8b5851594c | check C012 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*comsvcs*\" OR TO_LOWER(win… | ERROR |  |
| q-56a5507610 | check C013 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*lsass*\" OR TO_LOWER(message) LIKE \"*minidump*\" OR TO_LOWER(message) LIKE \"*procdump*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-3b5988d9d9 | check C013 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*lsass*\" OR TO_LOWER(message) LIKE \"*minidump*\" OR TO_LOWER(message) LIKE \"*procdump*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-4a09e89fc4 | check C014 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SECURITY* OR win.TargetFilename:*SYSTEM* OR win.TargetFilename:*.hiv OR win.TargetFilename:*.dit)", "time_from": null, "ti… | 3 |  |
| q-7d6e078214 | check C015 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*SAM* OR registry.path:*SECURITY* OR registry.path:*HKLM*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 11328 |  |
| q-5916cd2360 | check C016 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:2 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SECURITY* OR win.TargetFilename:*SYSTEM*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-ae4586cbc8 | check C017 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*save* OR process.command_line:*SAM* OR process.command_line:*ntds*)", "time_from": null, "time_to": null, "size"… | 6 |  |
| q-dcf974ed31 | check C018 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-b89f0b80df | check C019 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*reg save*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sam*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*hive*\" OR TO_LOWER(win.Scri… | ERROR |  |
| q-56966726ce | check C019 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*reg save*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sam*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*hive*\" OR TO_LOWER(win.Scri… | ERROR |  |
| q-0a1a62e8b1 | check C020 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*sam*\" OR TO_LOWER(message) LIKE \"*hive*\" OR TO_LOWER(message) LIKE \"*reg save*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-6265188d80 | check C020 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*sam*\" OR TO_LOWER(message) LIKE \"*hive*\" OR TO_LOWER(message) LIKE \"*reg save*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-e4da29d902 | check C021 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*ntds* OR win.TargetFilename:*.dit OR win.TargetFilename:*.dmp)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 2 |  |
| q-72d34368b5 | check C022 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:2 AND (win.TargetFilename:*ntds* OR win.TargetFilename:*.dit)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-3dac16ea7c | check C023 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*shadow* OR process.command_line:*diskshadow*)", "time_from": null, "time_to"… | 0 |  |
| q-bb11bdf2d8 | check C024 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*shadow*\" OR TO_LOWER(message) LIKE \"*ntds*\" OR TO_LOWER(message) LIKE \"*vssadmin*\" OR TO_LOWER(message) LIKE \"*diskshadow*\" \| KEEP @timestamp, host.name, event.code, … | ERROR |  |
| q-c920697cf6 | check C024 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*shadow*\" OR TO_LOWER(message) LIKE \"*ntds*\" OR TO_LOWER(message) LIKE \"*vssadmin*\" OR TO_LOWER(message) LIKE \"*diskshadow*\" \| KEEP @timestamp, host.name, event.code, … | ERROR |  |
| q-69030f3b16 | check C025 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*ntds*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*vssadmin*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*shadowcopy*\" OR TO_LOWER(w… | ERROR |  |
| q-1a225e2d14 | check C025 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*ntds*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*vssadmin*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*shadowcopy*\" OR TO_LOWER(w… | ERROR |  |
| q-19ccce0aea | check C026 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*SECURITY* OR registry.path:*Policy*Secrets* OR registry.path:*LSA*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5 |  |
| q-8ad84ebf78 | check C027 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*LSASS*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-7fbc5adcde | check C028 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*vault*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 47 |  |
| q-7fd7bebc52 | check C029 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-264609a1ed | check C030 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*secrets*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*security\\\\policy*\" OR TO_L… | ERROR |  |
| q-d01aab2a81 | check C030 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*secrets*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*security*policy*\" OR TO_LOWE… | ERROR |  |
| q-71b964909b | check C031 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*lsa*\" OR TO_LOWER(message) LIKE \"*secrets*\" OR TO_LOWER(message) LIKE \"*dpapi*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-d34d689ef3 | check C031 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*lsa*\" OR TO_LOWER(message) LIKE \"*secrets*\" OR TO_LOWER(message) LIKE \"*dpapi*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-4354ed8f3e | check C032 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*LSASS*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-ec072fb577 | check C033 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Cache* OR registry.path:*SECURITY* OR registry.path:*LogonCache*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 6625 |  |
| q-85332d5e5d | check C034 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-43b435fdaa | check C035 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*cache*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*dcc*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mscache*\" OR TO_LOWER(win.Scri… | ERROR |  |
| q-ea5362e7d9 | check C035 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*cache*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*dcc*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mscache*\" OR TO_LOWER(win.Scri… | ERROR |  |
| q-d6af943833 | check C036 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*cache*\" OR TO_LOWER(message) LIKE \"*mscache*\" OR TO_LOWER(message) LIKE \"*dcc*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-a365bbfce5 | check C036 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*cache*\" OR TO_LOWER(message) LIKE \"*mscache*\" OR TO_LOWER(message) LIKE \"*dcc*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-b9c9c84003 | check C037 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-f98fe0edb9 | check C038 | aggregate | {"dataset": "windows.security", "field": "win.Properties", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-d1983eb4a8 | check C039 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-718d481397 | check C040 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-0e95702575 | check C041 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*DCSync* OR win.ScriptBlockText:*lsadump* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*DRSUAPI*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-701f82e3fc | check C042 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-3503020dfe | check C043 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*netsh* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap*)", "time_from": null, "time_to": n… | 2 |  |
| q-cf3871991c | check C044 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*pktmon* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap* OR process.command_line:*netsh*cap*)", "time_from": null, "time_to": nu… | 1 | F07 |
| q-8b441103fa | check C045 | aggregate | {"dataset": "windows.sysmon", "field": "win.Image", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-bc91fce0f2 | check C046 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-10a4b55d50 | check C047 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*pktmon* OR win.ScriptBlockText:*NetEventSession* OR win.ScriptBlockText:*capture*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name"… | 0 |  |
| q-a31dc0de06 | check C048 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-cc06cbdde1 | check C049 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-bd1421f549 | check C050 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-b7d5786313 | check C051 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon* OR win.TargetImage:*csrss*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 495 |  |
| q-b57aa5c995 | check C052 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-f0b12c6787 | check C053 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 13 |  |
| q-3cdb74eb20 | check C054 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*keylog* OR win.ScriptBlockText:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obse… | 0 |  |
| q-1d99e790cd | check C055 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F12 |
| q-feb02b58ab | check C056 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetObject", "query": "event.code:13", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 17541 |  |
| q-580691273e | check C057 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*CurrentControlSet\\\\Services*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 1357 | F10 |
| q-29b79050ca | check C058 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 470 |  |
| q-e0d269d64a | check C059 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*winlogon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 13 |  |
| q-4bbc174c72 | check C060 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-a56542b9bb | check C061 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*keylog* OR win.ScriptBlockText:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obse… | 0 |  |
| q-490b91dccc | check C062 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-a58dffb1bf | check C063 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*consent* OR process.command_line:*prompt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 3 |  |
| q-42cf0b6c4b | check C064 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*CredentialPrompt* OR win.ScriptBlockText:*Get-Credential* OR win.ScriptBlockText:*Windows.Forms* OR win.ScriptBlockText:*MessageBox*)", "time_from": null, "time_to": null, "f… | 2 |  |
| q-b346b236c7 | check C065 | search | {"dataset": "windows.powershell", "query": "event.code:4103 OR event.code:4104", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 5494 |  |
| q-ce62473197 | check C066 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "use… | 3 |  |
| q-938aed3cba | check C067 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-0db7af3629 | check C068 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*wwwroot* OR file.path:*inetpub* OR file.path:*.aspx* OR file.path:*.asp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 0 |  |
| q-9622c2decc | check C069 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1649 |  |
| q-564e6105a6 | check C070 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*iis* OR process.command_line:*appcmd* OR process.command_line:*w3wp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datas… | 0 |  |
| q-084df28d26 | check C071 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*wwwroot* OR win.ScriptBlockText:*inetpub* OR win.ScriptBlockText:*appcmd*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-71f337dab1 | check C072 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-adb13a472b | check C073 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*auth* OR url.original:*signin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", … | 0 |  |
| q-51356424eb | check C074 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-0a69535a62 | check C075 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-2ac4c05ffb | check C076 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-9b98eebf74 | check C077 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:8", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 95 |  |
| q-3c111786bf | check C078 | aggregate | {"dataset": "windows.security", "field": "win.TargetProcessName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5337 |  |
| q-4c8c44e367 | check C079 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b2bb182459 | check C080 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e7d2581cc5 | check C081 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-a9331b14b1 | check C082 | aggregate | {"dataset": "windows.security", "field": "win.Status", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a1b29d9fe8 | check C083 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-c2aca5c94d | check C084 | search | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-b7f07bfc91 | check C085 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-cf8edf2f1c | check C086 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1649 |  |
| q-7ee170f67c | check C087 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-dd6aebcd09 | check C088 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 or event.code:4656 or event.code:4670", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-d0d5681d7c | check C089 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-9f8885de16 | check C090 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-9ee1130233 | check C091 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 15 |  |
| q-b1b0f5e430 | check C092 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-a0e88bd5da | check C093 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-355664bdab | check C094 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-b8289fdfee | check C095 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-c49a039279 | check C096 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*LSASS*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-e341cd588f | check C097 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*SmartCard* OR registry.path:*SCard* OR registry.path:*Crypto*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 6 | F19 |
| q-27f2602a34 | check C098 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SmartCard* OR win.ScriptBlockText:*MFA* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 3 |  |
| q-ef41b6a081 | check C099 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F19 |
| q-d9e41da768 | check C100 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*LSASS*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 6 |  |
| q-82fa903f79 | check C101 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 163 |  |
| q-8d8a3adeae | check C102 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.lnk OR win.TargetFilename:*.url OR win.TargetFilename:*.scf OR win.TargetFilename:*.library-ms)", "time_from": null, "time_to": null, "size": 50, "su… | 3 |  |
| q-086dcf242e | check C103 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 66 |  |
| q-4f90beecaa | check C104 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*WebDAV* OR win.ScriptBlockText:*NTLM* OR win.ScriptBlockText:*Responder*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-c1ee6ccd8a | check C105 | search | {"dataset": "windows.other", "query": "event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 4 |  |
| q-5f12b7581c | check C106 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-68013b8f7f | check C107 | aggregate | {"dataset": "windows.sysmon", "field": "process.parent.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-7e2bc8f922 | check C108 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:7045", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ef098255c8 | check C109 | search | {"dataset": "windows.security", "query": "event.code:4672", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 212 |  |
| q-15649324a3 | check C110 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name"… | 0 |  |
| q-7747cca19b | check C111 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:1", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 8 |  |
| q-f8a3522a0c | check C112 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*Web Data*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 162 |  |
| q-30f23f472d | check C113 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:2", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 209 |  |
| q-23a04a20e0 | check C114 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*chrome* OR win.TargetImage:*firefox* OR win.TargetImage:*msedge* OR win.TargetImage:*iexplore*)", "time_from": null, "time_to": null, "size": 50, "sub_field… | 0 |  |
| q-430678e47d | check C115 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-a8fb7ad8f1 | check C116 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*sqlite*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 13 |  |
| q-7797db2867 | check C117 | search | {"dataset": "windows.other", "query": "event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 4 |  |
| q-68e494441f | check C118 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.ini OR win.TargetFilename:*.ps1)", "time_from": null, "time_to… | 72 |  |
| q-7cac986929 | check C119 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential* OR registry.path:*Winlogon*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 24 |  |
| q-28bd39e452 | check C120 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-f25adf7d29 | check C121 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*password* OR win.ScriptBlockText:*credential* OR win.ScriptBlockText:*ConvertTo-SecureString*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 4 |  |
| q-6a6bbfae68 | check C122 | search | {"dataset": "windows.other", "query": "event.code:11 OR event.code:1", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 7 |  |
| q-e207c8a9fb | check C123 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*unattend* OR process.command_line:*sysprep*)", "time_from": null, "time_to"… | 0 |  |
| q-53b6d7de66 | check C124 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*unattend.xml OR win.TargetFilename:*web.config OR win.TargetFilename:*.kdbx OR win.TargetFilename:*id_rsa*)", "time_from": null, "time_to": null, "siz… | 0 |  |
| q-a135301fd0 | check C125 | aggregate | {"dataset": "windows.security", "field": "win.TargetName", "query": "event.code:4663 AND (win.TargetName:*unattend* OR win.TargetName:*.config OR win.TargetName:*.txt)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f39771b3c8 | check C126 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-54ed10319d | check C127 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Get-Content* OR win.ScriptBlockText:*Select-String* OR win.ScriptBlockText:*findstr*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.na… | 1 |  |
| q-a52087ca7f | check C128 | search | {"dataset": "windows.other", "query": "event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 4 |  |
| q-bbb660e44f | check C129 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential* OR registry.path:*Login* OR registry.path:*Secret*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20 |  |
| q-f85078a1d4 | check C130 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg\\ query* OR process.command_line:*reg\\ save* OR process.command_line:*reg\\ export*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name… | 0 |  |
| q-eebbc57ae1 | check C131 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*reg\\ query* OR win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name… | 4 |  |
| q-ef3331bfc0 | check C132 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*Password*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-181b9d0773 | check C133 | search | {"dataset": "windows.other", "query": "message:*reg* AND (message:*Password* OR message:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable",… | 1 |  |
| q-9989c86983 | check C134 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ConsoleHost_history* OR win.ScriptBlockText:*history* OR win.ScriptBlockText:*Get-Content*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 0 |  |
| q-0add32be0b | check C135 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ConsoleHost_history* OR process.command_line:*history.txt* OR process.command_line:*Get-Content*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 0 |  |
| q-b955ff90f1 | check C136 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ConsoleHost_history* OR file.path:*history*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 0 |  |
| q-fcbe77030e | check C137 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectName:*history*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-61f5d75069 | check C138 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*.pfx OR file.path:*.pem OR file.path:*.key OR file.path:*.p12 OR file.path:*.ppk OR file.path:*.cer OR file.path:*.asc OR file.path:*.gpg)", "time_from": null, "time_to… | 1 |  |
| q-c880c780b6 | check C139 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*.pfx OR process.command_line:*.pem OR process.command_line:*.p12 OR process.command_line:*.key OR process.command_line:*certutil*)", "time_from": null, "time_to": null, "fields": [… | 0 |  |
| q-a0cdd316b6 | check C140 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5145 AND (win.RelativeTargetName:*.pfx OR win.RelativeTargetName:*.pem OR win.RelativeTargetName:*.key OR win.RelativeTargetName:*.p12)", "time_from": null, "time_to": null, "size":… | 0 |  |
| q-0be87a3d0c | check C141 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*.pfx OR win.ScriptBlockText:*.pem OR win.ScriptBlockText:*.p12 OR win.ScriptBlockText:*Export-PfxCertificate*)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 1 |  |
| q-b116c86c74 | check C142 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cpassword* OR win.ScriptBlockText:*Groups.xml* OR win.ScriptBlockText:*gpprefdecrypt* OR win.ScriptBlockText:*AES*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-717787ad1b | check C143 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*Groups.xml* OR win.RelativeTargetName:*SYSVOL* OR win.RelativeTargetName:*Policies*)", "time_from": null, "time_to": null, "size": 50, "su… | 38 |  |
| q-661a47bdf3 | check C144 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Groups.xml* OR process.command_line:*SYSVOL* OR process.command_line:*cpassword*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-49458232d3 | check C145 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*Groups.xml* OR file.path:*SYSVOL*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executabl… | 0 |  |
| q-f34513bb9b | check C146 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-8f54256b36 | check C147 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-cba6f874f3 | check C148 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*MiniDump* OR process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*sekurlsa* OR process.command_line:*lsass*)", "time_from": null, "time_to": n… | 1 |  |
| q-0b848816d2 | check C149 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-f4e05d770a | check C150 | aggregate | {"dataset": "windows.security", "field": "win.TargetProcessName", "query": "event.code:4656 AND win.TargetProcessName:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-1618e30810 | check C151 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timest… | 0 |  |
| q-635135e162 | check C152 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Login\\ Data* OR file.path:*logins.json* OR file.path:*key4.db* OR file.path:*Cookies* OR file.path:*Local\\ State*)", "time_from": null, "time_to": null, "size": 50, "… | 1 |  |
| q-5414dec9ba | check C153 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Login\\ Data* OR process.command_line:*logins.json* OR process.command_line:*key4.db* OR process.command_line:*Local\\ State*)", "time_from": null, "time_to": null, "fields": ["@ti… | 0 |  |
| q-08b545bf11 | check C154 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Login\\ Data* OR win.ObjectName:*logins.json* OR win.ObjectName:*key4.db* OR win.ObjectName:*Local\\ State*)", "time_from": null, "time_to": null, "size":… | 0 |  |
| q-61ad6b1ff9 | check C155 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*chrome.exe OR win.TargetImage:*firefox.exe OR win.TargetImage:*msedge.exe OR win.TargetImage:*iexplore.exe)", "time_from": null, "time_to": null, "size":… | 0 |  |
| q-0ddefec532 | check C156 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Login\\ Data* OR win.ScriptBlockText:*logins.json* OR win.ScriptBlockText:*key4.db* OR win.ScriptBlockText:*CryptUnprotectData*)", "time_from": null, "time_to": null, "fields… | 0 |  |
| q-b66de73295 | check C157 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*vaultsvc* OR win.TargetImage:*Credential* OR win.TargetImage:*svchost.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 24315 |  |
| q-8ae5bfcad0 | check C158 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-ac3b7ac800 | check C159 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*vaultcmd* OR process.command_line:*cmdkey* OR process.command_line:*Credential* OR process.command_line:*vault*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-96c0b77e54 | check C160 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*vaultcmd* OR process.command_line:*cmdkey* OR process.command_line:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 0 |  |
| q-0e6c1a7e0b | check C161 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*vault* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 3 |  |
| q-c63b262d19 | check C162 | search | {"dataset": "windows.other", "query": "message:*vault* OR message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 | F30 |
| q-7234b1d77b | check C163 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*lastpass* OR process.command_line:*bitwarden* OR process.executable:*keepass* OR process.executable:*1password… | 0 |  |
| q-6491da6e93 | check C164 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*lastpass* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 0 |  |
| q-637796729a | check C165 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*.kdbx OR file.path:*keepass* OR file.path:*1password* OR file.path:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", … | 0 |  |
| q-0e4611d7ca | check C166 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*lastpass* OR process.command_line:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-894825a100 | check C167 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*kdbx* OR win.ScriptBlockText:*keepass* OR win.ScriptBlockText:*1password* OR win.ScriptBlockText:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-ed009ee8d2 | check C168 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*1password* OR message:*bitwarden* OR message:*lastpass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 0 |  |
| q-eac4a30f2f | check C169 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 326 |  |
| q-0b02b267cb | check C170 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-4712109f9c | check C171 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass.exe OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*wdigest* OR win.ImageLoaded:*kerberos*)", "time_from": null, "time_to": null, "fields": ["@timestamp… | 92 |  |
| q-6aa0573914 | check C172 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*Security* OR win.ObjectName:*SAM* OR win.ObjectName:*Notification Packages* OR win.ObjectName:*Authentication*)", "time_from": null, "time_to": null, "fiel… | 0 |  |
| q-f6ddb2023f | check C173 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*mimikatz*)", "time_from": null, "time_t… | 0 |  |
| q-1593521c62 | check C174 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*sekurlsa*)", "time_from": null, "time_to":… | 0 |  |
| q-3be52d4260 | check C175 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll* OR message:*Notification Packages*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.ex… | 4 |  |
| q-ee7d116a59 | check C176 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3 AND win.AuthenticationPackageName:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 218 | F33 |
| q-66a9699adb | check C177 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-82d928b933 | check C178 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-e704da0838 | check C179 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 326 |  |
| q-66191a0bf5 | check C180 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass.exe OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 33 |  |
| q-9163b0ef07 | check C181 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-6a25116ab1 | check C182 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*cryptdll* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*dcsync*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-1720e2952b | check C183 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*\\\\System32\\\\*.dll OR file.path:*PasswordFilter* OR file.path:*Notification*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 1 |  |
| q-5ba181910a | check C184 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass.exe OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*ntdsapi* OR win.ImageLoaded:*sam* )", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.nam… | 87 |  |
| q-cd55e711c1 | check C185 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Notification Packages* OR win.ObjectName:*lsa* OR win.ObjectName:*Password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 0 |  |
| q-a6b549aeab | check C186 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Notification* OR process.command_line:*PasswordFilter* OR process.command_line:*reg add*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer… | 2 |  |
| q-091abf5e23 | check C187 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Notification Packages* OR win.ScriptBlockText:*PasswordFilter* OR win.ScriptBlockText:*HKLM*lsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 0 |  |
| q-9278cc6a53 | check C188 | search | {"dataset": "windows.other", "query": "message:*Notification Packages* OR message:*PasswordFilter*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 5 |  |
| q-59a356a9eb | check C189 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*AllowReversiblePasswordEncryption* OR win.ScriptBlockText:*ReversibleEncryption* OR win.ScriptBlockText:*Set-ADAccountControl* OR win.ScriptBlockText:*Set-ADUser*)", "time_fr… | 1 |  |
| q-d7138f9e3f | check C190 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (win.Payload:*Reversible* OR win.Payload:*Set-ADAccountControl* OR win.Payload:*Set-ADUser*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-7ab1883e60 | check C191 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADAccountControl* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@… | 0 |  |
| q-47fd0587c5 | check C192 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-ef805c301a | check C193 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADAccountControl* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observ… | 0 |  |
| q-faf0f43d61 | check C194 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*Set-ADAccountControl*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proces… | 0 |  |
| q-d69d36050d | check C195 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthentication*\" OR TO_L… | ERROR |  |
| q-aacc7e29d0 | check C195 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthentication*\" OR TO_L… | ERROR |  |
| q-cc74d431da | check C196 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 41002 |  |
| q-eb0087345b | check C197 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-08866810c1 | check C198 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*authenticationpolicy*\") \| KEEP @timestamp, host.name, user.name, process.comm… | ERROR |  |
| q-2bd0d74941 | check C198 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*authenticationpolicy*\") \| KEEP @timestamp, host.name, user.name, process.comm… | ERROR |  |
| q-6a4cf09af4 | check C199 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*authenticationpolicy*\" OR TO_LOWER(message) LIKE \"*set-aduser*\" OR TO_LOWER(message) LIKE \"*strongauthentication*\" \| KEEP @timestamp, host.name, event.code, message, _i… | ERROR |  |
| q-c80c7872ef | check C199 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*authenticationpolicy*\" OR TO_LOWER(message) LIKE \"*set-aduser*\" OR TO_LOWER(message) LIKE \"*strongauthentication*\" \| KEEP @timestamp, host.name, event.code, message, _i… | ERROR |  |
| q-89e988858d | check C200 | search | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-38143723bd | check C201 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 41002 |  |
| q-585dd6e3cf | check C202 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-c456033002 | check C203 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*adfs*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aadconnect*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*c… | ERROR |  |
| q-c053dde279 | check C203 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*adfs*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aadconnect*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*c… | ERROR |  |
| q-9b744641bf | check C204 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*adfs*\" OR TO_LOWER(message) LIKE \"*azuread*\" OR TO_LOWER(message) LIKE \"*aadconnect*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-dc796f0dda | check C204 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*adfs*\" OR TO_LOWER(message) LIKE \"*azuread*\" OR TO_LOWER(message) LIKE \"*aadconnect*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-d21e215c64 | check C205 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND registry.path:*NetworkProvider*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-d12c838dd9 | check C206 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*NetworkProvider*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 0 |  |
| q-9bf2b2864f | check C207 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-f35f7c83cc | check C208 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*NetworkProvider*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proce… | 0 |  |
| q-031246c06d | check C209 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*networkprovider*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-cff80625e8 | check C209 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*networkprovider*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-fee2b3c028 | check C210 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-itemproperty*\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index"} | ERROR |  |
| q-e7999d59ac | check C210 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-itemproperty*\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index"} | ERROR |  |
| q-ef04a8c489 | check C211 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-f03c1203f0 | check C212 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-fef1ba0699 | check C213 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-a3b0497f33 | check C214 | search | {"dataset": "windows.security", "query": "event.code:4670", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 143 | F42 |
| q-40a428bd8d | check C215 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*arp*\" OR TO_LOWER(message) LIKE \"*llmnr*\" OR TO_LOWER(message) LIKE \"*nbt-ns*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-c29f8e67dc | check C215 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*arp*\" OR TO_LOWER(message) LIKE \"*llmnr*\" OR TO_LOWER(message) LIKE \"*nbt-ns*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-4e1c7218d2 | check C216 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*a… | ERROR |  |
| q-16bf0f5824 | check C216 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*a… | ERROR |  |
| q-73cef85056 | check C217 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-e2b2e383a8 | check C218 | esql | {"query": "FROM zeek METADATA _id, _index \| WHERE event.action == \"dns\" AND (dns.question.name LIKE \"*llmnr*\" OR dns.question.name LIKE \"*nbt*\" OR destination.port == 5355 OR destination.port == 137) \| KEEP @timestamp, source.ip, destination.ip, destin… | ERROR |  |
| q-d2301a75d4 | check C218 (repaired) | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"dns\" AND (dns.question.name LIKE \"*llmnr*\" OR dns.question.name LIKE \"*nbt*\" OR destination.port == 5355 OR destination.port == 137) \| KEEP @timestamp, source.ip, destinati… | 6 |  |
| q-492fee0eef | check C219 | aggregate | {"dataset": "zeek", "field": "source.ip", "query": "event.action:conn AND destination.port:445", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 45 |  |
| q-1b2f18aec9 | check C220 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-a8b026edd9 | check C221 | search | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 23 | F42 |
| q-01a7e5370c | check C222 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND registry.path:*DNSClient*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-0609830622 | check C223 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*enablemulticast*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*dnsclient*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" \| KEEP @timestamp, host.name, u… | ERROR |  |
| q-f4abe8fc47 | check C223 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*enablemulticast*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*dnsclient*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" \| KEEP @timestamp, host.name, u… | ERROR |  |
| q-0e7ba54567 | check C224 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*enablemulticast*\" OR TO_LOWER(message) LIKE \"*llmnr*\" OR TO_LOWER(message) LIKE \"*nbt-ns*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-923cd9951c | check C224 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*enablemulticast*\" OR TO_LOWER(message) LIKE \"*llmnr*\" OR TO_LOWER(message) LIKE \"*nbt-ns*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-1c74e3cfbe | check C225 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-8ce9aba940 | check C226 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-48225a6c4a | check C227 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 41002 |  |
| q-3d4a2ac7c5 | check C228 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*arp*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-0fc2e2218d | check C228 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*arp*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-6ed96ff4dd | check C229 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-netneighbor*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ethernet*\" \| KEEP @timestamp, host.name, user.n… | ERROR |  |
| q-a2c26aa211 | check C229 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-netneighbor*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ethernet*\" \| KEEP @timestamp, host.name, user.n… | ERROR |  |
| q-7fdde1a91d | check C230 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-b35ece4aa1 | check C231 | search | {"dataset": "windows.other", "query": "event.code:1341 OR event.code:1342 OR event.code:1020 OR event.code:1063", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.ex… | 0 |  |
| q-8e10b9ad96 | check C232 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 216 |  |
| q-c0682a66e9 | check C233 | search | {"dataset": "windows.security", "query": "event.code:5156 AND network.transport:udp", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-e5092f2b86 | check C234 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3 AND network.transport:udp", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 308 |  |
| q-95f69fbfd4 | check C235 | search | {"dataset": "windows.powershell", "query": "*dhcp* OR *DhcpServer* OR *rogue*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 0 |  |
| q-ce56de934e | check C236 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND network.transport:udp", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 62 |  |
| q-03f687ab3b | check C237 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4672 OR event.code:4634 OR event.code:4768 OR event.code:4769 OR event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 787 |  |
| q-748eb5860e | check C238 | search | {"dataset": "windows.security", "query": "event.code:4672", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 212 |  |
| q-807418b1bf | check C239 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*lsass.exe)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-d43bbb69fc | check C240 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-7853d8cbbe | check C241 | search | {"dataset": "windows.powershell", "query": "*kerberos* OR *Kerberos* OR *ticket* OR *Ticket*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-9308bfe3c3 | check C242 | search | {"dataset": "windows.other", "query": "*kerberos* OR *Kerberos* OR *ticket*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 1 |  |
| q-f332245a79 | check C243 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 35 |  |
| q-3d6b8f67d1 | check C244 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-02b7a2b688 | check C245 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-3e93859b14 | check C246 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-64d2a44c67 | check C247 | search | {"dataset": "windows.powershell", "query": "*krbtgt* OR *golden* OR *Golden* OR *mimikatz* OR *Mimikatz*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executabl… | 0 |  |
| q-f21d4d0b11 | check C248 | search | {"dataset": "windows.other", "query": "*krbtgt* OR *golden* OR *Golden*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 0 |  |
| q-826371dab3 | check C249 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 35 |  |
| q-07e1c0147c | check C250 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-f0691a2cc2 | check C251 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4672 OR event.code:4624", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 509 |  |
| q-6058e8f548 | check C252 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-69c06e8b44 | check C253 | search | {"dataset": "windows.powershell", "query": "*silver* OR *Silver* OR *service ticket* OR *Rubeus*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 24 |  |
| q-af57b6b3b0 | check C254 | search | {"dataset": "windows.other", "query": "*silver* OR *Silver* OR *service ticket*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line… | 0 |  |
| q-06710a59b6 | check C255 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 35 |  |
| q-7b95b1d41e | check C256 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-5e6eb3d54c | check C257 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-59dde034ae | check C258 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-378f91ad6e | check C259 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-f1bc8abe17 | check C260 | search | {"dataset": "windows.powershell", "query": "*SPN* OR *spn* OR *Kerberoast* OR *kerberoast* OR *Rubeus*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-23ec005a3f | check C261 | search | {"dataset": "windows.other", "query": "*Kerberoast* OR *kerberoast* OR *SPN*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-3c80817839 | check C262 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 35 |  |
| q-f231adbf40 | check C263 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-d64dbbd3e6 | check C264 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-8feec961dd | check C265 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*asreproast* OR process.command_line:*Asreproast* OR process.command_line:*GetNPUsers*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-3f5a9d81bc | check C266 | search | {"dataset": "windows.powershell", "query": "*asreproast* OR *Asreproast* OR *GetNPUsers* OR *DontReqPreAuth*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 0 |  |
| q-f21ca3d9be | check C267 | search | {"dataset": "windows.other", "query": "*asreproast* OR *Asreproast* OR *GetNPUsers*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-010099a273 | check C268 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 35 |  |
| q-fe0e94bb36 | check C269 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-79e17d7448 | check C270 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-895e4b0198 | check C271 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-3b062f8fe7 | check C272 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*token*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*saml*\" OR TO_LOWER(win.Scri… | ERROR |  |
| q-1211f4201d | check C272 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*token*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*saml*\" OR TO_L… | 1 | F48 |
| q-43eb74646c | check C273 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*token*\" OR TO_LOWER(message) LIKE \"*certificate*\" OR TO_LOWER(message) LIKE \"*adfs*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-6110310cc9 | check C273 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*token*\" OR TO_LOWER(message) LIKE \"*certificate*\" OR TO_LOWER(message) LIKE \"*adfs*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-796fdea098 | check C274 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1649 |  |
| q-bbd9b76de8 | check C275 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-b9ed61a8f1 | check C276 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*session*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*jwt*\") \| KEEP @timestamp… | ERROR |  |
| q-895eee3f4f | check C276 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*session*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*jwt*\") \| KEEP @timestamp… | ERROR |  |
| q-c7fde84122 | check C277 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*cookie*\" OR TO_LOWER(message) LIKE \"*session*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-8e25379de6 | check C277 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*cookie*\" OR TO_LOWER(message) LIKE \"*session*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-8a1c7d60aa | check C278 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 297 |  |
| q-64f0d3a9df | check C279 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 15 |  |
| q-d571a9896d | check C280 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*saml*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*assertion*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*signing*certificate*\" OR … | ERROR |  |
| q-7eacd657b2 | check C280 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*saml*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*assertion*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*signing*certificate*\" OR … | ERROR |  |
| q-48cd97908f | check C281 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*saml*\" OR TO_LOWER(message) LIKE \"*adfs*\" OR TO_LOWER(message) LIKE \"*assertion*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-309523ef98 | check C281 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*saml*\" OR TO_LOWER(message) LIKE \"*adfs*\" OR TO_LOWER(message) LIKE \"*assertion*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-05eff00e6e | check C282 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1649 |  |
| q-e9601c25da | check C283 | count | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null} | 0 |  |
| q-ef9e36bf54 | check C284 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-531e0186e8 | check C285 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-452c5a6553 | check C286 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*mfa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*2fa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*authenticator*\") \| KEEP @timest… | ERROR |  |
| q-a57c88e1a5 | check C286 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*mfa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*2fa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*authenticator*\") \| KEEP @timest… | ERROR |  |
| q-a26c842f1e | check C287 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*mfa*\" OR TO_LOWER(message) LIKE \"*authenticator*\" OR TO_LOWER(message) LIKE \"*multi-factor*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-fdb829d831 | check C287 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*mfa*\" OR TO_LOWER(message) LIKE \"*authenticator*\" OR TO_LOWER(message) LIKE \"*multi-factor*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-7cecd80124 | check C288 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 36 |  |
| q-7b724d7ccb | check C289 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 14 |  |
| q-7d82c47260 | check C290 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-f0b342b5a7 | check C291 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1649 |  |
| q-4d4c903f5a | check C292 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*certutil*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*export-pfxcertificate*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*certificat… | ERROR |  |
| q-96a9d59d91 | check C292 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*certutil*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*export-pfxcertificate*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*certificat… | ERROR |  |
| q-96e708c35a | check C293 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*certificate*\" OR TO_LOWER(message) LIKE \"*certutil*\" OR TO_LOWER(message) LIKE \"*pki*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-6836ea32d8 | check C293 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*certificate*\" OR TO_LOWER(message) LIKE \"*certutil*\" OR TO_LOWER(message) LIKE \"*pki*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-ce7a7de0be | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*LSASS*) AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x300… | 9 | F01, F03 |
| q-18b18aa251 | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*LSASS*) AND (win.SourceImage:*powershell* OR win.SourceImage:*wsmprovhost*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.… | 3 | F05 |
| q-0bfcc4bd43 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None | F01, F04 |
| q-e27f7de26c | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-fb84b18f03 | triage T1003 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*dump*\" OR TO… | 13 | F06 |
| q-37dcd9605a | triage T1003 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOWER(process.command_line) LIKE \"*credential*\" OR TO_L… | 1 |  |
| q-753c8ec8c8 | triage T1003 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-11c2553aea | triage T1003 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqzeO"} | None |  |
| q-67d9cc39b8 | triage T1003 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE (event.code == \"4663\" OR event.code == \"4656\" OR event.code == \"4670\") AND (win.ObjectName == \"SAM\" OR win.ObjectName LIKE \"*lsass.exe*\" OR win.ObjectName LIKE \"*SamSs*\") \… | 34 | F01, F02 |
| q-006998b065 | triage T1003 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*powershell*\" OR process.executable LIKE \"*PsExec*\" OR process.executable LIKE \"*rundll32*\" OR process.executable LIKE \"*python*\… | 28 |  |
| q-e84a1b1b4c | triage T1003 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtA"} | None | F02 |
| q-fb354cfb24 | triage T1003 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4662\" OR (event.code == \"4624\" AND win.LogonType == \"3\" AND win.TargetUserName LIKE \"*$\") \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.Subj… | 20 |  |
| q-85f65f66fb | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-54e0204376 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-50363501b3 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-9c2f950803 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-c437672fc9 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-d3cb133762 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-62394b989f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-a2d9532ef6 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-d8c1145c00 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtA"} | None |  |
| q-9d473979dc | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtA"} | None |  |
| q-e9a59676ce | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtA"} | None |  |
| q-a3c920d692 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsc9wP8"} | None |  |
| q-c78119c83d | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-223702da99 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-7ba3db5f63 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-5607bcc899 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1Ol"} | None |  |
| q-b1d98f56c0 | triage T1040 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None | F07 |
| q-90fa4df4a9 | triage T1040 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5KNV"} | None | F07 |
| q-9ebcff2a4c | triage T1040 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*trace* OR process.command_line:*etl* OR process.command_line:*NetworkWatcher* OR process.command_line:*logman*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 14 | F07 |
| q-5cc78db601 | triage T1040 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*TEMP* OR file.path:*etl*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proc… | 45 |  |
| q-ceab4de430 | triage T1040 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpp7sQg"} | None | F07 |
| q-b333104107 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:6 AND (win.ImageLoaded:*pktmon* OR win.ImageLoaded:*npcap* OR win.ImageLoaded:*winpcap* OR win.ImageLoaded:*ndiscap* OR win.ImageLoaded:*netmon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 0 |  |
| q-40359e4889 | triage T1040 step 2 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap* OR process.command_line:*NetworkWatcher* OR process.command_line:*… | 12 |  |
| q-67182f0352 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*pktmon* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap* OR process.command_line:*dumpcap* OR process.command_line:*Wireshark* O… | 0 |  |
| q-97b6bc6a4e | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:6 AND (win.ImageLoaded:*pktmon* OR win.ImageLoaded:*npcap* OR win.ImageLoaded:*wpcap* OR win.ImageLoaded:*Packet* OR win.ImageLoaded:*ndiscap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 0 |  |
| q-75e4548a7e | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-6cc9af848b | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-b2d3ad46cb | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpp7sQg"} | None |  |
| q-a2d89d174b | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5KNV"} | None |  |
| q-9d4a65fea9 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchIttyFQdU"} | None |  |
| q-3d701a489f | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpo7P8B"} | None |  |
| q-0f475335c4 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkORY1E"} | None |  |
| q-2d340ae96f | triage T1056 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.SourceImage:*cod.3aka3*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 4 | F09, F11 |
| q-64b3575842 | triage T1056 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.SourceImage:*python.exe*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comma… | 3 | F09 |
| q-fc79504bea | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.SourceImage LIKE \"*powershell.exe\" \| STATS c = COUNT(*) BY host.name, win.SourceImage, win.TargetImage, win.GrantedAccess \| SORT c DESC"} | ERROR |  |
| q-dc1b37cf20 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.SourceImage LIKE \"*powershell.exe\" \| STATS c = COUNT(*) BY host.name, win.SourceImage, win.TargetImage, win.GrantedAccess \| SORT c DESC"} | 57 |  |
| q-683af4d733 | triage T1056 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*cod.3aka3* OR process.command_line:*cod.3aka3* OR process.executable:*python.exe*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 7 |  |
| q-e0f3ed0e97 | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None | F09 |
| q-f542ea1495 | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ_4"} | None | F09 |
| q-d5ffdfe032 | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo4k"} | None | F08 |
| q-e50203f078 | triage T1056 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" O… | 0 |  |
| q-2ef2efbb9f | triage T1056 step 4 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*lsass* AND user.name:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 3 |  |
| q-6047f2377e | triage T1056 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None | F08 |
| q-431e79d3d6 | triage T1056 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None | F08 |
| q-e9295845e6 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo4k"} | None |  |
| q-51b99b6165 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo4k"} | None |  |
| q-c6c4f1291a | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-d205624d53 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-1c338664ec | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-0ccaeddfcc | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1Agy"} | None |  |
| q-fadde3ce1e | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1Agy"} | None |  |
| q-6de79cb1f3 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-707f3fba82 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ_4"} | None |  |
| q-59e7a38314 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ_5"} | None |  |
| q-4da5130e39 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1gg4"} | None |  |
| q-e074147ff8 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1Agy"} | None |  |
| q-c3eb2bac1b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWV3"} | None |  |
| q-4b7795e15d | triage T1110 step 1 | count | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null} | 0 |  |
| q-3216b5232b | triage T1110 step 1 | count | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null} | 218 |  |
| q-28058a530c | triage T1110 step 1 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:SAM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.ProcessName", "win.SubjectUserName", "win.AccessMask", "win.AccessList", "win.Ha… | 0 |  |
| q-5de6ff96e3 | triage T1110 step 1 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.SubjectUserName", "win.ProcessName", "win.IpAddress", "win.TargetServerName"], "size": 20, "sort": … | 15 | F16 |
| q-6cb0594009 | triage T1110 step 2 | search | {"dataset": "windows.security", "query": "win.ObjectName:SAM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ObjectName", "win.ProcessName", "win.SubjectUserName", "win.AccessMask", "win.AccessList", "win.HandleId… | 10 | F15 |
| q-e5a67a9e73 | triage T1110 step 2 | search | {"dataset": "windows.security", "query": "win.ObjectName:*lsass.exe*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ObjectName", "win.ProcessName", "win.SubjectUserName", "win.AccessMask", "win.AccessList", "win.… | 19 | F15 |
| q-24198424bc | triage T1110 step 2 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass.exe*", "time_from": null, "time_to": null, "size": 50, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-59984ef30f | triage T1110 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe* AND (win.SourceImage:*PowerShell.exe OR win.SourceImage:*wsmprovhost.exe OR win.SourceImage:*wininit.exe OR win.SourceImage:*csrss.exe)", "time_from": null, "time_to": null, … | 6 |  |
| q-fcafb4b18b | triage T1110 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*minidump* OR process.command_line:*sekurlsa* OR process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*Invoke-Mi… | 1 |  |
| q-22bb04bbc2 | triage T1110 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None | F15 |
| q-ee2269bc0e | triage T1110 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None | F15 |
| q-e4af1ec663 | triage T1110 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*powershell.exe OR process.executable:*wsmprovhost.exe OR process.executable:*cmd.exe OR process.executable:*python.exe OR process.executable:*PsExec64.exe)", "time_from": null, "time… | 39 | F16 |
| q-1a6b1a19af | triage T1110 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None | F15 |
| q-0fd05ea559 | triage T1110 step 5 | count | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776 OR event.code:4740 OR win.Status:0xc000006a OR win.Status:0xc000006d", "time_from": null, "time_to": null} | 1 |  |
| q-8ca88b4218 | triage T1110 step 5 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": "win.TargetUserName"} | 297 |  |
| q-956ae0b6d3 | triage T1110 step 6 | search | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776 OR event.code:4740 OR win.Status:0xc000006a OR win.Status:0xc000006d", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.… | 1 | F13, F14, F17 |
| q-96c0400e68 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-9fae62fdd6 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-d1df9e1c63 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-b5c6ed22bf | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-6c23fcfe4f | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-c8c1fc0d5b | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-94d6cca630 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-dbc5ebcd78 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-3e13c5b70b | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-beb5c39a34 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS38Vi"} | None |  |
| q-fd1c82c50e | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-9bf323d414 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-27fc87c0cf | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-9f1bd02668 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-7d4610742d | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-da4d0cc9ec | triage T1111 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*LSASS*) AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x300… | 9 | F18 |
| q-6fdbd7e81f | triage T1111 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*LSASS*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-de348c1862 | triage T1111 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None | F18 |
| q-5963549347 | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*PowerShell.exe AND host.name:scranton.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.… | 0 |  |
| q-59a9b9ede1 | triage T1111 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND win.ProcessId:2976", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executable", "user.name", "win.ProcessGuid", "… | 1 | F18 |
| q-02b5b30cd9 | triage T1111 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:00:00.000Z TO 2020-05-02T03:10:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win… | 99 |  |
| q-92fe524248 | triage T1111 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:04:00.000Z TO 2020-05-02T03:08:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win… | 44 | F18 |
| q-be0f77d253 | triage T1111 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.parent.executable:*PowerShell.exe AND host.name:scranton.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "p… | 0 |  |
| q-eb78728fa6 | triage T1111 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None | F18 |
| q-5328dbf2d7 | triage T1111 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None | F18 |
| q-df4e758aaa | triage T1111 step 6 | search | {"dataset": "windows.sysmon", "query": "(win.TargetFilename:*.pfx OR file.path:*.pfx OR win.TargetFilename:*SmartCard* OR win.TargetFilename:*SCard* OR win.TargetFilename:*cert* OR win.TargetFilename:*token*)", "time_from": null, "time_to": null, "fields": ["@… | 2 | F18 |
| q-1a3902d608 | triage T1111 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Certificate* OR registry.path:*Credential* OR registry.path:*Vault* OR registry.path:*Ngc* OR registry.path:*Token*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 61 |  |
| q-da6e8a9510 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-68520cb284 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-dda46ded7a | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-c4504f8fae | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5I18"} | None |  |
| q-fd90ed6dc3 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-41352b89cd | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-4590e20147 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-a84ee488e4 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-431e69e6b4 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkTWMJ0"} | None |  |
| q-a77066a09b | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkZdAbb"} | None |  |
| q-110ba54bba | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWV3"} | None |  |
| q-f91edc9952 | triage T1187 step 1 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*LSASS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.SubjectUserName", "win.ProcessName", "win.Access… | 6 | F20 |
| q-a1c51bceaf | triage T1187 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.lnk OR win.TargetFilename:*.url OR win.TargetFilename:*.scf OR win.TargetFilename:*.library-ms)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.Tar… | 3 | F20 |
| q-4af00a8e3b | triage T1187 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "destination.ip", "destination.port", "process.executable", "user.name", "win.So… | 66 | F20 |
| q-bb6ab74b13 | triage T1187 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpESdr2"} | None |  |
| q-8a8db0f1a5 | triage T1187 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*hostui* OR process.command_line:*StartUp* OR process.command_line:*lnk*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.… | 3 | F20 |
| q-bd87d81d54 | triage T1187 step 2 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 20, "sub_field": "host.name"} | 66 |  |
| q-4ea6d958d1 | triage T1187 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*hostui* OR win.ScriptBlockText:*StartUp* OR win.ScriptBlockText:*WScript.Shell* OR win.ScriptBlockText:*CreateShortcut*)", "time_from": null, "time_to": null, "fields": ["@ti… | 1 |  |
| q-49f359da26 | triage T1187 step 3 | search | {"dataset": "windows.sysmon", "query": "win.TargetFilename:*hostui*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetFilename", "process.executable", "process.command_line", "user.name"], "size": 20, "sort": … | 3 |  |
| q-f48a495834 | triage T1187 step 4 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:4104 AND @timestamp:[2020-05-02T03:00:00.000Z TO 2020-05-02T03:10:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "wi… | 99 |  |
| q-68e1b3c004 | triage T1187 step 4 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:00:00.000Z TO 2020-05-02T03:10:00.000Z] AND (process.command_line:*\\\\\\\\* OR dns.question.name:* OR event.code:22)", "time_from": null, "time_to": null, "… | 14 |  |
| q-d94c3f2eeb | triage T1187 step 5 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:4104 AND @timestamp:[2020-05-02T03:02:30.000Z TO 2020-05-02T03:05:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "wi… | 22 |  |
| q-e86d769b65 | triage T1187 step 5 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND (win.TargetFilename:*hostui.bat OR win.TargetFilename:*hostui.exe OR win.TargetFilename:*hostui*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.co… | 3 |  |
| q-6c83d86f27 | triage T1187 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCw1"} | None |  |
| q-597820e1dd | triage T1187 step 6 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:4104 AND (win.ScriptBlockText:*Invoke-Persistence* OR win.ScriptBlockText:*PersistStep*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ev… | 2 |  |
| q-322ae287c2 | triage T1187 step 7 | search | {"dataset": "windows.security", "query": "event.code:5145 AND win.ShareName:*IPC$*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ShareName", "win.SubjectUserName", "win.IpAddress", "win.RelativeTargetName"], "si… | 45 | F20 |
| q-1040e13e5f | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-6d2a3fdcf9 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-1b89363227 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsQ2P9A"} | None |  |
| q-c4e78b93ac | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpESdr2"} | None |  |
| q-5b2f3a6b8a | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItj59cFt"} | None |  |
| q-fdbe73e22b | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpIWWNw"} | None |  |
| q-5e1b047388 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0eh"} | None |  |
| q-b27e69a413 | triage T1212 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:\"C:\\\\windows\\\\system32\\\\lsass.exe\"", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a8147e9b4b | triage T1212 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:\"C:\\\\windows\\\\system32\\\\lsass.exe\"", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e3e20d0625 | triage T1212 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:\"C:\\\\windows\\\\system32\\\\lsass.exe\" AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess… | 9 | F21 |
| q-36dc7ca6da | triage T1212 step 2 | search | {"dataset": "windows.sysmon", "query": "process.parent.executable:\"C:\\\\ProgramData\\\\victim*\"", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "process.command_line", "process.parent.executabl… | 0 |  |
| q-c1a7a93707 | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None | F21 |
| q-c6d0278af5 | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-e89b3fd6e3 | triage T1212 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4104\",\"4103\",\"400\",\"800\") AND @timestamp >= \"2020-05-02T03:00:00Z\" AND @timestamp <= \"2020-05-02T03:12:00Z\" AND host.name == \"scranton.dmevals.local\" \|… | 40 |  |
| q-23b29e49f9 | triage T1212 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None | F21 |
| q-15c6e0f5dd | triage T1212 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText \| LIMIT 30"} | 30 |  |
| q-9d4ed0fb3c | triage T1212 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*Mimikatz*\" OR process.command_line LIKE \"*sekurlsa*\" OR process.command_line LIKE \"*pro… | 1 |  |
| q-1926e516ea | triage T1212 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, process.pid, process.executable, process.command_line, process.parent.executable… | 40 |  |
| q-e8abbee8ba | triage T1212 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4624\",\"4672\",\"4688\") AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:00:00Z\" AND @timestamp <= \"2020-05-02T03:12:00Z\" \| KEEP @ti… | 40 |  |
| q-ea6696bc23 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-285346fdda | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-cec42f03fc | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-4c30f115ee | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-4ce117c14a | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHon1uOFchItwxYBM6"} | ERROR |  |
| q-73e788c386 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYrx"} | None |  |
| q-b2e780d1f4 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None | F22 |
| q-1ddbfb985c | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" OR TO_LOWER(win.TargetFilename) … | ERROR |  |
| q-4e00adc18f | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| STATS c = COUNT(*) BY process.executable, host.name, user.name \| SORT c DESC \| LIMIT 60"} | 60 |  |
| q-3481d37317 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" OR TO_LOWER(win.TargetFilename) … | 7 | F22 |
| q-1e191d4abd | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(process.executable) LIKE \"*chrome*\" OR TO_LOWER(process.executable) LIKE \"*firefox*\" OR TO_LOWER(process.executable) LIKE \"*msedge*\" OR TO_LOWER(process.executable) LIKE \… | 0 |  |
| q-a1ad703d63 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (TO_LOWER(win.TargetFilename) LIKE \"*microsoftedge*\" OR TO_LOWER(win.TargetFilename) LIKE \"*google*\" OR TO_LOWER(win.TargetFilename) LIKE \"*mozilla*\" OR TO_LOWER(win.TargetFilename… | 3 | F22 |
| q-9f56e5ecd9 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(process.executable) LIKE \"*python*\" OR TO_LOWER(process.executable) LIKE \"*psexec*\" OR TO_LOWER(process.executable) LIKE \"*sdelete*\" OR TO_LOWER(process.executable) LIKE \… | 40 |  |
| q-011125b335 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(process.executable) LIKE \"*python*\" \| KEEP @timestamp, host.name, event.code, process.executable, process.command_line, process.parent.executable, user.name, win.TargetFilena… | 30 |  |
| q-9291514870 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*login data*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sqlite*\" … | 0 |  |
| q-5a5ede2d61 | triage T1539 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None | F22 |
| q-6288a137df | triage T1539 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*cookies*\" OR TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*microsoftedge*\" OR TO_LOW… | 0 |  |
| q-3a12824faf | triage T1539 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNpkH"} | None | F22 |
| q-6d47d240dc | triage T1539 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code IN (\"15\",\"17\",\"23\") AND (TO_LOWER(win.TargetFilename) LIKE \"*edge*\" OR TO_LOWER(win.TargetFilename) LIKE \"*chrome*\" OR TO_LOWER(win.TargetFilename) LIKE \"*firefox*\… | 2 |  |
| q-594e6f67e9 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNpkH"} | None |  |
| q-3191d77ac0 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNpkH"} | None |  |
| q-509b5cf54d | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkfkUhu"} | None |  |
| q-ca138e3f4b | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-5b5fb521e3 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItj59MFD"} | None |  |
| q-e20f1a344f | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-be7a4361aa | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-e30b443f1c | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None | F23, F27 |
| q-445961774a | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None | F24, F27 |
| q-7f1e281b52 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSwG"} | None | F27 |
| q-d4dee03f54 | triage T1552 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*.pfx", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "file.path", "process.executable", "process.command_line", "win.TargetFilename"], "size": 20, "so… | 1 | F23, F25 |
| q-0550904033 | triage T1552 step 2 | search | {"dataset": "windows.security", "query": "event.code:5145 AND (win.RelativeTargetName:*Groups.xml OR win.RelativeTargetName:*SYSVOL* OR win.RelativeTargetName:*Policies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", … | 38 | F26 |
| q-76318bb8d6 | triage T1552 step 3 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None | F24 |
| q-6c6baef5cc | triage T1552 step 3 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YsM"} | None |  |
| q-09a4c03fc8 | triage T1552 step 4 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None | F24 |
| q-b906c90290 | triage T1552 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*readme.ps1 OR process.command_line:*psversion.ps1 OR process.command_line:*Get-PrivateKeys OR process.command_line:*Export-PfxCertificate)", "time_from": null, "time_to": null, "fi… | 0 |  |
| q-2b96fcbc21 | triage T1552 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND process.executable:*powershell.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_lin… | 11 |  |
| q-4f0052ec56 | triage T1552 step 5 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential* OR registry.path:*Winlogon*)", "time_from": null, "time_to": null, "size": 20, "sub_field": "host.name"} | 24 |  |
| q-fb0bc8f1a7 | triage T1552 step 6 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*.pfx", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.ObjectName", "process.executable", "win.AccessMask"], "size": 20, "so… | 0 |  |
| q-8e8d913e2c | triage T1552 step 6 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:scranton.dmevals.local AND user.name:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.Path", "win.ScriptBlockText"], "s… | 146 |  |
| q-2f964314c3 | triage T1552 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHqJZm"} | None | F24 |
| q-599072a9bd | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-d3d5db4e15 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-b4e521aa74 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-fce1eaab87 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-996d20abbc | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHqJZm"} | None |  |
| q-a12ee812e6 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-668b83c036 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-081ea7a781 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-09e9729ca8 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-9808351134 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxXRM1"} | None |  |
| q-b3cc9291b7 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwsQxHO"} | None |  |
| q-0c7ee2ef2d | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-8b78f95f0e | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-ff4bf5a2bc | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSwG"} | None |  |
| q-dc16869130 | triage T1555 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1… | 33 | F30 |
| q-494ca0a439 | triage T1555 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND process.executable:*PowerShell.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.TargetIma… | 2 | F28 |
| q-fb0b32e5b9 | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None | F28 |
| q-2d764bfefc | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-bec23e3ede | triage T1555 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND process.executable:*PowerShell.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.… | 0 |  |
| q-214e3754a1 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC \| LIMIT 60"} | ERROR |  |
| q-89b1d4c2ef | triage T1555 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC \| LIMIT 60"} | 60 | F29 |
| q-3d960db916 | triage T1555 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executable", "process.parent.com… | 359 | F28, F31 |
| q-5825c3b911 | triage T1555 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:01:50.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, u… | 60 | F28 |
| q-d5ee83f6ab | triage T1555 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYrx"} | None |  |
| q-e9ce573dc9 | triage T1555 step 6 | search | {"dataset": "windows.security", "query": "host.name:scranton.dmevals.local AND (event.code:4688 OR event.code:4663 OR event.code:4656) AND (process.command_line:*lsass* OR process.command_line:*dump* OR win.ObjectName:*lsass* OR win.TargetProcessName:*lsass* O… | 12 |  |
| q-5b0119e96b | triage T1555 step 7 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo4k"} | None | F28 |
| q-298d525900 | triage T1555 step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key4.db*\" OR TO_LOWER(file.path) LIKE \"… | 1 | F29 |
| q-17997f184e | triage T1555 step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*vaultcmd*\" OR TO_LOWER(process.command_line) LIKE \"*cmdkey*\" OR TO_LOWER(process.command_line) LIKE \"*keepass*\" OR TO… | 0 |  |
| q-309cf58d04 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-28b4d0e7fe | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-d5aa02a376 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-61a8041ff2 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo4k"} | None |  |
| q-54c7865ce5 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo4k"} | None |  |
| q-13aa007512 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-77801af4c6 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-8816b1c578 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-b714bffd88 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHqJZm"} | None |  |
| q-fbf09fe7ea | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX1"} | None |  |
| q-64d82d0814 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkady05"} | None |  |
| q-32b46e752c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkbfEQ2"} | None |  |
| q-2013b39e20 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-a76d7f2143 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-3355cd9bc3 | triage T1556 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (win.SourceImage:*powershell* OR win.SourceImage:*wsmprovhost* OR win.SourceImage:*wininit* OR win.SourceImage:*csrss* OR win.SourceImage:*services.exe)", "time_from": nul… | 7 |  |
| q-5d7368eedd | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND win.SourceImage:*PowerShell.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 2 | F32 |
| q-52c8298d8b | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None | F32 |
| q-97e8dd9fab | triage T1556 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.pid:2976 AND host.name:scranton.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exe… | 1 |  |
| q-74ad192c78 | triage T1556 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*sekurl… | 3 | F35, F37 |
| q-481d5e2e17 | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None | F32 |
| q-4c3f95d0e1 | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None | F36 |
| q-50a35f3fa7 | triage T1556 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 1 | F32 |
| q-fa57115dd9 | triage T1556 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*lsa* OR registry.path:*NetworkProvider* OR registry.path:*Notification* OR registry.path:*WDigest* OR registry.path:*SecurityProviders*)", "time_from": null, "time_to": null, "fields": [… | 442 | F38 |
| q-2df8d448b8 | triage T1556 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*\\\\Lsa\\\\* OR registry.path:*SecurityProviders* OR registry.path:*NetworkProvider* OR registry.path:*Notification\\\\ Packages* OR registry.path:*WDigest*)", "time_from": null, "time_t… | 296 | F38 |
| q-ed70f80f7c | triage T1556 step 6 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*rundll32* OR process.command_line:*monk… | 8 | F34 |
| q-ae2048ee04 | triage T1556 step 7 | search | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 36 | F34 |
| q-33190cb883 | triage T1556 step 7 | search | {"dataset": "windows.security", "query": "event.code:4673 AND (win.ObjectName:*lsass* OR win.ObjectName:*Lsa* OR win.ObjectName:*SAM* OR win.ObjectName:*Security*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 0 |  |
| q-756c2923a5 | triage T1556 step 8 | search | {"dataset": "windows.security", "query": "event.code:4648 AND process.executable:*PSEXESVC*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 4 | F33 |
| q-92b0ae025c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-77907b7414 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-2c9f2762d6 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-6acc26fa87 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-afb5bd683e | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-b2cf19e89c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpo7f-g"} | None |  |
| q-eaed665a07 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-3ccd4ffc22 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-93dc7b4a1e | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBM5"} | None |  |
| q-3d7c52d97d | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-fa610e4e20 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjGP74"} | None |  |
| q-a8deeba5e1 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlAOq"} | None |  |
| q-cda723d84f | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-9196537582 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDl0_c"} | None |  |
| q-7e8ca91dab | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItphxmvL"} | None |  |
| q-b81633d648 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpeuBtX"} | None |  |
| q-cf24d843af | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND destination.port == 445 \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.orig_l2_addr, zeek.resp_l2_addr, zeek.duration, zeek.conn_state, _id, _in… | 45 | F39, F40 |
| q-82243fc5e4 | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND (destination.port == 137 OR destination.port == 138 OR destination.port == 53) \| KEEP @timestamp, source.ip, destination.ip, destination.port, network.transport, zeek… | 47 | F41 |
| q-9cf20e3fd4 | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE zeek.orig_l2_addr == \"fc:bd:67:e1:a9:c1\" OR zeek.resp_l2_addr == \"fc:bd:67:e1:a9:c1\" \| KEEP @timestamp, event.action, source.ip, destination.ip, destination.port, network.transport, zeek.orig… | 44 |  |
| q-3e9756d4d4 | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"smb_files\" OR event.action == \"smb_mapping\" OR event.action == \"dce_rpc\" OR event.action == \"notice\" \| KEEP @timestamp, event.action, source.ip, destination.ip, zeek.file… | 148 |  |
| q-b09f0aa5a1 | triage T1557 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" \| STATS cnt = COUNT(*), first = MIN(@timestamp), last = MAX(@timestamp) BY source.ip, zeek.orig_l2_addr \| SORT source.ip"} | ERROR |  |
| q-b31118b2e0 | triage T1557 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND source.ip == \"10.0.1.4\" \| STATS cnt = COUNT(*), first = MIN(@timestamp), last = MAX(@timestamp) BY zeek.orig_l2_addr, destination.ip, destination.port \| SORT cnt D… | ERROR |  |
| q-d7734c171f | triage T1557 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" \| STATS cnt = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp) BY source.ip, zeek.orig_l2_addr \| SORT source.ip"} | 3 |  |
| q-5e2ade5c25 | triage T1557 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND source.ip == \"10.0.1.4\" \| STATS cnt = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp) BY zeek.orig_l2_addr, destination.ip, destination.port \| SORT cn… | 24 |  |
| q-ccdf9c006f | triage T1557 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 3 AND (destination.ip == \"10.0.1.6\" OR destination.ip == \"10.0.1.4\" OR destination.ip == \"10.0.1.5\") \| STATS cnt = COUNT(*) BY host.name, process.executable, destina… | ERROR |  |
| q-c4653de944 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"5858\" OR event.code == \"5857\" OR event.code == \"5860\" OR event.code == \"1500\" OR event.code == \"98\" OR event.code == \"1136\" OR event.code == \"1149\" \| KEEP @t… | 95 |  |
| q-58bfa7d288 | triage T1557 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.ip == \"10.0.1.6\" OR destination.ip == \"10.0.1.4\" OR destination.ip == \"10.0.1.5\" OR destination.ip == \"10.0.1.255\") \| STATS cnt = COUNT(*) B… | 129 |  |
| q-e631b449f9 | triage T1557 step 6 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"1500\" OR event.code == \"98\" OR event.code == \"1136\" OR event.code == \"1149\" OR event.code == \"16962\" OR event.code == \"2004\" OR event.code == \"2006\" OR event.… | 21 |  |
| q-be48122999 | triage T1557 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE process.executable LIKE \"*PsExec*\" OR process.parent.executable LIKE \"*PsExec*\" OR process.executable LIKE \"*psexec*\" \| KEEP @timestamp, host.name, event.code, process.executable,… | 279 | F42 |
| q-d503867ced | triage T1557 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" \| STATS cnt = COUNT(*) BY host.name, win.LogonType, win.TargetUserName, win.IpAddress \| SORT cnt DESC"} | 29 |  |
| q-873d9a3f3e | triage T1557 step 8 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rk"} | None | F39 |
| q-5bbaeba100 | triage T1557 step 8 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ud"} | None | F39 |
| q-d96c782cf0 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rk"} | None |  |
| q-42ef0e592d | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rk"} | None |  |
| q-84e217d9f3 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rk"} | None |  |
| q-b667968f80 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ud"} | None |  |
| q-8a5f45e560 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ud"} | None |  |
| q-2a1404b152 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-65b9067c81 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-c42dc72b7e | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-bd2e3398d7 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-e94ea59feb | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-7f7e1ef4ec | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uM"} | None |  |
| q-a962d172dd | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uM"} | None |  |
| q-41810b3c7b | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rw"} | None |  |
| q-27159d33bf | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rw"} | None |  |
| q-0faf429603 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8vYpc"} | None |  |
| q-4a5232d404 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8vYpc"} | None |  |
| q-c1d81d1c4a | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxXBPl"} | None |  |
| q-49ab991040 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxXBPl"} | None |  |
| q-e7ac44ed33 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEck"} | None |  |
| q-97dff05571 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-e6710393fe | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-b20af04fa2 | triage T1557 step 10 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uM"} | None | F40 |
| q-f98ba0bbfc | triage T1557 step 10 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rw"} | None | F40 |
| q-94c1ae390c | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F43 |
| q-78044bdfeb | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.SourceImage:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.SourceImage", "win.GrantedAccess", "win.Ca… | 4 |  |
| q-e04d0825ee | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None | F43 |
| q-45e8f85162 | triage T1558 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND (win.ProcessId:2976 OR process.pid:2976)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "pr… | 1 | F43 |
| q-5e7743f795 | triage T1558 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-73c4ec6508 | triage T1558 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 OR event.code == 4103 \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*kerberos*\" OR TO_LOWER(win.ScriptBlockText)… | ERROR |  |
| q-74b96e465b | triage T1558 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" OR event.code == \"4103\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*kerberos*\" OR TO_LOWER(win.ScriptBl… | 1 |  |
| q-7888f3a6ae | triage T1558 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" OR event.code == \"1\" \| WHERE TO_LOWER(file.path) LIKE \"*monkey*\" OR TO_LOWER(process.command_line) LIKE \"*monkey*\" OR TO_LOWER(process.command_line) LIKE \"*l… | 3 | F43 |
| q-81d6f9242e | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4768\" OR event.code == \"4769\" \| KEEP @timestamp, host.name, event.code, user.name, win.TargetUserName, win.ServiceName, win.TicketEncryptionType, win.TicketOptions,… | 42 | F44, F45, F46, F47 |
| q-891de3b438 | triage T1558 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None | F43 |
| q-b3d31875d7 | triage T1558 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpizF2M"} | None |  |
| q-51e048f5e6 | triage T1558 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, host.name, win.ScriptBlockText, _id, _index \| LIMIT 20"} | 11 | F43 |
| q-10d7e5b3e5 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpizF2M"} | None |  |
| q-b3470e5398 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-7a9937929c | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-cf7c1be2f3 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-df6822d27d | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-56eee543a6 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz-ho2U"} | None |  |
| q-af897a855e | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1osm"} | None |  |
| q-2f075ab04e | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsZ8ncx"} | None |  |
| q-eb3f0faf3a | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-34r"} | None |  |
| q-63c238d94d | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1osw"} | None |  |
| q-7167428e5c | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjGP6m"} | None |  |
| q-5c6399610f | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsZ8ncx"} | None |  |
| q-6913697f7e | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None |  |
| q-1ee78a0c11 | triage T1606 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.GrantedAccess IN (\"0x1\", \"0x1000000\", \"0x101068\", \"0x121440\", \"0x14c0\", \"0x2200\", \"0x18\", \"0x70\", \"0x101040\", \"0x101400\") \| KEEP @timest… | 15 | F48 |
| q-54b35d6a38 | triage T1606 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.TargetServerName, win.SubjectUserName, win.ProcessName, win.IpAddress, _id, _index"} | 15 | F50 |
| q-1b3c3e6ce1 | triage T1606 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookie*\" OR TO_LOWER(process.command_line) LIKE \"*saml*\" OR TO_LOWER(process.command_line) LIKE \"*token*\" OR TO_LOWER… | 6 | F49 |
| q-350e0aa658 | triage T1606 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkv3sHT"} | None | F49 |
| q-1863d48ef1 | triage T1606 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:08:00.000Z\" AND @timestamp <= \"2020-05-02T03:11:00.000Z\" \| KEEP @timestamp, user.nam… | 11 | F49 |
| q-5539af7783 | triage T1606 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*adfs*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*saml*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*signing*cert*\" OR… | 2 |  |
| q-1dfae8f63e | triage T1606 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*adfs*\" OR TO_LOWER(process.command_line) LIKE \"*saml*\" OR TO_LOWER(process.command_line) LIKE \"*cookie*\" OR TO_L… | 6 |  |
| q-54d1a3acba | triage T1606 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:07:00.000Z\" AND @timestamp <= \"2020-05-02T03:09:00.000Z\" \| KEEP @timestamp, w… | 36 |  |
| q-479cfa8134 | triage T1606 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonProcessName IN (\"User32 \", \"-\", \"NtLmSsp \") \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.LogonProcessName, win.LogonType,… | 4 | F48 |
| q-5db27242ee | triage T1606 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None | F49 |
| q-0ee0335e22 | triage T1606 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*.pfx*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.p12*\" OR TO_LOWER(win.TargetFilename) LIKE \"*adfs*\" OR TO_LOWER(win.Ta… | 2 | F49, F50 |
| q-4ac689ddea | triage T1606 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-500e2c9c65 | triage T1606 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:03:00.000Z\" AND @timestamp <= \"2020-05-02T03:06:30.000Z\" AND win.ScriptBlockTe… | 34 | F50 |
| q-965f1b8552 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None |  |
| q-8141364f57 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1ovv"} | None |  |
| q-9daaae518a | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsc-QNb"} | None |  |
| q-53844f094c | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAv"} | None |  |
| q-413634a835 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkv3sHT"} | None |  |
| q-2a8281a0c7 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkv3sHT"} | None |  |
| q-5f3a99903e | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y2d"} | None |  |
| q-51473c6bef | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-286609cbab | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-593f792b2e | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-f8c4768c0c | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-5de824291a | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwiDnzA"} | None |  |
| q-789ae90775 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwiDnzL"} | None |  |
| q-2b72c8e9f3 | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 1 |  |
| q-d85b63e987 | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-7ee6b42d7c | triage T1649 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.p12\" OR TO_LOWER(win.TargetFilename) LIKE \"*.cer\" OR TO_LOWER(win.Target… | 1 | F51 |
| q-58c7936cc3 | triage T1649 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*certutil*\" OR TO_LOWER(process.command_line) LIKE \"*export-pfxcertificate*\" OR TO_LOWER(process.command_line) LIKE \"*c… | 0 |  |
| q-f05fe45a9a | triage T1649 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None | F51 |
| q-cc4b860899 | triage T1649 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*pfx*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*certificate*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*x509*\" OR T… | 52 |  |
| q-27d6dc4382 | triage T1649 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND process.executable LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command… | 11 |  |
| q-9547267d45 | triage T1649 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1N1"} | None | F51 |
| q-1c0349b5e8 | triage T1649 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*beach*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*pfx*\" OR TO_LOWER(win… | 17 | F51 |
| q-5d81e87ab6 | triage T1649 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None | F51 |
| q-ff7d417f39 | triage T1649 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None | F51 |
| q-71b7682708 | triage T1649 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None | F51 |
| q-435ea02448 | triage T1649 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"11\" OR event.code == \"23\") AND (TO_LOWER(win.TargetFilename) LIKE \"*officesupplies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*downloads*\") \| KEEP @timestamp, host.… | 319 | F51 |
| q-8d1231dd84 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-75cf8c39e1 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-2d4fa02eac | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-f1ff1d5ef0 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-1a73c9efef | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-d92bcf33a8 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-864739807e | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y3M"} | None |  |
| q-e4c52513ea | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5I18"} | None |  |
| q-61c5816d0f | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1N1"} | None |  |
| q-ed3eb20eb3 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-87fece93ee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-ba5d945b50 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-258da05e26 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-4e677bf239 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-3d63a6a37f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-504546e00a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-05795420d8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-cb80095d87 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-90676e366a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtA"} | None |  |
| q-40aa1a7913 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtA"} | None |  |
| q-c0bea81b77 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtA"} | None |  |
| q-a5d4173bc7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsc9wP8"} | None |  |
| q-4925f39819 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-44c65402a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-89663b9edd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-3e7c07180f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1Ol"} | None |  |
| q-b8789988eb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-35bca2a852 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-6a164c421a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpp7sQg"} | None |  |
| q-be1499d3c5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5KNV"} | None |  |
| q-d4f6410789 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchIttyFQdU"} | None |  |
| q-b091d19f62 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpo7P8B"} | None |  |
| q-01c2636440 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkORY1E"} | None |  |
| q-d72568ae81 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo4k"} | None |  |
| q-64ea56aca5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo4k"} | None |  |
| q-20c6f1c3be | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-b99c7a62d9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-dd0e63c955 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-e71d5f9237 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1Agy"} | None |  |
| q-fbe74e76b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1Agy"} | None |  |
| q-9ef656bae4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-84bdb4a951 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ_4"} | None |  |
| q-d9ad3f70dd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ_5"} | None |  |
| q-6a40975bbb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1gg4"} | None |  |
| q-7f937b179e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1Agy"} | None |  |
| q-0019beedaa | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWV3"} | None |  |
| q-5d63feedd9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-4baa6228f1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-12f88730ce | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-472f1a59fc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-94be79c701 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-0ae1347a24 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-4c1e56ae55 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-269257c1cc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-705a45265f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-b54bb509e1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS38Vi"} | None |  |
| q-901eb03e57 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-6796cec919 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-5f69bd854f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-9d8a272d3f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-bb17198ec5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-b226218164 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-0152408b01 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-893f1cf92d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-da8822fe26 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5I18"} | None |  |
| q-ceaace50ea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-047c6c2b98 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-304ebee07d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-fd436d2ab2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-313d927cb8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkTWMJ0"} | None |  |
| q-74748e673a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkZdAbb"} | None |  |
| q-35089d4eea | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWV3"} | None |  |
| q-0488a72795 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-18382d705c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-7570db90aa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsQ2P9A"} | None |  |
| q-abbe655c20 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpESdr2"} | None |  |
| q-350d6b60cb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItj59cFt"} | None |  |
| q-eef79001f7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpIWWNw"} | None |  |
| q-c0e2388b0d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0eh"} | None |  |
| q-8792e8a8a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-cf053765d3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-971b71e648 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-00d9099309 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-4d68023016 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-0ebb4543a0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNpkH"} | None |  |
| q-3224755b79 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNpkH"} | None |  |
| q-741ca78499 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkfkUhu"} | None |  |
| q-0b749af81e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-c0c90a1792 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItj59MFD"} | None |  |
| q-b9d01b0317 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-6adb3f89c4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-6aaac5174f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-d068c0f6da | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-246302110d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-ba78fd4103 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-2b5e80780f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHqJZm"} | None |  |
| q-3b0f3bd118 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-0532c3c06b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-d90ea2a6ed | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-e9e97a326a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-7edd78d82f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxXRM1"} | None |  |
| q-afcad18113 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwsQxHO"} | None |  |
| q-c37c3efd16 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-3236931cbf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-82d93d023e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSwG"} | None |  |
| q-5636f50718 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-0dccc7bb4b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-5e28111f35 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-4d9d3222e8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo4k"} | None |  |
| q-1af32f07f1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo4k"} | None |  |
| q-6ef76dadb5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-8df5860374 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-2e6b8ed030 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-dbfc651714 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHqJZm"} | None |  |
| q-25dc8b904f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX1"} | None |  |
| q-50553ff59d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkady05"} | None |  |
| q-3280929a24 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkbfEQ2"} | None |  |
| q-fad2298f68 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-985312f10b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-5e433d76b6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-171fd01d34 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-ec2583ee3e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-06bb35fa7b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-93acf3a6f4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpo7f-g"} | None |  |
| q-471b241070 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-e675240972 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-2d716fa217 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBM5"} | None |  |
| q-59c0d5f573 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-0f94b211ff | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjGP74"} | None |  |
| q-4737f427e9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlAOq"} | None |  |
| q-d9831a5eb9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-e3427ccc4b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDl0_c"} | None |  |
| q-244dd34910 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItphxmvL"} | None |  |
| q-206ddefdda | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpeuBtX"} | None |  |
| q-e510719c46 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rk"} | None |  |
| q-420e462de5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rk"} | None |  |
| q-563ca98c0e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rk"} | None |  |
| q-28118c4ffa | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ud"} | None |  |
| q-59c7a50e2c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ud"} | None |  |
| q-8b03ebf042 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-6efdf61699 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-8eb4124deb | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-ea786abb9c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-ab5dcd9e36 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-85e2442f8a | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uM"} | None |  |
| q-e399f7f536 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uM"} | None |  |
| q-81ddfa8bc2 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uM"} | None |  |
| q-5280bc8514 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rw"} | None |  |
| q-b8a7d962f9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rw"} | None |  |
| q-9564ffb343 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8vYpc"} | None |  |
| q-7dbb478093 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8vYpc"} | None |  |
| q-ab6aa6f2db | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxXBPl"} | None |  |
| q-ba176911c9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxXBPl"} | None |  |
| q-b4012d1ddb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEck"} | None |  |
| q-85df95a037 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-b5637db45f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-9d77cf6323 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpizF2M"} | None |  |
| q-fc6f56cc90 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-44032b284b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-0feea56dee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-b2ddb2c3be | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-8b63ba80b1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz-ho2U"} | None |  |
| q-8724b9c184 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1osm"} | None |  |
| q-62eda55c95 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsZ8ncx"} | None |  |
| q-07c2051cf6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-34r"} | None |  |
| q-88e9ef4170 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1osw"} | None |  |
| q-51ce783e04 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjGP6m"} | None |  |
| q-35e97ed6b1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsZ8ncx"} | None |  |
| q-e04db0a7ae | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None |  |
| q-bb6672919d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1ovv"} | None |  |
| q-52db4b6a82 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsc-QNb"} | None |  |
| q-9409cda296 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAv"} | None |  |
| q-43d3958df7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkv3sHT"} | None |  |
| q-942e07ec35 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkv3sHT"} | None |  |
| q-e3eec936ef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y2d"} | None |  |
| q-84b6989ea9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-597038611b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-206f716315 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-72fe46c839 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-88faf2ae7e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwiDnzA"} | None |  |
| q-94857c3f0f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwiDnzL"} | None |  |
| q-fc03c8c646 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-1070ec48a1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-3f45170025 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-fa8e5606bc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-185bc66d9b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-bdb2300856 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-ef9df245c3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y3M"} | None |  |
| q-d0db52bdc2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5I18"} | None |  |
| q-67a2e4ef94 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1N1"} | None |  |
| q-38a473deca | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-503f80e454 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": "process.parent.executable"… | 61 |  |
| q-c17cdf4d35 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-00c3ed82cd | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": "process.parent.execut… | 63 |  |
| q-1d6e002692 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-d94e5c3f4a | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:35:46+00:00", "size": 100, "sub_field": "process.parent.ex… | 359 |  |
| q-8ea3bf03ef | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:35:46+00:00", "size": 100, "sub_field": "process.executable"} | 1276 |  |
| q-ca6b256a43 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:35:46+00:00", "size": 100, "sub_field": "process.pare… | 370 |  |
| q-def5a096a5 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:35:46+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-f948a3072c | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*python.exe\" OR process.executable LIKE \"*Rar.exe\" OR process.executable LIKE \"*sdelete64… | 11 |  |
| q-0ac5006abf | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (process.executable LIKE \"*csc.exe\" OR process.executable LIKE \"*hostui.exe\" OR process.executable LIKE \"*sdclt.e… | 15 |  |
| q-5e0ea2849c | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"11\",\"22\",\"23\",\"3\",\"8\",\"10\",\"17\",\"18\") AND (process.executable LIKE \"*python.exe\" OR process.executable LIKE \"… | ERROR |  |
| q-0f7b480e0c | pivot step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"4104\",\"4103\",\"800\") \| KEEP @timestamp, event.code, user.name, powershell.file.script_block_text, powershell.command.n… | ERROR |  |
| q-abc7ff2496 | pivot step 3 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-a617bcd281 | pivot step 3 | get_fields | {"dataset": "windows.sysmon", "prefix": "win"} | None |  |
| q-e44e01a1d7 | pivot step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"11\",\"22\",\"23\",\"3\",\"8\",\"10\",\"17\",\"18\") AND (process.executable LIKE \"*python.exe\" OR process.executable LIKE \"… | 500 |  |
| q-05607a35c6 | pivot step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"4104\",\"4103\") \| KEEP @timestamp, event.code, user.name, win.ScriptBlockText, win.Message, _id, _index \| SORT @timestam… | 91 |  |
| q-7aa84fd4d5 | pivot step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND process.executable LIKE \"*python.exe\" AND event.code IN (\"11\",\"22\",\"23\",\"3\",\"8\",\"10\",\"17\",\"18\",\"1\") \| KEEP @timestamp, even… | 405 |  |
| q-96f929f075 | pivot step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp"} | 146 |  |
| q-1a348057cd | pivot step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"5145\",\"4673\",\"4688\") AND (win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*SECURITY*\" OR win.ObjectName LIKE \"*ntds*\" OR win.ObjectNam… | ERROR |  |
| q-4ed01eb003 | pivot step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND @timestamp > \"2020-05-02T03:01:51\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| SORT @t… | 106 |  |
| q-8a3d1616ad | pivot step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"5145\",\"4673\") AND (win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*SECURITY*\" OR win.ObjectName LIKE \"*ntds*\" OR win.ObjectName LIKE \"… | 29 |  |
| q-30ad4b3dfe | pivot step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND @timestamp > \"2020-05-02T03:06:47\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| SORT @t… | 63 |  |
| q-c947716309 | pivot step 8 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYpu"} | None |  |
| q-ef7560b8d8 | pivot step 8 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-ffb109cedf | pivot step 8 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS38Vi"} | None |  |
| q-3ece096d65 | pivot step 9 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*Keystrokes*\" OR win.ScriptBlockText LIKE \"*GetAsyncKeyState*\" OR win.ScriptBloc… | 4 |  |
| q-153f3f4b11 | pivot step 9 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4656\",\"4663\") AND win.ObjectName LIKE \"*lsass.exe\" AND win.SubjectUserName == \"pbeesly\" \| KEEP @timestamp, event.code, host.name, win.ObjectName, win.ProcessNa… | 4 |  |
| q-1175418323 | pivot step 10 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"3\" AND process.executable LIKE \"*python.exe\" \| STATS c = COUNT(*) BY win.DestinationIp, win.DestinationPort \| SORT c DESC"} | 1 |  |
| q-7633a4c564 | pivot step 10 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*pass*\" OR file.path LIKE \"*cred*\" OR file.path LIKE \"*vault*\" OR file.path LIKE \"*.pfx\" OR file.path LIKE \"*.kdbx\" OR file.path LIKE … | 13 |  |
| q-34ff1747dd | pivot step 11 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdI9"} | None |  |
| q-58e8b2f6bb | pivot step 11 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ_5"} | None |  |
| q-fdabdd9e1f | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopf"} | None |  |
| q-822d6b5828 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopc"} | None |  |
| q-9714a32598 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYpu"} | None |  |
| q-fe0919a86e | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz_iFNN"} | None |  |
| q-734a939017 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-a1c7164fec | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-3662ac06d0 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-9692a4acd7 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-29b6c3dc7a | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-d8148a4f2d | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS38Vi"} | None |  |
| q-7fe576f630 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS38Vi"} | None |  |
| q-c4f20ef3c0 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1OJ"} | None |  |
| q-f27da111cd | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdI9"} | None |  |
| q-6931cd49e2 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkjomHY"} | None |  |
| q-24863957f1 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdLv"} | None |  |
| q-7043c91512 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-ae1f70c0a8 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ_5"} | None |  |
| q-6d93c1280a | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ-S"} | None |  |
| q-00207ea8bf | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ_8"} | None |  |
| q-34b41dba90 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-a671ecf1a3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-850f1146f4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-ab5264e7b9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-e518134b16 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-150ee66370 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-6539b75d46 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-8ed46924be | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-51cf31e785 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtA"} | None |  |
| q-07b96576c7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtA"} | None |  |
| q-9e4a33525f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtA"} | None |  |
| q-cc5fe280f6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsc9wP8"} | None |  |
| q-4075f12402 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-35966def44 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-640831f145 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-767630d072 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1Ol"} | None |  |
| q-c17379ae4c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-537d85ae08 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-8931f0a7c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpp7sQg"} | None |  |
| q-09f77ff046 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5KNV"} | None |  |
| q-e465f6acf7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchIttyFQdU"} | None |  |
| q-07246aacf9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpo7P8B"} | None |  |
| q-25093261cf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkORY1E"} | None |  |
| q-1b6592f67b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo4k"} | None |  |
| q-09a58c5aab | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo4k"} | None |  |
| q-fb448fb57f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-b8c6760682 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-d91158a33b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-6b9e9661af | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1Agy"} | None |  |
| q-8069aaa9ea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1Agy"} | None |  |
| q-3543d4eba3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-550ea61dcc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ_4"} | None |  |
| q-29d1d7d931 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ_5"} | None |  |
| q-827c92dc2d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1gg4"} | None |  |
| q-78306fb4f2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1Agy"} | None |  |
| q-2d75e5c098 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWV3"} | None |  |
| q-53f655bd43 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-63abaaa456 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-4fa2144193 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-775000a594 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-8602f9a39c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-18bec6b551 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-5de5c60597 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-aa575e3501 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-a0ab9cc851 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-d3db6a01cf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS38Vi"} | None |  |
| q-de40469ae6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-dd3e257e23 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-e514df60d5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-ab2d831352 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-6f9c3da300 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-978be1c1e0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-d2c2c5cccd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-3f20355557 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-3fcd7c295d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5I18"} | None |  |
| q-061d7ed2e9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-acd3edabd4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-bf7ddb3154 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-92e83c7850 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-ac9e0a7583 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkTWMJ0"} | None |  |
| q-608f7aff23 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkZdAbb"} | None |  |
| q-b525836556 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWV3"} | None |  |
| q-477de5c71f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-45f59ba66b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-39c6dc6194 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsQ2P9A"} | None |  |
| q-86cf435be0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpESdr2"} | None |  |
| q-22886e934b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItj59cFt"} | None |  |
| q-7325ccb84e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpIWWNw"} | None |  |
| q-6609f81e31 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0eh"} | None |  |
| q-d94f485542 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-9cbcf7e828 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-150a286c95 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-a378cc709f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-d44c8e0b7c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-3519db334d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNpkH"} | None |  |
| q-444354ff41 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNpkH"} | None |  |
| q-fda6cbf958 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkfkUhu"} | None |  |
| q-89aae975d9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-8a74297247 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItj59MFD"} | None |  |
| q-f93e4d0805 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-10296141d4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-b3e3b0c920 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-c5097389d2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-c6b6ca6346 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-4e995c661e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-a5c2c70f35 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHqJZm"} | None |  |
| q-ba4c5bd6e1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-dd6a007da9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-44f6c1a3fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-a91be74ab8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-0c34e716a5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxXRM1"} | None |  |
| q-69fc9e66e6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwsQxHO"} | None |  |
| q-16e050fa6b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-13e5a40a88 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-97094128e7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSwG"} | None |  |
| q-a1825e5f90 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-8de88845a0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-5497186c9b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-3e4637137d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo4k"} | None |  |
| q-711282d4a7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo4k"} | None |  |
| q-783396a843 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-e35fe80b39 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-bb1f852de5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-526c2d8a28 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHqJZm"} | None |  |
| q-1f50e5ef1d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX1"} | None |  |
| q-f64c59a530 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkady05"} | None |  |
| q-4894c02b85 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkbfEQ2"} | None |  |
| q-b7d233a68b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-463a5e5504 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-6b3b1c5e36 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-0969aa751a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-0fae97b57e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-3e4c69ed1b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-7012d8b887 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpo7f-g"} | None |  |
| q-63a262e8ea | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-7955ba7149 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-1da809f161 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBM5"} | None |  |
| q-947b049c2b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-d134e9aeda | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjGP74"} | None |  |
| q-274f1a541e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlAOq"} | None |  |
| q-976bfdc000 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-5389eca6c0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDl0_c"} | None |  |
| q-1b99ad4445 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItphxmvL"} | None |  |
| q-7ddf469031 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpeuBtX"} | None |  |
| q-0656ad086a | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rk"} | None |  |
| q-88e65069da | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rk"} | None |  |
| q-e1a594b965 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rk"} | None |  |
| q-0b62ecc092 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ud"} | None |  |
| q-b12618cf61 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ud"} | None |  |
| q-d8df0db92c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-9b0d3bd340 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-229b1a4d0e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-a470b29804 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-4e1fca0001 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-203130a420 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uM"} | None |  |
| q-476764fdb1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uM"} | None |  |
| q-cfacf19410 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uM"} | None |  |
| q-3c7f172c64 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rw"} | None |  |
| q-8bfe200614 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rw"} | None |  |
| q-5c2be713e2 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8vYpc"} | None |  |
| q-1cbaf204df | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8vYpc"} | None |  |
| q-d695b4c3d6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxXBPl"} | None |  |
| q-2fcd4963fa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxXBPl"} | None |  |
| q-e9d6af43c9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEck"} | None |  |
| q-8e1e7cd0c4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-59973a03b0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-13dab739fc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpizF2M"} | None |  |
| q-065396c264 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-92392566f7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-6bdb252ee9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-e5b88985cf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-4ca76255e4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz-ho2U"} | None |  |
| q-51e8839a42 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1osm"} | None |  |
| q-d9df6287b8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsZ8ncx"} | None |  |
| q-f116822c96 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-34r"} | None |  |
| q-861031d82d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1osw"} | None |  |
| q-2c4076dd1e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjGP6m"} | None |  |
| q-3b757bfe39 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsZ8ncx"} | None |  |
| q-af3427580c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None |  |
| q-efeef1a451 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1ovv"} | None |  |
| q-05c107c9b6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsc-QNb"} | None |  |
| q-548f057ce8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAv"} | None |  |
| q-e858fde7c9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkv3sHT"} | None |  |
| q-8098331e54 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkv3sHT"} | None |  |
| q-6e7be3313a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y2d"} | None |  |
| q-927065e16c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-7129480d16 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-1d455974eb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-c74b5391d7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-2c44cea1ee | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwiDnzA"} | None |  |
| q-b3595d35a5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwiDnzL"} | None |  |
| q-f8a9154fe9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-34778c660b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-d61efca42e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-bc49bac160 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-90fa1d8fc7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-32277406a2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-5ef2f8eece | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y3M"} | None |  |
| q-e8bb3e6f29 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5I18"} | None |  |
| q-e0e82d4f68 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1N1"} | None |  |
| q-81bd71e1c0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |

## Verification

Evidence items cited: 181; confirmed against the stored events: 181; rejected: 0. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 4 item(s) in 3 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
