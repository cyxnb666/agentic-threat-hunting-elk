# Threat hunt report — 20261017-011820-converged-exp-B2

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 5 in-scope incident(s) of verified malicious findings (confidence >= medium): I02 T1003.001 (F01, F05, F13, F37, F39), I03 T1056.002 (F12), I06 T1552 (F02, F14, F33, F38), I07 T1552.001 (F32, F61, F62, F64), I08 T1552.004 (F31, F59)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-16T17:18:20+00:00 / 2026-10-16T17:27:37+00:00 (557.3 s) |
| LLM calls / tokens | 129 / {'prompt': 3513748, 'completion': 105412} |
| MCP tool calls | 1070 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003 | yes | suspicious/low | F65 | lsass.exe writing C:\Windows\debug\PASSWD.LOG on scranton |
| I02 | T1003.001 | yes | malicious/high | F01, F05, F13, F37, F39 | LSASS memory accessed with full-access masks by PowerShell on scranton and wsmprovhost on nashua |
| I03 | T1056.002 | yes | malicious/high | F12 | PowerShell screen-capture function (Invoke-ScreenCapture) run by pbeesly on scranton |
| I04 | T1187 | yes | suspicious/medium | F27 | PowerShell script blocks are credential/file collection, not forced authentication |
| I05 | T1539 | yes | suspicious/medium | F30 | APT29-style PowerShell screen capture and exfil present but unrelated to cookie theft |
| I06 | T1552 | yes | malicious/high | F02, F14, F33, F38 | Post-exploitation PowerShell credential toolkit run by pbeesly on scranton |
| I07 | T1552.001 | yes | malicious/high | F32, F61, F62, F64 | Hardcoded credentials in attacker PowerShell tooling and explicit-credential logons to NASHUA |
| I08 | T1552.004 | yes | malicious/high | F31, F59 | Get-PrivateKeys exported machine certificate private keys to .pfx on scranton |
| I09 | T1557.003 | yes | suspicious/low | F49 | No DHCP spoofing; NDIS Capture service toggle is a brief reverted change |
| I10 | out-of-scope:T1021 | no | suspicious/high | F11, F21, F24, F63 | PsExec lateral movement with plaintext credentials and python.exe payload on nashua |

## Findings

### F02 · malicious / high · T1003 · Post-exploitation PowerShell credential toolkit executed by pbeesly on scranton

Evidence status: **verified**

User pbeesly on scranton.dmevals.local ran a multi-function PowerShell post-exploitation toolkit (loaded from C:\Program Files\SysinternalsSuite\psversion.ps1) between 03:04 and 03:08 on 2020-05-02. Functions observed include Invoke-Discovery, Invoke-Persistence, Get-PrivateKeys (exports machine certificate private keys to .pfx files in the user's Downloads folder), Invoke-ScreenCapture, Get-Keystrokes (keylogging), and Invoke-Exfil (compresses the Downloads folder with 7-Zip and copies it to a WebDAV share at \\192.168.0.4\webdav). This credential-access-oriented toolkit is the context for the LSASS access on the same host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-9a851b7b21 | ok |
| 2 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21_Tx | q-9a851b7b21 | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-9e72d8a78e | ok |
| 4 | 2020-05-02 03:04:03.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Discovery {     $DiscoveryInfo =@()     $CurrentDir = Get-Location      $DiscoveryInfo += [PSCustomObject]@{                 CurrentDirectory = … | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21_RQ | q-c8a279ef0c | ok |

### F01 · malicious / high · T1003.001 · LSASS memory accessed with full-access masks by PowerShell.exe on scranton and wsmprovhost.exe on nashua

Evidence status: **verified**

On 2020-05-02 at 03:05:16, PowerShell.exe (PID 2976) on scranton.dmevals.local opened lsass.exe (PID 736) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) and 0x1f3fff, with a CallTrace ending in an UNKNOWN module (UNKNOWN(000001996D28200D)) rather than a signed system DLL — the classic signature of an in-memory LSASS dump. The same access mask 0x1f3fff against lsass.exe was used by wsmprovhost.exe (WinRM remote PowerShell) on nashua.dmevals.local at 03:09:29. This occurred in the middle of a post-exploitation PowerShell toolkit run by user pbeesly on scranton (Invoke-Discovery, Invoke-Persistence, Get-PrivateKeys, Invoke-ScreenCapture, Get-Keystrokes, Invoke-Exfil loaded from C:\Program Files\SysinternalsSuite\psversion.ps1). The Windows security log independently records pbeesly's powershell.exe accessing \Device\HarddiskVolume2\Windows\System32\lsass.exe at 03:05:16. The 0x1000 accesses by svchost.exe and the 0x1fffff accesses by wininit.exe/csrss.exe at 03:19:09 are normal system behaviour (boot-time), but the PowerShell/wsmprovhost accesses with read-memory masks are not.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-70b70f9207 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-276b49cd3d | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-70b70f9207 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-a1a02472a4 | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_j | q-d72fbd9bc9 | ok |
| 6 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-1e5c0b6563 | ok |

### F13 · malicious / high · T1056 · PowerShell opened LSASS with full access (0x1FFFFF) on scranton

Evidence status: **verified**

On 2020-05-02 at 03:05:16.654 UTC on scranton.dmevals.local, a PowerShell process (SourceImage C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe, SourceProcessId 2976, running as SYSTEM) opened a handle to C:\windows\system32\lsass.exe (TargetProcessId 736) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS). This is the classic credential-capture access to LSASS memory and coincides with the same pbeesly credential-access session (a 4663 event at 03:05:16 shows pbeesly's powershell reading lsass process memory, Access Mask 0x10). The remaining LSASS handle opens in the dataset are benign (svchost.exe 0x1000, Azure telemetry/antimalware 0x1400, and OS processes at boot).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-2c6a8a139b | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-2c6a8a139b | ok |
| 3 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | message | An attempt was made to access an object.    Subject:  	Security ID:		S-1-5-21-1830255721-3727074217-2423397540-1107  	Account Name:		pbeesly  	Account Domain:		… | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_j | q-05c0bfb95f | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | user.name | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_j | q-05c0bfb95f | ok |

### F14 · malicious / high · T1056 · Credential-file harvesting and exfiltration toolchain by pbeesly on scranton

Evidence status: **verified**

In the same session on scranton.dmevals.local, pbeesly ran PowerShell that recursively searched the user profile for credential-bearing files (*pass*, *login*, *admin*, *.pst, *.ost, *.vpn, *.pfx etc.) and compressed them, then defined Invoke-Exfil which 7-Zips the Downloads folder with password 'lolol' into %APPDATA%\OfficeSupplies.7z and copies it to a WebDAV share \\192.168.0.4\webdav using hardcoded credentials (cozy / MyCozyPassw0rd!), followed by Invoke-BeachCleanup deleting *.pfx/*.bmp/*.png and the archive. A steganographic loader was also executed from C:\Users\pbeesly\Downloads\monkey.png via IEX, and PsExec64 was used with cleartext credentials (dmevals\pbeesly / Fl0nk3rt0n!T0by) against \\NASHUA. This is credential collection and staging consistent with the T1056 input-capture family.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b87aOf | q-6ae9adb4b3 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-59304f684e | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-59304f684e | ok |
| 4 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxh3C | q-0ac0c2aea1 | ok |
| 5 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WdFNhN | q-24733c8a74 | ok |
| 6 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RqK7jn | q-24733c8a74 | ok |

### F12 · malicious / high · T1056.002 · PowerShell screen-capture function (Invoke-ScreenCapture) run by pbeesly on scranton

Evidence status: **verified**

On 2020-05-02 at 03:05:53 UTC on scranton.dmevals.local, user pbeesly (S-1-5-21-1830255721-3727074217-2423397540-1107) defined and then invoked a PowerShell function 'Invoke-ScreenCapture' (script block path C:\Program Files\SysinternalsSuite\psversion.ps1). The function starts a background job named 'Screenshot' that loops forever, using Add-Type -AssemblyName System.Windows.Forms and System.Drawing, [System.Windows.Forms.SystemInformation]::VirtualScreen and $graphic.CopyFromScreen(...) to capture the full virtual screen into a random .bmp file under $env:USERPROFILE\Downloads every 300 seconds. This is GUI input/screen capture for credential and session harvesting, part of a broader credential-access and exfiltration toolchain on the host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/ {     Start-Job -Name "Screenshot" -ScriptBlock {       … | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vTv | q-59304f684e | ok |
| 2 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Invoke-ScreenCapture;Start-Sleep -Seconds 3;View-Job -JobName "Screenshot" | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b22PTB | q-0ac0c2aea1 | ok |
| 3 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vTv | q-17804e4464 | ok |

### F33 · malicious / high · T1552 · Broad credential-access tooling run by pbeesly on scranton (encoded/hidden PowerShell, PsExec, sdelete)

Evidence status: **verified**

The same pbeesly session on scranton.dmevals.local shows a cluster of credential-access and post-access tooling: a hidden encoded PowerShell command (-nop -w hidden -e <base64>) at 03:21:28, a PowerShell one-liner reading HKLM:\SOFTWARE\Javasoft 'value Supplement' and piping it to Invoke-Expression at 03:21:27, a Start-Process hostui.exe -verb runas elevation attempt at 03:21:19, and a steganographic loader reading C:\Users\pbeesly\Downloads\monkey.png at 02:58:44. Process-creation stacking also shows PsExec64.exe/PSEXESVC.exe and sdelete64.exe on the hosts. These are the surrounding actions of the credential-theft campaign rather than a single unsecured-credentials artifact.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:28.949Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewAkAGIAPQAkAGUAbg… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MtUml9 | q-d588f949ad | ok |
| 2 | 2020-05-02 03:21:27.859Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MtUEbK | q-d588f949ad | ok |
| 3 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WdFNhN | q-d588f949ad | ok |

### F32 · malicious / high · T1552.001 · Hardcoded credentials in attacker PowerShell tooling (Invoke-Exfil) and explicit-credential logons to NASHUA

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell script block (loaded from C:\Program Files\SysinternalsSuite\psversion.ps1) defining Invoke-Exfil, which embeds plaintext credentials ($UserName 'cozy', $Password 'MyCozyPassw0rd!'), maps a WebDAV share \\192.168.0.4\webdav with those credentials, and copies a password-protected 7z archive of the user's Downloads to it. In the same window, security 4648 events show pbeesly performing explicit-credential logons from scranton (source.ip 10.0.1.6) targeting server NASHUA, and matching 4648 events on nashua.dmevals.local with process.executable C:\Windows\PSEXESVC.exe using account pbeesly — i.e. the harvested/embedded credentials were used to move laterally. Credentials-in-files/scripts and their reuse are the core of this technique.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-e1a1db8d39 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-e1a1db8d39 | ok |
| 3 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSP2J | q-bb891a2b61 | ok |
| 4 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YogQzA | q-bb891a2b61 | ok |

### F61 · malicious / high · T1552.001 · PowerShell credential-file harvesting on nashua (search for *pass*/*login*/*admin*/*vpn* and archive to working.zip)

Evidence status: **verified**

On nashua.dmevals.local, user pbeesly ran a PowerShell script block that recursively enumerates the user profile for credential-bearing file types (*psw*, *pass*, *login*, *admin*, *sifr*, *sifer*, *vpn, *.pst, *.ost, *.txt, *.lnk, etc.) and compresses the results into %APPDATA%\working.zip. This is a distinct credential-file collection step on nashua, separate from the scranton toolkit in the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | powershell.script_block_text | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxhdc | q-ceb9843d0f | ok |
| 2 | 2020-05-02 03:16:00.353Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RhB5tj | q-d069c05ce3 | ok |

### F62 · malicious / high · T1552.001 · Password-protected RAR archive of harvested files and sdelete wiping on nashua

Evidence status: **verified**

On nashua.dmevals.local, pbeesly ran C:\Windows\Temp\Rar.exe with a hardcoded password (-hpfGzq5yKw) to create working.zip from the harvested profile data, then ran C:\Windows\Temp\sdelete64.exe to securely delete the RAR binary and both working.zip copies. This is credential/data staging and anti-forensic cleanup on nashua, not present in the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RhBpvd | q-2bb038b8b5 | ok |
| 2 | 2020-05-02 03:16:52.456Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1Nd9MRE | q-fdbc7cddfd | ok |
| 3 | 2020-05-02 03:17:18.030Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Users\pbeesly\AppData\Roaming\working.zip"  | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1Nc7emY | q-fdbc7cddfd | ok |

### F31 · malicious / high · T1552.004 · Get-PrivateKeys PowerShell function exported machine certificate private keys to .pfx on scranton

Evidence status: **verified**

On 2020-05-02 03:04:56 (local 2020-05-01 23:04:56) user pbeesly on scranton.dmevals.local executed a PowerShell script block defining function Get-PrivateKeys, which enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a Thumbprint, writing each to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded password 'saribas'. The script was loaded from C:\Program Files\SysinternalsSuite\readme.ps1 (masquerading path). One second later sysmon recorded the resulting file creation C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx by powershell.exe, confirming the export actually ran. This is direct theft of private keys from the local certificate store.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-52e6fe6141 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-52e6fe6141 | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lUAH | q-0c217dbfce | ok |

### F37 · malicious / high · T1555 · LSASS memory accessed with full-access masks by PowerShell and remote WSMAN host

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976) opened a handle to lsass.exe (PID 736) with GrantedAccess 0x1f3fff at 03:05:16.623Z and 0x1fffff at 03:05:16.654Z — full-access masks consistent with credential dumping from LSASS memory. The same access is corroborated by a Windows Security 4663 object-access event on \Device\HarddiskVolume2\Windows\System32\lsass.exe by C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe under user pbeesly at 03:05:16. On nashua.dmevals.local, wsmprovhost.exe (PID 7720, the WSMAN remote-PowerShell host) opened lsass.exe (PID 728) with 0x1f3fff at 03:09:29.430Z, immediately after pbeesly ran remote PowerShell process/user enumeration on that host. These are the only non-system, non-Azure-agent processes in the dataset that touched LSASS with dump-capable access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-a4ab6acc67 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-a4ab6acc67 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-52785fcc89 | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_j | q-801f4a70a5 | ok |

### F38 · malicious / high · T1555.004 · PowerShell credential-access toolkit on scranton (private keys, keystrokes, clipboard)

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a post-exploitation PowerShell toolkit from C:\Program Files\SysinternalsSuite (psversion.ps1 / readme.ps1). At 03:04:56 the Get-PrivateKeys function exported all LocalMachine certificate private keys to .pfx files using the hardcoded password 'saribas'; at 03:04:03 Invoke-Discovery enumerated host/user context; at 03:06:42 Get-Clipboard captured clipboard contents; at 03:06:47-03:06:59 a Keystroke-Check / Get-Keystrokes keylogger was started. This is credential harvesting from the host's stores, and the LSASS full-access handle at 03:05:16 (see T1555 finding) is the memory-dump component. The Invoke-Exfil script (7-Zip password 'lolol', WebDAV to \\192.168.0.4\webdav) shows the stolen data was staged for exfiltration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-0292d027e1 | ok |
| 2 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21_Tx | q-ea0b4dbac1 | ok |
| 3 | 2020-05-02 03:06:42.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Get-Clipboard | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21_Qp | q-ea0b4dbac1 | ok |
| 4 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-21b11f4b8c | ok |

### F59 · malicious / high · T1649 · PowerShell script exports all LocalMachine private keys to .pfx files on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02 at 03:04:56 UTC, user pbeesly on host scranton.dmevals.local ran a PowerShell script block (EventID 4104) defining function Get-PrivateKeys, stored at C:\Program Files\SysinternalsSuite\readme.ps1. The script recursively enumerates cert:\LocalMachine, and for every certificate with a Thumbprint it calls Export-PfxCertificate to write the private key to "$env:USERPROFILE\Downloads\$RandomFileName.pfx" protected by the hardcoded password "saribas". One second later (03:04:57.460) Sysmon file-create (event 11) shows the same PowerShell process (PID 3876) creating C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx, and at 03:04:57.428 the same PID wrote to HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\48B5E43D09D080DF8863152FD22ED7C43443D499\Blob. This is direct theft of authentication certificate private keys (T1649). The 4657 Autologger registry changes and the 4663 SystemCertificates ROOT access by NASHUA$\Sysmon.exe are benign system/telemetry activity.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-bbdd2e3a69 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-bbdd2e3a69 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-bbdd2e3a69 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | message | File created:  RuleName: -  UtcTime: 2020-05-02 03:04:57.460  ProcessGuid: {47ab858c-e23d-5eac-c603-000000000400}  ProcessId: 3876  Image: C:\windows\system32\W… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lUAH | q-fc5f3fd1ff | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lUAH | q-fc5f3fd1ff | ok |
| 6 | 2020-05-02 03:04:57.428Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\48B5E43D09D080DF8863152FD22ED7C43443D499\Blob | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lED5 | q-42f06c14ab | ok |
| 7 | 2020-05-02 03:00:13.551Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SKyaCV | q-38e5cd826b | ok |

### F65 · suspicious / low · T1003 · lsass.exe writing C:\Windows\debug\PASSWD.LOG on scranton

Evidence status: **verified**

On scranton.dmevals.local, a Sysmon file-create event shows lsass.exe (PID 748) creating C:\Windows\debug\PASSWD.LOG. The CreationUtcTime is 2020-03-12, so this is likely a pre-existing file re-touched rather than a fresh dump; noted as a credential-named artifact on the compromised host but not a confirmed new extraction.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.994Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\debug\PASSWD.LOG | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3Hhd | q-39b497b67d | ok |

### F05 · suspicious / low · T1003.004 · No distinct LSA secrets extraction observed beyond LSASS access

Evidence status: **verified**

No dedicated LSA-secrets tooling (reg save of SECURITY\Policy\Secrets, secretsdump) was observed. LSA secrets reside in LSASS memory, so the LSASS accesses documented under T1003.001 are the relevant activity; no separate LSA-secrets-specific artifact was retrieved.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-70b70f9207 | ok |

### F11 · suspicious / high · T1040 · Concurrent malicious activity is credential theft/lateral movement, not sniffing

Evidence status: **verified**

While no sniffing occurred, the same window shows a real intrusion: user pbeesly on scranton.dmevals.local ran PsExec64.exe with a plaintext password ('-u dmevals\pbeesly -p Fl0nk3rt0n!T0by') to launch C:\Windows\Temp\python.exe on \\NASHUA (PSEXESVC service installed repeatedly), and sdelete64.exe was used to wipe files including C:\programdata\victim\???cod.3aka3.scr. The python.exe payload on nashua.dmevals.local made repeated outbound connections to 192.168.0.4:8443. This is credential access/lateral movement (not T1040) and is reported here only as context; it does not constitute network sniffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RqK7jn | q-1de4105183 | ok |
| 2 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SEqWk4 | q-1de4105183 | ok |
| 3 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RjDSP- | q-a9b60de965 | ok |

### F21 · suspicious / medium · T1110.003 · No password spraying; 4648 explicit-credential logons are PsExec-driven lateral movement by pbeesly

Evidence status: **verified**

The 15 event-4648 explicit-credential logons are all for the single account pbeesly, alternating between scranton.dmevals.local (SubjectUserName pbeesly, IpAddress 10.0.1.6, TargetServerName NASHUA) and nashua.dmevals.local (SubjectUserName NASHUA$, ProcessName C:\Windows\PSEXESVC.exe). This is one account being reused across hosts via PsExec, not many accounts tried against one host, so it does not match spraying. There are zero 4625 failures and no 4771 pre-auth failures. The pattern is consistent with lateral movement using stolen credentials rather than password spraying.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YogQzA | q-2c75e5c049 | ok |
| 2 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSP2J | q-2c75e5c049 | ok |
| 3 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.IpAddress | 10.0.1.6 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSP2J | q-2c75e5c049 | ok |

### F24 · suspicious / medium · T1111 · Explicit-credential logons (4648) reflect PsExec lateral movement and hardcoded-credential exfiltration, not MFA interception

Evidence status: **verified**

The 4648 events show pbeesly credentials being used explicitly: on nashua.dmevals.local via C:\Windows\PSEXESVC.exe (PsExec service) and on scranton.dmevals.local via svchost.exe from 172.18.39.2. A PowerShell 4104 script block on scranton.dmevals.local (user pbeesly) defines Invoke-Exfil, which builds a PSCredential from a hardcoded username 'cozy' and password and maps a WebDAV drive to \\192.168.0.4\webdav to copy an archive. This is credential use and data exfiltration, not interception of MFA tokens or smartcard material; it is suspicious but does not support T1111.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YogQzA | q-79c1734c96 | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\svchost.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHQbW | q-d92ab7365f | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-ddd37073d5 | ok |

### F27 · suspicious / medium · T1187 · PowerShell script blocks are credential/file collection, not forced authentication

Evidence status: **verified**

The 4104 script blocks matching UNC/backslash patterns on scranton.dmevals.local under user pbeesly are collection activity: recursive enumeration of user documents/credential-named files compressed to $env:APPDATA\Draft.Zip, and a System.Drawing bitmap steganography loader (monkey.png) that IEX-decodes a payload. These are credential-access/collection behaviors (T1074/T1560/T1027), not T1187 forced authentication — no UNC/WebDAV coercion or outbound authentication trigger is present in the scripts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b87aOf | q-2c0ad86c64 | ok |
| 2 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le … | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b87aMP | q-fcbc8fbea4 | ok |

### F30 · suspicious / medium · T1539 · APT29-style PowerShell (screen capture, exfil) present but unrelated to cookie theft

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly, PowerShell script blocks (event 4104) define Invoke-ScreenCapture (periodic screen grabs to Downloads) and Invoke-Exfil (7-Zip compression of the Downloads folder with password 'lolol' and copy to a WebDAV share \\192.168.0.4\webdav using hardcoded credentials). These are credential-access-adjacent/exfiltration tooling from the apt29-powershell source, but they do not touch browser cookie stores, so they are not T1539 activity. Reported as suspicious context only.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:45.000Z | scranton.dmevals.local | windows.powershell | message | Creating Scriptblock text (1 of 1):  <# PsTools Version in this package: 2.44 #> function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21gGA | q-88e0636b87 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-b209dcd79c | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-b209dcd79c | ok |

### F63 · suspicious / medium · T1552 · PyInstaller python.exe staged and executed via PsExec on nashua

Evidence status: **verified**

On nashua.dmevals.local, C:\Windows\Temp\python.exe (a PyInstaller bundle, extracting python27.dll under _MEI29522) was launched four times as a child of C:\Windows\PSEXESVC.exe by pbeesly, and it in turn spawned powershell.exe. This is attacker tool staging/execution on nashua via PsExec, distinct from the scranton anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\python.exe"  | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RpKsKx | q-2bb038b8b5 | ok |
| 2 | 2020-05-02 03:15:04.213Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Temp\_MEI29522\python27.dll | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RjDiN- | q-d069c05ce3 | ok |
| 3 | 2020-05-02 03:15:48.652Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RjDCOv | q-2bb038b8b5 | ok |

### F64 · suspicious / medium · T1552.001 · accesschk.exe writing passwordsDB on scranton

Evidence status: **verified**

On scranton.dmevals.local, C:\Program Files\SysinternalsSuite\accesschk.exe (launched by pbeesly's powershell.exe) created the file C:\Program Files\SysinternalsSuite\passwordsDB. This credential-named output artifact from a Sysinternals tool is new relative to the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lkD8 | q-7334a60f96 | ok |
| 2 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lkD_ | q-b48a4ebfb5 | ok |

### F39 · suspicious / high · T1556 · LSASS memory read by PowerShell on scranton (credential dumping, not auth-process modification)

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:05:16Z, PowerShell.exe (PID 2976, user pbeesly) opened lsass.exe with GrantedAccess 0x1FFFFF (full access), corroborated by Security 4663 showing pbeesly/powershell.exe reading \Device\HarddiskVolume2\Windows\System32\lsass.exe with AccessMask 0x10. This is credential theft from LSASS memory (T1003.001 behaviour), not modification of the authentication process. The same user pbeesly ran a PowerShell attack chain (Invoke-Discovery, Invoke-Persistence, Get-PrivateKeys, Invoke-Exfil) on scranton. No authentication-process tampering (Security Packages, Notification Packages, PasswordFilter, LSA registry writes) was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-b87216627b | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-b87216627b | ok |
| 3 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_j | q-5a2de4f7eb | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | user.name | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_j | q-5a2de4f7eb | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-438c7db524 | ok |

### F49 · suspicious / low · T1557.003 · No DHCP spoofing; NDIS Capture service toggle is a brief reverted change

Evidence status: **verified**

No DHCP traffic (UDP 67/68) exists in any dataset (sysmon UDP destination ports, zeek conn). The only network-configuration anomaly is on scranton.dmevals.local where SYSTEM changed the Microsoft NDIS Capture service (NdisCap) start type from demand start to system start at 03:19:22 and back to demand start at 03:19:26 — a 4-second toggle consistent with a packet-capture driver being briefly enabled, not a rogue DHCP server. The xDNSServerAddress PowerShell script blocks on newyork are the legitimate Microsoft xNetworking DSC resource (Path C:\Program Files\WindowsPowerShell\Modules\xNetworking\...). No rogue DHCP server or DHCP option tampering observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:22.000Z | scranton.dmevals.local | windows.other | message | The start type of the Microsoft NDIS Capture service was changed from demand start to system start. | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx1N | q-45ecf90dd1 | ok |
| 2 | 2020-05-02 03:19:26.000Z | scranton.dmevals.local | windows.other | message | The start type of the Microsoft NDIS Capture service was changed from system start to demand start. | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx2s | q-45ecf90dd1 | ok |
| 3 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | win.Path | C:\Program Files\WindowsPowerShell\Modules\xNetworking\DscResources\MSFT_xDNSServerAddress\MSFT_xDNSServerAddress.psm1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b43SyN | q-acdc2c0c1c | ok |

### F03 · benign / medium · T1003.002 · No SAM/SECURITY hive dumping observed

Evidence status: **verified**

No evidence of SAM/SECURITY registry hive dumping was found. Searches for reg save / esentutl / vssadmin command lines, SAM/SECURITY file writes, and 4663 access to SAM objects returned no hits. The only SAM-related object types seen (SAM_DOMAIN, SAM_SERVER, SAM_ALIAS) appeared in the general 4663/4656/4670 object-type stack but no 4663 event with a SAM ObjectName was retrieved, and the three file-create events matching *SAM*/*SECURITY*/*SYSTEM* were benign Prefetch files (SECURITYHEALTHSYSTRAY.EXE-41AD6DE1.pf etc.) created by svchost.exe. The credential theft on these hosts was via LSASS memory, not offline hive extraction.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:28.476Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\Prefetch\SECURITYHEALTHSYSTRAY.EXE-41AD6DE1.pf | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MtUmZF | q-260181d1ea | ok |

### F04 · benign / medium · T1003.003 · No NTDS.dit extraction observed

Evidence status: **verified**

No NTDS.dit access or extraction was observed. Searches for ntdsutil/vssadmin/diskshadow/ntds.dit command lines, ntds file writes, and PowerShell script blocks referencing ntds returned no hits. The only newly installed services (7045) were a Java VM support service and repeated PSEXESVC installs by pbeesly on nashua, none of which relate to NTDS extraction.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx2T | q-021002af4a | ok |

### F06 · benign / medium · T1003.005 · No cached domain credential extraction observed

Evidence status: **verified**

No evidence of cached domain credential (DCC2/mscache) extraction was found. Searches for 4663 access to Cache/SECURITY objects and PowerShell script blocks referencing cache/DCC2/mscache returned no hits.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-70b70f9207 | ok |

### F07 · benign / medium · T1003.006 · No DCSync observed

Evidence status: **verified**

No DCSync activity was observed. Searches for PowerShell script blocks referencing DCSync/Invoke-Mimikatz/lsadump returned no hits, and the zeek dataset (which does not overlap in time with the Windows datasets) contained no DRSUAPI dce_rpc operations.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-70b70f9207 | ok |

### F08 · benign / high · T1040 · Azure Network Watcher agent runs netsh trace capture on scranton (benign)

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-01T23:19:17-04:00, netsh.exe was launched with 'trace start capture=yes traceFile=...etl'. The parent process is the Microsoft Azure NetworkWatcherAgent (NetworkWatcherAgent.exe), and the surrounding process chain is the Azure Guest Agent lifecycle (WaAppAgent.exe logman stop/create/start of GAEvents/RTEvents, GuestAgent enable.cmd, NetworkWatcherAgent Install/Start). This is the platform's built-in network monitoring agent, not an adversary packet sniffer.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YYOcv1 | q-3fbdc6f7fd | ok |
| 2 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YYOcv1 | q-3fbdc6f7fd | ok |
| 3 | 2020-05-02 03:19:24.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YWMXHe | q-05018bad36 | ok |
| 4 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe"  Test /service /autoStart | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YJECPu | q-05018bad36 | ok |

### F09 · benign / high · T1040 · No packet-sniffing tooling observed on any Windows host

Evidence status: **verified**

Across windows.sysmon process-creation (event.code:1) and windows.security 4688, no execution of windump, tcpdump, wireshark, dumpcap, pktmon, rawcap, NetworkMiner or Npcap was found (queries returned 0 hits). No pcap/Npcap driver image-load (event.code:6) was observed either. The only capture-related binary is the legitimate Azure NetworkWatcherAgent/netsh pair. No PowerShell script block (4104) referenced sniffing, capture, pcap, promiscuous or netsh. There is no host-based evidence of network sniffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | win.Image | C:\Program Files\SysinternalsSuite\sdelete64.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SEqWk4 | q-1de4105183 | ok |
| 2 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | win.Image | C:\Program Files\SysinternalsSuite\PsExec64.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RqK7jn | q-1de4105183 | ok |

### F10 · benign / medium · T1040 · Zeek 'weird' records are sensor-side capture artifacts, not a sniffer on the wire

Evidence status: **verified**

The 12 zeek weird records on observers simplerockbuild.simplerock.lan and bobs.bigwheel.local are ip_hdr_len_zero, truncated_IP and unknown_dce_rpc_auth_type events, plus two SSL::Invalid_Server_Cert notices. These are normal Zeek parsing anomalies (malformed/truncated packets and self-signed certs), not indicators of a promiscuous-mode sniffer. The zeek window (2020-04-30) does not overlap the Windows host activity (2020-05-02), so it cannot be correlated to the credential-theft campaign.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:06:38.908Z | simplerockbuild.simplerock.lan | zeek | zeek.name | ip_hdr_len_zero | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO74ed | q-18ba428ae4 | ok |
| 2 | 2020-04-30 00:33:14.863Z | simplerockbuild.simplerock.lan | zeek | zeek.name | truncated_IP | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IdW | q-18ba428ae4 | ok |
| 3 | 2020-04-30 00:14:21.969Z | simplerockbuild.simplerock.lan | zeek | zeek.name | unknown_dce_rpc_auth_type | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IdY | q-18ba428ae4 | ok |

### F15 · benign / high · T1056.001 · Keyboard-related registry writes are benign Windows keyboard-layout/device enumeration

Evidence status: **verified**

The 26 registry SetValue events matching Keyboard/keylog/scancode on scranton.dmevals.local are all normal Windows activity: winlogon.exe and LogonUI.exe writing HKU\.DEFAULT keyboard-layout/CTF keys, and the System process (PID 4) writing HKLM\HARDWARE\DEVICEMAP\KeyboardClass and TERMINPUT_BUS device-enumeration keys. No keylogger driver, no SetWindowsHookEx/GetAsyncKeyState script blocks, and no keyboard-object access (4663) were found. No keylogging activity observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:55.020Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\HARDWARE\DEVICEMAP\KeyboardClass\\Device\KeyboardClass0 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NZ30AL | q-21650c7f54 | ok |
| 2 | 2020-05-02 03:19:22.416Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\.DEFAULT\Keyboard Layout\Preload\1 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WoRbhf | q-21650c7f54 | ok |

### F16 · benign / medium · T1056.003 · No web-portal credential capture observed

Evidence status: **verified**

No evidence of web portal capture: no writes to \\inetpub\\ or .aspx/.ashx/.asp files (C062 zero hits), no PowerShell writing web content (C064 zero hits), and no HTTP POST in the zeek window (C298-C301 zero hits). The only web-related activity is the WebDAV exfiltration destination \\192.168.0.4\webdav used by Invoke-Exfil, which is data staging rather than portal credential capture.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-59304f684e | ok |

### F17 · benign / medium · T1056.004 · No credential API hooking observed

Evidence status: **verified**

No evidence of credential API hooking: no lsass-related messages in windows.other (C072 zero hits), no injected/hooked credential-provider DLLs, and the LSASS handle opens are either benign OS/Azure processes or the single full-access PowerShell open already reported under T1056. No API-hooking artifacts were found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-2c6a8a139b | ok |

### F18 · benign / high · T1110 · No brute-force authentication activity observed; credential activity is theft, not guessing

Evidence status: **verified**

Across windows.security (41002 events, 02:55-03:28Z), windows.sysmon, windows.powershell and windows.other there is no evidence of repeated failed authentication. Event 4625 (failed logon) has zero hits, and the only 4771/4776-family event is a single successful NTLM validation (4776, Status 0x0) for pbeesly on newyork.dmevals.local. The C077/C085 hits (svchost.exe, conhost.exe, netsh.exe, userinit.exe command lines containing 'net'/'user'/'runas') are ordinary Windows service and shell command lines, not scripted authentication attempts. The genuine credential-access activity on scranton.dmevals.local (pbeesly) is credential theft/export (private-key export, LSASS handle access), which is outside the T1110 brute-force family.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | event.code | 4776 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHwYC | q-d95f97876d | ok |
| 2 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHwYC | q-d95f97876d | ok |
| 3 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SIwN6W | q-089510c19e | ok |

### F19 · benign / high · T1110.001 · No password-guessing activity; runas/net use hits are benign system processes

Evidence status: **verified**

The C085 aggregate of processes with 'runas'/'net use' in the command line is dominated by legitimate Windows binaries (svchost.exe 100, conhost.exe 65, backgroundTaskHost.exe 18, WmiPrvSE.exe 17, RuntimeBroker.exe 13, taskhostw.exe 13). No interactive credential-guessing tooling appears. windows.security has zero 4625 failed-logon events and no 4771 Kerberos pre-auth failures; the only Kerberos error in zeek is KDC_ERR_PREAUTH_REQUIRED (7), which is a normal pre-auth negotiation, not a failure. No evidence of password guessing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SIwN6W | q-089510c19e | ok |
| 2 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHwYC | q-d95f97876d | ok |

### F20 · benign / medium · T1110.002 · No password-cracking tooling; LSASS access is a single low-privilege handle, not hash dumping

Evidence status: **verified**

No hashcat/john/crack command lines exist (C088 zero hits) and no cracking output files (.pot/.hash) were created (C089 only shows benign .txt files such as WER temp files and Sysinternals readme.txt). The 326 lsass-targeted Sysmon event 10 accesses are overwhelmingly from svchost.exe (289) and Azure antimalware/telemetry agents (AntimalwareConfig.exe 15, WindowsAzureTelemetryService.exe 13) - normal security-product behaviour. Only 2 accesses come from powershell.exe on scranton.dmevals.local with GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION), which is not the memory-read access used for credential dumping. Registry hive reads (C091/C092) are by lsass.exe itself, i.e. normal. No cracking evidence.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SIwN6W | q-089510c19e | ok |
| 2 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SIwN6W | q-089510c19e | ok |

### F22 · benign / high · T1110.004 · No credential stuffing; PowerShell credential use is hardcoded, not list-driven

Evidence status: **verified**

No process was launched with a credential-list file argument (C108: only logman.exe with a .txt, a benign logging utility). The PowerShell 4104 hits referencing Credential/ConvertTo-SecureString are hardcoded single credentials, not imported credential lists: on scranton.dmevals.local pbeesly ran Get-PrivateKeys using ConvertTo-SecureString -String "saribas" to export machine private keys, and Invoke-Exfil using a hardcoded PSCredential (cozy / MyCozyPassw0rd!) to map a WebDAV share. These are credential theft/exfiltration, not stuffing of stolen credential pairs against many accounts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-13e33c4ebb | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-ed3bafe772 | ok |

### F23 · benign / high · T1111 · No MFA/smartcard interception artifacts; hits are benign Windows credential-service registration and credential use

Evidence status: **verified**

The T1111 hits contain no evidence of MFA interception. The 'Credential'/'Smartcard' registry writes on scranton.dmevals.local are ordinary Windows service registration by services.exe (CredentialEnrollmentManagerUserSvc_13619b service keys, SCardSvr.dll MuiCache entry) and lsass.exe setting CredentialGuard\Enabled to 0x0. The 4648 explicit-credential logons are pbeesly credentials used by PSEXESVC.exe (PsExec) and svchost.exe, plus normal winlogon/wininit/taskhostw infrastructure accounts (DWM-1, UMFD-0/1/2, SCRANTON$). No smartcard reader, MFA provider, or token-interception artifacts were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhV | q-1d5d5f12bb | ok |
| 2 | 2020-05-02 03:19:49.376Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKU\.DEFAULT\Software\Classes\Local Settings\MuiCache\4\52C64B7E\@%SystemRoot%\System32\SCardSvr.dll,-1 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NMoBQe | q-1d5d5f12bb | ok |
| 3 | 2020-05-02 03:20:48.264Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\System\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc_13619b\ImagePath | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NDgh5J | q-1d5d5f12bb | ok |
| 4 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx1Y | q-9516674789 | ok |
| 5 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YogQzA | q-79c1734c96 | ok |

### F25 · benign / high · T1187 · SMB traffic is normal internal domain activity, not forced authentication

Evidence status: **verified**

All outbound SMB (445/139) connections in windows.sysmon originate from the System process on internal hosts and terminate at internal addresses (10.0.0.4, 10.0.1.6, and IPv6 loopback fe80::e40c:95b6:b0a7:6429 on newyork.dmevals.local). No connection to an external or attacker-controlled SMB/WebDAV server was observed. Share access events (5140/5145) are machine-account accesses to SYSVOL and IPC$ by NEWYORK$, NASHUA$, UTICA$, WEC$ and SCRANTON$ — standard domain member/DC behavior. No file creation to UNC or WebDAV (DavWWWRoot) paths was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.0.4 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SEqmrA | q-bcba544114 | ok |
| 2 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SEqmrA | q-bcba544114 | ok |
| 3 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\SYSVOL | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YsmIP4 | q-44ea9654ea | ok |
| 4 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YsmIP4 | q-44ea9654ea | ok |
| 5 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\IPC$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtY0 | q-460a8972e1 | ok |

### F26 · benign / high · T1187 · NTLM-in-use warning is a benign per-boot LsaSrv informational event

Evidence status: **verified**

The single windows.other hit is event 6038 from provider LsaSrv on scranton.dmevals.local, which fires once per boot the first time a client uses NTLM with the server. It is an informational warning about NTLM being weaker than Kerberos, not evidence of coerced/forced authentication. No corresponding coercion trigger (UNC/WebDAV path, external SMB callback) was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.other | event.code | 6038 | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx3F | q-1168c63d36 | ok |
| 2 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.other | event.provider | LsaSrv | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx3F | q-cab7468f40 | ok |

### F28 · benign / medium · T1212 · No exploitation-for-credential-access activity; lsass access is benign svchost RPC and WebDAV python.exe fetch was denied

Evidence status: **verified**

Hunting T1212 across windows.sysmon, windows.security, windows.powershell, windows.other and zeek found no evidence of an adversary exploiting a vulnerability to obtain credentials. The 326 lsass process-access events (event.code 10) are dominated by C:\windows\system32\svchost.exe with GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION) and call traces through lsm.dll/RPCRT4.dll, i.e. normal LSA/RPC behaviour, not credential dumping (no 0x1010/0x1410 masks, no rundll32/powershell/mimikatz-style source images). The only network delivery candidate, a WebDAV GET for /webdav/python.exe from 10.0.1.4 to 192.168.0.4, returned HTTP 401 Unauthorized. The PowerShell 4104 hits are post-exploitation tradecraft (Invoke-Discovery, Invoke-Persistence, Invoke-Exfil, Invoke-SeaDukeStage) rather than exploitation of a service for credential theft. Kerberos 4768/4769 events are routine TGT/service-ticket requests for pbeesly. No crash/fault message indicating a failed exploit was found beyond a generic 'Crash dump initialization failed!' on scranton.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:24:18.178Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MuaKzP | q-683724a263 | ok |
| 2 | 2020-05-02 03:24:18.178Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MuaKzP | q-683724a263 | ok |
| 3 | 2020-05-02 03:24:18.178Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MuaKzP | q-683724a263 | ok |
| 4 | 2020-04-30 00:35:25.656Z | simplerockbuild.simplerock.lan | zeek | zeek.uri | /webdav/python.exe | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO74ey | q-0bd5591972 | ok |
| 5 | 2020-04-30 00:35:25.656Z | simplerockbuild.simplerock.lan | zeek | zeek.status_code | 401 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO74ey | q-0bd5591972 | ok |
| 6 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxQxZ | q-04b6cda122 | ok |
| 7 | 2020-05-02 03:18:54.000Z | scranton.dmevals.local | windows.other | message | Crash dump initialization failed! | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx1g | q-554324d00e | ok |

### F29 · benign / high · T1539 · No web session cookie theft observed; Edge profile writes are normal browser activity

Evidence status: **verified**

Across windows.sysmon, windows.security, windows.powershell and windows.other (2020-05-02 02:55–03:28Z) there is no evidence of web session cookie theft. The only files matching cookie/browser-profile patterns are written by MicrosoftEdge.exe itself on scranton.dmevals.local (Recovery store, DataStore _TempTestAccess.txt, AC\Temp files) and a system INetCookies folder created by svchost.exe under the LocalService profile — all normal browser/OS behaviour. No non-browser process opened, copied or archived a Cookies/Login Data/WebCache database; sysmon event 10 targeting browser images and event 2 file-creation of cookie DBs returned zero hits, and no 4104 script block references cookie/sqlite extraction. The C134 PowerShell hits were false positives from module-manifest text, not cookie tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.914Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\Recovery\Active\RecoveryStore.{5E6C474D-D0E6-4BC1-A0… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsPCud | q-ed614b1133 | ok |
| 2 | 2020-05-02 03:21:05.914Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsPCud | q-ed614b1133 | ok |
| 3 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsOhX7 | q-ed614b1133 | ok |
| 4 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsOhX7 | q-ed614b1133 | ok |
| 5 | 2020-05-02 03:21:05.198Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\DataStore\_TempTestAccess.txt | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MrOfHr | q-748e1fa83b | ok |

### F34 · benign / medium · T1552.002 · Registry credential-key writes are Windows-internal, not adversary credential hunting

Evidence status: **verified**

The 24 sysmon registry SetValue events matching Password/Credential/Winlogon are all written by legitimate system processes: svchost.exe writing HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength/CharacterGroups, winlogon.exe writing Winlogon\PUUActive/DP/LastLogOffEndTimePerCounter, lsass.exe writing DeviceGuard\Scenarios\CredentialGuard\Enabled, and services.exe writing CredentialEnrollmentManagerUserSvc keys. No adversary process read or exported autologon/credential registry values, and the reg query/save/export command-line check returned zero hits. No evidence of registry-based credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:28.255Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R8i4gn | q-b0d32da2b8 | ok |
| 2 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhV | q-b0d32da2b8 | ok |

### F36 · benign / medium · T1552.003 · No shell-history credential access observed

Evidence status: **verified**

Searches for ConsoleHost_history / PSReadLine references in PowerShell script blocks, sysmon process command lines and sysmon file-creation paths all returned zero hits. No evidence of adversaries reading PowerShell or shell history files for credentials in this dataset.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | event.code | 4104 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-011e0e9fd4 | ok |

### F35 · benign / medium · T1552.006 · SYSVOL/GPP file access is routine Group Policy client activity

Evidence status: **verified**

Sysmon file-creation events touching C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-...}\gpt.ini and ...\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf on nashua and scranton are all performed by C:\windows\system32\svchost.exe (the Group Policy client), and the zeek SMB reads of \\NEWYORK.dmevals.local\sysvol from 10.0.1.4/10.0.1.6 are normal domain-member policy retrieval. No Groups.xml/cpassword access, no gpprefdecrypt, and no adversary process reading SYSVOL was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:40.308Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RqLbie | q-6165a93970 | ok |
| 2 | 2020-04-30 00:12:01.658Z | simplerockbuild.simplerock.lan | zeek | message | {"@stream":"smb_mapping","@system":"simplerockbuild.simplerock.lan","@proc":"zeek","ts":1588205521.658912,"uid":"C6niUh1gdPBNBhfNDe","id_orig_h":"10.0.1.4","id_… | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Ida | q-0c18fcb01b | ok |

### F40 · benign / high · T1556.001 · No domain-controller authentication tampering observed

Evidence status: **verified**

LSASS access events on the four hosts were dominated by legitimate system processes (svchost.exe 289, AntimalwareConfig.exe 15, WindowsAzureTelemetryService.exe 13) with GrantedAccess 0x1000/0x1400. The only anomalous full-access reads were PowerShell.exe on scranton (0x1FFFFF/0x1F3FFF) and wsmprovhost.exe on nashua (0x1F3FFF), which are credential-read behaviour, not DC authentication patching. No 4657 registry modifications to LSA/Security Packages were found; the 4657 events present are benign WMI Autologger and certificate changes.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-5978a4ef75 | ok |
| 2 | 2020-05-02 03:19:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\WMI\Autologger\EventLog-Application\{7f3d17a3-0a3d-43f1-bbf2-80e3bb04d54d} | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YGDFf9 | q-a8af7b79ef | ok |

### F41 · benign / high · T1556.002 · No password filter DLL activity observed

Evidence status: **verified**

No file-creation events for lsass/PasswordFilter/cryptdll paths and no registry writes to Notification Packages or PasswordFilter were found. The cryptdll.dll/samlib.dll/samcli.dll image loads observed are normal Microsoft-signed DLLs loaded by SearchProtocolHost.exe, SearchFilterHost.exe, WmiPrvSE.exe, svchost.exe and powershell.exe, consistent with routine Windows operation.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:57:01.962Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\SearchProtocolHost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WgHZ_S | q-6c50b20e92 | ok |
| 2 | 2020-05-02 03:01:42.638Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SFrjYs | q-6c50b20e92 | ok |

### F42 · benign / high · T1556.005 · No reversible encryption configuration observed

Evidence status: **verified**

No 4739 events, no Set-ADUser/dsmod/Reversible command lines, and no reversible-encryption messages were found in the datasets. No evidence of enabling reversible password encryption.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-b87216627b | ok |

### F43 · benign / high · T1556.006 · No MFA modification observed

Evidence status: **verified**

No 4739 events, no 5136 directory-service changes, and no ADUser/AuthenticationPolicy command lines were found. No evidence of MFA registration or policy tampering.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | event.code | 4663 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_j | q-5a2de4f7eb | ok |

### F44 · benign / high · T1556.007 · No hybrid identity modification observed

Evidence status: **verified**

No 5136 directory-service object changes were found. The only hybrid-identity-adjacent activity was dsregcmd.exe loading cryptdll.dll on newyork, which is normal Azure AD device-registration behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:14.783Z | newyork.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\dsregcmd.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R5ewC0 | q-6c50b20e92 | ok |

### F45 · benign / high · T1556.008 · No network provider DLL registration observed

Evidence status: **verified**

No registry writes to NetworkProvider or credential-provider keys were observed; the registry modifications retrieved were Windows notification, LogonUI lock-screen image, and WMI Autologger keys, all benign.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:59:50.346Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Creative\S-1-5-21-1830255721-3727074217-2423397540-1107\LockImageFlags | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SO16KB | q-2e5d92b5b3 | ok |

### F46 · benign / medium · T1557 · No adversary-in-the-middle positioning observed; SMB/name-resolution activity is normal domain traffic

Evidence status: **verified**

Across windows.security, windows.sysmon, windows.other and zeek there is no evidence of an adversary positioning between hosts. SMB traffic in the security log is ordinary domain activity: machine accounts (NEWYORK$, SCRANTON$, NASHUA$, UTICA$, WEC$) reading SYSVOL GPO files (gpt.ini, GptTmpl.inf) and IPC$ SAMR access, plus pbeesly writing Temp\python.exe to nashua's ADMIN$ (PsExec-style lateral movement, not relay). Zeek shows only 3 distinct source MACs (00:0d:3a:13:e3:69, 00:0d:3a:4d:42:f2, fc:bd:67:e1:a9:c1) with no duplication. The 7045 service installs (PSEXESVC on nashua, Java(TM) Virtual Machine Support Service on scranton) are lateral-movement/execution artifacts, not interception tooling. A malicious payload C:\ProgramData\victim\â€®cod.3aka3.scr was executed on scranton by pbeesly and connected to 192.168.0.5:1234, but this is C2/execution, not AiTM.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.RelativeTargetName | Temp\python.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YjaXZO | q-26ced3eb30 | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\SYSVOL | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1Yph4sr | q-26ced3eb30 | ok |
| 3 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx2T | q-45ecf90dd1 | ok |
| 4 | 2020-05-02 02:55:59.631Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WiJUTX | q-74b63ae89e | ok |

### F47 · benign / medium · T1557.001 · No LLMNR/NBT-NS poisoning or SMB relay indicators

Evidence status: **verified**

Zeek shows only 2 connections to NBT-NS port 137 and no LLMNR (5355) traffic; DNS responses are 25 NOERROR / 12 NXDOMAIN with no anomalous resolution. SMB file/mapping sources are only the two normal internal hosts 10.0.1.4 and 10.0.1.6. Sysmon DNS queries are routine (host names, Microsoft telemetry, LDAP SRV records). No registry changes under DNSClient (C225 zero hits). The 4697/7045 service installs are PsExec (PSEXESVC) and a Java support service, not relay/poisoning components. No evidence of name-resolution poisoning or SMB relay.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx2T | q-45ecf90dd1 | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.RelativeTargetName | samr | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtY1 | q-26ced3eb30 | ok |

### F48 · benign / medium · T1557.002 · No ARP cache poisoning evidence

Evidence status: **verified**

Zeek conn records show only three distinct source MAC addresses (00:0d:3a:13:e3:69, 00:0d:3a:4d:42:f2, fc:bd:67:e1:a9:c1) with no duplicate/conflicting L2 addresses that would indicate ARP spoofing. Sysmon outbound destinations are normal internal peers and Microsoft/Internet endpoints. No network-stack tampering or object-permission changes tied to ARP manipulation were found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:42.231Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SErGop | q-5d05881afc | ok |

### F50 · benign / high · T1558 · No Kerberos ticket theft/forgery observed; Kerberos traffic is normal AES256

Evidence status: **verified**

Across windows.security, windows.other and zeek there is no evidence of stolen or forged Kerberos tickets. All 28 TGS requests (4769) use TicketEncryptionType 0x12 (AES256) and target only machine accounts (NEWYORK$, NASHUA$, SCRANTON$, WEC$) and krbtgt; no RC4 (0x17) tickets appear. Zeek kerberos records show only normal AS/TGS exchanges for pbeesly/DMEVALS.LOCAL with aes256-cts-hmac-sha1-96, the only failures being routine KDC_ERR_PREAUTH_REQUIRED. The 5857/5858 events on newyork are WMI/RSOP DeleteInstance noise from NT AUTHORITY\SYSTEM (ResultCode 0x80041002), not ticket handling. The 4672 privileged logons are all the NEWYORK$ machine account with standard service privileges.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYx | q-4cccbc197e | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYx | q-4cccbc197e | ok |
| 3 | 2020-04-30 00:24:19.119Z | simplerockbuild.simplerock.lan | zeek | zeek.cipher | aes256-cts-hmac-sha1-96 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IeV | q-653bcefced | ok |
| 4 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx1E | q-092178772c | ok |
| 5 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YtnqI_ | q-9398dbfd68 | ok |

### F51 · benign / high · T1558.001 · No golden ticket indicators (no RC4 TGTs, no krbtgt dumping tooling)

Evidence status: **verified**

No golden-ticket hallmarks were found. All 4769 tickets are AES256 (0x12), not the RC4 encryption typical of forged tickets. No PowerShell script block or process command line contains krbtgt, golden, Rubeus or ticket-forging strings (searches returned zero rows). The only LSASS access with full rights is by PowerShell.exe on scranton at 03:05:16 (GrantedAccess 0x1f3fff and 0x1fffff), which is generic credential dumping rather than KRBTGT extraction, and no forged-TGT use follows it. The 4672 privileged logons are all the NEWYORK$ machine account.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYx | q-4cccbc197e | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-1063443cdf | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-1063443cdf | ok |

### F52 · benign / high · T1558.002 · No silver ticket indicators; TGS requests are normal machine-account traffic

Evidence status: **verified**

No silver-ticket behavior was observed. The 28 TGS requests (4769) request services NEWYORK$, NASHUA$, SCRANTON$, WEC$ and krbtgt, all with AES256 (0x12) encryption and Status 0x0, consistent with normal machine-account service access. No RC4-encrypted service tickets and no anomalous service-account sessions appear. The 4672 privileged logons are all NEWYORK$ machine account with standard service privileges.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYv | q-4cccbc197e | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYv | q-4cccbc197e | ok |
| 3 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YtnqI_ | q-9398dbfd68 | ok |

### F53 · benign / high · T1558.003 · No Kerberoasting: no RC4 TGS tickets and no roasting tooling

Evidence status: **verified**

No Kerberoasting was observed. Every one of the 28 TGS requests (4769) uses TicketEncryptionType 0x12 (AES256), not the RC4 (0x17) encryption that Kerberoasting relies on for offline cracking. The requested SPNs are limited to machine accounts and krbtgt, with no mass enumeration of user service accounts. No PowerShell script block or process command line contains Kerberoast, Invoke-Kerberoast or GetUserSPNs strings (searches returned zero rows). The 4648 explicit-credential logons for pbeesly are PsExec (PSEXESVC.exe) lateral movement to NASHUA, not Kerberoasting.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYv | q-4cccbc197e | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YogQzA | q-2e43bfa458 | ok |
| 3 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYx | q-4cccbc197e | ok |

### F54 · benign / high · T1558.004 · No AS-REP Roasting: no pre-auth-disabled account enumeration or roasting tooling

Evidence status: **verified**

No AS-REP Roasting was observed. Zeek kerberos records show only normal AS exchanges for pbeesly/DMEVALS.LOCAL that succeed with aes256-cts-hmac-sha1-96 after a routine KDC_ERR_PREAUTH_REQUIRED, i.e. pre-authentication is enforced and no account without pre-auth is being targeted. No PowerShell script block or process command line contains AS-REP, asrep, GetNPUsers or Rubeus strings (searches returned zero rows).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:24:19.110Z | simplerockbuild.simplerock.lan | zeek | zeek.error_msg | KDC_ERR_PREAUTH_REQUIRED | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Idf | q-653bcefced | ok |
| 2 | 2020-04-30 00:24:19.119Z | simplerockbuild.simplerock.lan | zeek | zeek.cipher | aes256-cts-hmac-sha1-96 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IeV | q-653bcefced | ok |
| 3 | 2020-04-30 00:24:19.119Z | simplerockbuild.simplerock.lan | zeek | zeek.request_type | AS | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IeV | q-653bcefced | ok |

### F55 · benign / high · T1606 · No web-credential forging observed; hits reflect a credential-access/collection intrusion (PsExec, WebDAV exfil, sdelete cleanup)

Evidence status: **verified**

The T1606 checks surfaced no artifact of forged web credentials. The only 'cookie'-related hits are benign: rundll32 davclnt.dll,DavSetCookie is the normal WebDAV client cookie setter used by the exfil script's New-PSDrive to \\192.168.0.4\webdav (scranton, user pbeesly, 03:08-03:10), and the single Sysmon file-create matching *cookie* is a UWP package INetCookies store created by svchost.exe. The PowerShell 4104 hits matching *token*/*cookie*/*SAML*/*certificate* are unrelated Microsoft module manifests and PSScriptInfo strings, not token/cookie forging code. The 4624/4648 logon-process stacking shows only Kerberos/Advapi/User32/NtLmSsp - no seclogo or forged-token logon process. The real activity in this window is a credential-access/collection chain (PsExec64 with plaintext password Fl0nk3rt0n!T0by to \\NASHUA, python.exe, 7-Zip exfil to WebDAV, sdelete wiping archives), which is not T1606.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrMLE_ | q-c492dcf520 | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsOhX7 | q-b4674e2c05 | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-154edea314 | ok |
| 4 | 2020-05-02 03:12:25.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSCou | q-34f124bf23 | ok |

### F56 · benign / high · T1606.001 · No web-cookie forging; cookie-related hits are benign WebDAV/UWP artifacts

Evidence status: **verified**

The T1606.001 checks produced no evidence of forged web cookies. The only Sysmon file-create matching *cookie* is a UWP package INetCookies store (svchost.exe, scranton), and the only PowerShell 4104 matching *cookie*/*session* is a Microsoft module manifest (Get-AttributesMask / PSScriptInfo text), not cookie generation. The davclnt.dll,DavSetCookie invocations are the standard WebDAV client cookie mechanism used by the exfil script's New-PSDrive to \\192.168.0.4\webdav. No cookie-stealing or cookie-forging tooling was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsOhX7 | q-b4674e2c05 | ok |
| 2 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrMLE_ | q-c492dcf520 | ok |
| 3 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-AttributesMask($AttributesMask) {     &lt;#         SE_GROUP_MANDATORY          0x00000001  The group is mandatory.         SE_GROUP_ENABLED_BY_DEF… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b22vQJ | q-e848eb12f2 | ok |

### F57 · benign / high · T1606.002 · No SAML token forging; no ADFS/token-signing activity observed

Evidence status: **verified**

The T1606.002 checks found no SAML token forging. The PowerShell 4104 hits matching *SAML*/*ADFS*/*certificate* are Microsoft module manifest and PSScriptInfo strings (e.g. 'MissingRequiredPSScriptInfoProperties'), not token-signing code. No ADFS or token-signing service installs/changes were seen (7045/7040 events are Java VM Support Service, PSEXESVC, NDIS Capture and BITS start-type changes). The only certificate-like artifact is a downloaded .pfx (coyn5igj.3io.pfx) in pbeesly's Downloads, which is a collected file, not evidence of token-signing certificate abuse. LSASS process-access events (Sysmon 10) show only svchost.exe reading lsass with GrantedAccess 0x1000 via lsm.dll/RPCRT4.dll call traces - normal LSA RPC, not credential dumping.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:04.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | tFileInfo with -Force or New-ScriptFileInfo cmdlet to add the PSScriptInfo to the script file.  MissingRequiredPSScriptInfoProperties=Script '{0}' is missing re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b0zggh | q-a05902ceaa | ok |
| 2 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  Java(TM) Virtual Machine Support Service  Service File Name:  C:\Windows\System32\javamtsup.exe  Servic… | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx2I | q-60aa0f5d9a | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lUAH | q-e68c3d1e03 | ok |
| 4 | 2020-05-02 03:24:18.178Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MuaKzP | q-03b4f82beb | ok |

### F58 · benign / high · T1621 · No MFA request generation observed; hits are PsExec lateral movement and explicit-credential logons

Evidence status: **verified**

The T1621 hypothesis (MFA fatigue / repeated authentication request generation) is not supported by the data. The only 7045 service-install hits are four PSEXESVC installs on nashua.dmevals.local (2020-05-02 03:11:39-03:15:03 UTC, user pbeesly) and one 'Java(TM) Virtual Machine Support Service' (javamtsup.exe) on scranton.dmevals.local (03:04:15 UTC) - these are PsExec lateral-movement artifacts, not MFA-fatigue tooling. There are zero failed logons (event.code 4625 = 0) and no PowerShell script-block content matching MFA/2FA/Authenticator/Duo/Okta/Push. The authentication activity present is successful explicit-credential logons (4648, 15 events) using pbeesly's credentials against NASHUA over cifs/SMB (port 445) from 10.0.1.6, consistent with the PsExec movement rather than MFA request flooding. No T1621 activity is observable in these datasets.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx2T | q-2cbd2808c7 | ok |
| 2 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  Java(TM) Virtual Machine Support Service  Service File Name:  C:\Windows\System32\javamtsup.exe  Servic… | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx2I | q-2cbd2808c7 | ok |
| 3 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSP2J | q-a12ca5f17c | ok |
| 4 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSP2J | q-a12ca5f17c | ok |

### F60 · benign / medium · T1649 · Benign certificate-store registry and Kerberos activity (Autologger 4657, SystemCertificates ROOT 4663, TGT 4768)

Evidence status: **verified**

The remaining T1649-related hits are normal system behaviour: the 4657 registry-value changes are all under HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\EventLog-Application (event-log autologger configuration), the 4663 SystemCertificates\ROOT\Certificates access on nashua.dmevals.local is performed by the machine account NASHUA$ via C:\Windows\Sysmon.exe (telemetry agent reading the root store), and the 4768 TGT requests are for the normal account pbeesly and the machine account SCRANTON$. None of these show attacker certificate theft or forging.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcRioY | q-cee436308e | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcRioY | q-cee436308e | ok |
| 3 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | user.name | NASHUA$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcRioY | q-cee436308e | ok |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | suspicious | lsass.exe created C:\Windows\debug\PASSWD.LOG on scranton (CreationUtcTime 2020-03-12, likely pre-existing); no new distinct dump beyond the anchored LSASS access. |
| T1003.001 LSASS Memory | malicious | PowerShell.exe on scranton accessed lsass.exe with 0x1FFFFF/0x1f3fff and an UNKNOWN call-trace module; wsmprovhost.exe on nashua accessed lsass.exe with 0x1f3fff. |
| T1003.002 Security Account Manager | not_observed | No reg save/esentutl/vssadmin, no SAM/SECURITY hive file writes; only benign Prefetch files matched. |
| T1003.003 NTDS | not_observed | No ntdsutil/vssadmin/diskshadow/ntds.dit activity or ntds file writes. |
| T1003.004 LSA Secrets | suspicious | No dedicated LSA-secrets tooling, but LSASS memory was accessed (LSA secrets live in LSASS). |
| T1003.005 Cached Domain Credentials | not_observed | No 4663 access to Cache/SECURITY objects and no cache/DCC2/mscache script blocks. |
| T1003.006 DCSync | not_observed | No DCSync/lsadump script blocks and no DRSUAPI dce_rpc in zeek. |
| T1040 Network Sniffing | not_observed | No packet-sniffing tooling or promiscuous-mode capture was found on any host. The only capture activity is the legitimate Azure NetworkWatcherAgent invoking netsh trace (parent NetworkWatcherAgent.exe, part of the Azure … |
| T1056 Input Capture | malicious | PowerShell (PID 2976) opened lsass.exe with GrantedAccess 0x1FFFFF on scranton, and pbeesly's session harvested credential-bearing files and staged them for exfiltration. |
| T1056.001 Keylogging | not_observed | All Keyboard/keylog registry writes are benign Windows keyboard-layout and device-enumeration writes by System/winlogon/LogonUI; no keylogger driver, hook, or keyboard-object access found. |
| T1056.002 GUI Input Capture | malicious | pbeesly defined and invoked Invoke-ScreenCapture, a PowerShell loop using System.Windows.Forms CopyFromScreen to capture the full screen to .bmp files every 300s on scranton. |
| T1056.003 Web Portal Capture | not_observed | No inetpub/aspx/ashx writes, no PowerShell web-content writes, and no HTTP POST in the zeek window; only WebDAV exfiltration staging was seen. |
| T1056.004 Credential API Hooking | not_observed | No lsass-related messages in windows.other and no injected/hooked credential-provider DLLs; only the single full-access PowerShell LSASS open, already reported under T1056. |
| T1110 Brute Force | not_observed | Zero 4625 failed logons and no repeated authentication failures in any dataset; the only 4776 is a success (Status 0x0). No brute-force pattern. |
| T1110.001 Password Guessing | not_observed | No failed logons (4625=0, 4771=0); runas/net use hits are benign Windows binaries (svchost, conhost, WmiPrvSE). No guessing. |
| T1110.002 Password Cracking | not_observed | No hashcat/john/crack tooling and no cracking output files; lsass accesses are from svchost/Azure agents and one 0x1000 handle from powershell, not memory-read dumping. |
| T1110.003 Password Spraying | not_observed | 4648 explicit-credential logons are all one account (pbeesly) reused across scranton/nashua via PSEXESVC, i.e. lateral movement, not many accounts sprayed against one host; no 4625/4771 failures. |
| T1110.004 Credential Stuffing | not_observed | No credential-list file arguments (only logman.exe with .txt); PowerShell credential use is hardcoded single secrets (saribas, cozy/MyCozyPassw0rd!), not stuffing of stolen credential pairs. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA/smartcard interception artifacts. Registry 'Credential'/'Smartcard' hits are benign Windows service registration (CredentialEnrollmentManagerUserSvc, SCardSvr.dll MuiCache) and CredentialGuard\Enabled=0x0 set by l… |
| T1187 Forced Authentication | not_observed | No forced-authentication activity found. All SMB (445/139) connections are internal System-process traffic to internal hosts (10.0.0.4, 10.0.1.6, IPv6 loopback); share access is machine-account SYSVOL/IPC$ domain activit… |
| T1212 Exploitation for Credential Access | not_observed | No exploitation of a vulnerability for credential access was observed. All 326 lsass process-access events are svchost.exe with GrantedAccess 0x1000 via lsm.dll/RPCRT4 (normal LSA RPC), the only WebDAV payload fetch (/we… |
| T1539 Steal Web Session Cookie | not_observed | No process read, copied or archived a browser cookie/session database. The only cookie/browser-profile file events are MicrosoftEdge.exe writing its own profile files and svchost.exe creating a system INetCookies folder … |
| T1552 Unsecured Credentials | suspicious | PyInstaller python.exe staged/executed via PSEXESVC on nashua, spawning powershell.exe. |
| T1552.001 Credentials In Files | malicious | PowerShell credential-file harvesting on nashua (search for *pass*/*login*/*admin*/*vpn*, archive to working.zip), password-protected RAR staging, and accesschk.exe writing passwordsDB on scranton. |
| T1552.002 Credentials in Registry | benign | All Password/Credential/Winlogon registry writes came from svchost/winlogon/lsass/services; no reg query/save/export and no adversary registry credential reads. |
| T1552.003 Shell History | not_observed | Zero hits for ConsoleHost_history/PSReadLine in PowerShell, sysmon command lines and file paths. |
| T1552.004 Private Keys | malicious | Get-PrivateKeys exported machine certificate private keys to C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx, confirmed by the sysmon file-creation event. |
| T1552.006 Group Policy Preferences | benign | SYSVOL/GptTmpl.inf/gpt.ini access was routine svchost.exe Group Policy client activity and normal zeek SMB policy retrieval; no Groups.xml/cpassword access. |
| T1555 Credentials from Password Stores | malicious | PowerShell.exe on scranton opened lsass.exe with 0x1f3fff/0x1fffff (full access) at 03:05:16, corroborated by a 4663 object-access event by powershell.exe as pbeesly; wsmprovhost.exe on nashua opened lsass.exe with 0x1f3… |
| T1555.003 Credentials from Web Browsers | not_observed | All browser credential-store checks (Login Data, logins.json, key4.db, signons.sqlite, Local State) returned zero hits in sysmon, security and powershell datasets. |
| T1555.004 Windows Credential Manager | malicious | pbeesly on scranton ran Get-PrivateKeys (exported LocalMachine cert private keys with password 'saribas'), Get-Clipboard and a Get-Keystrokes keylogger from a SysinternalsSuite-hosted toolkit, alongside the LSASS full-ac… |
| T1555.005 Password Managers | not_observed | All password-manager checks (keepass, 1password, lastpass, bitwarden) and Vault/Credential hive checks returned zero hits across all four datasets. |
| T1556 Modify Authentication Process | suspicious | LSASS was opened with full access (0x1FFFFF) by PowerShell.exe under user pbeesly on scranton, and Security 4663 confirms pbeesly/powershell.exe reading lsass.exe. This is credential theft from LSASS memory rather than a… |
| T1556.001 Domain Controller Authentication | not_observed | No DC authentication tampering; LSASS access was dominated by legitimate system processes and no LSA/Security Packages registry modifications were found. |
| T1556.002 Password Filter DLL | not_observed | No password filter DLL file drops or Notification Packages/PasswordFilter registry writes; cryptdll/samlib loads are normal Microsoft DLLs. |
| T1556.005 Reversible Encryption | not_observed | No 4739 events and no reversible-encryption command lines or messages. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739 or 5136 events and no MFA/authentication-policy command lines. |
| T1556.007 Hybrid Identity | not_observed | No 5136 directory-service changes; dsregcmd.exe cryptdll load is normal Azure AD device registration. |
| T1556.008 Network Provider DLL | not_observed | No network provider DLL registration; observed registry writes were benign notification/LogonUI/WMI Autologger keys. |
| T1557 Adversary-in-the-Middle | not_observed | No AiTM positioning: SMB traffic is normal domain GPO/IPC$ activity and PsExec lateral movement; no interception tooling or MITM host identified. |
| T1557.001 Name Resolution Poisoning and SMB Relay | not_observed | No LLMNR/NBT-NS poisoning or SMB relay: only 2 NBT-NS connections, no LLMNR, normal DNS rcodes, SMB sources limited to normal internal hosts. |
| T1557.002 ARP Cache Poisoning | not_observed | No ARP cache poisoning: only 3 distinct source MACs in Zeek with no duplication or conflicting L2 addresses. |
| T1557.003 DHCP Spoofing | suspicious | No DHCP (67/68) traffic anywhere; the only anomaly is a brief, reverted Microsoft NDIS Capture service start-type toggle on scranton, which is low-confidence and not a rogue DHCP server. |
| T1558 Steal or Forge Kerberos Tickets | not_observed | No stolen/forged Kerberos tickets: all 4769 tickets are AES256 (0x12), zeek kerberos shows only normal AS/TGS for pbeesly with aes256, and 5857/5858 events are WMI/RSOP noise from SYSTEM. |
| T1558.001 Golden Ticket | not_observed | No RC4 TGTs, no krbtgt/golden/Rubeus strings in PowerShell or process command lines; the only full-access LSASS reads are generic PowerShell credential access, not KRBTGT extraction. |
| T1558.002 Silver Ticket | not_observed | TGS requests target only machine accounts and krbtgt with AES256 encryption and Status 0x0; no RC4 service tickets or anomalous service-account sessions. |
| T1558.003 Kerberoasting | not_observed | All 28 TGS requests use AES256 (0x12), not RC4; no Kerberoast/Invoke-Kerberoast/GetUserSPNs strings found; 4648 logons are PsExec lateral movement, not roasting. |
| T1558.004 AS-REP Roasting | not_observed | Zeek kerberos shows pre-auth enforced (KDC_ERR_PREAUTH_REQUIRED then AES256 success) for pbeesly; no AS-REP/GetNPUsers/Rubeus strings found. |
| T1606 Forge Web Credentials | not_observed | No forged web credential artifacts. Cookie/token-related hits are benign (WebDAV DavSetCookie, UWP INetCookies, Microsoft module manifests). Logon-process stacking shows only Kerberos/Advapi/User32/NtLmSsp. The window's … |
| T1606.001 Web Cookies | not_observed | No cookie theft or forging. Only cookie-related events are a UWP INetCookies file create and standard davclnt.dll DavSetCookie WebDAV client calls; no cookie-forging tooling or scripts. |
| T1606.002 SAML Tokens | not_observed | No SAML token forging. No ADFS/token-signing service activity; PowerShell *SAML*/*certificate* hits are Microsoft module manifest strings. LSASS access is normal svchost 0x1000 LSA RPC, not token-signing material theft. |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | No MFA request generation activity found. Zero failed logons (4625=0), no MFA/2FA/Authenticator/Duo/Okta/Push strings in PowerShell script blocks, and the only 7045 service installs are PsExec (PSEXESVC) and a Java suppo… |
| T1649 Steal or Forge Authentication Certificates | malicious | A PowerShell script (Get-PrivateKeys, from C:\Program Files\SysinternalsSuite\readme.ps1) run by user pbeesly on scranton.dmevals.local enumerated cert:\LocalMachine and exported every certificate's private key to a .pfx… |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 5 hits | 0 hits | 10977 hits | 39730 hits | n/a |
| T1003.001 LSASS Memory | n/a | 0 hits | 103 hits | 981 hits | n/a |
| T1003.002 Security Account Manager | n/a | 0 hits | 0 hits | 3 hits | n/a |
| T1003.003 NTDS | 5 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.004 LSA Secrets | n/a | 0 hits | 0 hits | 349 hits | n/a |
| T1003.005 Cached Domain Credentials | n/a | 0 hits | 0 hits | 330 hits | n/a |
| T1003.006 DCSync | 5 hits | 0 hits | 15 hits | 326 hits | 123 hits |
| T1040 Network Sniffing | 5 hits | 0 hits | 461 hits | 447 hits | 625 hits |
| T1056 Input Capture | n/a | 0 hits | 10983 hits | 39609 hits | 0 hits |
| T1056.001 Keylogging | 5 hits | 0 hits | 0 hits | 56850 hits | 0 hits |
| T1056.002 GUI Input Capture | n/a | 419 hits | 460 hits | 450 hits | 0 hits |
| T1056.003 Web Portal Capture | 5 hits | 0 hits | 5337 hits | 1649 hits | 62 hits |
| T1056.004 Credential API Hooking | 0 hits | 3 hits | 13 hits | 59963 hits | n/a |
| T1110 Brute Force | 0 hits | 4 hits | 0 hits | 31 hits | 35 hits |
| T1110.001 Password Guessing | 0 hits | 0 hits | 0 hits | 447 hits | 35 hits |
| T1110.002 Password Cracking | 11 hits | 0 hits | 4494 hits | 346 hits | 0 hits |
| T1110.003 Password Spraying | 0 hits | 22 hits | 15 hits | 0 hits | 35 hits |
| T1110.004 Credential Stuffing | 0 hits | 4 hits | 0 hits | 1 hits | 35 hits |
| T1111 Multi-Factor Authentication Interception | 2 hits | 3 hits | 312 hits | 39295 hits | n/a |
| T1187 Forced Authentication | 1 hits | 82 hits | 11140 hits | 1715 hits | 50 hits |
| T1212 Exploitation for Credential Access | 3 hits | 16 hits | 42 hits | 39730 hits | 2 hits |
| T1539 Steal Web Session Cookie | 3 hits | 13 hits | 460 hits | 163 hits | 0 hits |
| T1552 Unsecured Credentials | 2 hits | 4 hits | 460 hits | 1673 hits | 23 hits |
| T1552.001 Credentials In Files | 0 hits | 1 hits | 10849 hits | 2096 hits | 12 hits |
| T1552.002 Credentials in Registry | n/a | 8 hits | 1473 hits | 7 hits | n/a |
| T1552.003 Shell History | n/a | 0 hits | n/a | 0 hits | n/a |
| T1552.004 Private Keys | n/a | n/a | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | n/a | 0 hits | 0 hits | 0 hits | n/a |
| T1555 Credentials from Password Stores | n/a | 3 hits | 6 hits | 796 hits | n/a |
| T1555.003 Credentials from Web Browsers | n/a | 0 hits | 0 hits | 0 hits | n/a |
| T1555.004 Windows Credential Manager | 0 hits | 3 hits | 0 hits | 652 hits | n/a |
| T1555.005 Password Managers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556 Modify Authentication Process | 0 hits | 0 hits | 0 hits | 401 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | n/a | 213 hits | 359 hits | n/a |
| T1556.002 Password Filter DLL | 0 hits | n/a | 0 hits | 1 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 1 hits | 0 hits | 0 hits | n/a |
| T1556.006 Multi-Factor Authentication | 9 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556.007 Hybrid Identity | 5 hits | 0 hits | 297 hits | 20259 hits | n/a |
| T1556.008 Network Provider DLL | 9 hits | 0 hits | 36 hits | 59967 hits | n/a |
| T1557 Adversary-in-the-Middle | 5 hits | 0 hits | 10977 hits | 1310 hits | 613 hits |
| T1557.001 Name Resolution Poisoning and SMB Relay | 5 hits | 0 hits | 23 hits | 0 hits | 78 hits |
| T1557.002 ARP Cache Poisoning | 9 hits | 0 hits | 10977 hits | 1310 hits | 613 hits |
| T1557.003 DHCP Spoofing | 0 hits | 2 hits | 0 hits | 308 hits | 62 hits |
| T1558 Steal or Forge Kerberos Tickets | 89 hits | 0 hits | 448 hits | 326 hits | 35 hits |
| T1558.001 Golden Ticket | 89 hits | 0 hits | 268 hits | 326 hits | 35 hits |
| T1558.002 Silver Ticket | 89 hits | 0 hits | 268 hits | 326 hits | 35 hits |
| T1558.003 Kerberoasting | 89 hits | 0 hits | 368 hits | 326 hits | 35 hits |
| T1558.004 AS-REP Roasting | 89 hits | 0 hits | 28 hits | 0 hits | 35 hits |
| T1606 Forge Web Credentials | 9 hits | 1 hits | 312 hits | 39283 hits | n/a |
| T1606.001 Web Cookies | 5 hits | 1 hits | 312 hits | 1 hits | n/a |
| T1606.002 SAML Tokens | 9 hits | 2 hits | 312 hits | 39283 hits | n/a |
| T1621 Multi-Factor Authentication Request Generatio… | 5 hits | 0 hits | 0 hits | n/a | n/a |
| T1649 Steal or Forge Authentication Certificates | 9 hits | 1 hits | 50 hits | 25 hits | n/a |

Cells: 265, gaps: 0.

## Queries

Every MCP tool call of this run (1070), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-d9930fd41b | scope | list_data_sources | {} | None |  |
| q-f402b113e3 | scope | get_registry | {} | None |  |
| q-667301b367 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-60db0fc837 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-2505ae59f2 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-0015eea9fc | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-2749ce45ca | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-b75951f953 | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-810856bd2e | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-0a1c1cc3b3 | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-ff8deebd05 | check C004 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*mimikatz* OR powershell.script_block_text:*lsass* OR powershell.script_block_text:*sekurlsa* OR powershell.script_block_text:*DumpCreds*)", "time_from": null, "time_… | 0 |  |
| q-f300e62d50 | check C005 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-2f73e618af | check C006 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-f492c81db3 | check C007 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-24076d019c | check C008 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-fc2a90a45c | check C009 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*lsass* OR win.TargetFilename:*.dmp)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 2 |  |
| q-6a400eeeb1 | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 1 |  |
| q-2088435d48 | check C011 | search | {"dataset": "windows.security", "query": "event.code:4673 AND win.ProcessName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 103 |  |
| q-0912310f94 | check C012 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*MiniDump* OR powershell.script_block_text:*sekurlsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 0 |  |
| q-260181d1ea | check C013 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SECURITY* OR win.TargetFilename:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "… | 3 | F03 |
| q-8d3db952e1 | check C014 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg*save* OR process.command_line:*reg.exe*save* OR process.command_line:*vssadmin* OR process.command_line:*esentutl*)", "time_from": null, "time_to": null, "fields": ["@timestamp… | 0 |  |
| q-93c4084743 | check C015 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*reg*save* OR process.command_line:*reg.exe*save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 0 |  |
| q-d9ee75476e | check C016 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c8389ad870 | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proce… | 0 |  |
| q-aa1656710a | check C018 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*reg save* OR powershell.script_block_text:*SAM* OR powershell.script_block_text:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 0 |  |
| q-c471f26e8b | check C019 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-3a2c8c9930 | check C020 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntdsutil* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow* OR process.command_line:*ntds.dit*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 0 |  |
| q-6daa0784ea | check C021 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*ntdsutil* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name",… | 0 |  |
| q-021002af4a | check C022 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F04 |
| q-36ec3d203c | check C023 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*ntds* OR powershell.script_block_text:*vssadmin* OR powershell.script_block_text:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-9421439842 | check C024 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND win.TargetFilename:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 0 |  |
| q-e3a10ee89c | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-765b828cc6 | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*SECURITY*Policy*Secrets* OR process.command_line:*reg*save* OR process.command_line:*secretsdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obse… | 0 |  |
| q-e79d75c061 | check C027 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectName:*Secrets*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-6466ed754f | check C028 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*samlib* OR win.ImageLoaded:*vaultcli* OR win.ImageLoaded:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 23 |  |
| q-cf18fada45 | check C029 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Secrets* OR powershell.script_block_text:*LSA* OR powershell.script_block_text:*secretsdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 0 |  |
| q-58b8587ddc | check C030 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-d8945d6599 | check C031 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*DCC2* OR process.command_line:*mscache* OR process.command_line:*secretsdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 4 |  |
| q-98bf10cdbe | check C032 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Cache* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0efdfad590 | check C033 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cache* OR powershell.script_block_text:*DCC2* OR powershell.script_block_text:*mscache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 0 |  |
| q-7131a33b04 | check C034 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-a07aba2ca3 | check C035 | aggregate | {"dataset": "windows.security", "field": "win.Properties", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-3e331fc58b | check C036 | search | {"dataset": "windows.security", "query": "event.code:4662 AND win.Properties:*1131f6aa*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 1 |  |
| q-cf0adcad8a | check C037 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-067e127a01 | check C038 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*DCSync* OR powershell.script_block_text:*Invoke-Mimikatz* OR powershell.script_block_text:*lsadump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-7c30786c8a | check C039 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-8848d66926 | check C040 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-906496604e | check C041 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*netsh*cap*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 1 |  |
| q-2c6d4f79c0 | check C042 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-5deb100f74 | check C043 | aggregate | {"dataset": "windows.sysmon", "field": "win.Image", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-02c3f3d253 | check C044 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*pktmon* OR powershell.script_block_text:*pcap* OR powershell.script_block_text:*promiscuous*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 0 |  |
| q-6c670bd0cc | check C045 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-59ec776c8a | check C046 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.cod… | 6 |  |
| q-fea9d4baaa | check C047 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-5e164f379c | check C048 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-1a666cff39 | check C049 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Credential* OR powershell.script_block_text:*Credential*Prompt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 0 |  |
| q-6db061d1b2 | check C050 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 OR event.code:14", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-21650c7f54 | check C051 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*scancode*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 26 | F15 |
| q-6d2ae96380 | check C052 | aggregate | {"dataset": "windows.sysmon", "field": "win.Image", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-dba0606923 | check C053 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*Keyboard* OR win.ObjectName:*keylog*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proce… | 0 |  |
| q-c7c2d8b35d | check C054 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-585830dc03 | check C055 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*GetAsyncKeyState* OR powershell.script_block_text:*keylog* OR powershell.script_block_text:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@tim… | 0 |  |
| q-15eae9942e | check C056 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*PromptForCredential* OR powershell.script_block_text:*Windows.Forms*)", "time_from": null, "time_to": null, "fields": ["… | 5 |  |
| q-44f12483e0 | check C057 | aggregate | {"dataset": "windows.powershell", "field": "win.ScriptBlockId", "query": "event.code:4104", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 414 |  |
| q-d3f6907a68 | check C058 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-49178c5c75 | check C059 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 3 |  |
| q-a13d1f9361 | check C060 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-8051248af9 | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-e5e3447f44 | check C062 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*\\\\inetpub\\\\* OR win.TargetFilename:*.aspx OR win.TargetFilename:*.ashx OR win.TargetFilename:*.asp)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 0 |  |
| q-eb34786b34 | check C063 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5337 |  |
| q-3964265adf | check C064 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*inetpub* OR powershell.script_block_text:*Set-Content* OR powershell.script_block_text:*Invoke-WebRequest*)", "time_from": null, "time_to": null, "fields": ["@timest… | 0 |  |
| q-a270d19db4 | check C065 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-9b9c502aa4 | check C066 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-22fe9fb909 | check C067 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-7cfdca9c42 | check C068 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-286f5fb4a3 | check C069 | search | {"dataset": "windows.sysmon", "query": "event.code:8 AND win.StartModule:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 95 |  |
| q-3a95d9ba2d | check C070 | aggregate | {"dataset": "windows.security", "field": "win.CallerProcessName", "query": "event.code:4656 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-e4b41c16c6 | check C071 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*MiniDump* OR powershell.script_block_text:*Get-Process*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 3 |  |
| q-7aa1199eb1 | check C072 | search | {"dataset": "windows.other", "query": "message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-0dd617f6e9 | check C073 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-6978558a81 | check C074 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b8169d6923 | check C075 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-e783a3ef97 | check C076 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-ee4bfacd4d | check C077 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*user* OR process.command_line:*password*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 31 |  |
| q-9caaad7572 | check C078 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password* OR powershell.script_block_text:*Login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 4 |  |
| q-d72281b57a | check C079 | search | {"dataset": "windows.other", "query": "message:*logon* AND message:*fail*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-41e098b5a3 | check C080 | aggregate | {"dataset": "zeek", "field": "zeek.rcode_name", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 35 |  |
| q-9bc72e1954 | check C081 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-59c16a44a6 | check C082 | aggregate | {"dataset": "windows.security", "field": "win.Workstation", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c98ee26290 | check C083 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-dc2351ce94 | check C084 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*4625* OR powershell.script_block_text:*LogonUser* OR powershell.script_block_text:*New-Object*Net*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 0 |  |
| q-30b8c336d4 | check C085 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*runas* OR process.command_line:*net use*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-be7ae71dee | check C086 | search | {"dataset": "windows.other", "query": "message:*4625*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinati… | 0 |  |
| q-8c6a2e4ab7 | check C087 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 35 |  |
| q-3a9ebbedf8 | check C088 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*hashcat* OR process.command_line:*john* OR process.command_line:*crack*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-674fd64b91 | check C089 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.pot OR win.TargetFilename:*.hash)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20 |  |
| q-e72798afe9 | check C090 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-af3ccc763b | check C091 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*SYSTEM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 4484 |  |
| q-75c28331e2 | check C092 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4656 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10 |  |
| q-7fb4aba1a8 | check C093 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*hashcat* OR powershell.script_block_text:*Invoke-Mimikatz* OR powershell.script_block_text:*DumpCreds*)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 0 |  |
| q-32dee2ab91 | check C094 | search | {"dataset": "windows.other", "query": "message:*SAM* OR message:*SECURITY*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 11 |  |
| q-c421f7ad8f | check C095 | search | {"dataset": "zeek", "query": "event.action:smb_files AND (file.path:*SAM* OR file.path:*SECURITY* OR file.path:*NTDS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-1431b3dbb4 | check C096 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-914cd3dfe6 | check C097 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-80aeb06c79 | check C098 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-4d88a39bca | check C099 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-878c593dfa | check C100 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*foreach* OR powershell.script_block_text:*Get-ADUser* OR powershell.script_block_text:*Password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 22 |  |
| q-b2e0bc1dcc | check C101 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*net use* OR process.command_line:*runas*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ba1ff74a5d | check C102 | search | {"dataset": "windows.other", "query": "message:*4771* OR message:*4625*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 0 |  |
| q-0974d805d4 | check C103 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 35 |  |
| q-c72212d7da | check C104 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-b35684a77b | check C105 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-557a69ea1b | check C106 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-95fc95cafa | check C107 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*Import-Csv* OR powershell.script_block_text:*ConvertTo-SecureString*)", "time_from": null, "time_to": null, "fields": ["… | 4 |  |
| q-0159134455 | check C108 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*.txt OR process.command_line:*.csv)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-64ad2b3264 | check C109 | search | {"dataset": "windows.other", "query": "message:*4625*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinati… | 0 |  |
| q-37203543b7 | check C110 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 35 |  |
| q-ef1455fa18 | check C111 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-c179dbda18 | check C112 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-e06b52eea3 | check C113 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-1d5d5f12bb | check C114 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Smartcard* OR registry.path:*SCardSvr* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 12 | F23 |
| q-1d1f9b18d3 | check C115 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Smartcard* OR powershell.script_block_text:*Credential* OR powershell.script_block_text:*MFA*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 3 |  |
| q-ca243f2743 | check C116 | search | {"dataset": "windows.other", "query": "message:*Smartcard* OR message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 2 |  |
| q-9991fa1f1c | check C117 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-2b6f75bbc2 | check C118 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 163 |  |
| q-d5d7cd96d2 | check C119 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-bcba544114 | check C120 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 66 | F25 |
| q-fa383b6f21 | check C121 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*\\\\* OR powershell.script_block_text:*WebDAV* OR powershell.script_block_text:*PROPFIND*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name"… | 82 |  |
| q-1168c63d36 | check C122 | search | {"dataset": "windows.other", "query": "message:*445* OR message:*WebDAV* OR message:*NTLM*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 1 | F26 |
| q-6b4caf1029 | check C123 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-678e71a074 | check C124 | search | {"dataset": "windows.security", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proc… | 42 |  |
| q-a0a580d427 | check C125 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-191350f2f1 | check C126 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-583b6b5da6 | check C127 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Invoke-* OR powershell.script_block_text:*Exploit* OR powershell.script_block_text:*SeDebug*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 16 |  |
| q-554324d00e | check C128 | search | {"dataset": "windows.other", "query": "message:*crash* OR message:*fault* OR message:*Exploit*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proce… | 3 | F28 |
| q-c1ef08caae | check C129 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:POST OR http.request.method:GET)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 2 |  |
| q-3367f54c2f | check C130 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-76ac231a9e | check C131 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*WebCache*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 163 |  |
| q-80c93b96bd | check C132 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*chrome* OR win.TargetImage:*firefox* OR win.TargetImage:*iexplore* OR win.TargetImage:*msedge*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.na… | 0 |  |
| q-73753982ac | check C133 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", … | 0 |  |
| q-71ca52b04b | check C134 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Cookies* OR powershell.script_block_text:*Login Data* OR powershell.script_block_text:*sqlite*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 13 |  |
| q-b58dbb7029 | check C135 | search | {"dataset": "windows.other", "query": "message:*Cookies* OR message:*Login Data*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 3 |  |
| q-ad7f6ed49b | check C136 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-15794e9d16 | check C137 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-47a4edd087 | check C138 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-b0d32da2b8 | check C139 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential* OR registry.path:*Winlogon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 24 | F34 |
| q-011e0e9fd4 | check C140 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*password* OR powershell.script_block_text:*credential* OR powershell.script_block_text:*ConvertTo-SecureString*)", "time_from": null, "time_to": null, "fields": ["@t… | 4 | F36 |
| q-2e091519a9 | check C141 | search | {"dataset": "windows.other", "query": "message:*password* OR message:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 2 |  |
| q-0c18fcb01b | check C142 | search | {"dataset": "zeek", "query": "event.action:smb_files OR event.action:smb_mapping", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 23 | F35 |
| q-4fba84b120 | check C143 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-a01313f366 | check C144 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10834 |  |
| q-3a92451d3c | check C145 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*findstr* OR process.command_line:*type * OR process.command_line:*Get-Content*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null… | 447 |  |
| q-0a3584b97a | check C146 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-ec45480cf1 | check C147 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Content* OR powershell.script_block_text:*Select-String* OR powershell.script_block_text:*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp… | 1 |  |
| q-1fe94162dc | check C148 | search | {"dataset": "windows.other", "query": "message:*password* OR message:*unattend* OR message:*web.config*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 0 |  |
| q-7005aa29b2 | check C149 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-8c1ec96f0a | check C150 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*SAM* OR registry.path:*SECURITY* OR registry.path:*LSA* OR registry.path:*Control\\\\Set\\\\Control\\\\Lsa*)", "time_from": null, "time_to": null, "size": 50, "… | 7 |  |
| q-70f73ecee9 | check C151 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg*query* OR process.command_line:*reg*save* OR process.command_line:*reg*export*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 0 |  |
| q-e94eda4e69 | check C152 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*Lsa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1473 |  |
| q-2463d23b52 | check C153 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*HKLM* OR powershell.script_block_text:*HKCU* OR powershell.script_block_text:*Get-ItemProperty*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 8 |  |
| q-4fbd892bc8 | check C154 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*ConsoleHost_history* OR powershell.script_block_text:*PSReadLine* OR powershell.script_block_text:*history*)", "time_from": null, "time_to": null, "fields": ["@times… | 0 |  |
| q-2b472d909c | check C155 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ConsoleHost_history* OR process.command_line:*PSReadLine* OR process.command_line:*AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\PowerShell*)", "time_from": null, "time_to": null, … | 0 |  |
| q-c40cd8d7d9 | check C156 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*ConsoleHost_history* OR file.path:*PSReadLine*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ba6d30f373 | check C157 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*.key OR file.path:*.pem OR file.path:*.pfx OR file.path:*.p12 OR file.path:*.ppk OR file.path:*.pgp OR file.path:*.gpg OR file.path:*.asc OR file.path:*.p7b)", "time_fr… | 1 |  |
| q-009c93e7e3 | check C158 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*.pem OR process.command_line:*.pfx OR process.command_line:*.p12 OR process.command_line:*.key OR process.command_line:*.ppk)", "time_from": null, "time_to": null, "fields": ["@tim… | 0 |  |
| q-1b8b38abd5 | check C159 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:5145 AND (win.ObjectName:*.key OR win.ObjectName:*.pem OR win.ObjectName:*.pfx OR win.ObjectName:*.p12 OR win.ObjectName:*.ppk)", "time_from": null, "time_to": null, "size": 100, "… | 0 |  |
| q-96981cc388 | check C160 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Groups.xml* OR powershell.script_block_text:*gpprefdecrypt* OR powershell.script_block_text:*cpassword* OR powershell.script_block_text:*SYSVOL*)", "time_from": null… | 0 |  |
| q-2a7144a23a | check C161 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:5145 AND (win.ObjectName:*SYSVOL* OR win.ObjectName:*Groups.xml* OR win.ObjectName:*Policies*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-e5db9712ed | check C162 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Groups.xml OR process.command_line:*cpassword OR process.command_line:*gpprefdecrypt OR process.command_line:*SYSVOL*)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 0 |  |
| q-c1f24ba667 | check C163 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon* OR win.TargetImage:*Credential* OR win.TargetImage:*vault*)", "time_from": null, "time_to": null, "size": 50, "sub_fiel… | 470 |  |
| q-3ef3eaa665 | check C164 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-ab96ad49e1 | check C165 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*vault* OR win.ObjectName:*Credential*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-ea1f4d3073 | check C166 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*dump* OR process.command_line:*sekurlsa* OR process.command_line:*procdump*)", "time_from": null, "time_to": nul… | 0 |  |
| q-767e91d7a4 | check C167 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*sekurlsa* OR powershell.script_block_text:*MiniDump* OR powershell.script_block_text:*Credential*)", "time_from": null, "time… | 3 |  |
| q-85b9c073d0 | check C168 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Login Data* OR file.path:*logins.json* OR file.path:*key4.db* OR file.path:*signons.sqlite* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "size": 100, "… | 0 |  |
| q-0ac1a578bf | check C169 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Login Data* OR process.command_line:*logins.json* OR process.command_line:*key4.db* OR process.command_line:*Local State*)", "time_from": null, "time_to": null, "fields": ["@timest… | 0 |  |
| q-ef00aa62b8 | check C170 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Login Data* OR win.ObjectName:*logins.json* OR win.ObjectName:*key4.db* OR win.ObjectName:*signons.sqlite*)", "time_from": null, "time_to": null, "size": … | 0 |  |
| q-40ad73706f | check C171 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Login Data* OR powershell.script_block_text:*logins.json* OR powershell.script_block_text:*key4.db* OR powershell.script_block_text:*Local State*)", "time_from": nul… | 0 |  |
| q-11f9aac980 | check C172 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-cc79735b95 | check C173 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-f1855cabe1 | check C174 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*credential* OR process.command_line:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-17566b2474 | check C175 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*vault* OR powershell.script_block_text:*Credential* OR powershell.script_block_text:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 3 |  |
| q-681e834d0a | check C176 | search | {"dataset": "windows.other", "query": "win.HiveName:*SECURITY* OR win.HiveName:*SAM*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 0 |  |
| q-cf1494214a | check C177 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*lastpass* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 0 |  |
| q-09d179f890 | check C178 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*lastpass* OR process.command_line:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-4d880b65a1 | check C179 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keepass* OR powershell.script_block_text:*1password* OR powershell.script_block_text:*lastpass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 0 |  |
| q-23aa09f50e | check C180 | search | {"dataset": "windows.other", "query": "win.HiveName:*Vault* OR win.HiveName:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.com… | 0 |  |
| q-c6aa4eabc9 | check C181 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-6c50b20e92 | check C182 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*wdigest*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 75 | F41, F44 |
| q-a1c832d3dd | check C183 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*cryptdll* OR win.ObjectName:*wdigest* OR win.ObjectName:*Security Packages*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "o… | 0 |  |
| q-dd6808b066 | check C184 | search | {"dataset": "windows.other", "query": "win.HiveName:*SECURITY* OR win.HiveName:*SAM*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 0 |  |
| q-25328c8a6a | check C185 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*wdigest* OR powershell.script_block_text:*SecurityPackage*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 0 |  |
| q-ad6668fcdb | check C186 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-5189adf82a | check C187 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-c827c04867 | check C188 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3 AND win.TargetUserName:*$", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 198 |  |
| q-f9dae5156e | check C189 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-768b81a68f | check C190 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-3b3e27fe44 | check C191 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*lsass* OR win.TargetFilename:*PasswordFilter* OR win.TargetFilename:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.d… | 0 |  |
| q-7192919c93 | check C192 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*PasswordFilter* OR win.ImageLoaded:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 1 |  |
| q-24b1bc94a8 | check C193 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Notification Packages* OR win.ObjectName:*PasswordFilter* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 0 |  |
| q-a92e5f7d49 | check C194 | search | {"dataset": "windows.other", "query": "win.HiveName:*SECURITY* OR win.HiveName:*SAM*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 0 |  |
| q-bca6f37907 | check C195 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*AllowReversiblePasswordEncryption* OR powershell.script_block_text:*ReversibleEncryption* OR powershell.script_block_text:*Set-ADUser*)", "time_from": null, "time_to… | 1 |  |
| q-f49ac9c781 | check C196 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-60a634512c | check C197 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-8fad17d44a | check C198 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*Encryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-c303a604e7 | check C199 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*set-aduser*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*stro… | ERROR |  |
| q-fb9892bc22 | check C199 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*set-aduser*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*stro… | ERROR |  |
| q-11ee91ec90 | check C200 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-6ffd5c3f06 | check C201 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:5136", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-7d29ffeca4 | check C202 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*ADUser* OR process.command_line:*AuthenticationPolicy*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e926d7170b | check C203 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 9 |  |
| q-9ee29116da | check C204 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-dd7af51f18 | check C205 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:5136", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-94812eb891 | check C206 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-bf997b38d7 | check C207 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*azure*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*aad*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*connect-msol*\" OR TO_LOWER(powe… | ERROR |  |
| q-1de85e8d31 | check C207 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*azure*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*aad*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*connect-msol*\" OR TO_LOWER(powe… | ERROR |  |
| q-c7035ae410 | check C208 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-c8da043eda | check C209 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 36 |  |
| q-479bae54a8 | check C210 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-f3228bcd30 | check C211 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*NetworkProvider* OR win.TargetFilename:*System32*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 425 |  |
| q-5b6e5fbdff | check C212 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-079d4c7fd1 | check C213 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*networkprovider*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*credential*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*reg add*\" \| K… | ERROR |  |
| q-8eb17fed7e | check C213 (repaired) | esql | {"query": "FROM windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*networkprovider*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*credential*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*reg add… | ERROR |  |
| q-0188d4bd0a | check C214 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 9 |  |
| q-3d23b20a99 | check C215 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-a7734bbd13 | check C216 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-f0a597e415 | check C217 | aggregate | {"dataset": "windows.sysmon", "field": "dns.question.name", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-5dc2e1d374 | check C218 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*mitm*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*arp*\" OR TO_LOWER(powershe… | ERROR |  |
| q-77a9d7c800 | check C218 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*mitm*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*arp*\" OR TO_LOWER(powershe… | ERROR |  |
| q-bee0e4e905 | check C219 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-35bb75b9c0 | check C220 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-28701dc2b5 | check C221 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:5355 OR destination.port:137)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2 |  |
| q-9b5ad65954 | check C222 | aggregate | {"dataset": "zeek", "field": "source.ip", "query": "event.action:smb_files OR event.action:smb_mapping", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 23 |  |
| q-c12a6b384f | check C223 | aggregate | {"dataset": "zeek", "field": "zeek.rcode_name", "query": "event.action:dns", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 53 |  |
| q-ca27fbee1f | check C224 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-a2ac596144 | check C225 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND registry.path:*DNSClient*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-d3da1bf64c | check C226 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*llmnr*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*nbt-ns*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*enablemulticast*\" OR TO_LOWE… | ERROR |  |
| q-cc6f3a3416 | check C226 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*llmnr*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*nbt-ns*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*enablemulticast*\" OR TO_LOWE… | ERROR |  |
| q-9327cb1d7e | check C227 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-f1531ba51d | check C228 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-51ffac0bc7 | check C229 | aggregate | {"dataset": "windows.sysmon", "field": "dns.question.name", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-be41e92858 | check C230 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-9ab8ac46fa | check C231 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*arp*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*netsh*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*poison*\" \| KEEP @timestamp, ho… | ERROR |  |
| q-423740c9be | check C231 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*arp*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*netsh*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*poison*\" \| KEEP @timestamp, ho… | ERROR |  |
| q-b901ff3a77 | check C232 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 9 |  |
| q-6843d3c954 | check C233 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-14847635ac | check C234 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-d615c0067d | check C235 | search | {"dataset": "windows.security", "query": "event.code:5156 AND win.Direction:Inbound", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-4c4d54b0b9 | check C236 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3 AND network.transport:udp", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 308 |  |
| q-40e5c71b31 | check C237 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Dhcp* OR *dhcp* OR *New-NetIPAddress* OR *Set-DnsClientServerAddress*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "eve… | 2 |  |
| q-ecacca5f1b | check C238 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND network.transport:udp", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 62 |  |
| q-4007fbd78d | check C239 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-ce4bb3dbbd | check C240 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 236 |  |
| q-42b72613cb | check C241 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-1e523ae615 | check C242 | search | {"dataset": "windows.other", "query": "event.code:(5857 OR 5858 OR 5860 OR 5861)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 89 |  |
| q-6351f61d5f | check C243 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*kerberos* OR *Kerberos* OR *ticket* OR *Ticket* OR *kirbi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 0 |  |
| q-c7aa5c2e02 | check C244 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-cc96f2f98e | check C245 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-c4a576ffee | check C246 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-db81aaf60c | check C247 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-965ce439d0 | check C248 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-b158f36996 | check C249 | search | {"dataset": "windows.other", "query": "event.code:(5857 OR 5858 OR 5860 OR 5861)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 89 |  |
| q-f3e39166ea | check C250 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*golden* OR *Golden* OR *krbtgt* OR *KRBTGT* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "use… | 0 |  |
| q-2dd6740f97 | check C251 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-df9e7234f7 | check C252 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-8aedf5fe16 | check C253 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-788f37885c | check C254 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-d714643dfc | check C255 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-91b146a346 | check C256 | search | {"dataset": "windows.other", "query": "event.code:(5857 OR 5858 OR 5860 OR 5861)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 89 |  |
| q-b92fd8ec4e | check C257 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*silver* OR *Silver* OR *Rubeus* OR *ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-ddef956e3d | check C258 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-c2d777ee98 | check C259 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-a17a785bc3 | check C260 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-ddf6afd1cc | check C261 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-61cd3cd317 | check C262 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-792eb2a7d0 | check C263 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-af9b428fa2 | check C264 | search | {"dataset": "windows.other", "query": "event.code:(5857 OR 5858 OR 5860 OR 5861)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 89 |  |
| q-076dac0fa0 | check C265 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Kerberoast* OR *kerberoast* OR *Invoke-Kerberoast* OR *GetUserSPNs*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 0 |  |
| q-981188eafd | check C266 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-b410845b0a | check C267 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-cb66466b67 | check C268 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-4f81258f0b | check C269 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*roast* OR process.command_line:*Roast* OR process.command_line:*GetNPUsers* OR process.command_line:*Rubeus*)", "time_from": null, "time_to": null, "… | 0 |  |
| q-583801a54e | check C270 | search | {"dataset": "windows.other", "query": "event.code:(5857 OR 5858 OR 5860 OR 5861)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 89 |  |
| q-5510b1d686 | check C271 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*AS-REP* OR *asrep* OR *GetNPUsers* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", … | 0 |  |
| q-4a85cf50a4 | check C272 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-586cda2f7e | check C273 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-94f7ec77a0 | check C274 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-f467c026e2 | check C275 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*AADInternals* OR powershell.script_block_text:*SAML* OR powershell.script_block_text:*token* OR powershell.script_block_text:*cookie*)", "time_from": null, "time_to"… | 1 |  |
| q-60aa0f5d9a | check C276 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 9 | F57 |
| q-cb35d65fdc | check C277 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-3cb07c0571 | check C278 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-e1e2423c5d | check C279 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*session*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "eve… | 1 |  |
| q-66110cb105 | check C280 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-9a061a1bbb | check C281 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-90677343ec | check C282 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 9 |  |
| q-a05902ceaa | check C283 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAML* OR powershell.script_block_text:*ADFS* OR powershell.script_block_text:*certificate*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 2 | F57 |
| q-15beace598 | check C284 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-77414346a1 | check C285 | count | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null} | 0 |  |
| q-7e95922351 | check C286 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-d6f6bd170f | check C287 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*MFA* OR powershell.script_block_text:*2FA* OR powershell.script_block_text:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 0 |  |
| q-c5a31fe5ca | check C288 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-a69ec242a6 | check C289 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-5de17d8a18 | check C290 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-6317292d57 | check C291 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Certificate* OR registry.path:*Crypto*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 25 |  |
| q-3ce51cca0e | check C292 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Certify* OR powershell.script_block_text:*Certipy* OR powershell.script_block_text:*Export-PfxCertificate* OR powershell.script_block_text:*New-SelfSignedCertificate… | 1 |  |
| q-ec3789fc94 | check C293 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 9 |  |
| q-41c1adebad | check C294 | search | {"dataset": "zeek", "query": "event.action:dce_rpc AND zeek.operation:*DRSUAPI*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line… | 0 |  |
| q-e835c60001 | check C295 | aggregate | {"dataset": "zeek", "field": "zeek.operation", "query": "event.action:dce_rpc", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 123 |  |
| q-229f237661 | check C296 | aggregate | {"dataset": "zeek", "field": "zeek.history", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-f1be26005f | check C297 | search | {"dataset": "zeek", "query": "event.action:weird", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.ip… | 12 |  |
| q-3af6d4d058 | check C298 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-022ff5284f | check C299 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-94ff667062 | check C300 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-ddb80bd0c5 | check C301 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-d1acd469ce | check C302 | aggregate | {"dataset": "zeek", "field": "url.original", "query": "event.action:http", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 62 |  |
| q-a236d1d55e | triage T1003 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhL"} | None |  |
| q-18e6994ccf | triage T1003 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x1f3fff\",\"0x101001\",\"0x1000000\",\"0x1410\",\"0x1010\") \| KEEP @timestamp, host.name,… | ERROR |  |
| q-70b70f9207 | triage T1003 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x1f3fff\",\"0x101001\",\"0x1000000\",\"0x1410\",\"0x1010\") \| KEEP @timestamp, host.n… | 8 | F01, F05, F06, F07 |
| q-3ac462763a | triage T1003 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.SourceImage LIKE \"*PowerShell*\" \| KEEP @timestamp, host.name, process.executable, win.SourceImage, win.GrantedAccess,… | 4 |  |
| q-276b49cd3d | triage T1003 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None | F01 |
| q-c8a279ef0c | triage T1003 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:00.000Z\" \| KEEP @timestamp, host.name, user.name, powershell.script_block… | 35 | F02 |
| q-9e72d8a78e | triage T1003 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (powershell.script_block_text LIKE \"*lsass*\" OR powershell.script_block_text LIKE \"*MiniDump*\" OR powershell.script_block_text LIKE \"*sekurlsa*\" OR p… | 3 | F02 |
| q-d72fbd9bc9 | triage T1003 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*SECURITY*\" OR win.ObjectName LIKE \"*lsass*\") \| KEEP @timestamp, host.name, user.name, win.Object… | 6 | F01 |
| q-15cbfa7301 | triage T1003 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21gGA"} | None |  |
| q-72ab7d5780 | triage T1003 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:05:00.000Z\" AND @timestamp <= \"2020-05-02T03:05:20.000Z\" \| KEEP @timestamp, host.name, user.name, powershell.script_block… | 1 |  |
| q-1e5c0b6563 | triage T1003 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F01 |
| q-9a851b7b21 | triage T1003 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (powershell.script_block_text LIKE \"*Invoke-Credential*\" OR powershell.script_block_text LIKE \"*Get-Credential*\" OR powershell.script_block_text LIKE \… | 7 | F02 |
| q-a1a02472a4 | triage T1003 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.SourceImage LIKE \"*wsmprovhost*\" \| KEEP @timestamp, host.name, process.executable, win.SourceImage, win.GrantedAccess… | 1 | F01 |
| q-92430be715 | triage T1003 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectType IN (\"SAM_DOMAIN\",\"SAM_SERVER\",\"SAM_ALIAS\") \| KEEP @timestamp, host.name, user.name, win.ObjectName, win.ObjectType, win.ProcessName, wi… | 0 |  |
| q-f51d046fe6 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-ed9ea9c16c | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-4b375dc4c2 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-0cc3a612de | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-9078cc78ab | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-dd989864ee | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-1123ea141c | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-80dec82eaf | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Tx"} | None |  |
| q-0d0b555e68 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-6f455efc0a | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_RQ"} | None |  |
| q-6ee48c9067 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUmZF"} | None |  |
| q-db313101f5 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-2f1f92d713 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-6893a2d66f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-866a1e11c6 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-3fbdc6f7fd | triage T1040 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None | F08 |
| q-05018bad36 | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*trace* OR process.command_line:*capture* OR process.command_line:*pktmon* OR process.command_line:*logman* OR process.command_line:*NetworkWatcher*)", "time_from": null, "time… | 14 | F08 |
| q-1de4105183 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (win.Image:*sdelete* OR win.Image:*python* OR win.Image:*PsExec* OR win.Image:*PSEXESVC* OR win.Image:*netsh* OR win.Image:*windump* OR win.Image:*tcpdump*)", "time_from": null, "time_to": null, "fields"… | 21 | F09, F11 |
| q-2f7d79282b | triage T1040 step 2 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.executable:*sdelete* OR process.executable:*python* OR process.executable:*PsExec* OR process.executable:*PSEXESVC*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 19 |  |
| q-121953c4ed | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (win.Image:*windump* OR win.Image:*tcpdump* OR win.Image:*wireshark* OR win.Image:*dumpcap* OR win.Image:*pktmon* OR win.Image:*Npcap* OR win.Image:*rawcap* OR win.Image:*NetworkMiner*)", "time_from": nu… | 0 |  |
| q-34808e5f91 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:6 AND (win.Image:*npcap* OR win.Image:*pcap* OR win.Image:*windump* OR win.Image:*tcpdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.Image", "win.Device", "… | 0 |  |
| q-58fdcc4ac8 | triage T1040 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*sniff* OR powershell.script_block_text:*capture* OR powershell.script_block_text:*pcap* OR powershell.script_block_text:*promiscuous* OR powershell.script_block_text… | 0 |  |
| q-18ba428ae4 | triage T1040 step 4 | search | {"dataset": "zeek", "query": "event.action:notice OR event.action:weird", "time_from": null, "time_to": null, "fields": ["@timestamp", "observer.name", "event.action", "zeek.name", "zeek.note", "source.ip", "destination.ip", "destination.port", "zeek.msg"], "s… | 14 | F10 |
| q-a9b60de965 | triage T1040 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND process.executable:*python*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "destination.ip", "destination.port", "w… | 348 | F11 |
| q-efac1d98cd | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-155aff5d65 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-d34a2d807f | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YWMXHe"} | None |  |
| q-4687fd3806 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YJECPu"} | None |  |
| q-bbee1e5028 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqWk4"} | None |  |
| q-7db2f9a3c3 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqK7jn"} | None |  |
| q-48843edccf | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74ed"} | None |  |
| q-b6d1b1cc8f | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdW"} | None |  |
| q-8952a9882c | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdY"} | None |  |
| q-9098a1676f | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqK7jn"} | None |  |
| q-ca1ff45a22 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqWk4"} | None |  |
| q-b1cdd6c3c1 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDSP-"} | None |  |
| q-05c0bfb95f | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None | F13 |
| q-7f450dac97 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" \| STATS c = COUNT(*) BY process.executable, win.GrantedAccess \| SORT c DESC"} | ERROR |  |
| q-df269a8d17 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| STATS c = COUNT(*) BY process.executable, win.GrantedAccess \| SORT c DESC"} | 15 |  |
| q-2c6a8a139b | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND (win.GrantedAccess LIKE \"*1010*\" OR win.GrantedAccess LIKE \"*1410*\" OR win.GrantedAccess LIKE \"*1fffff*\" OR win.Grante… | 5 | F13, F17 |
| q-7a681e869c | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-6ae9adb4b3 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _id, _index \| SORT @timestamp ASC \| LIMIT 40"} | 40 | F14 |
| q-59304f684e | triage T1056 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (powershell.script_block_text LIKE \"*Credential*\" OR powershell.script_block_text LIKE \"*Windows.Forms*\" OR powershell.script_block_text LIKE \"*Prompt… | 5 | F12, F14, F16 |
| q-e43465f790 | triage T1056 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (powershell.script_block_text LIKE \"*lsass*\" OR powershell.script_block_text LIKE \"*MiniDump*\" OR powershell.script_block_text LIKE \"*DumpCred*\" OR p… | 0 |  |
| q-17804e4464 | triage T1056 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTv"} | None | F12 |
| q-764cf452b9 | triage T1056 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-0ac0c2aea1 | triage T1056 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (powershell.script_block_text LIKE \"*Invoke-Mimikatz*\" OR powershell.script_block_text LIKE \"*Invoke-Credential*\" OR powershell.script_block_text LIKE … | 5 | F12, F14 |
| q-24733c8a74 | triage T1056 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*monkey*\" OR process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*Credential*\" OR process.command_line LIKE \"*Sys… | 10 | F14 |
| q-3e21da8748 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTv"} | None |  |
| q-6be593a027 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22PTB"} | None |  |
| q-8fefd33771 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTv"} | None |  |
| q-fdf4ece9a2 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-ccaac1ee9b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-f02dd9ce92 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-4c0d58722c | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-41a355b633 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aOf"} | None |  |
| q-c26355acdf | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-5d17f8ad52 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-6477d71eb9 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-0020801cf4 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-79fa09d113 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqK7jn"} | None |  |
| q-1e3099be8a | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NZ30AL"} | None |  |
| q-eeef251e5f | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WoRbhf"} | None |  |
| q-9accaa23aa | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-3acadcc58c | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-13e33c4ebb | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None | F22 |
| q-ed3bafe772 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F22 |
| q-0f1f894caf | triage T1110 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-9a2fa440cd | triage T1110 step 1 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 15 |  |
| q-089510c19e | triage T1110 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.SourceImage:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.SourceImage", "win.TargetImage", "win.GrantedAccess", "process.c… | 2 | F18, F19, F20 |
| q-2c75e5c049 | triage T1110 step 2 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.SubjectUserName", "win.ProcessName", "win.IpAddress", "win.TargetServerName"], "size": 15, "sort": … | 15 | F21 |
| q-52aa962025 | triage T1110 step 2 | count | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776", "time_from": null, "time_to": null} | 1 |  |
| q-d95f97876d | triage T1110 step 3 | search | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "win.IpAddress", "win.LogonType", "win.Status", "win… | 1 | F18, F19 |
| q-d4f95fa4de | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-0338cbe7e9 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-708cdf714e | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-549e911346 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-d3cd9713bc | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-660905e155 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-5ca2bdd4df | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-cf2b11c51c | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-39496cc645 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-0ace636c6a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-6b100f7a71 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-0addb3822a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-0c7a92337c | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-ddd37073d5 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F24 |
| q-d92ab7365f | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHQbW"} | None | F24 |
| q-a7f2f5f8e0 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-9516674789 | triage T1111 step 2 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None | F23 |
| q-79c1734c96 | triage T1111 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None | F23, F24 |
| q-4b7302f1af | triage T1111 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.LogonType", "win.IpAddress", "win.Workstation", "win.AuthenticationPackageName"], "size… | 2 |  |
| q-c805a1bbf4 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-6438788940 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NMoBQe"} | None |  |
| q-8c4ce4bc3d | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NDgh5J"} | None |  |
| q-8e31c1967d | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None |  |
| q-631de22ad2 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-0ebbab17e4 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-8f7f43e7c9 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHQbW"} | None |  |
| q-1e9d848ec1 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-cab7468f40 | triage T1187 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx3F"} | None | F26 |
| q-bcf3d8d6f6 | triage T1187 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 66 |  |
| q-a9f9734e93 | triage T1187 step 1 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "size": 50, "sub_field": "host.name"} | 163 |  |
| q-2c0ad86c64 | triage T1187 step 2 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aOf"} | None | F27 |
| q-fcbc8fbea4 | triage T1187 step 2 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aMP"} | None | F27 |
| q-49fadf121d | triage T1187 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 3 AND (destination.port == 445 OR destination.port == 139) \| KEEP @timestamp, host.name, process.executable, source.ip, destination.ip, destination.port, win.Initiated \| … | ERROR |  |
| q-d816e36c7c | triage T1187 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == \"445\" OR destination.port == \"139\") \| KEEP @timestamp, host.name, process.executable, source.ip, destination.ip, destination.port, win.I… | ERROR |  |
| q-3aaeddcbe8 | triage T1187 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5140\" OR event.code == \"5145\" \| KEEP @timestamp, host.name, win.ShareName, win.SubjectUserName, win.IpAddress, win.RelativeTargetName \| LIMIT 25"} | 25 |  |
| q-8c414e12e0 | triage T1187 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 139) \| KEEP @timestamp, host.name, process.executable, source.ip, destination.ip, destination.port, win.Initiated… | 25 |  |
| q-f5e0d6eed1 | triage T1187 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (win.TargetFilename LIKE \"*DavWWWRoot*\" OR win.TargetFilename LIKE \"*WebDAV*\" OR win.TargetFilename LIKE \"\\\\\\\\*\") \| KEEP @timestamp, host.name, proces… | 0 |  |
| q-25afdd90cb | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqmrA"} | None |  |
| q-9475f59342 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqmrA"} | None |  |
| q-23504c0f26 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "q-3aaeddcbe8-row-0"} | ERROR |  |
| q-2ffdf1eca8 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "q-3aaeddcbe8-row-2"} | ERROR |  |
| q-61456e54f8 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx3F"} | None |  |
| q-aea5c86e4a | triage T1187 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx3F"} | None |  |
| q-a2742a31fa | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aOf"} | None |  |
| q-db5e89db3f | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aMP"} | None |  |
| q-44ea9654ea | triage T1187 step 6 | search | {"dataset": "windows.security", "query": "event.code:5140 AND win.ShareName:*SYSVOL*", "time_from": null, "time_to": null, "fields": ["host.name", "win.ShareName", "win.SubjectUserName", "win.RelativeTargetName"], "size": 3, "sort": "asc"} | 13 | F25 |
| q-460a8972e1 | triage T1187 step 6 | search | {"dataset": "windows.security", "query": "event.code:5140 AND win.ShareName:*IPC$*", "time_from": null, "time_to": null, "fields": ["host.name", "win.ShareName", "win.SubjectUserName", "win.RelativeTargetName"], "size": 3, "sort": "asc"} | 20 | F25 |
| q-dccb7dbca8 | triage T1212 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| STATS c = COUNT(*) BY win.SourceImage, host.name \| SORT c DESC \| LIMIT 30"} | 12 |  |
| q-683724a263 | triage T1212 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess LIKE \"*10*\" \| KEEP @timestamp, host.name, win.SourceImage, win.TargetImage, win.GrantedAccess, win.Call… | 30 | F28 |
| q-627323d8a3 | triage T1212 step 2 | search | {"dataset": "zeek", "query": "event.action:files OR event.action:smb_files OR event.action:http", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "source.ip", "destination.ip", "file.path", "url.original", "zeek.filename", "zeek.mi… | 522 |  |
| q-7f87e6b7dc | triage T1212 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (powershell.script_block_text LIKE \"*SeDebug*\" OR powershell.script_block_text LIKE \"*lsass*\" OR powershell.script_block_text LIKE \"*Mimikatz*\" OR po… | 3 |  |
| q-0bd5591972 | triage T1212 step 3 | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74ey"} | None | F28 |
| q-04b6cda122 | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQxZ"} | None | F28 |
| q-9261dd7aca | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-25cc086b88 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-7b5ed6aa8a | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-af884a9248 | triage T1212 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74ey"} | None |  |
| q-5ac3f95637 | triage T1212 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74ey"} | None |  |
| q-90081ad3a3 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQxZ"} | None |  |
| q-b02efa416e | triage T1212 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1g"} | None |  |
| q-88e0636b87 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21gGA"} | None | F30 |
| q-b209dcd79c | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F30 |
| q-ed614b1133 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (win.TargetFilename LIKE \"*INetCookies*\" OR win.TargetFilename LIKE \"*MicrosoftEdge*\" OR win.TargetFilename LIKE \"*Cookies*\" OR win.TargetFilename LIKE \"*… | 5 | F29 |
| q-a7ad725167 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*chrome*\" OR TO_LOWER(process.executable) LIKE \"*firefox*\" OR TO_LOWER(process.executable) LIKE \"*iexplore*\" OR TO_LOWER… | 0 |  |
| q-b8d51f0d3a | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (win.TargetFilename LIKE \"*Cookies*\" OR win.TargetFilename LIKE \"*Login Data*\" OR win.TargetFilename LIKE \"*WebCache*\" OR win.TargetFilename LIKE \"*Networ… | 5 |  |
| q-de8267f32a | triage T1539 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (win.ObjectName LIKE \"*Cookies*\" OR win.ObjectName LIKE \"*Login Data*\" OR win.ObjectName LIKE \"*WebCache*\") \| KEEP @timestamp, host.name, user.name, p… | 0 |  |
| q-748e1fa83b | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (win.TargetFilename LIKE \"*AppData*Local*Google*\" OR win.TargetFilename LIKE \"*AppData*Roaming*Mozilla*\" OR win.TargetFilename LIKE \"*AppData*Local*Microsof… | 4 | F29 |
| q-d3826644b9 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*cookie*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*login data*\" OR TO_LOWER(powershell.script_blo… | 0 |  |
| q-aff4c4494f | triage T1539 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND powershell.script_block_text LIKE \"*sqlite*\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _id, _index"} | 0 |  |
| q-750bafb5b6 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsPCud"} | None |  |
| q-1296d2945a | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsPCud"} | None |  |
| q-6c7d2eb6cf | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-d7fd0ae8c9 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-bc364fcfed | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MrOfHr"} | None |  |
| q-d242c22b70 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21gGA"} | None |  |
| q-5ca4e92284 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-d4f52ada7e | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-52e6fe6141 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None | F31 |
| q-e1a1db8d39 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F32 |
| q-e45151c169 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*unattend*\" OR TO_LOWER(process.command_line) LIKE \"*sysvol*\" OR TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR… | 0 |  |
| q-0c217dbfce | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.pem\" OR TO_LOWER(win.TargetFilename) LIKE \"*.key\" OR TO_LOWER(win.Target… | 1 | F31 |
| q-d588f949ad | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _inde… | 12 | F33 |
| q-43a3aea511 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.ObjectName) LIKE \"*sysvol*\" OR TO_LOWER(win.ObjectName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ObjectName) LIKE \"*policies*\" OR TO_LOWER(win… | 0 |  |
| q-0e420647f9 | triage T1552 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*.pfx\" OR TO_LOWER(win.ObjectName) LIKE \"*sysvol*\" OR TO_LOWER(win.ObjectName) LIKE \"*groups.xml*\" OR TO_LOWER(win.Obje… | 0 |  |
| q-bb891a2b61 | triage T1552 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.TargetServerName, process.executable, source.ip, _id, _index"} | 15 | F32 |
| q-6165a93970 | triage T1552 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*sysvol*\" OR TO_LOWER(win.TargetFilename) LIKE \"*gpttmpl*\" OR TO_LOWER(win.TargetFilename) LIKE \"*gpt.ini*\") \| KEEP @t… | 22 | F35 |
| q-4e800077aa | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-6618d61d26 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-7ec35f7ea9 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-889ad2f059 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-9f86cf6683 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-5a56411414 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-b51fbe8ac3 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-c8e5e37056 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUml9"} | None |  |
| q-b848e39802 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUEbK"} | None |  |
| q-4a409f7860 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-a526eb23f0 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-303d6a66c1 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-00cff2ad9a | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqLbie"} | None |  |
| q-bfd51e2ce3 | triage T1552 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ida"} | None |  |
| q-2a47e28f21 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-a4ab6acc67 | triage T1555 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.n… | 33 | F37 |
| q-21b11f4b8c | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F38 |
| q-4c6c0161e3 | triage T1555 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.SourceImage LIKE \"*PowerShell*\" \| KEEP @timestamp, host.name, process.executable, win.SourceImage, win.GrantedAccess,… | 4 |  |
| q-1132477b32 | triage T1555 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*vault*\" OR process.command_line LIKE \"*cmdkey*\" OR process.command_line LIKE \"*Credential*\" OR process.command_line LIKE \"*Log… | 1 |  |
| q-01267c2e2f | triage T1555 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-ea0b4dbac1 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:00.000Z\" \| KEEP @timestamp, host.name, user.name, powershell.script_block… | 35 | F38 |
| q-4706ed200a | triage T1555 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-801f4a70a5 | triage T1555 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectName LIKE \"*lsass*\" \| KEEP @timestamp, host.name, win.ObjectName, win.ProcessName, win.SubjectUserName, win.AccessMask, win.AccessList, _id, _in… | 6 | F37 |
| q-0292d027e1 | triage T1555 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None | F38 |
| q-45adebb279 | triage T1555 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" AND @timestamp >= \"2020-05-02T03:08:00.000Z\" AND @timestamp <= \"2020-05-02T03:11:00.000Z\" \| KEEP @timestamp, hos… | 2 |  |
| q-ea396b026c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-956879ab8e | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-82dceecda0 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-4db8bb5d34 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-ad7df192d7 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-54466271b8 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Tx"} | None |  |
| q-0401a0cebd | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Qp"} | None |  |
| q-7c2fddf787 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-52785fcc89 | triage T1555 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None | F37 |
| q-af3ad38003 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-e2f4819208 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-b87216627b | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F39, F42 |
| q-5978a4ef75 | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*wsmprovhost*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.GrantedAccess"… | 1 | F40 |
| q-8863c14f46 | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-7a3ca45f1c | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-438c7db524 | triage T1556 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*MiniDump* OR powershell.script_block_text:*Dump* OR powershell.script_block_text:*Credential*)", "time_from": null, "time_to"… | 3 | F39 |
| q-997d7b092d | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-5e50dd3a7b | triage T1556 step 4 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:9", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.LogonType", "win.LogonProcessName", "win.TargetUserName", "win.IpAddress", "event.code"]… | 0 |  |
| q-9d36b4d6fc | triage T1556 step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Invoke-Mimikatz* OR powershell.script_block_text:*DumpCreds* OR powershell.script_block_text:*sekurlsa* OR powershell.script_block_text:*Get-Process*lsass* OR powers… | 0 |  |
| q-5a2de4f7eb | triage T1556 step 5 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ObjectName", "win.AccessMask", "win.ProcessName", "event.code"], "size": 20, "sor… | 6 | F39, F43 |
| q-64de74fbc4 | triage T1556 step 6 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:4104 AND @timestamp:[2020-05-02T03:04:00.000Z TO 2020-05-02T03:07:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "pow… | 35 |  |
| q-aa4b2a00c7 | triage T1556 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Security*Packages* OR registry.path:*Notification* OR registry.path:*Lsa* OR registry.path:*wdigest* OR registry.path:*PasswordFilter*)", "time_from": null, "time_to": null, "fields": ["… | 445 |  |
| q-2e5d92b5b3 | triage T1556 step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Control\\\\Lsa* OR registry.path:*Security\\\\Packages* OR registry.path:*OSConfig* OR registry.path:*WDigest* OR registry.path:*Authentication*)", "time_from": null, "time_to": null, "f… | 66 | F45 |
| q-a8af7b79ef | triage T1556 step 7 | search | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ObjectName", "win.ObjectType", "win.OperationType", "event.code"], "size": 30, "sort": "asc"} | 36 | F40 |
| q-ebd6877c47 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-a9f6c7e7d9 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-6ffed81092 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-874dfd0bdf | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-5209770b40 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-c4b65e5453 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-2cae473b06 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YGDFf9"} | None |  |
| q-3e89b49889 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WgHZ_S"} | None |  |
| q-2a331bf972 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SFrjYs"} | None |  |
| q-499b007ebc | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-4eac698a9e | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-d5f6727cf5 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R5ewC0"} | None |  |
| q-539041a312 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SO16KB"} | None |  |
| q-e0bef6dfe8 | triage T1557 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1N"} | None |  |
| q-4e10803695 | triage T1557 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2I"} | None |  |
| q-acdc2c0c1c | triage T1557 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b43SyN"} | None | F49 |
| q-ae626675bf | triage T1557 step 2 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == 7040 OR event.code == 7045 \| KEEP @timestamp, host.name, event.code, win.param1, win.param2, win.param3, win.param4, win.ServiceName, win.ImagePath, user.name, _id, _index … | ERROR |  |
| q-626eebfdf9 | triage T1557 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 3 AND (destination.port == 67 OR destination.port == 68 OR destination.port == 5355 OR destination.port == 137 OR destination.port == 138) \| KEEP @timestamp, host.name, pr… | ERROR |  |
| q-45ecf90dd1 | triage T1557 step 3 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7040\" OR event.code == \"7045\" \| KEEP @timestamp, host.name, event.code, win.param1, win.param2, win.param3, win.param4, win.ServiceName, win.ImagePath, user.name, _id,… | 9 | F46, F47, F49 |
| q-8fc2751439 | triage T1557 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 67 OR destination.port == 68 OR destination.port == 5355 OR destination.port == 137 OR destination.port == 138) \| KEEP @timestamp, host.name… | 24 |  |
| q-1befbdccc3 | triage T1557 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" \| KEEP @timestamp, host.name, win.TargetUserName, win.IpAddress, win.LogonProcessName, win.AuthenticationPackageName, win.Workstation… | 218 |  |
| q-5d05881afc | triage T1557 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.ip == \"10.0.1.4\" OR destination.ip == \"10.0.1.5\" OR destination.ip == \"10.0.1.6\" OR destination.ip == \"10.0.0.4\" OR destination.ip == \"192.1… | 500 | F48 |
| q-11e5d8463e | triage T1557 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE process.executable LIKE \"*victim*\" OR process.executable LIKE \"*cod.3aka3*\" \| KEEP @timestamp, host.name, event.code, process.executable, process.command_line, process.parent.execut… | 96 |  |
| q-26ced3eb30 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5140\" OR event.code == \"5145\" \| KEEP @timestamp, host.name, win.ShareName, win.ShareLocalPath, win.SubjectUserName, win.IpAddress, win.RelativeTargetName, _id, _ind… | 163 | F46, F47 |
| q-79d10b6362 | triage T1557 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WiJkSG"} | None |  |
| q-74b63ae89e | triage T1557 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND process.executable LIKE \"*victim*\" \| KEEP @timestamp, host.name, process.executable, destination.ip, destination.port, win.SourceIp, _id, _index"} | 1 | F46 |
| q-fad3e6b59c | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXZO"} | None |  |
| q-8b2d18707e | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yph4sr"} | None |  |
| q-bdd415c186 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-3752f149eb | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WiJUTX"} | None |  |
| q-1eff61740f | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-53afea6d71 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtY1"} | None |  |
| q-e5ea2805d1 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SErGop"} | None |  |
| q-996f2cb023 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1N"} | None |  |
| q-4982a24775 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2s"} | None |  |
| q-71eab2369c | triage T1557 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b43SyN"} | None |  |
| q-4cccbc197e | triage T1558 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" \| KEEP @timestamp, host.name, win.TargetUserName, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.IpAddress, win.Status, win.LogonGuid, _id, _… | 28 | F50, F51, F52, F53 |
| q-1063443cdf | triage T1558 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.n… | 33 | F51 |
| q-d233fcca1d | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-031a7be770 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-79694a0256 | triage T1558 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _id, _index \| SORT @timestamp ASC \| LIMIT 60"} | 60 |  |
| q-a6a3fa1f1f | triage T1558 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:01:30.000Z\" AND @timestamp <= \"2020-05-02T03:21:30.000Z\" \| KEEP @timestamp, host.name, user.name, powershell.script_block… | 60 |  |
| q-2e43bfa458 | triage T1558 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.TargetServerName, win.ProcessName, win.IpAddress, _id, _index \| SORT @timestamp ASC"} | 15 | F53 |
| q-653bcefced | triage T1558 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"kerberos\" \| KEEP @timestamp, zeek.request_type, zeek.client, zeek.service, zeek.success, zeek.error_msg, zeek.id_orig_h, zeek.id_resp_h, zeek.cipher, _id, _index \| SORT @times… | 35 | F50, F54 |
| q-9398dbfd68 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.SubjectUserName, win.PrivilegeList, _id, _index \| SORT @timestamp ASC \| LIMIT 40"} | 40 | F50, F52 |
| q-2685c3fea0 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.TargetUserName IN (\"pbeesly\",\"NEWYORK$\",\"SCRANTON$\",\"NASHUA$\") \| KEEP @timestamp, host.name, win.TargetUserName, win.LogonType, win.LogonProcess… | 40 |  |
| q-6da2d16477 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \| SORT @timestamp ASC \| LIMIT 60"} | 60 |  |
| q-eaa292197a | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" AND win.TicketEncryptionType != \"0x12\" \| KEEP @timestamp, host.name, win.TargetUserName, win.ServiceName, win.TicketEncryptionType, _id, _index"} | 0 |  |
| q-18567b9307 | triage T1558 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (powershell.script_block_text LIKE \"*lsass*\" OR powershell.script_block_text LIKE \"*LSASS*\" OR powershell.script_block_text LIKE \"*sekurlsa*\" OR powe… | 0 |  |
| q-98f4fee330 | triage T1558 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*dump*\" OR process.command_line LIKE \"*procdump*\" OR process.command_line LIKE \"*sekurls… | 1 |  |
| q-092178772c | triage T1558 step 7 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code IN (\"5857\",\"5858\",\"5860\",\"5861\") \| KEEP @timestamp, host.name, event.code, user.name, message, _id, _index \| SORT @timestamp ASC \| LIMIT 30"} | 30 | F50 |
| q-40d3aa8b7a | triage T1558 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" \| STATS cnt = COUNT(*) BY win.TargetUserName, win.ServiceName \| SORT cnt DESC"} | 8 |  |
| q-14dc45a130 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-5cd197ea67 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-8463e7e4a0 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeV"} | None |  |
| q-f06100bfc2 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-0917fcf7b0 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YtnqI_"} | None |  |
| q-bbb0575f3b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-a374b87c1b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-2273d0b344 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-88cdc033c0 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-ceac781cc6 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-c1dd32244f | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YtnqI_"} | None |  |
| q-2770aafc67 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-96e4ec4ce4 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-2cf222fa60 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-de676f8197 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Idf"} | None |  |
| q-16c2a3202d | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeV"} | None |  |
| q-500921d88e | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeV"} | None |  |
| q-e848eb12f2 | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None | F56 |
| q-e63ece2465 | triage T1606 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (win.GrantedAccess == \"0x1410\" OR win.GrantedAccess == \"0x1010\" OR win.GrantedAccess == \"0x1438\" OR win.GrantedAccess == \"0x143a\" OR win.GrantedAccess ==… | 50 |  |
| q-03b4f82beb | triage T1606 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetImage, win.GrantedAccess, win.CallTrace, _id, … | 50 | F57 |
| q-c492dcf520 | triage T1606 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sdelete*\" OR TO_LOWER(process.command_line) LIKE \"*python*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" OR TO… | 22 | F55, F56 |
| q-b4674e2c05 | triage T1606 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*cookie*\" OR TO_LOWER(file.path) LIKE \"*token*\" OR TO_LOWER(file.path) LIKE \"*saml*\" OR TO_LOWER(file.path) LIKE \"*adfs*\") \| … | 1 | F55, F56 |
| q-7f8fbcad0f | triage T1606 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*davsetcookie*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*webdav*\" OR TO_LOWER(powershell.script_b… | 20 |  |
| q-154edea314 | triage T1606 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F55 |
| q-e68c3d1e03 | triage T1606 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*.pfx*\" OR TO_LOWER(file.path) LIKE \"*.7z*\" OR TO_LOWER(file.path) LIKE \"*officesupplies*\" OR TO_LOWER(file.path) LIKE \"*workin… | 7 | F57 |
| q-34f124bf23 | triage T1606 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.TargetServerName, win.ProcessName, win.LogonProcessName, _id, _index \| LIMIT 30"} | 15 | F55 |
| q-8f501e9dd4 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMLE_"} | None |  |
| q-0b4bf7e56f | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-09594574a7 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-884d7b17ee | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSCou"} | None |  |
| q-576d5ea618 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-435bf3f617 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMLE_"} | None |  |
| q-55ab6da39a | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None |  |
| q-d6a017f6a6 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b0zggh"} | None |  |
| q-e98c2bec5b | triage T1606 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2I"} | None |  |
| q-df6f3714e0 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-34f43196cb | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-2cbd2808c7 | triage T1621 step 1 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F58 |
| q-2b5069bf97 | triage T1621 step 1 | aggregate | {"dataset": "windows.other", "field": "win.ServiceName", "query": "event.code:7045", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 5 |  |
| q-e85e0e3639 | triage T1621 step 1 | search | {"dataset": "windows.powershell", "query": "event.code:4104", "time_from": null, "time_to": null, "fields": ["powershell.script_block_text", "host.name", "user.name"], "size": 20, "sort": "asc"} | 414 |  |
| q-8f0835b40a | triage T1621 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*mfa*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*authenticator*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*2fa*\" OR T… | 0 |  |
| q-1d790cfe99 | triage T1621 step 2 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4624 OR event.code:4625 OR event.code:4648 OR event.code:4776", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 313 |  |
| q-b02ef1689a | triage T1621 step 2 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-a12ca5f17c | triage T1621 step 3 | search | {"dataset": "windows.security", "query": "event.code:4648 OR event.code:4776", "time_from": null, "time_to": null, "fields": ["win.TargetUserName", "win.SubjectUserName", "win.TargetServerName", "host.name", "win.LogonProcessName", "win.IpAddress"], "size": 20… | 16 | F58 |
| q-a610db8e5c | triage T1621 step 3 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 297 |  |
| q-8ecfd03211 | triage T1621 step 4 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-6682f6479f | triage T1621 step 4 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.ImagePath, message, _id, _index"} | 5 |  |
| q-f6bed1282e | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-6c8d2e952d | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2I"} | None |  |
| q-5fa2db7621 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-376593e547 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-bbdd2e3a69 | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None | F59 |
| q-1f6d7622f7 | triage T1649 step 1 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*PrivateKey* OR powershell.script_block_text:*Export-Pfx* OR powershell.script_block_text:*cert:\\\\* OR powershell.script_block_text:*Thumbprint*)", "time_from": nul… | ERROR |  |
| q-5591c2b892 | triage T1649 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*.pfx OR file.path:*readme.ps1 OR file.path:*Downloads*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 314 |  |
| q-e65db3d023 | triage T1649 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND TO_LOWER(powershell.script_block_text) LIKE \"*export-pfxcertificate*\" \| KEEP @timestamp, host.name, user.name, _id, _index, powershell.script_block_text"} | ERROR |  |
| q-fc5f3fd1ff | triage T1649 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*.pfx", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 1 | F59 |
| q-f5ea863abc | triage T1649 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND TO_LOWER(powershell.script_block_text) LIKE \"*export-pfxcertificate*\" \| KEEP @timestamp, host.name, user.name, _id, _index, powershell.script_block_text… | 1 |  |
| q-f79e475771 | triage T1649 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*readme.ps1 OR process.command_line:*Get-PrivateKeys OR process.command_line:*Export-Pfx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name… | 0 |  |
| q-42f06c14ab | triage T1649 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*SystemCertificates*MY*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proc… | 3 | F59 |
| q-38e5cd826b | triage T1649 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.pid:3876", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 2 | F59 |
| q-cee436308e | triage T1649 step 5 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 2 | F60 |
| q-811bfb8fee | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-5f12393f36 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-edffd3674c | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-eabaa4a5d7 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-cb14c513e1 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-3312279a4c | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lED5"} | None |  |
| q-cc504ba71a | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SKyaCV"} | None |  |
| q-0beaa147df | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRioY"} | None |  |
| q-25c448d18b | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRioY"} | None |  |
| q-93ef42e689 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRioY"} | None |  |
| q-a2e42b3f4d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-cf00faeb18 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-9bbad3141a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-afc35bcc52 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-7acb65e139 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-ca88c2c0ed | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-02ce1fe30a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-fb12cf0571 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Tx"} | None |  |
| q-9789687b46 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-383c77f9aa | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_RQ"} | None |  |
| q-8352ccb1ec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUmZF"} | None |  |
| q-788b97306d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-0e2caf0b10 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-ef7ca1dd31 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-ff9d86da6c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-e3ffb79fc6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-5fa9602969 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-92481149b2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YWMXHe"} | None |  |
| q-122e793dc4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YJECPu"} | None |  |
| q-5c5e91ce93 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqWk4"} | None |  |
| q-65e59794b9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqK7jn"} | None |  |
| q-c3595cd06b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74ed"} | None |  |
| q-57be10be3d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdW"} | None |  |
| q-c9a6dadb74 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdY"} | None |  |
| q-50011cf374 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqK7jn"} | None |  |
| q-8b77e02d41 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqWk4"} | None |  |
| q-98b7320841 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDSP-"} | None |  |
| q-d770bd93b8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTv"} | None |  |
| q-2226f320bc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22PTB"} | None |  |
| q-0e2ec7e102 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTv"} | None |  |
| q-1160d1d98b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-187057ceb3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-ca5dc86a0b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-65a46bc69c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-407c3dcf87 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aOf"} | None |  |
| q-22e345df53 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-c59c04c250 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-1102668b28 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-07eac4ee34 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-5eee6368ad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqK7jn"} | None |  |
| q-60d846d9e9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NZ30AL"} | None |  |
| q-e5e49ea5ed | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WoRbhf"} | None |  |
| q-2bb65f7d87 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-da4c5f9a97 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-67fc8d5965 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-135954bbd3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-34bbea517a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-7568bef33f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-b170d8eeb8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-12fe46a3da | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-33f304f1a4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-daaa5e49d7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-13857013c3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-5f517e0f88 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-ab5497798c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-eea16ccf86 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-5c6e1ecd53 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-8118c8ef97 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NMoBQe"} | None |  |
| q-3b931cda1d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NDgh5J"} | None |  |
| q-322ad47454 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None |  |
| q-2e8ff9f828 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-b74668efc3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-f0353fef8f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHQbW"} | None |  |
| q-c6bb25e343 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-32d32be2c6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqmrA"} | None |  |
| q-924d34fb0c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqmrA"} | None |  |
| q-4d383810d2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmIP4"} | None |  |
| q-98cebc684a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmIP4"} | None |  |
| q-c736be73ce | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtY0"} | None |  |
| q-42c3749838 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx3F"} | None |  |
| q-0ae7fa9984 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx3F"} | None |  |
| q-54814ad163 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aOf"} | None |  |
| q-5b72f790d4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aMP"} | None |  |
| q-bbc06fa97e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-ed1aa20b8c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-5eef3ea27c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-df06957ad6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74ey"} | None |  |
| q-fb7d004677 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74ey"} | None |  |
| q-06041bcf02 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQxZ"} | None |  |
| q-a1fc5abf80 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1g"} | None |  |
| q-a44aa0bf3c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsPCud"} | None |  |
| q-d34e92b6b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsPCud"} | None |  |
| q-a5e3fff1e2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-f522df3412 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-03fda4ed00 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MrOfHr"} | None |  |
| q-3e38d42c7f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21gGA"} | None |  |
| q-04014983c7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-f5d32b11ac | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-27c795d934 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-f8f4e27d1e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-e6d4d76a75 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-b2cf6823d8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-633ec029fe | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-d6ba35aa73 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-6c176127e7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-0ab2b45acf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUml9"} | None |  |
| q-ed6012d054 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUEbK"} | None |  |
| q-01669cce96 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-302ee47439 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-15e767bcb5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-0bd68c5d78 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqLbie"} | None |  |
| q-fbc85dcbce | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ida"} | None |  |
| q-9d6f56388c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-96ea67536d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-892e74974d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-dee3075d2e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-aa2a795b09 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-1df4596877 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-0171c48904 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Tx"} | None |  |
| q-242ab32e9a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Qp"} | None |  |
| q-7a616d8f65 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-df1df4dc6c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-bd6b0bc393 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-08bfb02ac1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-ed4e10a236 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-f83ebdad4e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-9bfddaf595 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-4643ce73c9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YGDFf9"} | None |  |
| q-65e56becb9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WgHZ_S"} | None |  |
| q-e9ecb5b0da | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SFrjYs"} | None |  |
| q-d8285df3f3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-df124bc649 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-87c3a57d31 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R5ewC0"} | None |  |
| q-cb0866e531 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SO16KB"} | None |  |
| q-825631b36b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXZO"} | None |  |
| q-4d953a19ba | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yph4sr"} | None |  |
| q-8e2e74dfdd | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-46bcd414d9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WiJUTX"} | None |  |
| q-3581f53949 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-61edeebeee | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtY1"} | None |  |
| q-ed08ddb8bf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SErGop"} | None |  |
| q-d86f163316 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1N"} | None |  |
| q-82d741bfc7 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2s"} | None |  |
| q-a82a9a8303 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b43SyN"} | None |  |
| q-7569328e64 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-4f068f5336 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-f7532978dc | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeV"} | None |  |
| q-f92ecfe716 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-8b8073c9d9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YtnqI_"} | None |  |
| q-e39eb2b6f2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-505c8bfdd6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-462b713362 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-38bb0b7e64 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-bd4cbeee34 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-85479e8f62 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YtnqI_"} | None |  |
| q-d84aa88cde | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-c087cef1ab | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-fde9c661d2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-9a151bc651 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Idf"} | None |  |
| q-50070283c7 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeV"} | None |  |
| q-56e4ce74f9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeV"} | None |  |
| q-a8be3bff10 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMLE_"} | None |  |
| q-8e276fce39 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-e0305a5705 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-5c3318d6f4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSCou"} | None |  |
| q-6871ae738c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-0c073f8a0d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMLE_"} | None |  |
| q-68178b6448 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None |  |
| q-44be6fd729 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b0zggh"} | None |  |
| q-e8f831d368 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2I"} | None |  |
| q-6735a65d7f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-06bec9f48e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-b365822add | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-5d11e92924 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2I"} | None |  |
| q-aeb40cde13 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-c4e61831d9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-69ccd0d232 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-93c6c52999 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-1c9403edb2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-f9d1aeae06 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-e8b7104d20 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-5d301face6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lED5"} | None |  |
| q-451b2b47c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SKyaCV"} | None |  |
| q-717e70d008 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRioY"} | None |  |
| q-a6fc661458 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRioY"} | None |  |
| q-54ddf6aa47 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRioY"} | None |  |
| q-608f3fdb35 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29.430000+00:00", "time_to": "2020-05-02T03:30:05.142000+00:00", "size": 100, "sub_field": "process.pare… | 61 |  |
| q-5539a8e45c | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29.430000+00:00", "time_to": "2020-05-02T03:30:05.142000+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-c303bc64ce | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29.430000+00:00", "time_to": "2020-05-02T03:30:05.142000+00:00", "size": 100, "sub_field": "process… | 63 |  |
| q-24d91fb172 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29.430000+00:00", "time_to": "2020-05-02T03:30:05.142000+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-7680402683 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:46:30+00:00", "time_to": "2020-05-02T03:16:30+00:00", "size": 100, "sub_field": "process.parent.executable… | 16 |  |
| q-327db95b68 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:46:30+00:00", "time_to": "2020-05-02T03:16:30+00:00", "size": 100, "sub_field": "process.executable"} | 58 |  |
| q-36b1525878 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:46:30+00:00", "time_to": "2020-05-02T03:16:30+00:00", "size": 100, "sub_field": "process.parent.execu… | 16 |  |
| q-7681690513 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:46:30+00:00", "time_to": "2020-05-02T03:16:30+00:00", "size": 100, "sub_field": null} | 1210 |  |
| q-27353836fd | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:41:17+00:00", "time_to": "2020-05-02T03:36:28.949000+00:00", "size": 100, "sub_field": "process.parent.ex… | 359 |  |
| q-3f06f239ec | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:41:17+00:00", "time_to": "2020-05-02T03:36:28.949000+00:00", "size": 100, "sub_field": "process.executable"} | 1276 |  |
| q-c1748a382f | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:41:17+00:00", "time_to": "2020-05-02T03:36:28.949000+00:00", "size": 100, "sub_field": "process.pare… | 370 |  |
| q-ab66e6e408 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:41:17+00:00", "time_to": "2020-05-02T03:36:28.949000+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-cd357fb5f5 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*\\\\temp\\\\*\" OR TO_LOWER(file.path) LIKE \"*\\\\programdata\\\\*\" OR TO_LOWER(file.path) LIKE \"*\\\\users\\\\public\\\\*\" OR T… | ERROR |  |
| q-5da6b674fc | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*\\\\temp\\\\*\" OR TO_LOWER(process.executable) LIKE \"*\\\\programdata\\\\*\" OR TO_LOWER(process.executable) LIKE \"*\\\\u… | ERROR |  |
| q-cdfac7c062 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*temp*\" OR TO_LOWER(file.path) LIKE \"*programdata*\" OR TO_LOWER(file.path) LIKE \"*public*\" OR TO_LOWER(file.path) LIKE \"*.pfx\"… | 200 |  |
| q-fdbc7cddfd | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*temp*\" OR TO_LOWER(process.executable) LIKE \"*programdata*\" OR TO_LOWER(process.executable) LIKE \"*public*\" OR TO_LOWER… | 10 | F62 |
| q-13d49a8744 | pivot step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, user.name, powershell.file.script_block_text, _id, _index \| SORT @timestamp ASC \| LI… | ERROR |  |
| q-2bb038b8b5 | pivot step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (TO_LOWER(process.executable) LIKE \"*python*\" OR TO_LOWER(process.executable) LIKE \"*rar*\" OR TO_LOWER(process.execu… | 7 | F62, F63 |
| q-e55a517706 | pivot step 4 | get_fields | {"dataset": "windows.powershell", "prefix": "powershell"} | None |  |
| q-85605392a2 | pivot step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND (TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*.zip\" OR TO_LOWER(file.path) LIKE \"*.rar\" OR TO… | 29 |  |
| q-b6b6cf3e58 | pivot step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _id, _index \| SORT @timestamp ASC \| LIMIT 2… | 11 |  |
| q-7334a60f96 | pivot step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None | F64 |
| q-39b497b67d | pivot step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3Hhd"} | None | F65 |
| q-ceb9843d0f | pivot step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxhdc"} | None | F61 |
| q-b48a4ebfb5 | pivot step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (TO_LOWER(process.executable) LIKE \"*accesschk*\" OR TO_LOWER(process.executable) LIKE \"*pspasswd*\" OR TO_LOWER(pro… | 1 | F64 |
| q-cdc169c661 | pivot step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-d069c05ce3 | pivot step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"nashua.dmevals.local\" AND (TO_LOWER(file.path) LIKE \"*working.zip*\" OR TO_LOWER(file.path) LIKE \"*rar*\" OR TO_LOWER(file.path) LIKE \"*python… | 12 | F61, F63 |
| q-1207da1f52 | pivot step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND host.name == \"utica.dmevals.local\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, _id, _index \| SORT @timestamp ASC \… | 9 |  |
| q-fb2365732d | pivot step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(object.name) LIKE \"*sam*\" OR TO_LOWER(object.name) LIKE \"*security*\" OR TO_LOWER(object.name) LIKE \"*ntds*\" OR TO_LOWER(object.name) LIKE \"*… | ERROR |  |
| q-35ade13adf | pivot step 8 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*passw*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*cred… | 6 |  |
| q-fdadfed47c | pivot step 9 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.event_data.ObjectName) LIKE \"*sam*\" OR TO_LOWER(win.event_data.ObjectName) LIKE \"*ntds*\" OR TO_LOWER(win.event_data.ObjectName) LIKE \"*pas… | ERROR |  |
| q-886a338cc4 | pivot step 9 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.event_data.TargetUserName, win.event_data.TargetServerName, process.execu… | ERROR |  |
| q-db87fdd9a6 | pivot step 10 | get_fields | {"dataset": "windows.security", "prefix": "win"} | None |  |
| q-2e0987ccf5 | pivot step 10 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, user.name, process.executable, _id, _index \| SORT @timestamp ASC \| LIMIT 30"} | 4 |  |
| q-cc3e732722 | pivot step 11 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-533e6e8c6a | pivot step 11 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND TO_LOWER(process.command_line) LIKE \"*passwordsdb*\" \| KEEP @timestamp, host.name, user.name, process.executable, pr… | 0 |  |
| q-3273f05339 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxhdc"} | None |  |
| q-af4bd8e90b | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RhB5tj"} | None |  |
| q-87fe528002 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RhBpvd"} | None |  |
| q-39e93d32e4 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nd9MRE"} | None |  |
| q-b99bcd5526 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emY"} | None |  |
| q-48ad5b0e1a | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsKx"} | None |  |
| q-0a93a694fc | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDiN-"} | None |  |
| q-1eee8f3930 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDCOv"} | None |  |
| q-176cca943b | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-9c10609eea | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-4b3fde2300 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3Hhd"} | None |  |
| q-a6f395ab70 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-764de147a0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-fee78f4bba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-a65aaa2182 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-b2d3d91a67 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-7e742f3fb2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-e833b011e2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-a24e14c4c9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Tx"} | None |  |
| q-4129f1d517 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-354390d3d1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_RQ"} | None |  |
| q-38a854fc23 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUmZF"} | None |  |
| q-247aa41fc7 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-a02cc16157 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-e90180970e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-f4f225f808 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-ff07276813 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-de46a5322c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-ed349b3e46 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YWMXHe"} | None |  |
| q-0f85920ef1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YJECPu"} | None |  |
| q-1ce747838c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqWk4"} | None |  |
| q-9087d77974 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqK7jn"} | None |  |
| q-3ed44912f2 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74ed"} | None |  |
| q-0e5670cd95 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdW"} | None |  |
| q-a2d45c4678 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdY"} | None |  |
| q-6866ac3399 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqK7jn"} | None |  |
| q-0758e853a2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqWk4"} | None |  |
| q-35e47b425c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDSP-"} | None |  |
| q-4301befbc1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTv"} | None |  |
| q-209fce6aee | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22PTB"} | None |  |
| q-da7acfba6b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTv"} | None |  |
| q-16660b13d5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-07ee4f9f21 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-62677dbdb6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-266aeea653 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-6e8bd57e06 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aOf"} | None |  |
| q-5a901b9dc9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-fdf54676fb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-f9596391d5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-b2fd9d4497 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-eea093b8de | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqK7jn"} | None |  |
| q-10d6ea37e0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NZ30AL"} | None |  |
| q-190f494f89 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WoRbhf"} | None |  |
| q-a6d8854a58 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-0bcefabcd6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-8d324b05b0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-9211ee1693 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-c25eb7540c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-fbcabf3507 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-7b5f95195f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-b4d2dcdc93 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-c5fcc0070e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-3aa4d8bef0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-a1d7d6c4f8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-0ab44362a0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-0226d04d70 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-2bc0ea4fdd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-73a1b08b0e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-f54fa9df67 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NMoBQe"} | None |  |
| q-0064a61bb1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NDgh5J"} | None |  |
| q-f70bf54a74 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None |  |
| q-efccb5712c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-03eeca33ee | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-dbadb8190b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHQbW"} | None |  |
| q-a5a4141ef6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-4e1b1cc4e8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqmrA"} | None |  |
| q-42380cb678 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqmrA"} | None |  |
| q-e51169436d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmIP4"} | None |  |
| q-65f61dc90c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmIP4"} | None |  |
| q-203c3ef408 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtY0"} | None |  |
| q-11d4048ca7 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx3F"} | None |  |
| q-0b61e57f4b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx3F"} | None |  |
| q-4d8201b38e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aOf"} | None |  |
| q-ae89dcaf51 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aMP"} | None |  |
| q-d506fde22b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-c8183748b3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-a0b24bf994 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-6f5325f849 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74ey"} | None |  |
| q-de8c766874 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74ey"} | None |  |
| q-d0459a0567 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQxZ"} | None |  |
| q-57b461c573 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1g"} | None |  |
| q-373402c357 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsPCud"} | None |  |
| q-6665c70555 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsPCud"} | None |  |
| q-cfe26611bb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-5f546044b2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-ca1161a008 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MrOfHr"} | None |  |
| q-c7db72e6b2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21gGA"} | None |  |
| q-130d367e5e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-7fec35a114 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-2bdf6052f5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-547761c056 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-4c2dd9aa89 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-8c74e72acb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-48408ee23b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-2cf7bfc256 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-3485bec2a1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-63efb2080c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUml9"} | None |  |
| q-b2a37644b6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUEbK"} | None |  |
| q-ca68538ede | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-fae7f1d8f0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-9743caea11 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-36ffcbccb4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqLbie"} | None |  |
| q-49ed0763b7 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ida"} | None |  |
| q-7a08908877 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-bb97083b20 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-db857ae0e4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-505d06afca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-2c12a63a83 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-1f8116d23c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-0cfa426253 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Tx"} | None |  |
| q-aac3807439 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Qp"} | None |  |
| q-094cf656d3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-09a0603121 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-469a95481d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-30db13a324 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-0b86f316d3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-1347cf9578 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-136d515098 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-528924f4f0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YGDFf9"} | None |  |
| q-8e8d0952f9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WgHZ_S"} | None |  |
| q-84cc5a98b0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SFrjYs"} | None |  |
| q-49093d3403 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-1e4683ea2a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-b873d0b6e7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R5ewC0"} | None |  |
| q-467c842512 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SO16KB"} | None |  |
| q-f7ad500542 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXZO"} | None |  |
| q-f32f308298 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yph4sr"} | None |  |
| q-d7aeb55a80 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-4029e94f03 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WiJUTX"} | None |  |
| q-fbd821f65b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-a8f2409451 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtY1"} | None |  |
| q-f7a5a89e82 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SErGop"} | None |  |
| q-e1c695a92a | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1N"} | None |  |
| q-55b118506a | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2s"} | None |  |
| q-f83b30507d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b43SyN"} | None |  |
| q-85beab4537 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-71f763be7e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-5300e61cbb | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeV"} | None |  |
| q-5a8392bf86 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-8bf386d956 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YtnqI_"} | None |  |
| q-c927fcfac2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-1087baccb2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-3891dca6c5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-82da1a4840 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-0a2c9dbd75 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-63e84b4df7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YtnqI_"} | None |  |
| q-ae2da8df1b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-093f8c4f66 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-ffc7412cf1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-d0690c123e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Idf"} | None |  |
| q-9bef5eb1e9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeV"} | None |  |
| q-266c67c924 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeV"} | None |  |
| q-36783865ff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMLE_"} | None |  |
| q-be7f391ef9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-c769016267 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-0d86cab66e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSCou"} | None |  |
| q-f65f901a70 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-287d948ea2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMLE_"} | None |  |
| q-f13af8402c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None |  |
| q-5b50c11dc6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b0zggh"} | None |  |
| q-08c9eb1e57 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2I"} | None |  |
| q-8f9a1eb49a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-4c2573a6af | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-d8bf9c5827 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-e2869bffae | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2I"} | None |  |
| q-6c6b2969bc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-0f36ba49ea | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-16af9c6157 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-44382e69e3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-46628c7e59 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-960eece131 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-3a8e1de3a0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-69d1890830 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lED5"} | None |  |
| q-9de1fdb8ef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SKyaCV"} | None |  |
| q-2649f5f4e5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRioY"} | None |  |
| q-3eb12275ed | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRioY"} | None |  |
| q-28773e8d63 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRioY"} | None |  |
| q-a7da90bcb7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxhdc"} | None |  |
| q-44045b2985 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RhB5tj"} | None |  |
| q-b4dda0a1d9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RhBpvd"} | None |  |
| q-96fc2f37c4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nd9MRE"} | None |  |
| q-0dd07b363a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emY"} | None |  |
| q-f63bbaef72 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsKx"} | None |  |
| q-20c64c64d5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDiN-"} | None |  |
| q-98cae9282b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDCOv"} | None |  |
| q-2e6e3c9fd2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-6c5d8bb0c5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-a8707202cb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3Hhd"} | None |  |

## Verification

Evidence items cited: 187; confirmed against the stored events: 187; rejected: 0. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 4 item(s) in 3 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
