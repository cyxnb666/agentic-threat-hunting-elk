# Threat hunt report — 20261020-204158-converged-fixab-std3

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 6 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003.001 (F01, F08, F19, F28, F33, F44, F49), I02 T1003.004 (F03, F59, F61), I03 T1056.002 (F09), I06 T1552.001 (F25, F57), I07 T1552.002 (F26, F58), I08 T1552.004 (F24, F52, F56)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-20T12:41:58+00:00 / 2026-10-20T12:52:18+00:00 (620.4 s) |
| LLM calls / tokens | 153 / {'prompt': 4628582, 'completion': 137359} |
| MCP tool calls | 1297 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003.001 | yes | malicious/high | F01, F08, F19, F28, F33, F44, F49 | Hidden PowerShell (PID 2976) opens LSASS and winlogon with full-access masks on SCRANTON |
| I02 | T1003.004 | yes | malicious/high | F03, F59, F61 | Masqueraded .scr loader in C:\ProgramData\victim reads LSA registry key and drops steganographic carrier on SCRANTON |
| I03 | T1056.002 | yes | malicious/medium | F09 | PowerShell screen-capture loop run by pbeesly on SCRANTON |
| I04 | T1212 | yes | suspicious/medium | F20 | wsmprovhost.exe (PowerShell Remoting session) opens LSASS with 0x1F3FFF on NASHUA |
| I05 | T1539 | yes | suspicious/medium | F22 | PowerShell opens Microsoft Edge processes with full access on SCRANTON |
| I06 | T1552.001 | yes | malicious/high | F25, F57 | accesschk.exe writes passwordsDB and harvested credentials reused via PsExec -p to NASHUA |
| I07 | T1552.002 | yes | malicious/high | F26, F58 | Registry value HKLM\SOFTWARE\Javasoft 'value Supplement' used as hidden payload store and re-executed via Invoke-Expression |
| I08 | T1552.004 | yes | malicious/high | F24, F52, F56 | Get-PrivateKeys exports all LocalMachine certificates to password-protected .pfx files on SCRANTON |
| I09 | T1557.002 | yes | suspicious/medium | F40, F43 | Shared MAC 12:34:56:78:9a:bc answering for multiple IPs in Zeek logs |
| I10 | T1649 | yes | suspicious/low | F53 | Root certificate store 'Blob' value modified on NASHUA |
| I11 | out-of-scope:T1027 | no | malicious/high | F60 | Hidden PowerShell compiles attacker C# with csc.exe into DLLs on SCRANTON |
| I12 | out-of-scope:T1041 | no | malicious/high | F55 | PyInstaller python.exe pushed via PsExec to NASHUA beacons to 192.168.0.4:8443 and archives credential-named files |

## Findings

### F01 · malicious / high · T1003.001 · pbeesly's PowerShell opened LSASS with full access (0x1fffff / 0x1f3fff) on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02 at 03:05:16 UTC, PowerShell.exe (PID 2976, user pbeesly, DMEVALS domain) on scranton.dmevals.local opened a handle to lsass.exe (PID 736) with GrantedAccess 0x1F3FFF and then 0x1FFFFF — PROCESS_ALL_ACCESS-class masks used for memory dumping, with an UNKNOWN call trace (unbacked code). The same access is recorded in the Security channel as 4656 on \Device\HarddiskVolume2\Windows\System32\lsass.exe by powershell.exe as pbeesly with AccessMask 0x1fffff and 0x1f3fff. This occurred inside a hands-on-keyboard intrusion session on scranton (readme.ps1 / psversion.ps1 loaded from C:\Program Files\SysinternalsSuite, Invoke-Discovery, Invoke-Persistence, Get-PrivateKeys, Invoke-ScreenCapture, Get-Clipboard, Keystroke-Check, sdelete64 wiping of a malicious .scr). No dump file was observed on disk, but the LSASS read handle with full access by a non-system PowerShell is consistent with in-memory credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-5baa71608e | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-5baa71608e | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-5baa71608e | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D252982) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-bb31993b5d | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq7mb8 | q-62fe69e885 | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72YQ | q-62fe69e885 | ok |
| 7 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72YQ | q-62fe69e885 | ok |

### F09 · malicious / medium · T1056.002 · PowerShell screen-capture loop (System.Windows.Forms / CopyFromScreen) run by pbeesly on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local at 03:05:53Z and 03:05:59Z, user pbeesly executed PowerShell script blocks defining 'Invoke-ScreenCapture', which starts a background job that every 300 seconds grabs the full virtual screen via [System.Windows.Forms.SystemInformation]::VirtualScreen and System.Drawing CopyFromScreen and saves it as a .bmp in the user's Downloads folder (script path C:\Program Files\SysinternalsSuite\psversion.ps1). This is GUI input/screen capture of the interactive session, part of the same pbeesly toolset that also ran Invoke-Exfil (7-Zip password-protected archive of Downloads) and the remote Get-Process/UserName enumeration. No fake credential prompt (Get-Credential/PromptForCredential) was observed; the only consent.exe hits are the normal UAC consent process.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/ {     Start-Job -Name "Screenshot" -ScriptBlock {       … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSyuh | q-aa81eec8c0 | ok |
| 2 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSyuh | q-aa81eec8c0 | ok |
| 3 | 2020-05-02 03:05:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText |           Write-Host "`nJobPID`n------`n$PID"         while($true){             $RandomFileName = [System.IO.Path]::GetRandomFileName();              $Filepath=… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSitC | q-b219dd4ca7 | ok |

### F08 · malicious / high · T1056.004 · PowerShell and WinRM host processes opened LSASS with full access (0x1f3fff) on SCRANTON and NASHUA

Evidence status: **verified**

On 2020-05-02 at 03:05:16Z on scranton.dmevals.local, PowerShell.exe (PID 2976, running as SYSTEM) opened lsass.exe (PID 736) and winlogon.exe with GrantedAccess 0x1f3fff and 0x1fffff; the call trace ends in an UNKNOWN module (UNKNOWN(000001996D252982)), i.e. code not backed by a known on-disk DLL — consistent with in-memory credential-API hooking/reading of LSASS. At 03:09:29Z on nashua.dmevals.local the same pattern appears from wsmprovhost.exe (PID 7720, the WinRM host for the remote PowerShell session) against lsass.exe (PID 728) and winlogon.exe with 0x1f3fff, call trace through System.ni.dll / Microsoft.PowerShell.Commands.Management.ni.dll. This is the direct follow-on to the attacker's remote PowerShell: at 03:09:23Z user pbeesly on SCRANTON ran 'Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName ... }', which executed on NASHUA at 03:09:28Z in PID 7720 — the same PID that then opened LSASS. Security 4663 corroborates a handle to \Device\HarddiskVolume2\Windows\System32\lsass.exe from powershell.exe as pbeesly on SCRANTON at 03:05:16Z. The remaining LSASS/winlogon accesses (0x1000/0x1400/0x1478 from smss/wininit/lsasrv/themeservice, CollectGuestLogs.exe and MsMpEng.exe with 0x10) are normal system/AV behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-b9c29fae36 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-48368e996d | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D252982) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-48368e996d | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-9f90f7e065 | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-9f90f7e065 | ok |
| 6 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRbzS | q-def9c88c59 | ok |
| 7 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | process.pid | 7720 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRapX | q-a68f3173c0 | ok |
| 8 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72Yf | q-93e0aedfab | ok |

### F19 · malicious / high · T1212 · Offensive PowerShell toolkit on SCRANTON (pbeesly) opens LSASS with full access (0x1FFFFF) and 0x1F3FFF after steganographic loader execution

Evidence status: **verified**

On scranton.dmevals.local, user DMEVALS\pbeesly (logon 0x372e81, high integrity, session 2) ran a hidden, execution-policy-bypass PowerShell one-liner spawned by control.exe /name Microsoft.BackupAndRestoreCenter that decoded a payload from a bitmap (C:\Users\pbeesly\Downloads\monkey.png) and IEX'd it (PID 2976, 2020-05-02T02:58:44Z). That same PID 2976 then opened lsass.exe with GrantedAccess 0x1f3fff at 03:05:16.623Z and 0x1fffff at 03:05:16.654Z — full-process access masks consistent with reading LSASS memory for credential extraction. In the same session pbeesly loaded offensive PowerShell functions from C:\Program Files\SysinternalsSuite\psversion.ps1 / readme.ps1: Get-AttributesMask (token/group attribute parsing), Keystroke-Check (AV product enumeration), Invoke-Exfil (7-Zip staging to C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z and WebDAV upload to \\192.168.0.4\webdav with hardcoded creds), and remote Invoke-Command to NASHUA. pbeesly also installed a LocalSystem service 'javamtsup' pointing at C:\Windows\System32\javamtsup.exe (4697, 03:04:15Z) after dropping javamtsup.exe from the SysinternalsSuite archive, and used PsExec64 with plaintext credentials (dmevals\pbeesly / Fl0nk3rt0n!T0by) to run C:\Windows\Temp\python.exe on NASHUA (PSEXESVC installed 4x). Sdelete64 was used to wipe staging artifacts. The LSASS access is not attributable to a signed security product or OS component; it comes from an interactive attacker-controlled PowerShell session, so it is assessed as exploitation/abuse for credential access rather than benign behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-ff5a8ec69d | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-ff5a8ec69d | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-ff5a8ec69d | ok |
| 4 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-fd2da63a03 | ok |
| 5 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-fd2da63a03 | ok |
| 6 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-AttributesMask($AttributesMask) {     &lt;#         SE_GROUP_MANDATORY          0x00000001  The group is mandatory.         SE_GROUP_ENABLED_BY_DEF… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvTCvl | q-05544a5e31 | ok |
| 7 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Keystroke-Check {     Get-Process \| Where-Object { $_.ProcessName -Eq "avp" -or $_.ProcessName -Eq "acs" -or $_.ProcessName -Eq "outpost" -or $_.Proce… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSitD | q-05544a5e31 | ok |
| 8 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-05544a5e31 | ok |
| 9 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.security | win.ServiceFileName | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72Zr | q-87003c866a | ok |
| 10 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-afdc9edf1b | ok |
| 11 | 2020-05-02 03:00:32.751Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\SysinternalsSuite\javamtsup.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7habqTS | q-cb7f4cd980 | ok |

### F59 · malicious / high · T1552 · Masqueraded .scr loader in C:\ProgramData\victim drops the steganographic monkey.png carrier on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local at 02:55:56, pbeesly launched C:\ProgramData\victim\â€®cod.3aka3.scr (a masqueraded .scr with a leading RTL character) from explorer.exe with the /S switch. It wrote C:\Users\pbeesly\Downloads\monkey.png at 02:57:00, which the hidden PowerShell then decoded pixel-by-pixel into an IEX payload. This is the loader that precedes the credential-access tooling; it is reported here as a candidate assessment because it is the entry point of the chain.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy0krT | q-50d0ed37a2 | ok |
| 2 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\explorer.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy0krT | q-50d0ed37a2 | ok |
| 3 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\monkey.png | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hwyqdH | q-15c92b8b29 | ok |

### F60 · malicious / high · T1552 · Hidden PowerShell compiles attacker C# with csc.exe into qkbkqqbs.dll and 0piklvia.dll on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local, pbeesly's hidden PowerShell (-noni -noexit -ep bypass -window hidden) decoded the steganographic monkey.png and invoked IEX, which caused csc.exe to compile attacker C# at 02:58:45 (qkbkqqbs.dll) and again at 03:08:03 (0piklvia.dll) into per-run temp folders. These in-memory assemblies are the tooling that subsequently opened LSASS and Edge with full access, so the compiler activity is part of the credential-theft chain rather than legitimate .NET use.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.cmdline" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htvuyY | q-06e195d022 | ok |
| 2 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htvuyY | q-06e195d022 | ok |
| 3 | 2020-05-02 02:58:45.292Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.dll | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htvuyT | q-15c92b8b29 | ok |
| 4 | 2020-05-02 02:58:45.621Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.dll | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htvuxL | q-15c92b8b29 | ok |

### F25 · malicious / medium · T1552.001 · accesschk.exe writes a 'passwordsDB' file in SysinternalsSuite; harvested credentials reused via PsExec -p to NASHUA

Evidence status: **verified**

On scranton.dmevals.local, accesschk.exe (parent powershell.exe, user pbeesly) was launched at 2020-05-02T03:04:34Z and created C:\Program Files\SysinternalsSuite\passwordsDB at 03:04:35Z — a file name indicating collected credentials, written into the same SysinternalsSuite directory that hosted the attacker's readme.ps1/psversion.ps1 scripts. Minutes later (03:11:18–03:14:42Z) PsExec64.exe was run four times from the same directory with an explicit plaintext credential: \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe, and nashua.dmevals.local logged 4648 explicit-credential logons from C:\Windows\PSEXESVC.exe for pbeesly. The credential used for lateral movement is consistent with credentials gathered on the host rather than typed interactively.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hRQwNS | q-5eef112df2 | ok |
| 2 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\accesschk.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hRQwNS | q-5eef112df2 | ok |
| 3 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-6c606417d8 | ok |
| 4 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-fef1e7cf0c | ok |
| 5 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-fef1e7cf0c | ok |

### F55 · malicious / high · T1552.001 · PyInstaller-packed python.exe pushed via PsExec to NASHUA beacons to 192.168.0.4:8443 and archives pbeesly's credential-named files into a password-protected RAR

Evidence status: **verified**

On nashua.dmevals.local, C:\Windows\Temp\python.exe (a PyInstaller bundle that unpacks _MEI29522 with _socket.pyd/_ssl.pyd/_hashlib.pyd) was launched 4x by C:\Windows\PSEXESVC.exe as user pbeesly between 03:11:40 and 03:15:03, after SCRANTON ran PsExec64.exe against \\NASHUA with the harvested password. The binary opened 348 outbound connections to 192.168.0.4:8443 (the same IP the shared-MAC anomaly answers for) and spawned powershell.exe, which enumerated the user profile for *psw*, *pass*, *login*, *admin*, *sifr*, *sifer*, *vpn*, *.pst, *.ost and archive files and compressed them into C:\Users\pbeesly\AppData\Roaming\working.zip. Rar.exe then created a password-protected copy (C:\Users\pbeesly\Desktop\working.zip) and sdelete64.exe wiped Rar.exe and both zips. This is credential-file harvesting plus staging/exfil over the C2 channel, not covered by the LSASS anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82OhP | q-3edeca6d5c | ok |
| 2 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c5ylrT | q-d1fa1701a0 | ok |
| 3 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.port | 8443 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c5ylrT | q-d1fa1701a0 | ok |
| 4 | 2020-05-02 03:15:04.150Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Temp\_MEI29522\_socket.pyd | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c5y1od | q-df53748518 | ok |
| 5 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRC92 | q-337a6e4909 | ok |
| 6 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c4xY6Y | q-3edeca6d5c | ok |
| 7 | 2020-05-02 03:16:52.456Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cri_p- | q-3edeca6d5c | ok |

### F57 · malicious / high · T1552.001 · SCRANTON PowerShell uses PsExec64 with a plaintext password to run python.exe on NASHUA, and accesschk.exe is run from the SysinternalsSuite folder

Evidence status: **verified**

On scranton.dmevals.local, pbeesly's PowerShell launched C:\Program Files\SysinternalsSuite\PsExec64.exe four times (03:11:18, 03:12:25, 03:13:28, 03:14:42) with the cleartext credential '-u dmevals\pbeesly -p Fl0nk3rt0n!T0by' to start C:\Windows\Temp\python.exe on \\NASHUA, and ran accessChk.exe from the same folder at 03:04:34. The tooling was downloaded and unpacked from C:\Users\pbeesly\Downloads\SysinternalsSuite.zip at 02:59:42-03:00:27 and the archive was later shredded with sdelete64.exe. This is the credential-reuse/lateral-movement step that delivered the NASHUA harvester.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-f24858ad8b | ok |
| 2 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hRQwNZ | q-f24858ad8b | ok |
| 3 | 2020-05-02 02:59:42.544Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\SysinternalsSuite.zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hjk9tr | q-15c92b8b29 | ok |
| 4 | 2020-05-02 03:03:33.984Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\Users\pbeesly\Downloads\SysinternalsSuite.zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hTSlP6 | q-f24858ad8b | ok |

### F26 · malicious / high · T1552.002 · Registry value HKLM\SOFTWARE\Javasoft\'value Supplement' used as a hidden payload store and read back with Invoke-Expression

Evidence status: **verified**

On scranton.dmevals.local, powershell.exe (PID 3876, SYSTEM context per Sysmon UserID S-1-5-18) set registry value HKLM\SOFTWARE\Javasoft\value Supplement at 2020-05-02T03:04:23Z to a base64-encoded 'powershell.exe -nop -w hidden -e ...' command that decompresses a GZip stream and runs it via ScriptBlock::Create. At 23:21:28-04:00 the same user pbeesly executed Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression, retrieving and executing the stored payload from the registry. This is registry-based staging/retrieval of hidden content (not a credential store per se), so it is reported as suspicious registry abuse rather than confirmed credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:23.572Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Javasoft\value Supplement | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hSRzrP | q-b8affe1bcb | ok |
| 2 | 2020-05-02 03:04:23.572Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hSRzrP | q-b8affe1bcb | ok |
| 3 | 2020-05-02 03:21:28.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qzXFrk | q-f1d607ed89 | ok |

### F58 · malicious / medium · T1552.002 · hostui.exe launched with 'runas' from PowerShell re-reads the hidden HKLM\SOFTWARE\Javasoft 'value Supplement' payload via Invoke-Expression

Evidence status: **verified**

On scranton.dmevals.local at 03:21:19-03:21:27, pbeesly's cmd.exe ran C:\Windows\System32\hostui.bat, which started 'powershell.exe -c "Start-Process C:\Windows\System32\hostui.exe -verb runas"' (triggering consent.exe). hostui.exe then spawned 'powershell.exe -c "Get-ItemPropertyValue 'HKLM:\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression"', i.e. the registry-stored payload was re-read and executed from a new elevated context. This is a new execution of the registry credential/payload store rather than the previously anchored read.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\System32\hostui.exe"  | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YE3lVE | q-bfba95c5f7 | ok |
| 2 | 2020-05-02 03:21:27.859Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YJ9aYA | q-bfba95c5f7 | ok |
| 3 | 2020-05-02 03:21:19.014Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\cmd.exe /c ""C:\Windows\System32\hostui.bat" " | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YE3lWA | q-bfba95c5f7 | ok |
| 4 | 2020-05-02 03:21:26.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Start-Process C:\Windows\System32\hostui.exe -verb runas | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qzXFri | q-10df766361 | ok |

### F24 · malicious / high · T1552.004 · PowerShell Get-PrivateKeys exports every LocalMachine certificate to password-protected .pfx files in Downloads

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a script block (PowerShell 4104, ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b, Path C:\Program Files\SysinternalsSuite\readme.ps1) at 2020-05-01T23:04:56-04:00 defining Get-PrivateKeys, which enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate into $env:USERPROFILE\Downloads\<random>.pfx using the hardcoded password 'saribas'. Sysmon file-create confirms the resulting artifact C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx written by powershell.exe at 2020-05-02T03:04:57Z. A later script block Invoke-BeachCleanup (23:08:51) deletes Downloads\*.pfx, *.bmp, *.png and %APPDATA%\OfficeSupplies.7z, i.e. anti-forensic cleanup of the stolen key material. This is private-key harvesting, not normal administration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-de4b487302 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-de4b487302 | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-faccc0e9d5 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-faccc0e9d5 | ok |
| 5 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRC9i | q-5065f80df3 | ok |

### F56 · malicious / high · T1552.004 · Get-PrivateKeys on SCRANTON exports every LocalMachine certificate to password-protected .pfx files, then deletes them in a cleanup routine

Evidence status: **verified**

On scranton.dmevals.local at 03:04:56, pbeesly's PowerShell (script path C:\Program Files\SysinternalsSuite\readme.ps1) defined and invoked Get-PrivateKeys, which walks cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint into $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded password 'saribas'. At 03:08:51 a companion function Invoke-BeachCleanup removes Downloads\*.pfx, *.bmp, *.png and %APPDATA%\OfficeSupplies.7z, confirming the exported key material was staged and then wiped. This is a distinct private-key theft step beyond the LSASS/certificate-store anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-15527df82b | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-15527df82b | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvTSsN | q-10df766361 | ok |
| 4 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRC9i | q-10df766361 | ok |

### F28 · malicious / high · T1555 · PowerShell opens LSASS with full access (0x1FFFFF / 0x1F3FFF) on scranton and nashua under user pbeesly

Evidence status: **verified**

On 2020-05-02 at 03:05:16 UTC, PowerShell.exe (PID 2976) on scranton.dmevals.local opened C:\windows\system32\lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff — full-process access masks used for memory dumping, not the 0x1000/0x1400 masks seen from svchost/Azure telemetry. Windows Security 4656 corroborates the same handle request by C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe with SubjectUserName pbeesly (AccessMask 0x1fffff and 0x1f3fff). The same user's remote PowerShell host (wsmprovhost.exe, PID 7720) on nashua.dmevals.local opened lsass.exe with 0x1f3fff at 03:09:29 UTC (also 4656 with SubjectUserName pbeesly). This is part of a broader hands-on-keyboard intrusion by pbeesly on scranton (SysinternalsSuite dropped, readme.ps1/psversion.ps1 loaded, Invoke-Discovery, Invoke-Persistence, Invoke-Exfil, sdelete64 anti-forensics, accesschk.exe).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-a750a6ce72 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-a750a6ce72 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-a750a6ce72 | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq7mb8 | q-0e52c2be5d | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq7mb8 | q-0e52c2be5d | ok |
| 6 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-a750a6ce72 | ok |
| 7 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-a750a6ce72 | ok |
| 8 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7njy6Co | q-0e52c2be5d | ok |

### F33 · malicious / high · T1556 · PowerShell.exe opened LSASS and winlogon with full access (0x1FFFFF / 0x1F3FFF) on scranton during an interactive attacker PowerShell session

Evidence status: **verified**

On scranton.dmevals.local, at 2020-05-02T03:05:16.623Z-03:05:17.029Z, C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe (PID 2976, user pbeesly) obtained GrantedAccess 0x1f3fff and 0x1fffff on both C:\windows\system32\lsass.exe (PID 736) and C:\windows\system32\winlogon.exe. The CallTrace ends in UNKNOWN(000001996D28200D), i.e. code not backed by a loaded module, consistent with injected/reflective code. This is the only process in the whole dataset that requested full-access masks on the authentication processes; all other LSASS/winlogon access came from svchost.exe, smss.exe, csrss.exe, wininit.exe, LogonUI.exe and Azure agent binaries with benign masks (0x1000/0x1400). The same pbeesly PowerShell session on scranton had just run discovery, persistence and private-key theft functions (Invoke-Discovery, Invoke-Persistence, Get-PrivateKeys) and installed the service 'javamtsup' (C:\Windows\System32\javamtsup.exe, LocalSystem) at 03:04:15, so the LSASS/winlogon access is part of a hands-on intrusion, not administration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-87402cd70e | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-87402cd70e | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-87402cd70e | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\winlogon.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhF | q-c59425beee | ok |
| 5 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-c59425beee | ok |
| 6 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.security | win.ServiceFileName | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72Zr | q-491d1c8f6e | ok |

### F44 · malicious / high · T1558 · LSASS opened with full access by attacker-launched PowerShell on scranton (credential theft, not ticket theft)

Evidence status: **verified**

On scranton.dmevals.local a malicious chain ran as user pbeesly: C:\ProgramData\victim\â€®cod.3aka3.scr (spawned by explorer.exe at 02:55:56Z) launched cmd.exe and powershell.exe, then sdclt.exe -> control.exe (UAC bypass) spawned a hidden PowerShell (PID 2976, '-noni -noexit -ep bypass -window hidden') that decoded a payload from C:\Users\pbeesly\Downloads\monkey.png and IEX'd it. At 03:05:16Z that same PID 2976 opened lsass.exe (PID 736) with GrantedAccess 0x1F3FFF and 0x1FFFFF (full access, call trace ending in UNKNOWN module) — classic LSASS credential dumping. The PowerShell script blocks show shellcode injection (VirtualAlloc/CreateThread) and screen capture, not Kerberos ticket manipulation. No ticket-forging/roasting artefacts (no krbtgt/klist/mimikatz/Rubeus strings, no 4769 anomalies) were found, so the credential access observed is LSASS memory theft rather than T1558 ticket abuse.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-9a86794145 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-9a86794145 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-5e8c34a2de | ok |
| 4 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-5aaaeb368d | ok |
| 5 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-5aaaeb368d | ok |
| 6 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy0krT | q-e8908eb9d2 | ok |
| 7 | 2020-05-02 02:58:43.212Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\System32\control.exe"  /name Microsoft.BackupAndRestoreCenter | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwewi | q-e8908eb9d2 | ok |
| 8 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7q0Y_4v | q-0a00e86493 | ok |

### F52 · malicious / high · T1649 · Get-PrivateKeys PowerShell function exported all LocalMachine private-key certificates to .pfx files on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02 at 03:04:56 UTC (23:04:56 local) on scranton.dmevals.local, in the context of user pbeesly (SID S-1-5-21-1830255721-3727074217-2423397540-1107, PowerShell PID 3876), a script block named 'Get-PrivateKeys' was created and then invoked. The function enumerates every certificate under cert:\LocalMachine recursively, and for each certificate with a thumbprint calls Export-PfxCertificate into $env:USERPROFILE\Downloads\<random>.pfx protected by a hardcoded password ('saribas'), suppressing errors. One second later Sysmon recorded the resulting file creation C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx by powershell.exe (PID 3876). This is direct theft of authentication certificates/private keys from the host's machine certificate store. The script was staged as 'C:\Program Files\SysinternalsSuite\readme.ps1' (masquerading path), and at 03:08:51 the same user ran a second function 'Invoke-BeachCleanup' (from psversion.ps1) that deletes $env:USERPROFILE\Downloads\*.pfx, *.bmp, *.png and $env:APPDATA\OfficeSupplies.7z — anti-forensic cleanup of the stolen certificate bundles and other staged artifacts. Surrounding activity on the same host/user in the same window (hidden -ep bypass PowerShell decoding a bitmap payload from monkey.png, a HKLM:\SOFTWARE\Javasoft 'value Supplement' Invoke-Expression, and hostui.exe/hostui.bat runas) shows this is part of an active intrusion, not administration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-3759cf4fab | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-ec757a6807 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-ec757a6807 | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvTSsN | q-8e5a30d451 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-c414a94b16 | ok |
| 6 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-393a5afc9d | ok |
| 7 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRC9i | q-82efaedda7 | ok |
| 8 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-b1b1d7fe2a | ok |

### F03 · suspicious / medium · T1003.004 · Malicious C:\ProgramData\victim\cod.3aka3.scr read HKLM\SYSTEM\ControlSet001\Control\Lsa on scranton

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-01 22:55:56 local (02:55:56 UTC), the masquerading binary C:\ProgramData\victim\â€®cod.3aka3.scr — launched from explorer.exe by pbeesly at 02:55:56 UTC with command line '"C:\ProgramData\victim\â€®cod.3aka3.scr" /S' — was the first process recorded reading the LSA registry key \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa (AccessMask 0x1). The Lsa key holds LSA secrets (service account passwords, DPAPI machine keys). The binary was later wiped with sdelete64.exe from PowerShell (03:02:04 UTC), indicating anti-forensics. The read itself is a single query-value access and no secret export was observed, so this is suspicious rather than confirmed LSA-secret dumping.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rxFDLy | q-240248664a | ok |
| 2 | 2020-05-02 02:55:56.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rxFDLy | q-240248664a | ok |
| 3 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy0krT | q-9ca27e8bdf | ok |
| 4 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hWVSlm | q-9ca27e8bdf | ok |

### F20 · suspicious / medium · T1212 · wsmprovhost.exe (PowerShell Remoting session) opens LSASS with 0x1F3FFF on NASHUA

Evidence status: **verified**

On nashua.dmevals.local, wsmprovhost.exe (PID 7720) opened lsass.exe with GrantedAccess 0x1f3fff at 2020-05-02T03:09:29.430Z; the call trace runs through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll, i.e. the access was made from inside a PowerShell Remoting runspace rather than by an OS component. This follows pbeesly's Invoke-Command -ComputerName NASHUA script block (Get-Process -IncludeUserName) logged at 03:09:23Z on scranton and 03:09:28Z on nashua, and precedes the PSEXESVC/python.exe execution on NASHUA. The access mask is a full-memory mask on LSASS from a remote PowerShell session, which is consistent with credential access via the remoting channel, but no dump file or credential-tooling command line was observed for it, so it is rated suspicious rather than confirmed malicious.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-ff5a8ec69d | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-ff5a8ec69d | ok |
| 3 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRbzS | q-05544a5e31 | ok |
| 4 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.security | win.ServiceName | PSEXESVC | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNuI | q-6d4ffd3263 | ok |

### F22 · suspicious / medium · T1539 · PowerShell opened Microsoft Edge processes with full access (0x1FFFFF) on scranton.dmevals.local

Evidence status: **verified**

On scranton.dmevals.local, at 2020-05-02T03:05:17Z, C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe (PID 2976, running as SYSTEM per UserID S-1-5-18) opened handles to MicrosoftEdge.exe (PID 7748), MicrosoftEdgeCP.exe and MicrosoftEdgeSH.exe with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) and a call trace ending in an UNKNOWN module (ntdll.dll+9c584\|KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D)). Full-access handles to a browser process are the prerequisite for reading session cookies out of browser memory, and this occurred in the middle of a clearly malicious hands-on-keyboard session by user pbeesly on the same host: a steganographic PowerShell loader (monkey.png -> IEX) at 02:58:44, an archive-staging command collecting *pass*, *login*, *admin*, *vpn* files at 02:56:17, SysinternalsSuite deployment, sdelete64 anti-forensics, and Invoke-Discovery at 03:04:03. No script block text mentioning cookies/Edge/OpenProcess was recovered, so the exact purpose of the handle is not proven; the earlier 03:01:03 powershell.exe accesses to the same Edge processes used only 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION), consistent with get-process enumeration. No cookie file was read or copied: the only cookie-named file event in the whole dataset is a benign INetCookies directory creation by svchost (LocalService) on scranton at 03:21:05, and no archive/copy of Cookies, Login Data or Web Data was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:17.076Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQPxjx | q-4874f97d25 | ok |
| 2 | 2020-05-02 03:05:17.076Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQPxjx | q-4874f97d25 | ok |
| 3 | 2020-05-02 03:05:17.076Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQPxjx | q-4874f97d25 | ok |
| 4 | 2020-05-02 03:05:17.076Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQPxjx | q-4874f97d25 | ok |
| 5 | 2020-05-02 03:05:17.076Z | scranton.dmevals.local | windows.sysmon | host.name | scranton.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQPxjx | q-4874f97d25 | ok |
| 6 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7habKTs | q-afb051e3e1 | ok |
| 7 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cPCBow | q-5678faf8c2 | ok |
| 8 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7q0ZP57 | q-abc39cce61 | ok |
| 9 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-9a2bffe1aa | ok |

### F61 · suspicious / low · T1552 · sdclt.exe started three times by cmd.exe from the attacker working directory C:\ProgramData\victim on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local at 02:58:42-43, pbeesly's cmd.exe (running with CurrentDirectory C:\ProgramData\victim\) started sdclt.exe three times, and sdclt spawned control.exe. sdclt is a known UAC-bypass/backup-abuse binary and its invocation from the attacker's working directory during the loader chain is anomalous, but no credential-store, SAM or vault access was observed from it, so it is rated suspicious rather than confirmed credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\sdclt.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7huwtP3 | q-92c1b8e45a | ok |
| 2 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\cmd.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7huwtP3 | q-92c1b8e45a | ok |
| 3 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\sdclt.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7huwtP3 | q-92c1b8e45a | ok |

### F43 · suspicious / low · T1557 · No end-to-end AiTM chain confirmed; only the shared-MAC anomaly in Zeek

Evidence status: **verified**

Across the Windows datasets (2020-05-02) there is no evidence of traffic interception: outbound Sysmon 3 destinations are the normal internal peers (10.0.0.4, 10.0.1.4, 10.0.1.6, 192.168.0.4) plus Microsoft/Internet ranges, and object-access events (4663/4656/4670) are dominated by routine registry reads (Session Manager\Environment, Lsa, Winlogon). The only AiTM-relevant anomaly is the Zeek MAC 12:34:56:78:9a:bc answering for 10.0.0.4, 10.0.1.6 and 192.168.0.4 concurrently from 00:30Z on 2020-04-30, which is reported under T1557.002. Because the Zeek window does not overlap any Windows dataset, this cannot be tied to the credential-access activity seen on 2020-05-02, and the placeholder nature of the MAC keeps confidence low.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:35:25.619Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1ad | q-9b557b4a63 | ok |
| 2 | 2020-04-30 00:35:25.606Z | bobs.bigwheel.local | zeek | zeek.resp_l2_addr | 00:0d:3a:13:e3:69 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7qVdaE6 | q-9b557b4a63 | ok |
| 3 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.IpAddress | 172.18.39.2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nKg4v2 | q-89ae72f1fe | ok |

### F40 · suspicious / medium · T1557.002 · Single MAC 12:34:56:78:9a:bc answering for three distinct IPs (10.0.0.4, 10.0.1.6, 192.168.0.4) in Zeek conn logs

Evidence status: **verified**

In the Zeek window (2020-04-30 00:06-00:45Z) the responding L2 address 12:34:56:78:9a:bc is recorded for four different destination IPs: 10.0.0.4 (120 conns, 00:06:38-00:43:59), 10.0.1.6 (44 conns, 00:33:26-00:45:00), 192.168.0.4 (392 conns, 00:32:14-00:44:44) and 192.168.0.5 (3 conns, 00:08:02-00:15:18). From 00:30Z onward the same MAC answers for three IPs within the same 5-minute buckets (42, 66 and 404 conns), which is the classic signature of one device claiming multiple IPs on the segment (ARP cache poisoning / on-path interception). Notably 10.0.0.4 is the domain controller NEWYORK (DNS answers for newyork.dmevals.local resolve to 10.0.0.4) and 10.0.1.6 is NASHUA, so traffic to the DC and to a member server appears to be answered by the same MAC. Caveat: 12:34:56:78:9a:bc is a well-known placeholder MAC and the Zeek sensor may be normalising/rewriting MACs, so this could be a capture artefact rather than real poisoning; no ARP-specific log source is available to confirm. No Windows-side corroboration exists because the Windows datasets (2020-05-02) do not overlap the Zeek window (2020-04-30).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:06:38.903Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_aFZ1 | q-9b557b4a63 | ok |
| 2 | 2020-04-30 00:06:39.827Z | bobs.bigwheel.local | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7qVdaFb | q-9b557b4a63 | ok |
| 3 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 192.168.0.4 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1a3 | q-9b557b4a63 | ok |
| 4 | 2020-04-30 00:40:44.730Z | bobs.bigwheel.local | zeek | destination.ip | 192.168.0.4 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7qVdaEh | q-5e6a9aac96 | ok |
| 5 | 2020-04-30 00:06:38.899Z | simplerockbuild.simplerock.lan | zeek | zeek.answers | ["10.0.0.4"] | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_aFYa | q-edbbdb2e5f | ok |

### F49 · suspicious / medium · T1606 · No forged web-credential material observed; LSASS access on scranton/nashua is PowerShell/.NET credential-enumeration tooling, not token forgery

Evidence status: **verified**

On 2020-05-02 the only high-privilege LSASS handles in the window came from PowerShell-based tooling, not from any web-credential forging utility. At 03:05:16 on scranton.dmevals.local PowerShell.exe (PID 2976) opened lsass.exe with GrantedAccess 0x1f3fff and then 0x1fffff with a CallTrace ending in UNKNOWN(000001996D28200D) — an unbacked/private code region, i.e. in-memory .NET/PowerShell code rather than a signed DLL. At 03:09:29 on nashua.dmevals.local wsmprovhost.exe (PID 7720, PowerShell Remoting host) opened lsass.exe with 0x1f3fff, the call trace running through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll — consistent with PowerShell credential/privilege enumeration (e.g. token/group enumeration) executed over WinRM. Both are consistent with the credential-access hypothesis (harvesting), but nothing in the data shows creation or use of forged web credentials: no SAML/ADFS artefacts, no cookie-store theft, and the 4624 logon-process/authentication-package stacks are dominated by Kerberos (217) and Negotiate (78) with only a single NTLM/NtLmSsp logon (pbeesly, logon type 3, from 172.18.39.2 at 03:20:41 on scranton), which is a normal remote-auth pattern rather than forged-token use. The 4648 explicit-credential events are pbeesly re-authenticating to localhost via PSEXESVC on nashua and normal DWM-/UMFD-/machine-account logons on scranton.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-031de0bb00 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-b237a6c068 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-031de0bb00 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-1b126d702c | ok |
| 5 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.AuthenticationPackageName | NTLM | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nQi3T7 | q-aec0f8771d | ok |

### F53 · suspicious / low · T1649 · Root certificate store 'Blob' value modified on nashua.dmevals.local by C:\Windows\Sysmon.exe

Evidence status: **verified**

On nashua.dmevals.local at 2020-05-02 03:16:19 UTC, Security event 4657 shows the registry value 'Blob' under \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 being modified, with the modifying process reported as C:\Windows\Sysmon.exe running as NASHUA$ (S-1-5-18, logon 0x3e7). This is the only 4657 touching a certificate store in the whole dataset (all other 4657s are WMI Autologger EventLog-Application keys written by wevtutil.exe). A change to a trusted root certificate blob is consistent with root CA store tampering, but the recorded process name is anomalous for a genuine certificate install (Sysmon does not manage certificate stores) and the old/new values are not auditable for REG_BINARY, so the actual content change cannot be verified. No matching certificate export, PKINIT logon or forged-certificate use was observed on nashua, so this is recorded as suspicious rather than confirmed malicious.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rzHZUI | q-b1b26a3ae1 | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rzHZUI | q-ba14812b8e | ok |
| 3 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectValueName | Blob | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rzHZUI | q-b1b26a3ae1 | ok |
| 4 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | host.name | nashua.dmevals.local | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rzHZUI | q-b1b26a3ae1 | ok |

### F02 · benign / high · T1003.001 · nashua.dmevals.local LSASS 0x1f3fff handle by wsmprovhost is benign Get-Process -IncludeUserName

Evidence status: **verified**

On nashua.dmevals.local at 03:09:29 UTC, wsmprovhost.exe (PID 7720, pbeesly) opened lsass.exe with 0x1F3FFF. The call trace runs through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll, and the corresponding PowerShell 4104 script block at 03:09:28 is 'Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" }'. This is the standard .NET/PowerShell process-owner enumeration, not a memory dump. Other LSASS handles in the window are from svchost.exe (0x1000, lsm.dll call traces), WindowsAzureTelemetryService.exe (0x1400, CorperfmonExt.dll), CollectGuestLogs.exe (0x1410), MsMpEng.exe and wininit/csrss at lsass restart — all normal system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-d2c44b2944 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-d2c44b2944 | ok |
| 3 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRapX | q-3bb779ed4e | ok |
| 4 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7njy6Co | q-62fe69e885 | ok |

### F04 · benign / medium · T1003.002 · No SAM hive dumping observed

Evidence status: **verified**

No evidence of SAM/SECURITY/SYSTEM hive export: no 'reg save' command lines (only dsregcmd.exe and sc.exe start pushtoinstall registration matched the reg/save pattern), no file-create events for SAM/SECURITY hive copies (only Prefetch .pf files for SecurityHealth* binaries), and no 4663 object access to SAM/SECURITY registry hives. The 4663 hits on \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa and Winlogon are routine registry reads by svchost/powershell/cmd across all hosts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:28.476Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\Prefetch\SECURITYHEALTHSYSTRAY.EXE-41AD6DE1.pf | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRfJfH5wFd7b7vVsn | q-bdea748046 | ok |

### F05 · benign / medium · T1003.006 · No DCSync / directory replication abuse observed

Evidence status: **verified**

No PowerShell script blocks referencing DCSync, DirectorySearcher, Get-ADReplAccount or replication APIs. The only credential-adjacent PowerShell activity was Get-PrivateKeys (Export-PfxCertificate of local machine certificates with password 'saribas') on scranton, which is certificate theft rather than DCSync.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-b43ffd7720 | ok |

### F06 · benign / high · T1040 · Azure Network Watcher agent ran netsh trace packet capture on scranton (benign, platform telemetry)

Evidence status: **verified**

On scranton.dmevals.local the only packet-capture activity in the dataset is the Azure Network Watcher agent. At 2020-05-02T03:19:17Z SYSTEM launched C:\Windows\System32\netsh.exe with 'trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl"' and at 03:19:24Z 'netsh.exe trace stop'. Both were spawned by C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe /service, the legitimate Azure VM monitoring extension, and the same agent is seen making its normal 169.254.169.254:80 metadata calls. The Microsoft NDIS Capture (NdisCap) service start type was flipped demand->system at 23:19:22 local and back system->demand at 23:19:26 local, exactly bracketing the trace, which is the expected side effect of netsh trace. No attacker-controlled capture tooling, no pcap/npcap/WinPcap/WinDivert driver load, no promiscuous-mode or raw-socket artifacts, and no capture-related PowerShell script blocks were found. The genuine malicious activity in this window (PsExec64 with plaintext credentials dmevals\pbeesly to NASHUA, python.exe PyInstaller payload, sdelete64 wiping) is lateral movement/defense evasion, not network sniffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cla5Dm | q-d318eb949d | ok |
| 2 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cla5Dm | q-d318eb949d | ok |
| 3 | 2020-05-02 03:19:24.835Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cjZNnV | q-d318eb949d | ok |
| 4 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nVnj7M | q-ac8a70ca0d | ok |
| 5 | 2020-05-02 03:19:22.000Z | scranton.dmevals.local | windows.other | message | The start type of the Microsoft NDIS Capture service was changed from demand start to system start. | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCI | q-3230d0ab8e | ok |
| 6 | 2020-05-02 03:19:26.000Z | scranton.dmevals.local | windows.other | message | The start type of the Microsoft NDIS Capture service was changed from system start to demand start. | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuAu | q-370f38434b | ok |
| 7 | 2020-05-02 02:55:26.000Z | scranton.dmevals.local | windows.security | win.Application | \device\harddiskvolume2\packages\plugins\microsoft.azure.networkwatcher.networkwatcheragentwindows\1.4.1421.1\networkwatcheragent\networkwatcheragent.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rxFTIA | q-8b1968f71c | ok |

### F07 · benign / medium · T1040 · No attacker network sniffing observed; PsExec lateral movement with plaintext credentials is the real activity

Evidence status: **verified**

Hunting for T1040 across windows.security, windows.sysmon, windows.other and windows.powershell produced no attacker sniffing. The only capture-related command lines were the two Azure Network Watcher netsh trace calls on scranton. No pcap/npcap/WinPcap/WinDivert/nmnt driver image loads (sysmon event 7 query returned 0), no capture-related PowerShell script blocks (4104 query returned 0), and no inbound 5156 firewall records. The rare processes in the window are malicious but unrelated to sniffing: PsExec64.exe was run from scranton's PowerShell four times against \\NASHUA with the cleartext password '-p Fl0nk3rt0n!T0by', installing PSEXESVC (7045) on nashua and launching C:\Windows\Temp\python.exe (a PyInstaller bundle extracting _MEI29522 with _socket.pyd) as pbeesly; sdelete64.exe was used to wipe files including C:\programdata\victim\???cod.3aka3.scr. Those belong to lateral movement / credential use / defense evasion, not T1040, so T1040 itself is assessed as not observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNv3 | q-dc608bd8be | ok |
| 2 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCk | q-e0fa2ba50f | ok |
| 3 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.command_line | "C:\Windows\Temp\python.exe"  | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNum | q-dc608bd8be | ok |
| 4 | 2020-05-02 03:15:04.135Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Temp\_MEI29522 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c5y1oY | q-4aba49bfda | ok |
| 5 | 2020-05-02 03:02:04.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ns9wrd | q-dc608bd8be | ok |

### F10 · benign / medium · T1056.001 · No keylogger artefacts: no keyboard-API scripts, no scancode-map tampering, no keylogger service

Evidence status: **verified**

Searches for GetAsyncKeyState/SetWindowsHookEx/keylog in PowerShell script blocks returned zero hits, and the 26 keyboard-related registry writes are all default Windows keyboard-layout/device-enumeration values (HKU\.DEFAULT Keyboard Layout\Preload, CTF KeyboardLayout, TERMINPUT_BUS device parameters). The five 7045 service installs are javamtsup.exe and PSEXESVC (PsExec) — lateral-movement tooling, not a keyboard filter driver. No keylogging was observed in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | process.executable | %SystemRoot%\PSEXESVC.exe | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCk | q-bd3cec09f2 | ok |

### F11 · benign / medium · T1056.003 · No web-portal credential capture: no IIS/wwwroot page writes or web-shell scripts

Evidence status: **verified**

No process creation referencing wwwroot/inetpub/iis, no 4663 object access to wwwroot/inetpub, and no script blocks writing login pages. The only file creations matching login/logon/credential names are SysinternalsSuite binaries (Autologon.exe, logonsessions.exe) downloaded by pbeesly and normal netlogon.ftl / Netlogon operational log files. No web portal capture observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.342Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\Explorer.EXE | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOx9 | q-0994f58710 | ok |

### F12 · benign / high · T1110 · No brute-force authentication activity; credential theft on scranton.dmevals.local is not brute force

Evidence status: **verified**

Across windows.security (02:55–03:28Z on 2020-05-02) there are zero 4625 failed-logon events, zero 4740 lockouts and zero 4771 Kerberos pre-auth failures; the only NTLM validation (4776) is a single successful pbeesly logon from 10.0.1.4 on newyork.dmevals.local (Status 0x0). windows.other contains no lockout or failed-auth messages. The credential-related hits (PowerShell Get-PrivateKeys / Invoke-Exfil on scranton.dmevals.local, LSASS handle opens) are credential theft/exfiltration, not password guessing, so the T1110 family hypothesis is not supported by authentication-failure telemetry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nKhItZ | q-0e322871be | ok |
| 2 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nKhItZ | q-0e322871be | ok |
| 3 | 2020-05-02 03:20:48.000Z | scranton.dmevals.local | windows.other | message | Remote Desktop Services: Session logon succeeded:    User: DMEVALS\pbeesly  Session ID: 2  Source Network Address: 172.18.39.2 | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuA_ | q-8adc11ba36 | ok |

### F13 · benign / high · T1110.001 · No password-guessing tooling or failed logons; PowerShell 'Password' hits are certificate export and archive encryption

Evidence status: **verified**

No hydra/ncrack/medusa command lines exist in sysmon, and no 4625 events exist in windows.security. The two 4104 script blocks matching 'Password' on scranton.dmevals.local are (1) Get-PrivateKeys, which exports machine certificates to .pfx files protected with a hardcoded password, and (2) Invoke-Exfil, which 7-Zips the Downloads folder with a password and uploads it to \\192.168.0.4\webdav using a hardcoded 'cozy' credential. Both are credential/data theft and exfiltration, not iterative password guessing against accounts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-79c99fa7e6 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-79c99fa7e6 | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-e15eb8a659 | ok |
| 4 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-e15eb8a659 | ok |

### F14 · benign / medium · T1110.002 · No offline-cracking artifacts (no hive/NTDS dumps, no hashcat/john); LSASS handle opens by PowerShell are memory access, not cracking

Evidence status: **verified**

No reg save / ntdsutil / vssadmin command lines and no hashcat/john/Invoke-Mimikatz script blocks were found. The only .dmp files created are Windows Error Reporting dumps (WER51F5.tmp.dmp, WER5437.tmp.dmp), not credential dumps. The 4663 'SAM' object accesses on scranton.dmevals.local are all by C:\Windows\System32\lsass.exe under SCRANTON$ (normal LSA hive access), and the 16962 message about SAM remote-call restrictions is a default security-descriptor notice. PowerShell did open LSASS with GrantedAccess 0x1fffff at 03:05:16Z on scranton.dmevals.local, which is credential dumping (T1003.001) rather than password cracking, so no T1110.002 cracking activity is evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-3f2cbf8df0 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-3f2cbf8df0 | ok |
| 3 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nOhtev | q-eb36ba6da8 | ok |
| 4 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.other | message | Remote calls to the SAM database are being restricted using the default security descriptor: O:SYG:SYD:(A;;RC;;;BA).  For more information please see http://go.… | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuA- | q-74dff33e93 | ok |

### F15 · benign / high · T1110.003 · No password spraying: explicit-credential logons are a single account (pbeesly) reused for PsExec, not one password across many accounts

Evidence status: **verified**

All 15 4648 explicit-credential events involve the same account pbeesly: four on scranton.dmevals.local targeting server NASHUA and four on nashua.dmevals.local via C:\Windows\PSEXESVC.exe (03:11–03:15Z), plus localhost DWM/UMFD/SCRANTON$ system logons. No 4625 failures, no lockouts and no 4771 failures exist, and the only 4776 NTLM validation succeeded. Reusing one known credential for lateral movement is not spraying across many accounts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:14:42.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nixAb0 | q-c775a73b55 | ok |
| 2 | 2020-05-02 03:15:03.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niwwaQ | q-c775a73b55 | ok |
| 3 | 2020-05-02 03:15:03.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niwwaQ | q-c775a73b55 | ok |

### F16 · benign / high · T1110.004 · No credential stuffing: no web/HTTP credential submission and no failed-auth bursts

Evidence status: **verified**

No curl/wget/Invoke-WebRequest command lines were found in sysmon, and the only 4104 blocks mentioning Credential/Login are the Get-PrivateKeys and Invoke-Exfil scripts plus a benign AD-cmdlet help block on newyork.dmevals.local. windows.security has no 4625 events at all, so there is no pattern of many distinct credential pairs being tried against authentication endpoints. The Invoke-Exfil script does use a hardcoded credential to map \\192.168.0.4\webdav, but that is a single known credential used for exfiltration, not stuffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-e15eb8a659 | ok |
| 2 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | host.name | newyork.dmevals.local | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qwUVsT | q-4e32e79350 | ok |

### F17 · benign / medium · T1111 · No MFA/smartcard/vault interception observed; LSASS handle from PowerShell is a side effect of a credential/certificate-theft toolkit on scranton

Evidence status: **verified**

Hunting for T1111 (Multi-Factor Authentication Interception) produced no evidence of smartcard, SCardSvr, VaultSvc or credential-provider interception. A security-wide search for smartcard/vault/credential/NGC object names, service names and process names returned 0 hits, and the windows.other check for scardsvr/vaultsvc service installs or image paths also returned 0 hits. The only LSASS handle events with unusual access masks were: PowerShell.exe (PID 2976) on scranton.dmevals.local opening lsass.exe with 0x1f3fff and 0x1fffff at 2020-05-02T03:05:16, plus routine system readers (svchost.exe via lsm.dll/sysmain.dll, csrss.exe, wininit.exe, wsmprovhost.exe). The PowerShell LSASS access occurred in the same session where user pbeesly was running a credential/certificate collection toolkit from C:\Program Files\SysinternalsSuite\readme.ps1 (Get-PrivateKeys exporting cert:\LocalMachine certificates to .pfx with Export-PfxCertificate, Invoke-Discovery, Invoke-Persistence, Invoke-Exfil, sdelete64 wiping of C:\programdata\victim\???cod.3aka3.scr and Draft.Zip). That is credential/certificate theft (T1552/T1555/T1649 territory), not MFA interception: no smartcard reader, no vault, no MFA token or OTP interception artefact was retrieved. The 4648 explicit-credential logons for pbeesly (scranton -> NASHUA, and PSEXESVC.exe on nashua) and the Kerberos KDC_ERR_PREAUTH_REQUIRED failures from 10.0.1.4/10.0.1.6 in the non-overlapping zeek window are consistent with normal pre-auth negotiation and lateral use of harvested credentials, not with intercepted MFA. T1111 is therefore assessed as not observed in this data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-97bd2da6bc | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-97bd2da6bc | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-97bd2da6bc | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-47902c7811 | ok |
| 5 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-47902c7811 | ok |
| 6 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-59648e79fc | ok |
| 7 | 2020-04-30 00:24:19.110Z | simplerockbuild.simplerock.lan | zeek | message | {"@stream":"kerberos","@system":"simplerockbuild.simplerock.lan","@proc":"zeek","ts":1588206259.11049,"uid":"C6f4oNkbm2Uhvs1Q5","id_orig_h":"10.0.1.4","id_orig_… | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1bT | q-f036823d46 | ok |

### F18 · benign / medium · T1187 · WebDAV/SMB and NTLM hits on scranton are credential-based exfiltration and normal system traffic, not forced authentication

Evidence status: **verified**

No forced-authentication (T1187) activity was found. The WebDAV traffic in zeek (10.0.1.4 -> 192.168.0.4:80, PROPFIND/OPTIONS with user agents Microsoft-WebDAV-MiniRedir/10.0.18362 and DavClnt, 401/403 responses) is the upload leg of an exfiltration routine, not a coercion lure: the PowerShell script block 'Invoke-Exfil' on scranton.dmevals.local (user pbeesly, 2020-05-02T03:08:02Z) explicitly supplies credentials ($UserName = "cozy", $Password = "MyCozyPassw0rd!") and maps \\192.168.0.4\webdav via New-PSDrive before Copy-Item of OfficeSupplies.7z. That is authenticated WebDAV access with known credentials, not an attacker harvesting NTLM hashes via a malicious .lnk/.scf/WebDAV path. The only shortcut created on a host was C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk by powershell.exe on scranton (2020-05-02T03:04:23Z), but no evidence ties it to a remote UNC/WebDAV target. The single NTLM network logon (4624 type 3, NtLmSsp, pbeesly, from 172.18.39.2 on scranton at 2020-05-02T03:20:41Z) and the matching LsaSrv 6038 NTLM-in-use warning on scranton are consistent with ordinary NTLM fallback, not with a Responder-style capture. All outbound 139/445 connections in sysmon are from the System process to internal addresses (10.0.0.4, 10.0.1.6, fe80::e40c:95b6:b0a7:6429) — normal SMB client traffic, no rare or attacker-owned destination. Note: the WebDAV/exfil activity is itself malicious (credential use and data theft), but it does not constitute T1187 forced authentication.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-7e3c3821dd | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-7e3c3821dd | ok |
| 3 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | zeek.user_agent | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1br | q-e7266edf16 | ok |
| 4 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | zeek.user_agent | DavClnt | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1YZ | q-38610d730b | ok |
| 5 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hSRzrG | q-e531907973 | ok |
| 6 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | NtLmSsp  | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nQi3T7 | q-62ff3e976f | ok |
| 7 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.other | event.code | 6038 | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuAv | q-8be223f8e0 | ok |
| 8 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hSRzrG | q-e531907973 | ok |

### F21 · benign / high · T1212 · Routine LSASS handle access by OS components and Azure agents (benign baseline)

Evidence status: **verified**

The bulk of the 326 LSASS process-access events are explained by legitimate components: svchost.exe (289, mostly GrantedAccess 0x1000/0x1400, with lsm.dll and sysmain.dll call traces), the Azure IaaSAntimalware AntimalwareConfig.exe (15) and WindowsAzureTelemetryService.exe (13), plus csrss.exe, wininit.exe and services.exe opening LSASS with full masks during session/init and RPC handling (e.g. csrss.exe 0x1fffff via basesrv.DLL/CSRSRV.dll at 03:19:09Z, wininit.exe 0x1fffff/0x1000000, services.exe 0x1000 via RPCRT4.dll). These are expected OS and monitoring behaviours, not exploitation. The 4697 service installs by SCRANTON$ at 23:20:48Z are per-user Windows 10 services (AarSvc, CDPUserSvc, UnistackSvcGroup etc.) created by svchost.exe, also benign. No Mimikatz/sekurlsa/MiniDump/procdump strings were found in PowerShell script blocks or windows.other messages (checks C127/C128 returned zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\csrss.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpgKyU | q-40405afe2e | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000000 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpgKyV | q-ff5a8ec69d | ok |
| 3 | 2020-05-02 03:19:13.337Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\services.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cofd-n | q-40405afe2e | ok |
| 4 | 2020-05-02 03:20:48.000Z | scranton.dmevals.local | windows.security | win.ServiceFileName | C:\windows\system32\svchost.exe -k AarSvcGroup -p | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nKg4vE | q-6d4ffd3263 | ok |

### F23 · benign / high · T1539 · No browser cookie-store theft observed on other hosts; C129 hits are wildcard false positives

Evidence status: **verified**

The 162 hits of check C129 are not cookie-store activity: 133 are svchost.exe writes of C:\Windows\ServiceState\EventLog\Data\lastalive0.dat / lastalive1.dat on all four hosts, and the remainder are GroupPolicy DataStore files. A case-insensitive re-query for *cookies*, *login data* and *web data* in win.TargetFilename returned exactly one event — the INetCookies directory creation by svchost on scranton — and no file-copy (event.code 2) of Cookies/Login Data, no process creation command line referencing cookies/Login Data/Web Data/sqlite, and no PowerShell script block referencing them. Edge file creations on scranton (03:21:05-03:21:06) are normal browser profile writes by MicrosoftEdge.exe itself. Zeek HTTP traffic (62 events, all to 192.168.0.4 with WebDAV user agents) is in a non-overlapping window and shows no session-replay tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:28.893Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceState\EventLog\Data\lastalive1.dat | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy1EsG | q-bedaf4b67a | ok |
| 2 | 2020-05-02 03:21:05.198Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\DataStore\_TempTestAccess.txt | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YE4VZs | q-370ac88599 | ok |
| 3 | 2020-05-02 03:21:05.198Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YE4VZs | q-370ac88599 | ok |

### F27 · benign / medium · T1552 · SAM hive handle opens are lsass.exe self-access (benign); no hive dumping or credential-file access observed

Evidence status: **verified**

The 10 SAM-related 4656 events on scranton.dmevals.local are all C:\Windows\System32\lsass.exe running as the machine account SCRANTON$ with AccessMask 0xf003f, i.e. the local security authority opening its own SAM database — expected behaviour, not an adversary reading the hive. No reg save / ntds.dit / SECURITY hive file creation was found, no SYSVOL/Groups.xml/cpassword access, no shell-history (PSReadLine/ConsoleHost_history) access, and the zeek SMB data (separate, non-overlapping window) shows only IPC$ and sysvol gpt.ini/GptTmpl.inf reads with no credential-bearing filenames. The remaining registry 'Password/Credential' hits are Windows defaults (IdentityCRL, CredentialEnrollmentManagerUserSvc, CredentialGuard, Winlogon PasswordExpiryNotification).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ryFh2_ | q-2157b3315d | ok |
| 2 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectName | SAM | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ryFh2_ | q-2157b3315d | ok |
| 3 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | user.name | SCRANTON$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ryFh2_ | q-2157b3315d | ok |

### F29 · benign / high · T1555 · Routine LSASS handle access by svchost, Azure telemetry and AV — benign baseline

Evidence status: **verified**

The bulk of the 326 LSASS process-access events are low-privilege query handles (0x1000, 293 events) from C:\windows\system32\svchost.exe, plus 0x1400 from WindowsAzureTelemetryService.exe and AntimalwareConfig.exe, and 0x1410 from CollectGuestLogs.exe (4656). These are standard Windows/Azure-guest-agent/AV telemetry reads, not credential dumping. The 0x1fffff/0x1f3fff masks from csrss.exe/wininit.exe at 03:19:09 coincide with an lsass.exe process creation (system restart) and are OS-internal.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hx0W8_ | q-5caa0999a4 | ok |
| 2 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hx0W8_ | q-5caa0999a4 | ok |
| 3 | 2020-05-02 03:19:42.009Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cUGJOD | q-a750a6ce72 | ok |
| 4 | 2020-05-02 03:03:38.000Z | newyork.dmevals.local | windows.security | win.ProcessName | C:\WindowsAzure\Packages\CollectGuestLogs.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq8Ga8 | q-0e52c2be5d | ok |
| 5 | 2020-05-02 03:20:15.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Program Files\Windows Defender\MsMpEng.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nSlNDC | q-0e52c2be5d | ok |

### F30 · benign / medium · T1555.003 · No browser credential-store access observed

Evidence status: **verified**

Searches for browser credential artifacts (Login Data, logins.json, key4.db, Cookies, Web Data) across sysmon file-create, process-creation, security object-access and PowerShell script blocks returned zero hits. The only cookie-related file event is an INetCookies file under a LocalService package profile written by svchost.exe, which is normal OS behaviour. No evidence of browser credential theft in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cPCBow | q-2b9be4561a | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cPCBow | q-2b9be4561a | ok |

### F31 · benign / medium · T1555.004 · No Windows Credential Manager / Vault access; only a benign Credential Guard config event

Evidence status: **verified**

No process creation, file creation under \Microsoft\Credentials or \Microsoft\Vault, or PowerShell script block referencing vault/cmdkey/credential APIs was found. The only 'Credential' string in windows.other is a routine Credential Guard configuration status message (event code 14) on scranton, and the PowerShell 4104 hits for 'Credential' were unrelated module help text. The credential theft on these hosts targeted LSASS memory (see T1555 finding), not the Credential Manager store.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuA9 | q-c9f9643e73 | ok |
| 2 | 2020-05-02 03:16:32.000Z | newyork.dmevals.local | windows.powershell | user.name | SYSTEM | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qyVUi_ | q-b809315f5e | ok |

### F32 · benign / medium · T1555.005 · No password-manager artifacts observed

Evidence status: **verified**

Searches for KeePass/1Password/Bitwarden/LastPass process creation, .kdbx file creation, process access to password-manager processes, and PowerShell script blocks referencing them returned zero hits. The windows.other 'password manager' style hits were unrelated kernel power-manager and file-system-filter messages. No password-manager theft observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:39.000Z | scranton.dmevals.local | windows.other | message | The kernel power manager has initiated a shutdown transition.    Shutdown Reason: Kernel API | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCQ | q-942106f18f | ok |

### F34 · benign / medium · T1556.001 · No evidence of domain-controller authentication tampering; DC logon activity is normal Kerberos/Advapi machine and user logons

Evidence status: **verified**

Logon process names for 4624/4648 are the expected Kerberos (217), Advapi (76), User32 (2), NtLmSsp (1) and '-' (1). Network (type 3) logons are dominated by machine accounts (NEWYORK$ 123, SCRANTON$ 37, NASHUA$ 25, UTICA$ 5, WEC$ 8) plus pbeesly (20). No 4739 directory-policy change events exist in the security log at all, and no lsass/cryptdll/skeleton-key related script blocks or messages were found. The only anomalous authentication-process access is the PowerShell full-access handle to lsass on scranton (reported under T1556), which is a member server, not a DC authentication modification.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.LogonProcessName | Kerberos | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niytuv | q-d6d3f563c8 | ok |
| 2 | 2020-05-02 03:05:26.000Z | nashua.dmevals.local | windows.security | win.LogonProcessName | Advapi   | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7np7lpF | q-d6d3f563c8 | ok |

### F35 · benign / high · T1556.002 · No password filter / Notification Packages DLL registration observed

Evidence status: **verified**

The only DLL-like file creation matching System32/Notification/PasswordFilter patterns was C:\Users\pbeesly\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db-shm (a Windows notification database file, not a password filter). Modules loaded matching lsass/Notification were NotificationControllerPS.dll (7), NotificationController.dll (1) and lsass.exe (1) - all legitimate Windows components. No 4657 registry change to a 'Notification Packages' or 'PasswordFilter' value exists, and no PowerShell script block references Notification Packages or PasswordFilter. The 'Notification Packages' message hits in windows.other were unrelated CEP/DHCP/RDP notification messages.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:48.000Z | scranton.dmevals.local | windows.other | message | Remote Desktop Services: Shell start notification received:    User: DMEVALS\pbeesly  Session ID: 2  Source Network Address: 172.18.39.2 | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuBA | q-a64aa8e0a8 | ok |
| 2 | 2020-05-02 03:18:35.000Z | scranton.dmevals.local | windows.other | message | DHCPv4 client received shutdown notification | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCm | q-a64aa8e0a8 | ok |

### F36 · benign / medium · T1556.005 · No reversible-encryption account change; the single Set-ADUser/ReversibleEncryption script-block hit is a benign module fragment

Evidence status: **verified**

The only 4104 script block matching AllowReversiblePasswordEncryption/ReversibleEncryption/Set-ADAccountControl/Set-ADUser on newyork.dmevals.local (2020-05-01T23:01:30-04:00, SYSTEM) is a generic PowerShell module fragment dealing with TimeSpan validation ('Seconds','Minutes','Hours','Days'), not an account-control change. No 4739 policy-change events, no 4663 access to a 'Reversible' object, no process command line containing Reversible/ADAccountControl/Set-ADUser, and no windows.other message mentioning Reversible/PasswordEncryption were found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | process.command_line | alidateSet('Seconds','Minutes','Hours','Days')]         [System.String]         $TimeSpanType     )     switch ($TimeSpanType)     {         'Seconds' { return … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qwUVsT | q-58966b232d | ok |

### F39 · benign / medium · T1556.008 · No Network Provider DLL registration; winlogon access is dominated by legitimate system processes

Evidence status: **verified**

No registry write to a NetworkProvider key, no file creation under a NetworkProvider path, and no 4657 change to a NetworkProvider object were found. The 144 winlogon accesses came from svchost.exe (64), lsass.exe (24), AntimalwareConfig.exe (15), svchost.exe System32 (14), WindowsAzureTelemetryService.exe (13), powershell.exe (4), LogonUI.exe (3), smss.exe (2) and wsmprovhost.exe (2) with ordinary masks; the only full-access (0x1fffff/0x1f3fff) winlogon handles came from PowerShell.exe on scranton and wsmprovhost.exe on nashua, which are reported under T1556 as credential-access behaviour rather than a registered network-provider credential capture DLL.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.634Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c93tyW | q-c59425beee | ok |
| 2 | 2020-05-02 03:09:29.634Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c93tyW | q-c59425beee | ok |

### F41 · benign / medium · T1557.001 · No name-resolution poisoning or SMB relay observed; DNS/LLMNR lookups and SMB auth are normal

Evidence status: **verified**

Sysmon 22 DNS queries on 2020-05-02 (81 events) are all routine: DC/member-server resolution (NEWYORK.dmevals.local -> 10.0.0.4, NASHUA -> 10.0.1.6, SCRANTON), localhost, and Microsoft/Office telemetry domains, all with QueryStatus 0. The only LLMNR/NBT-NS-style lookups are short-name queries (NASHUA, SCRANTON, NEWYORK, wpad) that resolved normally to the correct internal IPs; Zeek shows only 2 LLMNR/NBT-NS connections, both to the broadcast address 10.0.1.255, and wpad.dmevals.local returned NXDOMAIN from the DC. SMB (445/139) traffic in Zeek is 40 RSTO + 10 REJ with no successful relay-style authentication; Windows 4624 type 3 logons are Kerberos from expected hosts (10.0.1.4, 10.0.1.6, 10.0.0.4, 10.0.1.10, 10.0.1.5, ::1). The single NTLM network logon (pbeesly from 172.18.39.2 on scranton) is LogonType 10 (RDP), not an SMB relay. The PowerShell hits for DNSClient/DNSServerAddress are built-in DSC resource module scriptblocks run by SYSTEM on newyork, not poisoning tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:42.257Z | scranton.dmevals.local | windows.sysmon | win.QueryResults | ::ffff:10.0.0.4; | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hWWCli | q-cab9b70c5c | ok |
| 2 | 2020-05-02 03:09:23.809Z | scranton.dmevals.local | windows.sysmon | win.QueryName | nashua | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c-4MbO | q-cab9b70c5c | ok |
| 3 | 2020-04-30 00:07:59.132Z | simplerockbuild.simplerock.lan | zeek | dns.response_code | NXDOMAIN | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_aFYW | q-edbbdb2e5f | ok |
| 4 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.LogonType | 3 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nQi3T7 | q-89ae72f1fe | ok |
| 5 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.AuthenticationPackageName | NTLM | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nQi3T7 | q-89ae72f1fe | ok |
| 6 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | user.name | SYSTEM | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qwUVuD | q-b8b1efceeb | ok |

### F42 · benign / medium · T1557.003 · No DHCP spoofing indicators; no DHCP server/lease events and only routine ipconfig usage

Evidence status: **verified**

The windows.other dataset (216 events, 2020-05-02) contains no DHCP-server or DHCP-client configuration events (no 1341/1342/1020/1063), and the only DHCP-related process activity in Sysmon is 3 executions of C:\Windows\System32\ipconfig.exe, i.e. read-only inspection. The only PowerShell touching DNS client settings is the built-in xDNSServerAddress DSC resource scriptblock executed by SYSTEM on newyork.dmevals.local, which is a standard module load rather than rogue gateway/DNS injection. Logon process names for 4624 are Kerberos/Advapi/User32/NtLmSsp only, with no unusual authentication source that would follow a DHCP spoof. No rogue DHCP server or lease change is observable in the available data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | host.name | newyork.dmevals.local | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qwUVuD | q-b8b1efceeb | ok |
| 2 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | user.name | SYSTEM | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qwUVuD | q-b8b1efceeb | ok |

### F45 · benign / medium · T1558.001 · No golden-ticket indicators; Kerberos TGT activity is normal pre-auth logons

Evidence status: **verified**

All 43 Kerberos ticket events in windows.security come from newyork.dmevals.local and are ordinary: 4768 TGT requests for pbeesly and SCRANTON$ with PreAuthType 2 and encryption type 0x12, all Status 0x0, plus 4769 service-ticket requests for NEWYORK$, NASHUA$, SCRANTON$, WEC$ and krbtgt. No 4769 with RC4 (0x17) bulk service requests, no 4771 failures, no krbtgt hash theft or DCSync strings in PowerShell (C260 zero hits), and no krbtgt/ticket messages in windows.other (C261 zero hits). The only LSASS full-access reads were by the attacker's PowerShell on scranton (see T1558 finding) and by wsmprovhost.exe on nashua, whose call trace shows .NET/PowerShell Management module frames (Get-Process style access), not a ticket-forging tool. No golden ticket use is evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNvO | q-fb285653ae | ok |
| 2 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNvO | q-fb285653ae | ok |
| 3 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ncs5pu | q-fb285653ae | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-cad798abf1 | ok |

### F46 · benign / medium · T1558.002 · No silver-ticket indicators; service-ticket requests are routine machine-account TGS

Evidence status: **verified**

4769 events on newyork.dmevals.local are all Status 0x0 with encryption type 0x12 for machine accounts (SCRANTON$ -> NEWYORK$/SCRANTON$/WEC$/krbtgt) and pbeesly -> NASHUA$/NEWYORK$, matching the PSEXESVC/WinRM lateral movement seen in windows.other and sysmon. No service-account TGS requests with RC4, no 4770/4771, and no silver/kerberoast/SPN strings in PowerShell script blocks (C265 zero hits). Zeek Kerberos (2020-04-30, non-overlapping window) shows only 11 TGS requests, all by pbeesly/DMEVALS.LOCAL for cifs/NASHUA, cifs/NEWYORK, ldap/NEWYORK.dmevals.local, HTTP/NASHUA, host/nashua.dmevals.local and krbtgt, all successful with aes256 — normal service access, not forged service tickets.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:14.000Z | newyork.dmevals.local | windows.security | win.ServiceName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ncs5ob | q-fb285653ae | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72bs | q-fb285653ae | ok |
| 3 | 2020-04-30 00:35:25.646Z | simplerockbuild.simplerock.lan | zeek | zeek.service | cifs/NASHUA | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Zlbp | q-c9fe90bfd3 | ok |
| 4 | 2020-04-30 00:33:14.816Z | simplerockbuild.simplerock.lan | zeek | zeek.service | ldap/NEWYORK.dmevals.local | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Zlbx | q-c9fe90bfd3 | ok |

### F47 · benign / medium · T1558.003 · No Kerberoasting: no bulk RC4 service-ticket requests or roasting tooling

Evidence status: **verified**

Kerberoasting would show many 4769 requests for distinct SPNs with RC4 (0x17) encryption from one account. In windows.security all 4769 events use TicketEncryptionType 0x12 (AES256) and target only a handful of machine accounts, all Status 0x0. In the non-overlapping Zeek window, only 11 TGS requests exist, all from pbeesly/DMEVALS.LOCAL, all successful with aes256-cts-hmac-sha1-96. No kerberoast/GetUserSPNs/Invoke-Kerberoast/SPN strings appear in PowerShell script blocks (C270 zero hits). The credential access that did occur on scranton was LSASS memory access, not service-ticket harvesting.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72bs | q-fb285653ae | ok |
| 2 | 2020-05-02 03:10:23.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niytvM | q-fb285653ae | ok |
| 3 | 2020-04-30 00:33:26.292Z | simplerockbuild.simplerock.lan | zeek | zeek.cipher | aes256-cts-hmac-sha1-96 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Zlby | q-c9fe90bfd3 | ok |
| 4 | 2020-04-30 00:24:19.122Z | simplerockbuild.simplerock.lan | zeek | zeek.client | pbeesly/DMEVALS.LOCAL | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1bV | q-c9fe90bfd3 | ok |

### F48 · benign / medium · T1558.004 · No AS-REP roasting: AS exchanges all require pre-authentication

Evidence status: **verified**

AS-REP roasting requires AS-REQ for accounts with pre-authentication disabled. Every AS exchange observed returned KDC_ERR_PREAUTH_REQUIRED followed by a successful pre-authenticated AS-REP (Zeek: 7 KDC_ERR_PREAUTH_REQUIRED for pbeesly/dmevals, each followed by success with aes256), and all 4768 events in windows.security carry PreAuthType 2 with Status 0x0. No asrep/GetNPUsers/Rubeus strings in PowerShell (C275 zero hits), no AS-REP/preauth messages in windows.other (C276 zero hits), and no sysmon process-creation hits for AS-REP tooling (C274 zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:24:19.110Z | simplerockbuild.simplerock.lan | zeek | zeek.error_msg | KDC_ERR_PREAUTH_REQUIRED | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1bT | q-c9fe90bfd3 | ok |
| 2 | 2020-04-30 00:24:19.119Z | simplerockbuild.simplerock.lan | zeek | zeek.success | True | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1bU | q-c9fe90bfd3 | ok |
| 3 | 2020-05-02 03:12:25.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nix9vF | q-fb285653ae | ok |

### F50 · benign / high · T1606.001 · Only browser-cookie file event is a benign LocalService INetCookies write by svchost.exe

Evidence status: **verified**

The single file-creation hit for cookie stores in the whole window is on scranton.dmevals.local at 03:21:05, where C:\windows\System32\svchost.exe created C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies — a per-package WinINet cookie container under the LocalService service profile, written by the service host itself. There is no access to user browser cookie databases (no Chrome/Edge/Firefox Cookies, Login Data or Web Data files were created), no PowerShell script block referencing cookies (zero hits), and no cookie file path in windows.other. Nothing indicates cookie theft or forged web cookies.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cPCBow | q-55c3fa3a4e | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cPCBow | q-55c3fa3a4e | ok |

### F51 · benign / high · T1606.002 · No SAML/ADFS token activity; no token or SAML files created

Evidence status: **verified**

Searches for ADFS/SAML strings in windows.other and for token/saml file creations in windows.sysmon returned zero hits, and the PowerShell script-block search for token/cookie/SAML/certificate content returned only unrelated module help text (PSScriptInfo/NuGet messages) and a group-attribute helper function on scranton.dmevals.local. No SAML token forging or signing-certificate abuse is observable in these datasets.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | process.command_line | function Get-AttributesMask($AttributesMask) {     &lt;#         SE_GROUP_MANDATORY          0x00000001  The group is mandatory.         SE_GROUP_ENABLED_BY_DEF… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvTCvl | q-37399317a6 | ok |

### F54 · benign / medium · T1649 · Kerberos TGT requests show only password pre-authentication (no PKINIT / certificate-based logons)

Evidence status: **verified**

All 14 Kerberos TGT requests (event 4768) in the window, on newyork.dmevals.local, have win.PreAuthType = 2 (password pre-authentication) — none used PKINIT (PreAuthType 16) or certificate-based authentication, so there is no evidence of forged/stolen authentication certificates being used to obtain tickets. The requests are for user pbeesly from 10.0.1.4/10.0.1.6 and for the machine account SCRANTON$ from 10.0.1.4 at 03:19:13 UTC, which is consistent with the SCRANTON host re-authenticating during the intrusion rather than with certificate abuse. No certificate-based logon was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ncs5pb | q-b3197ed971 | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ncs5pb | q-b3197ed971 | ok |
| 3 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | user.name | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNvO | q-b3197ed971 | ok |

### F37 · not_observed / medium · T1556.006 · No MFA / directory-policy modification events present in the telemetry

Evidence status: **verified**

Event 4739 (directory service policy change) does not appear anywhere in the 41002-event windows.security population nor in windows.other, so no MFA-related authentication policy change was recorded. The security log does contain 4768/4769 Kerberos events and 4624 logons, but nothing indicating MFA registration or policy tampering.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | event.code | 4624 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niytuv | q-d6d3f563c8 | ok |

### F38 · not_observed / medium · T1556.007 · No hybrid-identity (AD FS / Azure AD / federation) tampering observed

Evidence status: **verified**

No 5136 directory-object modification events exist in windows.security or windows.other, and no PowerShell script block references adfs/azuread/federation-related terms. The 5058/5061 events present are routine KSP key operations: on scranton pbeesly opened machine RSA key {ADA1F326-B4FE-4C0C-B68C-1B4CA6F364AC} via 'Microsoft Software Key Storage Provider' (Operation 'Open Key', ReturnCode 0x0) at 2020-05-01T23:04:57-04:00, and NEWYORK$ performed similar key operations - consistent with the Get-PrivateKeys certificate activity, not with federation trust modification.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:57.000Z | scranton.dmevals.local | windows.security | win.ProviderName | Microsoft Software Key Storage Provider | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72ZP | q-98cee39eec | ok |
| 2 | 2020-05-02 03:04:57.000Z | scranton.dmevals.local | windows.security | win.KeyName | {ADA1F326-B4FE-4C0C-B68C-1B4CA6F364AC} | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72ZP | q-98cee39eec | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Self-parented Skype app start on NASHUA; only produced a WerFault crash report and telemetry DNS (watson.telemetry.microsoft.com). No credential access. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | PyInstaller bundle dropped in C:\Windows\Temp, started 4x by PSEXESVC.exe as pbeesly, unpacks _MEI29522 with _socket/_ssl/_hashlib, makes 348 connections to 192… |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Dropped in C:\Windows\Temp and run by PowerShell to create a password-protected archive (-hpfGzq5yKw) of the harvested working.zip, then shredded by sdelete64.e… |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Anti-forensics: run 3x by cmd.exe to wipe Rar.exe and both working.zip copies on NASHUA. |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure guest agent diagnostic collection started by WaAppAgent.exe; standard platform behaviour, no credential access. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher extension binary started by services.exe/cmd.exe; only spawned netsh/dispdiag diagnostics. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure IaaS antimalware configuration helper launched by WindowsAzureGuestAgent.exe; platform provisioning. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure VM custom script extension handler started by cmd.exe during guest agent provisioning; no credential-related child activity. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure AD domain-join extension handler started by cmd.exe; standard provisioning, no credential theft. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler child of GoogleUpdate.exe; routine updater behaviour. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | 64-bit Google Update crash handler child of GoogleUpdate.exe; routine updater behaviour. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Google Update service/updater started by services.exe/svchost.exe; benign software update activity. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Sysinternals tool run by pbeesly's PowerShell from the attacker-unpacked SysinternalsSuite folder minutes after the steganographic loader; used for permission r… |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Run 4x by pbeesly's PowerShell with cleartext credentials (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by) to launch C:\Windows\Temp\python.exe on \\NASHUA. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Run 3x by pbeesly's PowerShell to shred the loader (cod.3aka3.scr), Draft.Zip and SysinternalsSuite.zip - anti-forensics of the credential-theft tooling. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Windows Defender service binary started by services.exe; legitimate AV engine. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Windows Defender network inspection service started by services.exe; legitimate. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Masqueraded .scr in C:\ProgramData\victim started from explorer.exe with /S, wrote monkey.png (steganographic payload carrier) and spawned cmd.exe/conhost - the… |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Invoked twice by pbeesly's hidden PowerShell to compile attacker C# into C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.dll and 0piklvia\0piklvia.dll - i… |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Started via 'Start-Process ... -verb runas' from PowerShell (consent.exe prompt) and then spawned powershell.exe reading HKLM\SOFTWARE\Javasoft 'value Supplemen… |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | Started 3x by cmd.exe under pbeesly at 02:58:42-43 with CurrentDirectory C:\ProgramData\victim\ and spawned control.exe; sdclt is a known UAC-bypass/backup-abus… |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent firewall helper started by WindowsAzureGuestAgent.exe; platform provisioning. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent volume discovery utility; standard provisioning. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure Windows guest agent service started by services.exe; legitimate platform component. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | 1 | C:\Windows\System32\services.exe | benign | Azure telemetry service started by services.exe; legitimate platform component. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\WaAppAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure agent host service started by services.exe; legitimate platform component. |
| scranton.dmevals.local | C:\WindowsAzure\SecAgent\WaSecAgentProv.exe | 2 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure security agent provider started by WaAppAgent.exe; legitimate platform component. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\Plugins\VFPl… | 1 | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | benign | Azure network agent plugin child of WindowsAzureNetAgent.exe; legitimate platform component. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | 1 | C:\Windows\System32\services.exe | benign | Azure network agent service started by services.exe; legitimate platform component. |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | Hands-on-keyboard intrusion on scranton.dmevals.local by pbeesly (readme.ps1/psversion.ps1 from SysinternalsSuite, discovery, persistence, screen capture, clipboard, sdelete anti-forensics) culminating in full-access LSA… |
| T1003.001 LSASS Memory | malicious | PowerShell.exe (PID 2976, pbeesly) opened lsass.exe with 0x1F3FFF then 0x1FFFFF on scranton at 03:05:16 UTC, confirmed by 4656 with AccessMask 0x1fffff/0x1f3fff; nashua wsmprovhost 0x1f3fff handle is benign Get-Process -… |
| T1003.002 Security Account Manager | not_observed | No reg save of SAM/SECURITY/SYSTEM, no hive-copy file creations, no 4663 access to SAM/SECURITY hives. |
| T1003.003 NTDS | not_observed | No ntds.dit file access, no ntdsutil/vssadmin/diskshadow execution, no NTDS object access. |
| T1003.004 LSA Secrets | suspicious | Masquerading C:\ProgramData\victim\cod.3aka3.scr read HKLM\SYSTEM\ControlSet001\Control\Lsa on scranton and was then wiped with sdelete64; single query-value access, no secret export observed. |
| T1003.005 Cached Domain Credentials | not_observed | No SECURITY\Cache registry access, no 4656 on SECURITY objects, no mscache/dcc PowerShell. |
| T1003.006 DCSync | not_observed | No DCSync, DirectorySearcher, Get-ADReplAccount or replication-API activity in PowerShell or security logs. |
| T1040 Network Sniffing | benign | The only packet-capture activity is the legitimate Azure Network Watcher agent on scranton.dmevals.local: netsh.exe 'trace start capture=yes traceFile=...etl' / 'trace stop' at 2020-05-02T03:19:17Z and 03:19:24Z, parente… |
| T1056 Input Capture | malicious | Input/credential capture tooling (screen capture + LSASS handle access with full rights from PowerShell/WinRM host) executed by pbeesly on SCRANTON and NASHUA. |
| T1056.001 Keylogging | not_observed | No keylogger APIs in script blocks, no scancode-map/keyboard-filter registry tampering, no keylogger service installed. |
| T1056.002 GUI Input Capture | malicious | Invoke-ScreenCapture PowerShell loop using System.Windows.Forms/CopyFromScreen captured the interactive desktop every 300s on SCRANTON. |
| T1056.003 Web Portal Capture | not_observed | No IIS/wwwroot page creation, no web-shell or fake login page scripts, no object access to web roots. |
| T1056.004 Credential API Hooking | malicious | PowerShell.exe (SCRANTON) and wsmprovhost.exe (NASHUA) opened lsass.exe/winlogon.exe with 0x1f3fff/0x1fffff and an UNKNOWN call-trace module, indicating in-memory credential API access. |
| T1110 Brute Force | not_observed | Zero 4625/4740/4771 events in windows.security; the only 4776 NTLM validation succeeded (Status 0x0). No authentication-failure or lockout telemetry indicating brute force. |
| T1110.001 Password Guessing | not_observed | No hydra/ncrack/medusa command lines and no failed logons. PowerShell 'Password' hits are certificate .pfx export and 7-Zip archive encryption on scranton.dmevals.local, not password guessing. |
| T1110.002 Password Cracking | not_observed | No reg save/ntdsutil/vssadmin, no hashcat/john/Invoke-Mimikatz, no hive or NTDS dumps (only WER crash dumps). SAM 4663 accesses are by lsass.exe under SCRANTON$; the PowerShell LSASS handle open (0x1fffff) is memory cred… |
| T1110.003 Password Spraying | not_observed | All 4648 explicit-credential logons are the single account pbeesly (scranton->NASHUA and PSEXESVC on nashua), with no failures or lockouts — lateral movement with one known credential, not spraying across many accounts. |
| T1110.004 Credential Stuffing | not_observed | No curl/wget/Invoke-WebRequest credential submission and no 4625 events; the only hardcoded credential use is a single WebDAV mapping for exfiltration, not stuffing of many credential pairs. |
| T1111 Multi-Factor Authentication Interception | not_observed | No smartcard/SCardSvr/VaultSvc/credential-provider activity in any dataset: security-wide search for smartcard/vault/credential/NGC object, service and process names returned 0 hits, and the windows.other scardsvr/vaults… |
| T1187 Forced Authentication | benign | The WebDAV/SMB and NTLM hits are explained without forced authentication: the WebDAV traffic to 192.168.0.4 is the exfil upload leg of Invoke-Exfil, which supplies explicit credentials (cozy / MyCozyPassw0rd!) via New-PS… |
| T1212 Exploitation for Credential Access | malicious | On scranton.dmevals.local an attacker-controlled hidden PowerShell session (PID 2976, spawned by control.exe, decoding a payload from monkey.png) opened lsass.exe with GrantedAccess 0x1fffff/0x1f3fff, alongside offensive… |
| T1539 Steal Web Session Cookie | suspicious | On scranton.dmevals.local, PowerShell.exe (PID 2976, SYSTEM) opened MicrosoftEdge.exe/EdgeCP/EdgeSH with GrantedAccess 0x1fffff and an UNKNOWN-module call trace at 03:05:17Z, during a malicious pbeesly session (steganogr… |
| T1552 Unsecured Credentials | malicious | Unsecured credential material (plaintext domain password in PsExec command line, hardcoded pfx password, registry-stored payload) was used and re-used across SCRANTON and NASHUA. |
| T1552.001 Credentials In Files | malicious | PsExec64.exe used with cleartext password Fl0nk3rt0n!T0by to reach NASHUA, and the NASHUA python.exe/PowerShell chain harvested *pass*/*psw*/*login*/*admin*/*vpn* files into a password-protected RAR. |
| T1552.002 Credentials in Registry | malicious | hostui.exe (runas) spawned PowerShell reading HKLM\SOFTWARE\Javasoft 'value Supplement' and piping it to Invoke-Expression. |
| T1552.003 Shell History | not_observed | No PSReadLine/ConsoleHost_history/.bash_history file creation, process command line or 4663 access was found in any dataset. |
| T1552.004 Private Keys | malicious | Get-PrivateKeys exported every LocalMachine certificate to Downloads\<random>.pfx with hardcoded password 'saribas', followed by Invoke-BeachCleanup deleting the .pfx files. |
| T1552.006 Group Policy Preferences | not_observed | No Groups.xml/cpassword/gpprefdecrypt activity in PowerShell, Sysmon or Security; zeek SMB only shows gpt.ini and GptTmpl.inf reads on sysvol with no GPP credential file access. |
| T1555 Credentials from Password Stores | malicious | PowerShell.exe (PID 2976) on scranton opened lsass.exe with 0x1f3fff/0x1fffff at 03:05:16 UTC and wsmprovhost.exe (PID 7720) on nashua opened lsass.exe with 0x1f3fff at 03:09:29 UTC, both under user pbeesly, corroborated… |
| T1555.003 Credentials from Web Browsers | not_observed | No hits for browser credential files (Login Data, logins.json, key4.db, Cookies, Web Data) in sysmon, security or PowerShell telemetry; only a benign svchost INetCookies write. |
| T1555.004 Windows Credential Manager | not_observed | No vault/cmdkey/credential API usage, no file writes to \Microsoft\Credentials or \Microsoft\Vault; only a routine Credential Guard configuration event. |
| T1555.005 Password Managers | not_observed | No KeePass/1Password/Bitwarden/LastPass process, file or script activity found in any dataset. |
| T1556 Modify Authentication Process | malicious | PowerShell.exe (PID 2976, user pbeesly) on scranton.dmevals.local opened lsass.exe and winlogon.exe with 0x1fffff/0x1f3fff and an UNKNOWN call-trace module at 03:05:16-03:05:17, inside a hands-on session that also instal… |
| T1556.001 Domain Controller Authentication | benign | Logon process names are normal (Kerberos/Advapi/User32/NtLmSsp), network logons are machine accounts plus pbeesly, and no 4739 or lsass/cryptdll script activity exists; no DC authentication modification seen. |
| T1556.002 Password Filter DLL | not_observed | No password-filter DLL written to System32, no Notification Packages/PasswordFilter registry change, and only legitimate NotificationController DLLs loaded. |
| T1556.005 Reversible Encryption | not_observed | No 4739, no Reversible object access, no Set-ADUser/ADAccountControl command lines; the single script-block hit is a TimeSpan validation fragment. |
| T1556.006 Multi-Factor Authentication | not_observed | Event 4739 is absent from both windows.security and windows.other; no MFA policy change recorded. |
| T1556.007 Hybrid Identity | not_observed | No 5136 directory modifications and no adfs/azuread script content; 5058/5061 events are routine KSP key opens by pbeesly and NEWYORK$. |
| T1556.008 Network Provider DLL | not_observed | No NetworkProvider registry/file/4657 activity; winlogon handles come from system processes, with the anomalous PowerShell/wsmprovhost full-access handles reported under T1556. |
| T1557 Adversary-in-the-Middle | suspicious | Only AiTM-relevant signal is the Zeek shared-MAC anomaly (12:34:56:78:9a:bc answering for 10.0.0.4, 10.0.1.6 and 192.168.0.4 concurrently from 00:30Z on 2020-04-30); no Windows-side corroboration possible because the Zee… |
| T1557.001 Name Resolution Poisoning and SMB Relay | benign | DNS/LLMNR lookups resolved normally to correct internal IPs, wpad returned NXDOMAIN, SMB 445/139 connections were RSTO/REJ with no relay authentication, and the only NTLM network logon (pbeesly from 172.18.39.2) was Logo… |
| T1557.002 ARP Cache Poisoning | suspicious | One MAC (12:34:56:78:9a:bc) is recorded as responder for four distinct IPs including the DC 10.0.0.4 and NASHUA 10.0.1.6, with three IPs answered in the same 5-minute buckets from 00:30Z; consistent with ARP cache poison… |
| T1557.003 DHCP Spoofing | not_observed | No DHCP server/client configuration events (1341/1342/1020/1063) in windows.other; only 3 routine ipconfig.exe executions and a built-in xDNSServerAddress DSC scriptblock run by SYSTEM on newyork. |
| T1558 Steal or Forge Kerberos Tickets | suspicious | No Kerberos ticket theft/forging was observed, but the credential-access precondition was met: attacker-launched hidden PowerShell (PID 2976) on scranton.dmevals.local opened lsass.exe with 0x1F3FFF/0x1FFFFF, i.e. LSASS … |
| T1558.001 Golden Ticket | not_observed | All 4768/4769 events are normal pre-authenticated AES256 TGT/TGS for pbeesly and machine accounts with Status 0x0; no krbtgt/DCSync/mimikatz strings in PowerShell or windows.other, no forged-ticket logon anomalies. |
| T1558.002 Silver Ticket | not_observed | Service-ticket requests are routine machine-account TGS (SCRANTON$->NEWYORK$/WEC$, pbeesly->NASHUA$) with AES256 and Status 0x0; no silver/kerberoast/SPN tooling strings and no anomalous service-account network logons. |
| T1558.003 Kerberoasting | not_observed | No bulk RC4 (0x17) 4769 requests for distinct SPNs; all 4769 use 0x12, and Zeek shows only 11 successful aes256 TGS requests from pbeesly. No kerberoasting tooling in script blocks. |
| T1558.004 AS-REP Roasting | not_observed | Every AS exchange shows KDC_ERR_PREAUTH_REQUIRED followed by a successful pre-authenticated AS-REP; all 4768 have PreAuthType 2. No AS-REP roasting tooling or messages found. |
| T1606 Forge Web Credentials | not_observed | No forged web-credential artefacts. The high-privilege LSASS handles (PowerShell.exe 0x1fffff on scranton, wsmprovhost.exe 0x1f3fff on nashua) indicate credential enumeration/harvesting, not token forgery; 4624 stacks ar… |
| T1606.001 Web Cookies | not_observed | Only cookie-related file event is a LocalService INetCookies write by svchost.exe on scranton; no user browser cookie/Login Data/Web Data access and no cookie-referencing script blocks. |
| T1606.002 SAML Tokens | not_observed | Zero hits for ADFS/SAML strings in windows.other and for token/saml file creations in sysmon; no SAML token forging evidence. |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | 6 planned checks, all with zero hits |
| T1649 Steal or Forge Authentication Certificates | malicious | On scranton.dmevals.local, user pbeesly ran a 'Get-PrivateKeys' PowerShell function (staged as C:\Program Files\SysinternalsSuite\readme.ps1) that recursively exported every cert:\LocalMachine certificate with a private … |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 5 hits | 0 hits | 5797 hits | 39730 hits | n/a |
| T1003.001 LSASS Memory | 7 hits | 0 hits | 947 hits | 981 hits | n/a |
| T1003.002 Security Account Manager | 7 hits | 4 hits | 6 hits | 3 hits | n/a |
| T1003.003 NTDS | 9 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.004 LSA Secrets | 7 hits | 0 hits | 0 hits | 517 hits | n/a |
| T1003.005 Cached Domain Credentials | 7 hits | 0 hits | 0 hits | 24319 hits | n/a |
| T1003.006 DCSync | 5 hits | 0 hits | 14 hits | 326 hits | 132 hits |
| T1040 Network Sniffing | 5 hits | 0 hits | 2 hits | 2 hits | n/a |
| T1056 Input Capture | n/a | 3 hits | 10983 hits | 470 hits | n/a |
| T1056.001 Keylogging | 5 hits | 0 hits | 10977 hits | 521 hits | n/a |
| T1056.002 GUI Input Capture | n/a | 5499 hits | 4 hits | 4 hits | n/a |
| T1056.003 Web Portal Capture | n/a | 2 hits | 0 hits | 8 hits | n/a |
| T1056.004 Credential API Hooking | 0 hits | 2 hits | 13 hits | 59870 hits | n/a |
| T1110 Brute Force | 2 hits | 4 hits | 0 hits | 31 hits | 613 hits |
| T1110.001 Password Guessing | 2 hits | 2 hits | 0 hits | 0 hits | 45 hits |
| T1110.002 Password Cracking | 1 hits | 0 hits | 15461 hits | 328 hits | 12 hits |
| T1110.003 Password Spraying | 2 hits | 4 hits | 15 hits | 1 hits | 35 hits |
| T1110.004 Credential Stuffing | 4 hits | 3 hits | 0 hits | 0 hits | 613 hits |
| T1111 Multi-Factor Authentication Interception | 0 hits | 4 hits | 312 hits | 652 hits | 42 hits |
| T1187 Forced Authentication | 1 hits | 0 hits | 252 hits | 69 hits | 148 hits |
| T1212 Exploitation for Credential Access | 0 hits | 0 hits | 483 hits | 652 hits | 648 hits |
| T1539 Steal Web Session Cookie | 0 hits | 0 hits | 0 hits | 162 hits | 124 hits |
| T1552 Unsecured Credentials | 2 hits | 0 hits | 16 hits | 17 hits | 68 hits |
| T1552.001 Credentials In Files | 1 hits | 1 hits | 15 hits | 46 hits | 12 hits |
| T1552.002 Credentials in Registry | 2 hits | 5 hits | 0 hits | 17 hits | n/a |
| T1552.003 Shell History | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1552.004 Private Keys | 0 hits | 2 hits | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1555 Credentials from Password Stores | 0 hits | 0 hits | 29 hits | 653 hits | n/a |
| T1555.003 Credentials from Web Browsers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1555.004 Windows Credential Manager | 2 hits | 3 hits | 0 hits | 326 hits | n/a |
| T1555.005 Password Managers | 14 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556 Modify Authentication Process | 0 hits | 0 hits | 0 hits | 739 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | 0 hits | 530 hits | 359 hits | n/a |
| T1556.002 Password Filter DLL | 5 hits | 0 hits | 0 hits | 10 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 1 hits | 0 hits | 0 hits | n/a |
| T1556.006 Multi-Factor Authentication | 0 hits | 0 hits | 41002 hits | n/a | n/a |
| T1556.007 Hybrid Identity | 0 hits | 0 hits | 0 hits | 20259 hits | n/a |
| T1556.008 Network Provider DLL | 0 hits | n/a | 0 hits | 144 hits | n/a |
| T1557 Adversary-in-the-Middle | 0 hits | 0 hits | 10977 hits | 1310 hits | 100 hits |
| T1557.001 Name Resolution Poisoning and SMB Relay | 0 hits | 4 hits | 241 hits | 147 hits | 52 hits |
| T1557.002 ARP Cache Poisoning | 0 hits | 0 hits | 218 hits | 1310 hits | 1226 hits |
| T1557.003 DHCP Spoofing | 216 hits | 2 hits | 297 hits | 3 hits | n/a |
| T1558 Steal or Forge Kerberos Tickets | 1 hits | 0 hits | 509 hits | 652 hits | 70 hits |
| T1558.001 Golden Ticket | 0 hits | 0 hits | 448 hits | 326 hits | 70 hits |
| T1558.002 Silver Ticket | 36 hits | 0 hits | 430 hits | 326 hits | 105 hits |
| T1558.003 Kerberoasting | 1 hits | 0 hits | 509 hits | 326 hits | 53 hits |
| T1558.004 AS-REP Roasting | 0 hits | 0 hits | 515 hits | 0 hits | 84 hits |
| T1606 Forge Web Credentials | 5 hits | 3 hits | 609 hits | 39283 hits | 186 hits |
| T1606.001 Web Cookies | 0 hits | 0 hits | 15 hits | 163 hits | 186 hits |
| T1606.002 SAML Tokens | 0 hits | 1 hits | 312 hits | 0 hits | 186 hits |
| T1621 Multi-Factor Authentication Request Generatio… | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1649 Steal or Forge Authentication Certificates | 0 hits | 1 hits | 100 hits | 1 hits | n/a |

Cells: 265, gaps: 0.

## Queries

Every MCP tool call of this run (1297), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-2e572fb75c | scope | list_data_sources | {} | None |  |
| q-f08f56abba | scope | get_registry | {} | None |  |
| q-aa2740751e | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-13940d8ca6 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-d9283e0012 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-9bb1c2e23d | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-d0371e4ca3 | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-daa8f50c67 | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-00da0bc92e | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-3b42acf818 | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5337 |  |
| q-eb27dbcade | check C004 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-a4e8558bb8 | check C005 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*procdump* OR win.ScriptBlockText:*MiniDump*)", "time_from": null, "time_to"… | 0 |  |
| q-185cc0200a | check C006 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-f751335ce5 | check C007 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-11ab164e91 | check C008 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-52d90abbdf | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-db54f2cf19 | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*lsass* OR win.TargetFilename:*.dmp)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 2 |  |
| q-d6f809ee0e | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 1 |  |
| q-c4f13c49b1 | check C012 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 934 |  |
| q-db18af072e | check C013 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 13 |  |
| q-81b6453b56 | check C014 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-fdf2b637ae | check C015 | search | {"dataset": "windows.other", "query": "event.code:10 OR event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source… | 7 |  |
| q-bdea748046 | check C016 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SECURITY* OR win.TargetFilename:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "… | 3 | F04 |
| q-6732e3a216 | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg\\ save* OR process.command_line:*reg.exe* OR process.command_line:*save*HKLM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-7a5ffa934a | check C018 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proce… | 0 |  |
| q-4a048733da | check C019 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*save*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 6 |  |
| q-6f48f37fd6 | check C020 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-61990eb068 | check C021 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*reg* AND win.ScriptBlockText:*save* OR win.ScriptBlockText:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset"… | 4 |  |
| q-65bbed0227 | check C022 | search | {"dataset": "windows.other", "query": "event.code:11 OR event.code:1", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 7 |  |
| q-9d8e8bd212 | check C023 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-8fe819a200 | check C024 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*ntdsutil* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-40915755e4 | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND win.TargetFilename:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 0 |  |
| q-3032f12921 | check C026 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*ntdsutil* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "size": 100, "sub_fie… | 0 |  |
| q-12840c8962 | check C027 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectName:*ntds*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-16d4417261 | check C028 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ntds* OR win.ScriptBlockText:*vssadmin* OR win.ScriptBlockText:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-6cd0406400 | check C029 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 9 |  |
| q-2d99e32782 | check C030 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*services*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 506 |  |
| q-8a30c741c6 | check C031 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*secrets* OR win.ImageLoaded:*vault*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 7 |  |
| q-d2357f2764 | check C032 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*secrets* OR process.command_line:*lsadump* OR process.command_line:*cache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 4 |  |
| q-595089d598 | check C033 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SECURITY*Policy*Secrets* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-aed021e03e | check C034 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4656 AND win.ObjectName:*SECURITY*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-d7f9393c2b | check C035 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsadump* OR win.ScriptBlockText:*Secrets* OR win.ScriptBlockText:*vault*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-9343a88f9d | check C036 | search | {"dataset": "windows.other", "query": "event.code:10 OR event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source… | 7 |  |
| q-fe732e999a | check C037 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*svchost*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 24315 |  |
| q-1710183715 | check C038 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*dcc* OR process.command_line:*mscache* OR process.command_line:*lsadump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name"… | 4 |  |
| q-52b5e05853 | check C039 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SECURITY*Cache* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-1782d5fedd | check C040 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4656 AND win.ObjectName:*SECURITY*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-769aad6cc5 | check C041 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*mscache* OR win.ScriptBlockText:*cache* OR win.ScriptBlockText:*dcc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 0 |  |
| q-4ab95c4854 | check C042 | search | {"dataset": "windows.other", "query": "event.code:10 OR event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source… | 7 |  |
| q-00d04d9a2a | check C043 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-361d3029e0 | check C044 | aggregate | {"dataset": "windows.security", "field": "win.Properties", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-17f6e7bb2a | check C045 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*ntds*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-fbc7c1fc96 | check C046 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-83d9ea49a8 | check C047 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*DCSync* OR win.ScriptBlockText:*DirectorySearcher* OR win.ScriptBlockText:*Get-ADReplAccount* OR win.ScriptBlockText:*lsass*)", "time_from": null, "time_to": null, "fields": … | 0 |  |
| q-dd48488b55 | check C048 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*pcap* OR process.command_line:*netsh* OR process.command_line:*promisc* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR p… | 2 |  |
| q-e0fa2ba50f | check C049 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F07 |
| q-3885304cc3 | check C050 | aggregate | {"dataset": "windows.sysmon", "field": "win.Image", "query": "event.code:1 AND (process.command_line:*pcap* OR process.command_line:*netsh* OR process.command_line:*promisc* OR process.command_line:*windump* OR process.command_line:*tcpdump*)", "time_from": nu… | 2 |  |
| q-6772c7016e | check C051 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*pcap* OR win.ScriptBlockText:*promisc* OR win.ScriptBlockText:*NetSh* OR win.ScriptBlockText:*WinDivert*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 0 |  |
| q-57345a8695 | check C052 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon* OR win.TargetImage:*explorer*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 470 |  |
| q-3cfc70e53a | check C053 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-1ed2840371 | check C054 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*Credential*)", "time_from": null, "time_to": null, "size": 50, "sub_fie… | 6 |  |
| q-337142d3d0 | check C055 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*SetWindowsHookEx* OR win.ScriptBlockText:*GetKeyboardState* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": nul… | 3 |  |
| q-3222d00c0e | check C056 | aggregate | {"dataset": "windows.sysmon", "field": "win.Image", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon* OR win.TargetImage:*csrss*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 495 |  |
| q-762749ad92 | check C057 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*Scancode* OR registry.path:*CurrentControlSet\\\\Control\\\\Keyboard*)", "time_from": null, "time_to": null, "size": 50, "sub_field"… | 26 |  |
| q-230afcc6d0 | check C058 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-bd3cec09f2 | check C059 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F10 |
| q-c0e675606d | check C060 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*SetWindowsHookEx* OR win.ScriptBlockText:*keylog*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obse… | 0 |  |
| q-f700cac20b | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*consent* OR process.command_line:*UAC* OR process.command_line:*runas*)", "time… | 4 |  |
| q-b219dd4ca7 | check C062 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*PromptForCredential* OR win.ScriptBlockText:*Get-Credential* OR win.ScriptBlockText:*Windows.Forms*)", "time_from": null, "time_to": null,… | 5 | F09 |
| q-600e8ccc97 | check C063 | search | {"dataset": "windows.powershell", "query": "event.code:4103 OR event.code:4104", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 5494 |  |
| q-4ea1e800af | check C064 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*consent* OR process.command_line:*runas*)", "time_from": null, "time_to": null, "size": 50, "sub_field": nu… | 4 |  |
| q-68d2d979bb | check C065 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*login* OR win.TargetFilename:*logon* OR win.TargetFilename:*credential* OR win.TargetFilename:*wwwroot* OR win.TargetFilename:*.aspx OR win.TargetFile… | 8 |  |
| q-f0c1cb14ef | check C066 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*wwwroot* OR process.command_line:*inetpub* OR process.command_line:*iis*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a70ed4a121 | check C067 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*wwwroot* OR win.ScriptBlockText:*inetpub* OR win.ScriptBlockText:*login* OR win.ScriptBlockText:*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 2 |  |
| q-042dd15a00 | check C068 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*wwwroot* OR win.ObjectName:*inetpub*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-64876bc4f1 | check C069 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-8d1977bed8 | check C070 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a8809506a9 | check C071 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-7c2c3888d2 | check C072 | search | {"dataset": "windows.sysmon", "query": "event.code:8 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 2 |  |
| q-2aa83bf21b | check C073 | aggregate | {"dataset": "windows.security", "field": "win.CallerProcessName", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-40f505ea93 | check C074 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*VirtualProtect* OR win.ScriptBlockText:*GetProcAddress*)", "time_from": null, "time_to": null, "fields": ["@t… | 2 |  |
| q-d641713b58 | check C075 | search | {"dataset": "windows.other", "query": "message:*lsass* OR process.executable:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 0 |  |
| q-c781144078 | check C076 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c00ddf1fc6 | check C077 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-cd8318b6ce | check C078 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-cc2fbfdc62 | check C079 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*user* OR process.command_line:*password*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 31 |  |
| q-f9d90b57da | check C080 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Brute* OR win.ScriptBlockText:*Password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 4 |  |
| q-8adc11ba36 | check C081 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 2 | F12 |
| q-0eab1c4b3c | check C082 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-a34be9e526 | check C083 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c92de2b78a | check C084 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-629d191d75 | check C085 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*hydra* OR process.command_line:*ncrack* OR process.command_line:*medusa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 0 |  |
| q-8f612bc120 | check C086 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.na… | 2 |  |
| q-a4511f42d2 | check C087 | search | {"dataset": "windows.other", "query": "message:*4625* OR message:*failed*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 2 |  |
| q-fb83aa440d | check C088 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn AND destination.port:445", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 45 |  |
| q-f324daae96 | check C089 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-17c7af81bb | check C090 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SYSTEM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*ntds*)", "time_from": null, "time_to": null, "size": 50, "sub_field": nul… | 4484 |  |
| q-6079fc805f | check C091 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg*save* OR process.command_line:*ntdsutil* OR process.command_line:*vssadmin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-42dbadd783 | check C092 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.dit OR win.TargetFilename:*.hiv OR win.TargetFilename:*.dmp)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2 |  |
| q-571009fc78 | check C093 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-55b867f5b5 | check C094 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*hashcat* OR win.ScriptBlockText:*john* OR win.ScriptBlockText:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-74dff33e93 | check C095 | search | {"dataset": "windows.other", "query": "message:*SAM* OR message:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 1 | F14 |
| q-92c891e2b2 | check C096 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-2fd976417c | check C097 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-484e825768 | check C098 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-f1ad7df23c | check C099 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-18e8a96a19 | check C100 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*runas* OR process.command_line:*net*use*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 1 |  |
| q-4e32e79350 | check C101 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 4 | F16 |
| q-e9117090ca | check C102 | search | {"dataset": "windows.other", "query": "message:*lockout* OR message:*logon*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 2 |  |
| q-b455f74ede | check C103 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-33fbe92781 | check C104 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-6418ceb2ea | check C105 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-2901e095a2 | check C106 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-13c28f80e8 | check C107 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*curl* OR process.command_line:*Invoke-WebRequest* OR process.command_line:*wget*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-9465213119 | check C108 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-WebRequest* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.n… | 3 |  |
| q-286865e93e | check C109 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*failed*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 4 |  |
| q-b9e71d5b55 | check C110 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-7abad5f502 | check C111 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*smartcard* OR win.TargetImage:*scardsvr* OR win.TargetImage:*vaultsvc*)", "time_from": null, "time_to": null, "size": 50, "sub_… | 326 |  |
| q-32e09d4060 | check C112 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-28fb3c471f | check C113 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-e0e3098e21 | check C114 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-6570312233 | check C115 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*smartcard* OR *scardsvr* OR *vault* OR *Credential* OR *MFA* OR *token*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 4 |  |
| q-54b4e08188 | check C116 | search | {"dataset": "windows.other", "query": "win.ServiceName:(*scardsvr* OR *SCardSvr* OR *VaultSvc*) OR win.ImagePath:(*scardsvr* OR *vaultsvc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.cod… | 0 |  |
| q-9f7ba9ff5a | check C117 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*\\\\*.lnk OR win.TargetFilename:*\\\\*.url OR win.TargetFilename:*\\\\*.scf OR win.TargetFilename:*\\\\*.library-ms OR win.TargetFilename:*\\\\*.searc… | 3 |  |
| q-eacf7bd9e3 | check C118 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 66 |  |
| q-10e3ae2327 | check C119 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4663 OR 4656 OR 4670) AND win.ObjectType:*File*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 34 |  |
| q-fa0000af16 | check C120 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 218 |  |
| q-5f1e527496 | check C121 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*WebDAV* OR *\\\\@SSL* OR *DavWWWRoot* OR *net use* OR *Invoke-WebRequest*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 0 |  |
| q-36fe4357fe | check C122 | search | {"dataset": "windows.other", "query": "win.Message:(*WebDAV* OR *DavWWWRoot* OR *NTLM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 1 |  |
| q-9d9a7c6060 | check C123 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-bfecad0851 | check C124 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-cb058f58b2 | check C125 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4697 OR event.code:7045", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 23 |  |
| q-92ee2778fe | check C126 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-2804656f41 | check C127 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*Invoke-Mimikatz* OR *sekurlsa* OR *lsass* OR *MiniDump* OR *procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 0 |  |
| q-76387cd787 | check C128 | search | {"dataset": "windows.other", "query": "win.Message:(*lsass* OR *MiniDump* OR *procdump* OR *Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-24a96f80b8 | check C129 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*Web Data*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 162 |  |
| q-7d1a8684d2 | check C130 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*chrome* OR win.TargetImage:*firefox* OR win.TargetImage:*msedge* OR win.TargetImage:*iexplore*)", "time_from": null, "time_to": null, "size": 50, "sub_fi… | 0 |  |
| q-173cb2943e | check C131 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:2 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-7f40ca7a3d | check C132 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*Cookies* OR process.command_line:*\"Login Data\"* OR process.command_line:*chrome* OR process.command_line:*firefox*)", "time_from": null, "time… | 0 |  |
| q-a98597f587 | check C133 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*Cookies* OR *Login Data* OR *chrome* OR *firefox* OR *sqlite*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-18cc301f44 | check C134 | search | {"dataset": "windows.other", "query": "win.Message:(*Cookies* OR *Login Data* OR *chrome* OR *firefox*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 0 |  |
| q-c49a4a13ae | check C135 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential* OR registry.path:*Secret*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17 |  |
| q-83ec9f71dd | check C136 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*\\\\SAM OR win.TargetFilename:*ntds.dit OR win.TargetFilename:*\\\\SECURITY OR win.TargetFilename:*\\\\SYSTEM OR win.TargetFilename:*unattend* OR win.… | 0 |  |
| q-bd7603cc76 | check C137 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4663 OR 4656) AND (win.ObjectName:*SAM* OR win.ObjectName:*ntds* OR win.ObjectName:*SECURITY* OR win.ObjectName:*Credential*)", "time_from": null, "time_to": null, "size": 50, "su… | 10 |  |
| q-8c6eb81815 | check C138 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*vault* OR process.command_line:*findstr* OR process.command_line:*password*)", "time_from": null, "time_to": null,… | 6 |  |
| q-7b1f916ba3 | check C139 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*password* OR *credential* OR *ConvertTo-SecureString* OR *Get-Credential* OR *reg save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datas… | 0 |  |
| q-3e4cd4e8c4 | check C140 | search | {"dataset": "windows.other", "query": "win.Message:(*password* OR *credential* OR *SAM* OR *ntds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 2 |  |
| q-b57b3d3b8f | check C141 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*password* OR win.TargetFilename:*credential* OR win.TargetFilename:*secret* OR win.TargetFilename:*.config OR win.TargetFilename:*.txt OR win.TargetFi… | 45 |  |
| q-7f6463e303 | check C142 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*findstr* OR process.command_line:*type* OR process.command_line:*Select-String* OR process.command_line:*grep*)", "time_from": null, "time_to": null,… | 1 |  |
| q-872209aa06 | check C143 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4663 OR 4656) AND (win.ObjectName:*.config OR win.ObjectName:*.txt OR win.ObjectName:*.xml OR win.ObjectName:*.ini)", "time_from": null, "time_to": null, "size": 50, "sub_field": … | 0 |  |
| q-018139780e | check C144 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-2c33b14d5c | check C145 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*Get-Content* OR *Select-String* OR *findstr* OR *password* OR *.config*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 1 |  |
| q-22217d9a02 | check C146 | search | {"dataset": "windows.other", "query": "win.Message:(*password* OR *.config* OR *credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 1 |  |
| q-6dd3247cac | check C147 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*password* OR registry.path:*Credential* OR registry.path:*credential*)", "time_from": null, "time_to": null, "size": 50, "sub_field"… | 17 |  |
| q-53b5953dfe | check C148 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg*query* OR process.command_line:*reg.exe*query* OR process.command_line:*Password* OR process.command_line:*credential*)", "time_from": null, "time_to": null, "fields": ["@times… | 0 |  |
| q-2446eabb2e | check C149 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*reg*query* OR win.ScriptBlockText:*HKLM*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 5 |  |
| q-cd4e51cc16 | check C150 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Password* OR win.ObjectName:*Credential* OR win.ObjectName:*SAM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0677fb9049 | check C151 | search | {"dataset": "windows.other", "query": "message:*Password* OR message:*Credential* OR win.Message:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execut… | 2 |  |
| q-22e12c5a4a | check C152 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*history* OR win.ScriptBlockText:*Get-History* OR win.ScriptBlockText:*ConsoleHost_history* OR win.ScriptBlockText:*PSReadLine*)", "time_from": null, "time_to": null, "fields"… | 0 |  |
| q-c496cba559 | check C153 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ConsoleHost_history* OR process.command_line:*PSReadLine* OR process.command_line:*Get-History* OR process.command_line:*.bash_history*)", "time_from": null, "time_to": null, "fiel… | 0 |  |
| q-ec78b50fad | check C154 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*ConsoleHost_history* OR file.path:*.bash_history* OR file.path:*PSReadLine*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a1ce18c957 | check C155 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*ConsoleHost_history* OR win.ObjectName:*.bash_history* OR win.ObjectName:*PSReadLine*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null… | 0 |  |
| q-8ee3380d08 | check C156 | search | {"dataset": "windows.other", "query": "message:*history* AND (message:*PSReadLine* OR message:*ConsoleHost*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 0 |  |
| q-339c8375fb | check C157 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*.key OR file.path:*.pem OR file.path:*.pfx OR file.path:*.p12 OR file.path:*.ppk OR file.path:*.pgp OR file.path:*.gpg OR file.path:*.cer OR file.path:*.p7b OR file.pat… | 1 |  |
| q-08a1780382 | check C158 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*.pfx* OR process.command_line:*.pem* OR process.command_line:*.key* OR process.command_line:*.ppk* OR process.command_line:*certutil*)", "time_from": null, "time_to": null, "fields… | 0 |  |
| q-0fa40abb7f | check C159 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*.key OR win.RelativeTargetName:*.pem OR win.RelativeTargetName:*.pfx OR win.RelativeTargetName:*.p12 OR win.RelativeTargetName:*.ppk)", "t… | 0 |  |
| q-e5e330162e | check C160 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*.pfx OR win.ObjectName:*.pem OR win.ObjectName:*.key OR win.ObjectName:*.p12)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-dd94b14a29 | check C161 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*.pfx* OR win.ScriptBlockText:*.pem* OR win.ScriptBlockText:*.ppk* OR win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*certutil*)", "time_from": null, "time… | 2 |  |
| q-87c3518c8e | check C162 | search | {"dataset": "windows.other", "query": "message:*.pfx* OR message:*.pem* OR message:*.ppk* OR message:*.p12*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execut… | 0 |  |
| q-5713c0f6b8 | check C163 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Groups.xml* OR win.ScriptBlockText:*cpassword* OR win.ScriptBlockText:*gpprefdecrypt* OR win.ScriptBlockText:*SYSVOL* OR win.ScriptBlockText:*AES*)", "time_from": null, "time… | 0 |  |
| q-38a778f1d1 | check C164 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*Groups.xml* OR win.RelativeTargetName:*SYSVOL* OR win.RelativeTargetName:*.xml)", "time_from": null, "time_to": null, "size": 50, "sub_fie… | 0 |  |
| q-944eb2aef8 | check C165 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*SYSVOL* OR process.command_line:*Groups.xml* OR process.command_line:*cpassword* OR process.command_line:*gpprefdecrypt*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-a5e8672007 | check C166 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Groups.xml* OR file.path:*SYSVOL* OR file.path:*cpassword*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-af7548bea0 | check C167 | search | {"dataset": "windows.other", "query": "message:*SYSVOL* OR message:*Groups.xml* OR message:*cpassword*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-7ef301003a | check C168 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*LSASS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-2c44936743 | check C169 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*LSASS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-913d6f3892 | check C170 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*procdump* OR process.command_line:*mimikatz* OR process.command_line:*sekurlsa* OR process.command_line:*comsvcs*MiniDump*)", "time_from": null, "ti… | 1 |  |
| q-9abd9e2d21 | check C171 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-0fbe3a6fa6 | check C172 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 23 |  |
| q-6572bb29cc | check C173 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timest… | 0 |  |
| q-2f9baa93dc | check C174 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*MiniDump* OR message:*mimikatz*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-2000249214 | check C175 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Login Data* OR file.path:*logins.json* OR file.path:*key4.db* OR file.path:*Cookies* OR file.path:*Web Data*)", "time_from": null, "time_to": null, "size": 50, "sub_fie… | 0 |  |
| q-6a33775406 | check C176 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Login Data* OR process.command_line:*logins.json* OR process.command_line:*key4.db* OR process.command_line:*Cookies*)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 0 |  |
| q-2aa06f3c5f | check C177 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Login Data* OR win.ObjectName:*logins.json* OR win.ObjectName:*key4.db* OR win.ObjectName:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "su… | 0 |  |
| q-c523f2af9c | check C178 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4656 AND (win.ObjectName:*Login Data* OR win.ObjectName:*logins.json* OR win.ObjectName:*key4.db*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c12e74ed34 | check C179 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*logins.json* OR win.ScriptBlockText:*key4.db* OR win.ScriptBlockText:*DPAPI*)", "time_from": null, "time_to": null, "fields": ["@timestamp… | 0 |  |
| q-e984f99337 | check C180 | search | {"dataset": "windows.other", "query": "message:*Login Data* OR message:*logins.json* OR message:*key4.db*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 0 |  |
| q-cb32fcf272 | check C181 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*vault* OR process.command_line:*credential* OR process.command_line:*cmdkey* OR process.command_line:*CredMan*)", "time_from": null, "time_to": null,… | 0 |  |
| q-5caa0999a4 | check C182 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*vault* OR win.TargetImage:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 326 | F29 |
| q-0cbfd48f03 | check C183 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*\\Microsoft\\Credentials\\* OR win.TargetFilename:*\\Microsoft\\Vault\\* OR win.TargetFilename:*\\Protect\\*)", "time_from": null, "time_to": null, "s… | 0 |  |
| q-dfebb81d95 | check C184 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*cmdkey* OR process.command_line:*credential*)", "time_from": null, "time_to": null, "size": 50, "sub_field": nul… | 0 |  |
| q-b809315f5e | check C185 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*vault* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 3 | F31 |
| q-c9f9643e73 | check C186 | search | {"dataset": "windows.other", "query": "message:*Vault* OR message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 | F31 |
| q-aa57ea744c | check C187 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*lastpass* OR process.command_line:*password… | 0 |  |
| q-a5221e27a5 | check C188 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.kdbx OR win.TargetFilename:*1password* OR win.TargetFilename:*keepass* OR win.TargetFilename:*bitwarden*)", "time_from": null, "time_to": null, "size… | 0 |  |
| q-cc7fbefc9c | check C189 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*bitwarden* OR win.TargetImage:*lastpass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 0 |  |
| q-b3d49beddf | check C190 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*lastpass*)", "time_from": null, "time_… | 0 |  |
| q-cc54f5945e | check C191 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*keepass* OR win.ScriptBlockText:*1password* OR win.ScriptBlockText:*bitwarden* OR win.ScriptBlockText:*.kdbx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 0 |  |
| q-942106f18f | check C192 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*1password* OR message:*bitwarden* OR message:*password manager*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 14 | F32 |
| q-7ba59dddc8 | check C193 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-f381c481d3 | check C194 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-2e73d7536f | check C195 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*ntds*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 87 |  |
| q-bd44ba50ea | check C196 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657 AND (win.ObjectName:*SAM* OR win.ObjectName:*lsass* OR win.ObjectName:*cryptdll* OR win.ObjectName:*Notification Packages*)", "time_from": null, "time_to": null, "size": 50, "… | 0 |  |
| q-f27ca07f03 | check C197 | aggregate | {"dataset": "windows.security", "field": "win.TargetProcessName", "query": "event.code:4663 AND win.TargetProcessName:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-54db512dea | check C198 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*MiniDump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-bacd12a525 | check C199 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-f16eba1300 | check C200 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-28b0a06694 | check C201 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 33 |  |
| q-156368ab51 | check C202 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-f5f289e344 | check C203 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 218 |  |
| q-e4fd68bc7b | check C204 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-a23d967334 | check C205 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*cryptdll* OR win.ScriptBlockText:*skeleton*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-a437c6719b | check C206 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*\\System32\\*.dll OR win.TargetFilename:*Notification* OR win.TargetFilename:*PasswordFilter*)", "time_from": null, "time_to": null, "size": 100, "sub… | 1 |  |
| q-3273b23693 | check C207 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*PasswordFilter* OR win.ImageLoaded:*Notification*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 9 |  |
| q-949e56d323 | check C208 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657 AND (win.ObjectName:*Notification Packages* OR win.ObjectName:*PasswordFilter* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c09e119f5c | check C209 | aggregate | {"dataset": "windows.security", "field": "win.NewValue", "query": "event.code:4657 AND win.ObjectName:*Notification Packages*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-14c673e54a | check C210 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Notification Packages* OR win.ScriptBlockText:*PasswordFilter* OR win.ScriptBlockText:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 0 |  |
| q-a64aa8e0a8 | check C211 | search | {"dataset": "windows.other", "query": "message:*Notification Packages* OR message:*PasswordFilter*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 5 | F35 |
| q-58966b232d | check C212 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*AllowReversiblePasswordEncryption* OR win.ScriptBlockText:*ReversibleEncryption* OR win.ScriptBlockText:*Set-ADAccountControl* OR win.ScriptBlockText:*Set-ADUser*)", "time_fr… | 1 | F36 |
| q-493b68ac29 | check C213 | search | {"dataset": "windows.powershell", "query": "event.code:4103 OR event.code:4104 AND win.ScriptBlockText:*ADAccount*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 0 |  |
| q-55c0220d09 | check C214 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4739 OR event.code:4663 AND win.ObjectName:*Reversible*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-88fb55d3a0 | check C215 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*ADAccountControl* OR process.command_line:*Set-ADUser*)", "time_from": null, "time_to": null, "size": 50, "sub_f… | 0 |  |
| q-f048207d76 | check C216 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*PasswordEncryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-d3804f419c | check C217 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthentication*\" OR TO_L… | ERROR |  |
| q-f3845c1370 | check C217 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthentication*\" OR TO_L… | ERROR |  |
| q-03618a1f1f | check C218 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 41002 |  |
| q-6a87314275 | check C219 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-1d393a6e69 | check C220 | search | {"dataset": "windows.other", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-a07eaff72a | check C221 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-2e793fe99f | check C222 | search | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-3a12ad61ab | check C223 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*adfs*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlockText) … | ERROR |  |
| q-541b5bc7bc | check C223 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*adfs*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.Scri… | 0 |  |
| q-f5d5c945ed | check C224 | search | {"dataset": "windows.other", "query": "event.code:5136", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-04353de9dd | check C225 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetObject", "query": "event.code:13 AND registry.path:*NetworkProvider*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-abf6ece755 | check C226 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND registry.path:*NetworkProvider*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.co… | 0 |  |
| q-77a111ec21 | check C227 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND win.TargetImage:*winlogon*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 144 |  |
| q-4c30015462 | check C228 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*NetworkProvider*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proce… | 0 |  |
| q-0539aa48a7 | check C229 | search | {"dataset": "windows.other", "query": "event.code:4657 AND win.ObjectName:*NetworkProvider*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-d1d20fa11f | check C230 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:22", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 81 |  |
| q-b32df59b4b | check C231 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-47d611e61d | check C232 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-61d4bee4ce | check C233 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-5f4bd1353a | check C234 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*a… | ERROR |  |
| q-a04c399bae | check C234 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*a… | ERROR |  |
| q-169a6a4b34 | check C235 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 81 |  |
| q-03af74d911 | check C236 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND destination.port:445", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 66 |  |
| q-5c8252d4a8 | check C237 | aggregate | {"dataset": "windows.security", "field": "win.IpAddress", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 218 |  |
| q-dc79217d30 | check C238 | search | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 23 |  |
| q-59e6947e68 | check C239 | search | {"dataset": "windows.other", "query": "event.code:4697", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-c797522dcb | check C240 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*enablemulticast*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*dnsclient*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockTex… | ERROR |  |
| q-b8b1efceeb | check C240 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*enablemulticast*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*dnsclient*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.S… | 4 | F41, F42 |
| q-f63b75921c | check C241 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-fdc50d805d | check C242 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:22", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 81 |  |
| q-7a760d3cb1 | check C243 | aggregate | {"dataset": "windows.security", "field": "win.IpAddress", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 218 |  |
| q-1d5aafe4d1 | check C244 | search | {"dataset": "windows.other", "query": "event.code:5156 OR event.code:5157", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-436e4cd2dc | check C245 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*poison*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ettercap*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*bette… | ERROR |  |
| q-5a095f9cc9 | check C245 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*poison*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ettercap*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*bette… | ERROR |  |
| q-209da4e6b6 | check C246 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-2be6656c4b | check C247 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 216 |  |
| q-b9eae500a3 | check C248 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-263eeb5a47 | check C249 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*dhcp* OR process.command_line:*ipconfig*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3 |  |
| q-2ba1b8a68a | check C250 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*Dhcp* OR *dhcp* OR *New-NetIPAddress* OR *Set-DnsClientServerAddress*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 2 |  |
| q-61d0f29e66 | check C251 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-cd74868079 | check C252 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-6f283927da | check C253 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-275201c541 | check C254 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-9fe99a2cca | check C255 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*kerberos* OR *Kerberos* OR *ticket* OR *Ticket* OR *klist* OR *mimikatz* OR *Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-5ab9552749 | check C256 | search | {"dataset": "windows.other", "query": "message:(*Kerberos* OR *kerberos* OR *ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 1 |  |
| q-270b46a4ef | check C257 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-18b71478dd | check C258 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 236 |  |
| q-599f5b801f | check C259 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-91638cba69 | check C260 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*krbtgt* OR *KRBTGT* OR *golden* OR *Golden* OR *mimikatz* OR *DCSync*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 0 |  |
| q-18dfa222a1 | check C261 | search | {"dataset": "windows.other", "query": "message:(*krbtgt* OR *KRBTGT* OR *4769* OR *ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-4fdcdc92c0 | check C262 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-3f7a6fe7a5 | check C263 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 218 |  |
| q-33e9424a3b | check C264 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-edb1aca52d | check C265 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*silver* OR *Silver* OR *kerberoast* OR *Kerberoast* OR *SPN* OR *service ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 0 |  |
| q-6cf820fb78 | check C266 | search | {"dataset": "windows.other", "query": "message:(*TGS* OR *service ticket* OR *Kerberos*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.com… | 36 |  |
| q-c146e80a95 | check C267 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 297 |  |
| q-0ead2dc3fb | check C268 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-f24e823453 | check C269 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-b3a97038a2 | check C270 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*kerberoast* OR *Kerberoast* OR *GetUserSPNs* OR *Invoke-Kerberoast* OR *SPN*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 0 |  |
| q-dedac24800 | check C271 | search | {"dataset": "windows.other", "query": "message:(*Kerberos* OR *TGS* OR *SPN*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 1 |  |
| q-e4652ddfd3 | check C272 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-0e23747011 | check C273 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 218 |  |
| q-2cdf628dea | check C274 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*asrep* OR process.command_line:*ASREP* OR process.command_line:*GetNPUsers* OR process.command_line:*rubeus*)", "time_from": null, "time_to": null, "… | 0 |  |
| q-2c635cde8b | check C275 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*asrep* OR *ASREP* OR *GetNPUsers* OR *Rubeus* OR *rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 0 |  |
| q-0b10621569 | check C276 | search | {"dataset": "windows.other", "query": "message:(*4768* OR *preauth* OR *PreAuth* OR *AS-REP*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proces… | 0 |  |
| q-a1079bbd07 | check C277 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-3d8bf128c3 | check C278 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-a25d96def6 | check C279 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-f5dd6d3ed0 | check C280 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-37399317a6 | check C281 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*token* OR win.ScriptBlockText:*cookie* OR win.ScriptBlockText:*SAML* OR win.ScriptBlockText:*certificate*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 3 | F51 |
| q-ff862d66d3 | check C282 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-29cd134158 | check C283 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-dcb89ff727 | check C284 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*Web Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 162 |  |
| q-0ffc532823 | check C285 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-8b576e3e80 | check C286 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cookie* OR win.ScriptBlockText:*Cookies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.na… | 0 |  |
| q-fe9d7403d8 | check C287 | search | {"dataset": "windows.other", "query": "event.code:11 AND (file.path:*Cookies* OR file.path:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", … | 0 |  |
| q-11646b9006 | check C288 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-18db56d9d8 | check C289 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-8c5cb733c3 | check C290 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SAML* OR win.ScriptBlockText:*token* OR win.ScriptBlockText:*ADFS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 1 |  |
| q-750a214aaa | check C291 | search | {"dataset": "windows.other", "query": "message:*ADFS* OR message:*SAML*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 0 |  |
| q-ac83827198 | check C292 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*token* OR win.TargetFilename:*saml*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-27750b316d | check C293 | count | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null} | 0 |  |
| q-e96c00dacc | check C294 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-757c31e2c4 | check C295 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-7c7bff92d4 | check C296 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MFA* OR win.ScriptBlockText:*2FA* OR win.ScriptBlockText:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-6c881d4478 | check C297 | search | {"dataset": "windows.other", "query": "message:*MFA* OR message:*multi-factor*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 0 |  |
| q-944a57d176 | check C298 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*login* OR process.command_line:*auth*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0109bd7639 | check C299 | search | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 36 |  |
| q-c3fd3412e3 | check C300 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-b3197ed971 | check C301 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 | F54 |
| q-a2edf72528 | check C302 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-c414a94b16 | check C303 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.pfx OR win.TargetFilename:*.p12 OR win.TargetFilename:*.cer OR win.TargetFilename:*.crt)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name"… | 1 | F52 |
| q-3759cf4fab | check C304 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*certutil* OR win.ScriptBlockText:*Certificate*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 1 | F52 |
| q-a8a21f3c1f | check C305 | search | {"dataset": "windows.other", "query": "message:*certificate* OR message:*Certificate*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 0 |  |
| q-175b8008b0 | check C306 | aggregate | {"dataset": "zeek", "field": "zeek.endpoint", "query": "event.action:dce_rpc", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 123 |  |
| q-7b840c012b | check C307 | search | {"dataset": "zeek", "query": "event.action:dce_rpc AND (zeek.endpoint:*drsuapi* OR zeek.endpoint:*DRSUAPI*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execut… | 9 |  |
| q-f4b52375ce | check C308 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-f036823d46 | check C309 | search | {"dataset": "zeek", "query": "event.action:kerberos AND zeek.success:false", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 7 | F17 |
| q-70c3945d06 | check C310 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:139 OR destination.port:445)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-d7a3f6f5cf | check C311 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:OPTIONS OR http.request.method:MOVE)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 |  |
| q-3d84f3fdfd | check C312 | aggregate | {"dataset": "zeek", "field": "zeek.user_agent", "query": "event.action:http", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 62 |  |
| q-e53ba6f2e9 | check C313 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-7d03712467 | check C314 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-484c702b13 | check C315 | aggregate | {"dataset": "zeek", "field": "url.domain", "query": "event.action:http", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 62 |  |
| q-3ccb3370d3 | check C316 | aggregate | {"dataset": "zeek", "field": "zeek.user_agent", "query": "event.action:http", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 62 |  |
| q-bb0aef1d93 | check C317 | aggregate | {"dataset": "zeek", "field": "zeek.filename", "query": "event.action:smb_files", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 12 |  |
| q-28f6495776 | check C318 | aggregate | {"dataset": "zeek", "field": "zeek.path", "query": "event.action:smb_mapping", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 11 |  |
| q-3603a1b1b2 | check C319 | search | {"dataset": "zeek", "query": "event.action:files AND (zeek.mime_type:*text* OR zeek.mime_type:*script*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 45 |  |
| q-49e00fc73d | check C320 | aggregate | {"dataset": "zeek", "field": "zeek.filename", "query": "event.action:smb_files", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 12 |  |
| q-f5e218d7fe | check C321 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-c0ae44c163 | check C322 | aggregate | {"dataset": "zeek", "field": "zeek.conn_state", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-ca7f6d0924 | check C323 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn AND (destination.port:5355 OR destination.port:137)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2 |  |
| q-114d2d0df1 | check C324 | aggregate | {"dataset": "zeek", "field": "zeek.conn_state", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-a1cb5da236 | check C325 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-2e01d3e5ca | check C326 | aggregate | {"dataset": "zeek", "field": "zeek.resp_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-3ae2ab814f | check C327 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-c6c2a0be50 | check C328 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-299c9c45a6 | check C329 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-efcad1a0a5 | check C330 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-44d7a0d753 | check C331 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 35 |  |
| q-e162f98a2c | check C332 | aggregate | {"dataset": "zeek", "field": "zeek.success", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 10, "sub_field": null} | 35 |  |
| q-f73e84c0af | check C333 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-15c2e26191 | check C334 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 35 |  |
| q-b7ccbe425c | check C335 | aggregate | {"dataset": "zeek", "field": "zeek.client", "query": "event.action:kerberos AND zeek.request_type:TGS", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 11 |  |
| q-03ef8e674e | check C336 | search | {"dataset": "zeek", "query": "event.action:kerberos AND zeek.error_msg:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 7 |  |
| q-1c62b942d7 | check C337 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 35 |  |
| q-ce46c35c4d | check C338 | aggregate | {"dataset": "zeek", "field": "zeek.client", "query": "event.action:kerberos AND zeek.request_type:AS", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 14 |  |
| q-cd7d214bb3 | check C339 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-ac0885ac97 | check C340 | aggregate | {"dataset": "zeek", "field": "http.request.method", "query": "event.action:http", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 62 |  |
| q-09cba53e40 | check C341 | aggregate | {"dataset": "zeek", "field": "url.domain", "query": "event.action:http", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 62 |  |
| q-9ff9de71b4 | check C342 | search | {"dataset": "zeek", "query": "event.action:http", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.ip"… | 62 |  |
| q-50da40269e | check C343 | aggregate | {"dataset": "zeek", "field": "zeek.user_agent", "query": "event.action:http", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 62 |  |
| q-2c529b6c46 | check C344 | aggregate | {"dataset": "zeek", "field": "url.domain", "query": "event.action:http", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 62 |  |
| q-7212b15a0f | check C345 | search | {"dataset": "zeek", "query": "event.action:http", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.ip"… | 62 |  |
| q-f129791809 | check C346 | aggregate | {"dataset": "zeek", "field": "url.domain", "query": "event.action:http", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 62 |  |
| q-7d5526526e | check C347 | aggregate | {"dataset": "zeek", "field": "http.request.method", "query": "event.action:http", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 62 |  |
| q-985144569f | check C348 | search | {"dataset": "zeek", "query": "event.action:http", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.ip"… | 62 |  |
| q-5baa71608e | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND NOT win.GrantedAccess:0x1000", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.SourceImage", "win.GrantedAccess", "win.CallTrace", "user.name"]… | 33 | F01 |
| q-d2c44b2944 | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.SourceImage:*PowerShell* OR win.SourceImage:*wsmprovhost* OR win.SourceImage:*wininit* OR win.SourceImage:*csrss* OR win.SourceImage:*services*)", "time_from": null, "ti… | 9 | F02 |
| q-bb31993b5d | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None | F01 |
| q-30ad65eb72 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-3254ad11dd | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-5dd570983f | triage T1003 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:11:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.Scri… | ERROR |  |
| q-9ca27e8bdf | triage T1003 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*cod.3aka3* OR process.command_line:*3aka3* OR process.executable:*victim*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.… | 2 | F03 |
| q-b43ffd7720 | triage T1003 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:03:00.000Z\" AND @timestamp <= \"2020-05-02T03:11:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.… | 87 | F05 |
| q-be31377d4f | triage T1003 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-66b6071628 | triage T1003 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyvc"} | None |  |
| q-3bb779ed4e | triage T1003 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" AND @timestamp >= \"2020-05-02T03:08:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, use… | 2 | F02 |
| q-2fad02ed6a | triage T1003 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:57.000Z\" AND @timestamp <= \"2020-05-02T03:05:20.000Z\" \| KEEP @timestamp, u… | 2 |  |
| q-62fe69e885 | triage T1003 step 6 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ObjectName", "win.ProcessName", "win.SubjectUserName", "win.AccessMask", "win.… | 13 | F01, F02 |
| q-5bd2364e09 | triage T1003 step 7 | search | {"dataset": "windows.security", "query": "event.code:4673 AND (win.ProcessName:*powershell* OR win.ProcessName:*PsExec* OR win.ProcessName:*python* OR win.ProcessName:*sdelete* OR win.ProcessName:*rundll32* OR win.ProcessName:*cmd.exe)", "time_from": null, "ti… | 46 |  |
| q-115bb99bd8 | triage T1003 step 7 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*Lsa*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ObjectName", "win.ProcessName", "win.SubjectUserName", "win.AccessMask", "win.Acce… | 1473 |  |
| q-b938a054c2 | triage T1003 step 8 | search | {"dataset": "windows.security", "query": "event.code:4673 AND win.ProcessId:0xba0", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ProcessName", "win.SubjectUserName", "win.PrivilegeList", "win.ProcessId", "win.Obj… | 2 |  |
| q-240248664a | triage T1003 step 8 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ProcessName:*cod.3aka3*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ObjectName", "win.ProcessName", "win.SubjectUserName", "win.AccessMask"], "… | 1 | F03 |
| q-1eec1cefda | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-90c9eba54d | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-cec370a1e9 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-0c631c6dce | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-ba75772393 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-dab2afb7ec | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72YQ"} | None |  |
| q-2b26a14ad9 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72YQ"} | None |  |
| q-e89671edad | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-15ef0abada | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-d6e82d127e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRapX"} | None |  |
| q-485e38ad4d | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-1762d261b8 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFDLy"} | None |  |
| q-13160a0f9d | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFDLy"} | None |  |
| q-7713b53f9e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-340e79616e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVSlm"} | None |  |
| q-be932a08ec | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b7vVsn"} | None |  |
| q-3cf55ffb41 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-ac8a70ca0d | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pcap* OR process.command_line:*netsh* OR process.command_line:*promisc* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap*)",… | 2 | F06 |
| q-d318eb949d | triage T1040 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*pcap* OR process.command_line:*netsh* OR process.command_line:*promisc* OR process.command_line:*windump* OR process.command_line:*tcpdump*)", "time_from": null, "time_to": null, "… | 2 | F06 |
| q-56dea2f5d8 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*pcap* OR win.ImageLoaded:*npf* OR win.ImageLoaded:*WinDivert* OR win.ImageLoaded:*nmnt* OR win.ImageLoaded:*Packet*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 0 |  |
| q-483f96e1b1 | triage T1040 step 2 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 60, "sub_field": null} | 460 |  |
| q-dc608bd8be | triage T1040 step 3 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.executable:*python.exe OR process.executable:*sdelete64.exe OR process.executable:*logman.exe OR process.executable:*PsExec64.exe OR process.executable:*PSEXESVC.exe)", "time_from": null, "… | 26 | F07 |
| q-67e50624b6 | triage T1040 step 3 | search | {"dataset": "windows.security", "query": "event.code:5156 AND (win.Direction:*inbound* OR win.Direction:*Inbound*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.Protocol", "win.Direction", "win.FilterName", "win… | 0 |  |
| q-1686cbcb57 | triage T1040 step 4 | search | {"dataset": "windows.sysmon", "query": "host.name:nashua.dmevals.local AND (process.executable:*python* OR win.Image:*python* OR process.command_line:*python*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.e… | 514 |  |
| q-8b1968f71c | triage T1040 step 4 | search | {"dataset": "windows.security", "query": "event.code:5156", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.Protocol", "win.Direction", "win.FilterName", "win.Application", "win.DestAddress", "win.DestPort", "win.So… | 3163 | F06 |
| q-a7af769d1a | triage T1040 step 5 | search | {"dataset": "windows.sysmon", "query": "host.name:nashua.dmevals.local AND process.executable:*python.exe AND NOT event.code:7", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "destination.ip", "de… | 420 |  |
| q-771c9b68e9 | triage T1040 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*wpcap* OR win.ImageLoaded:*Packet.dll OR win.ImageLoaded:*npf* OR win.ImageLoaded:*WinDivert* OR win.ImageLoaded:*ws2_32* OR win.ImageLoaded:*mswsock*)", "time_from": null, "time_to": n… | 241 |  |
| q-614c206d32 | triage T1040 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND host.name:nashua.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "destination.ip", "destination.port", "network.transport", "… | 428 |  |
| q-4aba49bfda | triage T1040 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5y1oY"} | None | F07 |
| q-0e385d3ff3 | triage T1040 step 7 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040 OR event.code:7036", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ServiceName", "win.ImagePath", "process.executable", "message"], "size":… | 17 |  |
| q-4aac51514b | triage T1040 step 7 | search | {"dataset": "windows.sysmon", "query": "win.TargetFilename:(*.etl OR *.pcap OR *.cap OR *npcap* OR *winpcap*) OR win.ImageLoaded:(*npcap* OR *winpcap* OR *wpcap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "proces… | 49 |  |
| q-3230d0ab8e | triage T1040 step 8 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCI"} | None | F06 |
| q-370f38434b | triage T1040 step 8 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuAu"} | None | F06 |
| q-88b253d576 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-7aa550d148 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-1f4b29cf6a | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cjZNnV"} | None |  |
| q-0a786db112 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nVnj7M"} | None |  |
| q-f8644886a3 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCI"} | None |  |
| q-9c55518cff | triage T1040 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuAu"} | None |  |
| q-28030380b3 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFTIA"} | None |  |
| q-952b8982d2 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNv3"} | None |  |
| q-c534409f01 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-3a99b8864b | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNum"} | None |  |
| q-69f1de1ecc | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5y1oY"} | None |  |
| q-01c20e4ac1 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns9wrd"} | None |  |
| q-c88940ad74 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND (TO_LOWER(win.TargetImage) LIKE \"*lsass*\" OR TO_LOWER(win.TargetImage) LIKE \"*winlogon*\" OR TO_LOWER(win.TargetImage) LIKE \"*explorer*\") AND win.GrantedAccess … | ERROR |  |
| q-aa81eec8c0 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None | F09 |
| q-0994f58710 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass*\" OR TO_LOWER(win.TargetImage) LIKE \"*winlogon*\" OR TO_LOWER(win.TargetImage) LIKE \"*explorer*\") AND win.GrantedAcc… | 500 | F11 |
| q-93e0aedfab | triage T1056 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (win.ObjectName LIKE \"*lsass*\" OR win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*SECURITY*\" OR win.ObjectName LIKE \"*Credential*\") \| KEEP @tim… | 6 | F08 |
| q-b9c29fae36 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass*\" OR TO_LOWER(win.TargetImage) LIKE \"*winlogon*\" OR TO_LOWER(win.TargetImage) LIKE \"*explorer*\") AND win.GrantedAcc… | 42 | F08 |
| q-af74e8f176 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass*\" OR TO_LOWER(win.TargetImage) LIKE \"*winlogon*\" OR TO_LOWER(win.TargetImage) LIKE \"*csrss*\") \| STATS c = COUNT(*)… | 22 |  |
| q-48368e996d | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None | F08 |
| q-9f90f7e065 | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None | F08 |
| q-812359c60d | triage T1056 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*MiniDump*\" OR win.ScriptBlockText LIKE \"*Dump*\" OR win.ScriptBlockText LIKE \"*Open… | 6 |  |
| q-7fbe448952 | triage T1056 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOWER(process.command_line) LIKE \"*keylog*\" OR TO_LOWER… | 1 |  |
| q-def9c88c59 | triage T1056 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None | F08 |
| q-a68f3173c0 | triage T1056 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRapX"} | None | F08 |
| q-96c0a158ea | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-7827b2cee1 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-1e8118c06f | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-36a9c82b89 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-ed28847b0e | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-6709291ac7 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-16f023d483 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRapX"} | None |  |
| q-75f88f187c | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yf"} | None |  |
| q-c86ccd0123 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None |  |
| q-036dd8bc67 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None |  |
| q-92f98fbe97 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitC"} | None |  |
| q-5d22af134c | triage T1056 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-1153b093cc | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOx9"} | None |  |
| q-79c99fa7e6 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None | F13 |
| q-e15eb8a659 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F13, F16 |
| q-ff2a0a9920 | triage T1110 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND process.executable LIKE \"*owerShell*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, win.… | ERROR |  |
| q-2fb26ade21 | triage T1110 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4624 \| STATS c = COUNT(*) BY win.LogonType, win.TargetUserName, host.name \| SORT c DESC \| LIMIT 40"} | ERROR |  |
| q-9e43f6d755 | triage T1110 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND process.executable LIKE \"*owerShell*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, … | 4 |  |
| q-017565a05a | triage T1110 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" \| STATS c = COUNT(*) BY win.LogonType, win.TargetUserName, host.name \| SORT c DESC \| LIMIT 40"} | 23 |  |
| q-c775a73b55 | triage T1110 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.TargetServerName, win.ProcessName, win.SubjectUserName, _id, _index"} | 15 | F15 |
| q-3f2cbf8df0 | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F14 |
| q-e99e7d9100 | triage T1110 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4625\",\"4740\",\"4771\",\"4776\",\"4648\") \| STATS c = COUNT(*) BY event.code \| SORT c DESC"} | 2 |  |
| q-d043d4a019 | triage T1110 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectName == \"SAM\" \| KEEP @timestamp, host.name, user.name, win.ProcessName, win.ObjectName, win.AccessMask, win.AccessList, _id, _index"} | 0 |  |
| q-0e322871be | triage T1110 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4776\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.Status, win.Workstation, win.PackageName, _id, _index"} | 1 | F12 |
| q-eb36ba6da8 | triage T1110 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\") AND win.ObjectName LIKE \"*SAM*\" \| KEEP @timestamp, host.name, user.name, win.ProcessName, win.ObjectName, win.AccessMask, win.AccessList, _id, _ind… | 10 | F14 |
| q-db5cecf7b5 | triage T1110 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*net user*\" OR process.command_line LIKE \"*net group*\" OR process.command_line LIKE \"*net localgroup*\") \| KEEP @timestamp, host… | 0 |  |
| q-978413770b | triage T1110 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*powershell.exe\" AND (process.command_line LIKE \"*readme.ps1*\" OR process.command_line LIKE \"*psversion.ps1*\" OR process.command_li… | 0 |  |
| q-37da715ca9 | triage T1110 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*powershell.exe\" \| KEEP @timestamp, host.name, user.name, process.command_line, process.parent.executable, _id, _index \| LIMIT 30"} | 12 |  |
| q-62e4ddbe80 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-3aa6b041dd | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-bd35dfc760 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuA_"} | None |  |
| q-473278e567 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-ec0f15754e | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-98a618ebb8 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-f70797034c | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-c8f0bf78fd | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-d12ce5b47b | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-3747a45566 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOhtev"} | None |  |
| q-0bc20388ff | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuA-"} | None |  |
| q-1596d83c68 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixAb0"} | None |  |
| q-5b3364bb60 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niwwaQ"} | None |  |
| q-e077941384 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niwwaQ"} | None |  |
| q-03064ac3a1 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-a4375049ea | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVsT"} | None |  |
| q-a5d033d0fe | triage T1111 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 |  |
| q-013a0c33d4 | triage T1111 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.GrantedAccess",… | 4 |  |
| q-97bd2da6bc | triage T1111 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F17 |
| q-62d8c65559 | triage T1111 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:(*lsass* OR *MiniDump* OR *DumpCreds* OR *sekurlsa* OR *LogonPasswords* OR *Invoke-Mimikatz* OR *Credential*) OR process.command_line:(*lsass* OR *MiniDump*))", "time_from": n… | 3 |  |
| q-b5771b40b3 | triage T1111 step 3 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND (process.command_line:(*lsass* OR *MiniDump* OR *dump* OR *Credential* OR *token* OR *smartcard* OR *vault*) OR win.TargetFilename:(*.dmp OR *lsass*))", "time_from": null, "time_to": … | 3 |  |
| q-59648e79fc | triage T1111 step 3 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "win.SubjectUserName", "win.ProcessName", "win.IpAddress", "win.TargetServerName", "win.Lo… | 15 | F17 |
| q-640574bdee | triage T1111 step 4 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:4104 AND @timestamp:[2020-05-02T03:00:00.000Z TO 2020-05-02T03:10:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "eve… | 99 |  |
| q-0dc0c9ea63 | triage T1111 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:00:00.000Z TO 2020-05-02T03:10:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.e… | 42 |  |
| q-15c2395075 | triage T1111 step 5 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:4104 AND @timestamp:[2020-05-02T03:03:30.000Z TO 2020-05-02T03:07:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "eve… | 41 |  |
| q-f04614abba | triage T1111 step 5 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:04:30.000Z TO 2020-05-02T03:06:30.000Z] AND (event.code:1 OR event.code:10 OR event.code:11)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 936 |  |
| q-5de587d0ce | triage T1111 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-fcc66b7abc | triage T1111 step 6 | search | {"dataset": "windows.security", "query": "win.ObjectName:(*smartcard* OR *SCardSvr* OR *VaultSvc* OR *Vault* OR *Credential* OR *NGC* OR *MicrosoftAccount*) OR win.ServiceName:(*SCardSvr* OR *VaultSvc*) OR win.ProcessName:(*scardsvr* OR *vaultsvc*)", "time_fro… | 0 |  |
| q-bf36f178e7 | triage T1111 step 7 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:05:00.000Z TO 2020-05-02T03:06:00.000Z] AND (event.code:1 OR event.code:10 OR event.code:11 OR event.code:23)", "time_from": null, "time_to": null, "fields":… | 516 |  |
| q-df5095bae0 | triage T1111 step 7 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:4104 AND @timestamp:[2020-05-02T03:04:30.000Z TO 2020-05-02T03:06:30.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "eve… | 18 |  |
| q-47902c7811 | triage T1111 step 8 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None | F17 |
| q-2addf0c51e | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-38e24d2e4c | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-e8d21dbd8c | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-2299e32d55 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-21268ccd53 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-58102f0fa7 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-d2182adbd8 | triage T1111 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bT"} | None |  |
| q-e7266edf16 | triage T1187 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1br"} | None | F18 |
| q-38610d730b | triage T1187 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YZ"} | None | F18 |
| q-5c45bafe65 | triage T1187 step 1 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3 AND win.LogonProcessName:\"NtLmSsp\"", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.IpAddress", "win.Workstation", "win.LogonP… | 0 |  |
| q-e531907973 | triage T1187 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*hostui.lnk", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.TargetFilename", "win.Image"], … | 1 | F18 |
| q-0c6e06ea08 | triage T1187 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrG"} | None |  |
| q-7e3c3821dd | triage T1187 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\" AND host.name == \"scranton.dmevals.local\" AND event.code IN (\"4104\",\"4103\",\"800\") \|… | 6 | F18 |
| q-c01ef01f2b | triage T1187 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-b970fe19bd | triage T1187 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 3 AND destination.port IN (445, 139) \| STATS cnt = COUNT(*) BY host.name, destination.ip, process.executable \| SORT cnt DESC \| LIMIT 30"} | ERROR |  |
| q-87d299dd17 | triage T1187 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND destination.port IN (\"445\", \"139\") \| STATS cnt = COUNT(*) BY host.name, destination.ip, process.executable \| SORT cnt DESC \| LIMIT 30"} | ERROR |  |
| q-62ff3e976f | triage T1187 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" AND win.LogonProcessName RLIKE \".*NtLm.*\" \| KEEP @timestamp, host.name, win.TargetUserName, win.TargetDomainName, win.IpAddress, wi… | 1 | F18 |
| q-be9ccdbd68 | triage T1187 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND destination.port IN (445, 139) \| STATS cnt = COUNT(*) BY host.name, destination.ip, process.executable \| SORT cnt DESC \| LIMIT 30"} | 7 |  |
| q-8be223f8e0 | triage T1187 step 5 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuAv"} | None | F18 |
| q-38d931218b | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-35ad90f201 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-345d63d8ac | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1br"} | None |  |
| q-79568e3fb7 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YZ"} | None |  |
| q-400c2ddd1b | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrG"} | None |  |
| q-407a164158 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-c6636b2cf8 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuAv"} | None |  |
| q-e13f0b1980 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrG"} | None |  |
| q-ff5a8ec69d | triage T1212 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F19, F20, F21 |
| q-40405afe2e | triage T1212 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (process.executable:*PowerShell* OR process.executable:*wsmprovhost* OR process.executable:*wininit* OR process.executable:*csrss* OR process.executable:*services.exe)", "tim… | 9 | F21 |
| q-cd744de92b | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-88d068db5c | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-05544a5e31 | triage T1212 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:(*lsass* OR *MiniDump* OR *procdump* OR *sekurlsa* OR *Mimikatz* OR *Credential* OR *Dump* OR *token* OR *Get-Process*))", "time_from": null, "time_to": null, "fields": ["@tim… | 7 | F19, F20 |
| q-f70dd8b2be | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-77a9efea49 | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-2b79268299 | triage T1212 step 3 | search | {"dataset": "windows.security", "query": "user.name:pbeesly AND (event.code:4688 OR event.code:4624 OR event.code:4672 OR event.code:4697 OR event.code:7045)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name",… | 142 |  |
| q-45aa8d6341 | triage T1212 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-6d4ffd3263 | triage T1212 step 4 | search | {"dataset": "windows.security", "query": "event.code:4697 OR event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "win.ServiceName", "win.ImagePath", "win.ServiceFileName", "win.ServiceAccount",… | 23 | F20, F21 |
| q-8c99e73c26 | triage T1212 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:(*lsass* OR *MiniDump* OR *procdump* OR *sekurlsa* OR *mimikatz* OR *dump* OR *credential* OR *token*))", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 1 |  |
| q-afdc9edf1b | triage T1212 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*PowerShell* OR process.executable:*javamtsup* OR process.executable:*PsExec* OR process.executable:*sdelete* OR process.executable:*python*)", "time_from": null, "time_to": null, "fi… | 28 | F19 |
| q-cb7f4cd980 | triage T1212 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*javamtsup* OR win.TargetFilename:*OfficeSupplies* OR win.TargetFilename:*readme.ps1 OR win.TargetFilename:*psversion.ps1 OR win.TargetFilename:*lsass*)", "time_from": null, "time_to… | 3 | F19 |
| q-87003c866a | triage T1212 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Zr"} | None | F19 |
| q-fd2da63a03 | triage T1212 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None | F19 |
| q-216ce61e57 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-7077b1bab6 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-15f715dc9e | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-71b0b13b85 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-0607cb4313 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-3bff5d02a7 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-387520df59 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-2aec3c67d0 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-464a84a009 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Zr"} | None |  |
| q-739a1783db | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-8caf72b297 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7habqTS"} | None |  |
| q-28fe47b81d | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-1b0ed60d53 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-52518dd1ee | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-bf5f32db4e | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuI"} | None |  |
| q-7098d4bb73 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyU"} | None |  |
| q-f2bc5e5e4a | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyV"} | None |  |
| q-97a63afb41 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cofd-n"} | None |  |
| q-310c7c09ea | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4vE"} | None |  |
| q-2ac730f77f | triage T1539 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*Web Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetFilename", "proc… | 162 |  |
| q-c465086259 | triage T1539 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\") \| STATS … | ERROR |  |
| q-25dfec763e | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\") \| ST… | 1 |  |
| q-370ac88599 | triage T1539 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*MicrosoftEdge*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetFilename", "process.executable", "process.command_line", "user.name"], "size": 1… | 4 | F23 |
| q-bedaf4b67a | triage T1539 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy1EsG"} | None | F23 |
| q-5678faf8c2 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\") \| KE… | 1 | F22 |
| q-20dd015d71 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookies*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*web data*\" O… | 0 |  |
| q-8e3b0a873e | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*edge*\" OR TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\" OR TO_LOWER(win.TargetI… | 35 |  |
| q-afb051e3e1 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*edge*\") AND (TO_LOWER(process.executable) LIKE \"*powershell*\" OR TO_LOWER(process.executable) LIKE \"*wsmprovhost*\") \| KE… | 12 | F22 |
| q-4874f97d25 | triage T1539 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQPxjx"} | None | F22 |
| q-5f039f8b5a | triage T1539 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*edge*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*0x1fffff*\" OR T… | 0 |  |
| q-abc39cce61 | triage T1539 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC \| LIMIT 15"} | 15 | F22 |
| q-9a2bffe1aa | triage T1539 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (TO_LOWER(process.executable) LIKE \"*powershell*\" OR TO_LOWER(process.executable) LIKE \"*wsmprovhost*\") \| KEEP @t… | 11 | F22 |
| q-ea3468f738 | triage T1539 step 8 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\" \| KEEP @timestamp, u… | 25 |  |
| q-fdd54e4e61 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQPxjx"} | None |  |
| q-65c5d4d66b | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQPxjx"} | None |  |
| q-f82906645d | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQPxjx"} | None |  |
| q-4bbb65b4fa | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQPxjx"} | None |  |
| q-61f339abec | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQPxjx"} | None |  |
| q-c3ded43c53 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7habKTs"} | None |  |
| q-f3d5476b91 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-ab81100637 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0ZP57"} | None |  |
| q-92d5919d4b | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-f221bd1aaf | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy1EsG"} | None |  |
| q-f8cfce0243 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-4187b5f1e4 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-de4b487302 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None | F24 |
| q-f1d607ed89 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qzXFrk"} | None | F26 |
| q-71f9a13e23 | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*passwordsDB*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "file.path", "process.executable", "process.command_line"], "size": 20, "sort": "asc"} | 1 |  |
| q-faccc0e9d5 | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*.pfx", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "file.path", "process.executable", "process.command_line"], "size": 20, "sort": "asc"} | 1 | F24 |
| q-6c606417d8 | triage T1552 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*passwordsDB* OR process.command_line:*accesschk* OR process.command_line:*readme.ps1* OR process.command_line:*SysinternalsSuite*)", "time_from": null, "time_to": null, "fields": [… | 8 | F25 |
| q-2157b3315d | triage T1552 step 2 | search | {"dataset": "windows.security", "query": "event.code:(4663 OR 4656) AND win.ObjectName:SAM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.ObjectName", "win.AccessMask"… | 10 | F27 |
| q-5065f80df3 | triage T1552 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*Invoke-Exfil* OR *OfficeSupplies* OR *Get-PrivateKeys* OR *Invoke-BeachCleanup* OR *Invoke-Discovery*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 7 | F24 |
| q-2ca3856033 | triage T1552 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:(11 OR 13) AND (win.TargetFilename:*passwords* OR registry.path:*Javasoft* OR win.TargetFilename:*OfficeSupplies* OR win.TargetFilename:*.7z)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 5 |  |
| q-fef1e7cf0c | triage T1552 step 3 | search | {"dataset": "windows.security", "query": "event.code:4648 AND win.TargetUserName:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.TargetUserName", "win.LogonProc… | 9 | F25 |
| q-b8affe1bcb | triage T1552 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrP"} | None | F26 |
| q-5eef112df2 | triage T1552 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None | F25 |
| q-15a65c5c67 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-9219986c84 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-81f306c0ae | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-9000be174e | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-081cd9569b | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-8d87453677 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None |  |
| q-3f44e52685 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None |  |
| q-da4fa568a9 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-f76b7f8498 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-0fdde76d19 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-a9c22f3b84 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrP"} | None |  |
| q-c09b273a22 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrP"} | None |  |
| q-e384d76111 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qzXFrk"} | None |  |
| q-24f4dd23ed | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-83a0429481 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-9829cec324 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-fe233f73aa | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7habKTo"} | None |  |
| q-a750a6ce72 | triage T1555 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass*) AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x14… | 33 | F28, F29 |
| q-ce95f6d1a2 | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-1f1447bf1d | triage T1555 step 2 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:04:00.000Z TO 2020-05-02T03:06:30.000Z] AND (event.code:1 OR event.code:11 OR event.code:13)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 296 |  |
| q-c1daeeddd4 | triage T1555 step 3 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND (process.pid:2976 OR win.ProcessId:2976 OR win.SourceProcessId:2976 OR win.TargetProcessId:2976)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.cod… | 589 |  |
| q-7f4db2f2be | triage T1555 step 3 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:03:00.000Z TO 2020-05-02T03:07:00.000Z] AND event.code:4104", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "us… | 43 |  |
| q-2d8a984c94 | triage T1555 step 4 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*OpenProcess* OR win.ScriptBlockText:*AdjustTokenPrivileges* OR win.Scrip… | 0 |  |
| q-0b94559cc5 | triage T1555 step 4 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND event.code:1 AND @timestamp:[2020-05-02T03:04:30.000Z TO 2020-05-02T03:06:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.e… | 12 |  |
| q-acebfce4f5 | triage T1555 step 5 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:4104 AND @timestamp:[2020-05-02T03:04:50.000Z TO 2020-05-02T03:06:30.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "us… | 17 |  |
| q-0e52c2be5d | triage T1555 step 5 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ProcessName", "win.ObjectName", "win.AccessMask", "win.SubjectUserName", "win.Pr… | 13 | F28, F29 |
| q-47594926f9 | triage T1555 step 6 | search | {"dataset": "windows.sysmon", "query": "host.name:nashua.dmevals.local AND @timestamp:[2020-05-02T03:08:30.000Z TO 2020-05-02T03:10:30.000Z] AND (event.code:1 OR event.code:10 OR event.code:11)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 404 |  |
| q-e31a70a0bc | triage T1555 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*logins.json*\" OR TO_LOWER(win.TargetFilename) LIKE \"*key4.db*\" OR TO_L… | ERROR |  |
| q-2b9be4561a | triage T1555 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*logins.json*\" OR TO_LOWER(win.TargetFilename) LIKE \"*key4.db*\" OR … | 2 | F30 |
| q-35affc3d5e | triage T1555 step 7 | search | {"dataset": "windows.sysmon", "query": "host.name:nashua.dmevals.local AND (process.executable:*wsmprovhost* OR win.TargetImage:*lsass*) AND event.code:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.execut… | 148 |  |
| q-d0ec8bf584 | triage T1555 step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-f268e4fa82 | triage T1555 step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-0801db1543 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-c5952b5650 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-43eec4fd9f | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-a11c74a6d7 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-94c86ed4ca | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-7018b1c735 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-3a5a32abef | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-ddc3024aca | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-45b410193d | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0W8_"} | None |  |
| q-9d9c279ec0 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0W8_"} | None |  |
| q-2f17a7f915 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGJOD"} | None |  |
| q-bf54aee0ad | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq8Ga8"} | None |  |
| q-a0a65f2b70 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nSlNDC"} | None |  |
| q-8b44b2f670 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-aeb8f0d24e | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-a2879705ce | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuA9"} | None |  |
| q-2a929067ad | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qyVUi_"} | None |  |
| q-b543acf39e | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCQ"} | None |  |
| q-cee4b56a9c | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-e051be0b6b | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*winlogon*", "time_from": null, "time_to": null, "size": 50, "sub_field": "win.GrantedAccess"} | 144 |  |
| q-c59425beee | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon*) AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "proces… | 12 | F33, F39 |
| q-10667f8cf8 | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*powershell.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executable", "user.name"], "si… | 12 |  |
| q-87402cd70e | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F33 |
| q-c8f08625b6 | triage T1556 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND @timestamp:[2020-05-02T03:04:00.000Z TO 2020-05-02T03:07:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "win.ScriptBlockText", "win… | 35 |  |
| q-48e745a8a2 | triage T1556 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND @timestamp:[2020-05-02T03:05:00.000Z TO 2020-05-02T03:06:30.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "win.ScriptBlockText", "win… | 13 |  |
| q-18be8d05eb | triage T1556 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:nashua.dmevals.local AND @timestamp:[2020-05-02T03:08:00.000Z TO 2020-05-02T03:11:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.exe… | 4 |  |
| q-0a05916e05 | triage T1556 step 5 | search | {"dataset": "windows.powershell", "query": "host.name:nashua.dmevals.local AND event.code:4104 AND @timestamp:[2020-05-02T03:08:00.000Z TO 2020-05-02T03:12:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user… | 2 |  |
| q-d6d3f563c8 | triage T1556 step 5 | search | {"dataset": "windows.security", "query": "event.code:4624 AND host.name:nashua.dmevals.local AND @timestamp:[2020-05-02T03:05:00.000Z TO 2020-05-02T03:12:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.n… | 15 | F34, F37 |
| q-4ea1840775 | triage T1556 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Lsa* OR registry.path:*NetworkProvider* OR registry.path:*Notification* OR registry.path:*Winlogon* OR registry.path:*Password*)", "time_from": null, "time_to": null, "fields": ["@timest… | 456 |  |
| q-b2e0af211d | triage T1556 step 6 | search | {"dataset": "windows.security", "query": "event.code:4657 OR event.code:4697 OR event.code:4702 OR event.code:4611 OR event.code:5058 OR event.code:5061", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "win… | 111 |  |
| q-eef8202797 | triage T1556 step 7 | search | {"dataset": "windows.security", "query": "event.code:5061 OR event.code:5058", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "win.ObjectName", "win.OperationType", "win.Properties", "win.ProcessName", "win… | 24 |  |
| q-c380d73fe3 | triage T1556 step 7 | search | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "win.ObjectName", "win.OperationType", "win.NewValue", "win.ProcessName", "win.SubjectUserName"], "… | 36 |  |
| q-98cee39eec | triage T1556 step 8 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72ZP"} | None | F38 |
| q-491d1c8f6e | triage T1556 step 8 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Zr"} | None | F33 |
| q-b93361bcfa | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-fef8cf654b | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-bf0f31c8ce | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-1b91d2d416 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhF"} | None |  |
| q-5d43a372d8 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-cee12d3261 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Zr"} | None |  |
| q-c5688ba294 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytuv"} | None |  |
| q-bc8cb935cb | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7np7lpF"} | None |  |
| q-57203db5f7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuBA"} | None |  |
| q-2914531f1f | triage T1556 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCm"} | None |  |
| q-af8a9d84ab | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVsT"} | None |  |
| q-ffa873cf56 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytuv"} | None |  |
| q-d049f765c7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72ZP"} | None |  |
| q-cb85fc8c96 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72ZP"} | None |  |
| q-9543c31830 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c93tyW"} | None |  |
| q-d25ba6c9aa | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c93tyW"} | None |  |
| q-8a29fd79da | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" \| STATS cnt = COUNT(*), ips = COUNT_DISTINCT(source.ip), dsts = COUNT_DISTINCT(destination.ip) BY zeek.orig_l2_addr, zeek.resp_l2_addr \| SORT cnt DESC"} | 5 |  |
| q-e433db0162 | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND zeek.resp_l2_addr == \"12:34:56:78:9a:bc\" \| STATS cnt = COUNT(*) BY source.ip, destination.ip, destination.port, zeek.conn_state \| SORT cnt DESC \| LIMIT 30"} | 30 |  |
| q-09797e23ae | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" \| STATS cnt = COUNT(*) BY zeek.resp_l2_addr, destination.ip \| SORT zeek.resp_l2_addr, cnt DESC"} | 6 |  |
| q-9b557b4a63 | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND (destination.port == 445 OR destination.port == 139) \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.conn_state, zeek.orig_l2_addr, zeek.resp_l2_… | 50 | F40, F43 |
| q-edbbdb2e5f | triage T1557 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action IN (\"dns\",\"notice\",\"kerberos\",\"smb_files\",\"smb_mapping\") \| KEEP @timestamp, event.action, source.ip, destination.ip, dns.question.name, dns.response_code, zeek.answers, zee… | 80 | F40, F41 |
| q-700f644d8f | triage T1557 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 22 \| KEEP @timestamp, host.name, user.name, win.QueryName, win.QueryResults, win.QueryStatus, win.Image, _id, _index \| SORT @timestamp \| LIMIT 90"} | ERROR |  |
| q-cab9b70c5c | triage T1557 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"22\" \| KEEP @timestamp, host.name, user.name, win.QueryName, win.QueryResults, win.QueryStatus, win.Image, _id, _index \| SORT @timestamp \| LIMIT 90"} | 81 | F41 |
| q-230145af11 | triage T1557 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND (source.ip == \"192.168.0.5\" OR destination.ip == \"192.168.0.5\" OR source.ip == \"192.168.0.4\" OR destination.ip == \"192.168.0.4\") \| STATS cnt = COUNT(*) BY sou… | 8 |  |
| q-056d0d24a9 | triage T1557 step 5 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action IN (\"http\",\"ssl\",\"x509\",\"notice\") AND (source.ip == \"192.168.0.4\" OR destination.ip == \"192.168.0.4\" OR source.ip == \"192.168.0.5\" OR destination.ip == \"192.168.0.5\") … | 40 |  |
| q-24c27c24b2 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" \| STATS cnt = COUNT(*) BY win.IpAddress, win.TargetUserName, win.AuthenticationPackageName, win.LogonProcessName \| SORT cnt DESC \| … | 15 |  |
| q-89ae72f1fe | triage T1557 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.IpAddress == \"172.18.39.2\" \| KEEP @timestamp, host.name, event.code, win.IpAddress, win.IpPort, win.TargetUserName, win.AuthenticationPackageName, win… | 3 | F41, F43 |
| q-f842d42464 | triage T1557 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"5140\",\"5145\") \| STATS cnt = COUNT(*) BY win.IpAddress, win.ShareName, win.SubjectUserName, win.RelativeTargetName \| SORT cnt DESC \| LIMIT 30"} | 30 |  |
| q-54eca1a10d | triage T1557 step 7 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND zeek.resp_l2_addr == \"12:34:56:78:9a:bc\" \| STATS first = MIN(@timestamp), last = MAX(@timestamp), cnt = COUNT(*) BY destination.ip \| SORT destination.ip"} | ERROR |  |
| q-5e6a9aac96 | triage T1557 step 7 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND destination.ip == \"192.168.0.4\" AND destination.port == 8443 \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.conn_state, zeek.orig_l2_addr, zee… | 8 | F40 |
| q-0b53ef09f5 | triage T1557 step 8 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND zeek.resp_l2_addr == \"12:34:56:78:9a:bc\" \| STATS min_ts = MIN(@timestamp), max_ts = MAX(@timestamp), cnt = COUNT(*) BY destination.ip \| SORT destination.ip"} | 4 |  |
| q-a4abb1b180 | triage T1557 step 8 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND zeek.resp_l2_addr == \"12:34:56:78:9a:bc\" \| EVAL bucket = DATE_TRUNC(5 minutes, @timestamp) \| STATS ips = COUNT_DISTINCT(destination.ip), cnt = COUNT(*) BY bucket \… | 9 |  |
| q-3ab331e365 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_aFZ1"} | None |  |
| q-1292441534 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qVdaFb"} | None |  |
| q-73f61f5858 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1a3"} | None |  |
| q-63e919b00c | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qVdaEh"} | None |  |
| q-4f2cad8c14 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_aFYa"} | None |  |
| q-95b8715d95 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWWCli"} | None |  |
| q-d66496f917 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbO"} | None |  |
| q-ec14ed9b3e | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_aFYW"} | None |  |
| q-1e21c2e3de | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-88b745b26d | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-3410875470 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVuD"} | None |  |
| q-4de124e5a7 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVuD"} | None |  |
| q-7d77d023e3 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVuD"} | None |  |
| q-25a999d0c1 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1ad"} | None |  |
| q-e956e5ee4a | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qVdaE6"} | None |  |
| q-c13228fe96 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None |  |
| q-9a86794145 | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F44 |
| q-0c7b9a3c26 | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.GrantedAccess",… | 4 |  |
| q-5e8c34a2de | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F44 |
| q-0b04c64188 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-5aaaeb368d | triage T1558 step 3 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND (process.pid:2976 OR win.ProcessId:2976 OR win.ParentProcessId:2976 OR process.parent.pid:2976)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code… | 546 | F44 |
| q-e8908eb9d2 | triage T1558 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "process.command_line", "process.parent.executable", "proc… | 359 | F44 |
| q-0a00e86493 | triage T1558 step 4 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*LSASS* OR win.ScriptBlockText:*monkey* OR win.ScriptBlockText:*IEX* OR win.ScriptBlockText:*Add-Type*)", "… | 4 | F44 |
| q-bd4fdd72ac | triage T1558 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (4768, 4769, 4770, 4771, 4776, 4765, 4766) \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, wi… | ERROR |  |
| q-3691463839 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE TO_STRING(event.code) IN (\"4768\",\"4769\",\"4770\",\"4771\",\"4776\",\"4765\",\"4766\",\"4672\") \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.ServiceName, win.T… | 60 |  |
| q-e17a9ae81f | triage T1558 step 5 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:(2 OR 10 OR 0)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "win.LogonType", "win.IpAddress", "win.Workstation", "win… | 18 |  |
| q-c92add138a | triage T1558 step 6 | count | {"dataset": "windows.security", "query": "event.code:(4768 OR 4769 OR 4770 OR 4771 OR 4776 OR 4765 OR 4766)", "time_from": null, "time_to": null} | 43 |  |
| q-c9fe90bfd3 | triage T1558 step 6 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"kerberos\" AND zeek.request_type IS NOT NULL \| KEEP @timestamp, source.ip, destination.ip, zeek.request_type, zeek.client, zeek.service, zeek.success, zeek.error_msg, zeek.ciphe… | 25 | F46, F47, F48 |
| q-fb285653ae | triage T1558 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE TO_STRING(event.code) IN (\"4768\",\"4769\",\"4770\",\"4771\",\"4776\",\"4765\",\"4766\") \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.ServiceName, win.TicketEncr… | 43 | F45, F46, F47, F48 |
| q-cad798abf1 | triage T1558 step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None | F45 |
| q-9359cfa5d7 | triage T1558 step 8 | search | {"dataset": "windows.sysmon", "query": "host.name:nashua.dmevals.local AND (event.code:1 OR event.code:3 OR event.code:11) AND (process.executable:*wsmprovhost* OR process.parent.executable:*wsmprovhost* OR process.executable:*powershell* OR process.executable… | 22 |  |
| q-e09001c757 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-2156601e60 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-3893fa9802 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-3f867b1ee0 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-fda1e5af57 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-b3e1697137 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwewi"} | None |  |
| q-d1341d957e | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Yv7J"} | None |  |
| q-b45c2b5fd0 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-4853a0d19d | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-4c28797c7e | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5pu"} | None |  |
| q-07f7d1553c | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-ba797501e9 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5ob"} | None |  |
| q-0dd4a818e2 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72bs"} | None |  |
| q-2ce83d4a7f | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlbp"} | None |  |
| q-5676892be2 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlbx"} | None |  |
| q-145390d6b5 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72bs"} | None |  |
| q-f718fc5339 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytvM"} | None |  |
| q-ea70208e9c | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlby"} | None |  |
| q-83731d7832 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bV"} | None |  |
| q-25b0224710 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bT"} | None |  |
| q-b42708fc04 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bU"} | None |  |
| q-788b098f5d | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nix9vF"} | None |  |
| q-0a8604fcc0 | triage T1606 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.GrantedAccess IN (\"0x1fffff\",\"0x1f3fff\",\"0x101541\",\"0x101441\",\"0x121440\",\"0x101068\",\"0x2200\",\"0x14c0\",\"0x1000000\",\"0x18\",\"0x1\",\"0x70\") \|… | ERROR |  |
| q-f3419e2112 | triage T1606 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (win.TargetFilename LIKE \"*Cookies*\" OR win.TargetFilename LIKE \"*Login Data*\" OR win.TargetFilename LIKE \"*Web Data*\") \| KEEP @timestamp, host.name, process.… | ERROR |  |
| q-8ceab86742 | triage T1606 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x1f3fff\",\"0x101541\",\"0x101441\",\"0x121440\",\"0x101068\",\"0x2200\",\"0x14c0\",\"0x1000000\",\"0x18\",\"0x1\",\"0x70\"… | 60 |  |
| q-55c3fa3a4e | triage T1606 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (win.TargetFilename LIKE \"*Cookies*\" OR win.TargetFilename LIKE \"*Login Data*\" OR win.TargetFilename LIKE \"*Web Data*\") \| KEEP @timestamp, host.name, proc… | 1 | F50 |
| q-75ff6b0cc2 | triage T1606 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, win.CallTrace, _id, _index \| SORT @times… | 40 |  |
| q-a17af0fcbe | triage T1606 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*psexe*\" OR process.command_line LIKE \"*psexe*\" OR process.executable LIKE \"*3aka3*\" OR process.command_line LIKE \"*3aka3*\" OR p… | 3 |  |
| q-031de0bb00 | triage T1606 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess != \"0x1000\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, win.C… | 33 | F49 |
| q-aec0f8771d | triage T1606 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonProcessName LIKE \"*NtLmSsp*\" OR (event.code == \"4624\" AND win.AuthenticationPackageName == \"NTLM\") OR (event.code == \"4624\" AND win.LogonPro… | 3 | F49 |
| q-b237a6c068 | triage T1606 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F49 |
| q-1b126d702c | triage T1606 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None | F49 |
| q-f9b55860eb | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-560f9b0ab5 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-5b4fe7e51c | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-387e5eb097 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-ce4ae58195 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-61b322eafc | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-2bb1f28a46 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-49108f49fe | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-ec757a6807 | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None | F52 |
| q-393a5afc9d | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None | F52 |
| q-ba14812b8e | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None | F53 |
| q-9df82fa8cf | triage T1649 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.p12\" OR TO_LOWER(win.TargetFilename) LIKE \"*.cer\" OR TO_LOWER(win.TargetF… | 1 |  |
| q-bca36cae56 | triage T1649 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*pfx*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cert:\\\\*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*certutil*\" OR TO_LOWER(win.ScriptBlockTex… | 3 |  |
| q-8e5a30d451 | triage T1649 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSsN"} | None | F52 |
| q-82efaedda7 | triage T1649 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None | F52 |
| q-b1b1d7fe2a | triage T1649 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND TO_LOWER(process.executable) LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.executable, proce… | 11 | F52 |
| q-b1b26a3ae1 | triage T1649 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND TO_LOWER(win.ObjectName) LIKE \"*systemcertificates*\" \| KEEP @timestamp, host.name, user.name, process.executable, win.ObjectName, win.ObjectValueName, _id… | 1 | F53 |
| q-3e7ebad43e | triage T1649 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*certutil*\" OR TO_LOWER(process.command_line) LIKE \"*pfx*\" OR TO_LOWER(process.command_line) LIKE \"*cert:\\\\*\" OR TO_… | 0 |  |
| q-b421c2d909 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-b66b653206 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-753e2f54f7 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-b2d244a214 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSsN"} | None |  |
| q-0407625f98 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-3e97dc5812 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-df0c36d188 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-d621492ce6 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-cf686a7e62 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-8f64ee3f16 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-5124c9a849 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-9ad961a810 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-7b2d0ac04e | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5pb"} | None |  |
| q-4dd8247a81 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5pb"} | None |  |
| q-3b38935b9d | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-de97e5308e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-033a94541a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-17fab41b1f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-c604105a98 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-55ddb25722 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-5ba170beb8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72YQ"} | None |  |
| q-af761807a1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72YQ"} | None |  |
| q-6f7f720532 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-1c83df9136 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-9d61518f07 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRapX"} | None |  |
| q-c25725324d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-674dcb193b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFDLy"} | None |  |
| q-1a17ef3ceb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFDLy"} | None |  |
| q-6eade7385b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-0e586ba783 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVSlm"} | None |  |
| q-5316880655 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b7vVsn"} | None |  |
| q-5afea248de | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-151336c239 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-26e5af2e6c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-988b6d3305 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cjZNnV"} | None |  |
| q-874a20fa2e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nVnj7M"} | None |  |
| q-53df4c64a6 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCI"} | None |  |
| q-6664eaed1d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuAu"} | None |  |
| q-805a65ec20 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFTIA"} | None |  |
| q-3fba077c78 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNv3"} | None |  |
| q-19c7c606a2 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-dc6ccfe17c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNum"} | None |  |
| q-8a66b0ad2e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5y1oY"} | None |  |
| q-c74bc55b5f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns9wrd"} | None |  |
| q-2942ebbba8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-0a4f663a55 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-eedadc58c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-ffb5033d2a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-bac0523fb4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-14ad3c8a6c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-93ebad5f36 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRapX"} | None |  |
| q-8b15551272 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yf"} | None |  |
| q-c44cedb02d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None |  |
| q-741b8f4398 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None |  |
| q-d1d31cbd0e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitC"} | None |  |
| q-74044da457 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-c573404ae2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOx9"} | None |  |
| q-bcda2c08a2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-9179a5be8a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-df787b318c | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuA_"} | None |  |
| q-3bbf665b2a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-236799ef83 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-6e32a74bbb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-ecb73bf368 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-4ad7e67979 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-d3c8636f9e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-2768e68388 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOhtev"} | None |  |
| q-65fbe0ee03 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuA-"} | None |  |
| q-127a0e70a6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixAb0"} | None |  |
| q-ffdda3cb4e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niwwaQ"} | None |  |
| q-749dea77db | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niwwaQ"} | None |  |
| q-9425459e28 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-d4ccc438a1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVsT"} | None |  |
| q-985cff2aea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-d032d6e5ee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-8479e66e3d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-13e7db2622 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-bd0eb6720c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-c1a5e36245 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-74da00babc | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bT"} | None |  |
| q-6c704690f5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-60c1d98a40 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-894480cf16 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1br"} | None |  |
| q-906e7501ba | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YZ"} | None |  |
| q-74fc3e6866 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrG"} | None |  |
| q-be29503553 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-e41933e30a | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuAv"} | None |  |
| q-6fff32ba76 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrG"} | None |  |
| q-d1dccb94be | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-db1a3a0a16 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-4ecc2006e7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-d96f56b64e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-e89a011d5f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-04fecb1841 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-c4966f696d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-529b44f585 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-f331fbb17b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Zr"} | None |  |
| q-d1f91820b7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-b13f8f135b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7habqTS"} | None |  |
| q-de5b3421cf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-4e5d19e34f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-495f3a2974 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-6ba1c4403e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuI"} | None |  |
| q-213c67a9f1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyU"} | None |  |
| q-bbbb69ad6e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyV"} | None |  |
| q-72844603e9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cofd-n"} | None |  |
| q-a2dcfce9d8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4vE"} | None |  |
| q-b8faa25511 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQPxjx"} | None |  |
| q-89db9055d7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQPxjx"} | None |  |
| q-bbc45dd64b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQPxjx"} | None |  |
| q-1655fadf00 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQPxjx"} | None |  |
| q-fee299a3aa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQPxjx"} | None |  |
| q-8d9632852c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7habKTs"} | None |  |
| q-8182d980ae | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-3d0eee3cd3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0ZP57"} | None |  |
| q-9e7f14005c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-a07cf7b712 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy1EsG"} | None |  |
| q-1845f040c5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-c9355ad4b1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-77593e8e9a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-2ee32cfe22 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-2a3245983e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-c72f025e1d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-9724429f08 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-ce1da6fe6b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None |  |
| q-cda54301c6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None |  |
| q-c618f7eb22 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-d3e654cc8d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-385172f185 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-c9ab48f6e2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrP"} | None |  |
| q-0d8765342a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrP"} | None |  |
| q-2c7c621af6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qzXFrk"} | None |  |
| q-b332bee1ab | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-41cf920d90 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-108cdb270c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-270d02acca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-a020ba2a71 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-f2dfc9cd46 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-cd00b02e0a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-2d618f514e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-be008b1941 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-2e348a569d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-b8b9116b30 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-2ca1ba311b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0W8_"} | None |  |
| q-bfb1f1e6a9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0W8_"} | None |  |
| q-70381826a5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGJOD"} | None |  |
| q-ed5b1778b7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq8Ga8"} | None |  |
| q-4416f60699 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nSlNDC"} | None |  |
| q-8725626039 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-0492f2a03f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-3935956b0f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuA9"} | None |  |
| q-1621d7ef7b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qyVUi_"} | None |  |
| q-cc459d48cd | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCQ"} | None |  |
| q-2f06d75fd3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-107e85c486 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-d427c94f58 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-f29150ba90 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhF"} | None |  |
| q-f17e266483 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-736abd93a7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Zr"} | None |  |
| q-ea275f26b3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytuv"} | None |  |
| q-c09186b6c7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7np7lpF"} | None |  |
| q-4ac1cc1155 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuBA"} | None |  |
| q-5c60bc25fb | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCm"} | None |  |
| q-8482af7758 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVsT"} | None |  |
| q-2c3e51715c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytuv"} | None |  |
| q-d68a3b269f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72ZP"} | None |  |
| q-d194681fea | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72ZP"} | None |  |
| q-3f35357146 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c93tyW"} | None |  |
| q-ab46ec425e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c93tyW"} | None |  |
| q-8a7e807982 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_aFZ1"} | None |  |
| q-ff26bca6e8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qVdaFb"} | None |  |
| q-8ba189053b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1a3"} | None |  |
| q-d4956174fe | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qVdaEh"} | None |  |
| q-a3e5ddf6c7 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_aFYa"} | None |  |
| q-2ce8a85248 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWWCli"} | None |  |
| q-389bc7f114 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbO"} | None |  |
| q-c080d09f71 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_aFYW"} | None |  |
| q-443a062fac | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-a358f62cd6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-3c37d7ddee | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVuD"} | None |  |
| q-bb0cf14eca | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVuD"} | None |  |
| q-55f010660b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVuD"} | None |  |
| q-df028b7ae9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1ad"} | None |  |
| q-a4ec4d4369 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qVdaE6"} | None |  |
| q-1ab0e9227b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None |  |
| q-6b51ef6efa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-3a83f41130 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-a2c217bd6d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-513f0e3a2c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-66015963be | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-09cb06ae20 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-cc3a62ed4a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwewi"} | None |  |
| q-d8189aa141 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-cfe4bc4bfb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-ce185dd601 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-ed1ef33a4a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5pu"} | None |  |
| q-861f45d7b9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-53016e5829 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5ob"} | None |  |
| q-3f2846d793 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72bs"} | None |  |
| q-409ec333cf | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlbp"} | None |  |
| q-0c206833a5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlbx"} | None |  |
| q-469c40bae1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72bs"} | None |  |
| q-eab17581dc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytvM"} | None |  |
| q-f04aa5e2a0 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlby"} | None |  |
| q-6e13f472a2 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bV"} | None |  |
| q-96597e2e1e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bT"} | None |  |
| q-545a795e8f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bU"} | None |  |
| q-4733e5b8cd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nix9vF"} | None |  |
| q-99dae525e1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-aa0533e103 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-820ac4de9a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-3922ac2a64 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-b3787451fa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-e31f21454a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-c0965d32ae | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-1f6faeb316 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-208fc96196 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-10b35ad577 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-59b5e67d81 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-3a4dde59e6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSsN"} | None |  |
| q-3a56abdd9c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-7f2ccaacc3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-48dbbc3c40 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-0665136364 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-4e0697540f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-85ca289723 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-7e08d9426e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-a9209e5e33 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-e2c6681061 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5pb"} | None |  |
| q-114db5a493 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5pb"} | None |  |
| q-4b459c490c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-76fa0cc629 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": "process.parent.executable"… | 61 |  |
| q-c12722fa11 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-24c7a92017 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": "process.parent.execut… | 63 |  |
| q-9c2e96c00e | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-983778bf8c | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:36:28+00:00", "size": 100, "sub_field": "process.parent.executabl… | 359 |  |
| q-6c57ae2813 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:36:28+00:00", "size": 100, "sub_field": "process.executable"} | 1276 |  |
| q-191786678f | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:36:28+00:00", "size": 100, "sub_field": "process.parent.exec… | 370 |  |
| q-b0260d9988 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:36:28+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-3edeca6d5c | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*\\\\\\\\Temp\\\\\\\\*\" OR process.parent.executable LIKE \"*PSEXESVC*\" OR process.executab… | 11 | F55 |
| q-f24858ad8b | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (process.executable LIKE \"*SysinternalsSuite*\" OR process.executable LIKE \"*csc.exe\" OR process.executable LIKE \"… | 16 | F57 |
| q-cc297ef59b | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"11\",\"3\",\"22\",\"23\",\"17\",\"18\") AND (process.executable LIKE \"*python*\" OR process.executable LIKE \"*Rar*\" OR proce… | ERROR |  |
| q-caf2d5f4c2 | pivot step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"4104\",\"4103\",\"800\") \| KEEP @timestamp, event.code, user.name, powershell.file.script_block_text, powershell.command.n… | ERROR |  |
| q-e43cabc078 | pivot step 3 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-f4a6e703c5 | pivot step 3 | get_fields | {"dataset": "windows.sysmon", "prefix": "network"} | None |  |
| q-41527cde14 | pivot step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"11\",\"3\",\"22\",\"23\",\"17\",\"18\") AND (process.executable LIKE \"*python*\" OR process.executable LIKE \"*Rar*\" OR proce… | 439 |  |
| q-5b5166b381 | pivot step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"4104\",\"4103\") \| KEEP @timestamp, event.code, user.name, win.ScriptBlockText, win.Message, _id, _index \| SORT @timestam… | 40 |  |
| q-11d3f945d1 | pivot step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"3\",\"22\") \| KEEP @timestamp, event.code, process.executable, file.path, dns.question.name, source.ip, destination.ip, destin… | 441 |  |
| q-15c92b8b29 | pivot step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"11\" AND (file.path LIKE \"*0piklvia*\" OR file.path LIKE \"*qkbkqqbs*\" OR file.path LIKE \"*Downloads*\" OR file.path LIKE \… | 334 | F57, F59, F60 |
| q-10df766361 | pivot step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*passw*\" OR win.ScriptBlockText LIKE \"*.pfx*\" OR win.ScriptBlockText LIKE \"*SAM… | 4 | F56, F58 |
| q-c972bcedd5 | pivot step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"11\" AND (file.path LIKE \"*passw*\" OR file.path LIKE \"*.pfx\" OR file.path LIKE \"*SysinternalsSuite*\" OR file.path LIKE \… | 314 |  |
| q-15527df82b | pivot step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None | F56 |
| q-6316780ceb | pivot step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"11\",\"23\",\"12\",\"13\",\"14\") AND process.executable LIKE \"*python*\" AND (file.path LIKE \"*passw*\" OR file.path LIKE \"… | 0 |  |
| q-df53748518 | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND process.executable LIKE \"*python*\" AND event.code IN (\"11\",\"23\",\"12\",\"13\",\"14\",\"2\") \| KEEP @timestamp, event.code, file.path, reg… | 45 | F55 |
| q-5b32fc2b65 | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND (file.path LIKE \"*passw*\" OR file.path LIKE \"*credential*\" OR file.path LIKE \"*Login Data*\" OR file.path LIKE \"*Cookies*\" OR file.path L… | 0 |  |
| q-fe85e7a74b | pivot step 9 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*passw*\" OR win.ScriptBlockText LIKE \"*credential*\" OR win.ScriptBlockText LIKE \"… | 3 |  |
| q-9fcb09ca90 | pivot step 9 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"1\" AND process.parent.executable LIKE \"*cmd.exe\" AND @timestamp >= \"2020-05-02T02:58:00\" AND @timestamp <= \"2020-05-02T0… | 4 |  |
| q-337a6e4909 | pivot step 10 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC92"} | None | F55 |
| q-bfba95c5f7 | pivot step 10 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"1\" AND @timestamp >= \"2020-05-02T03:21:00\" \| KEEP @timestamp, user.name, process.executable, process.command_line, process… | 58 | F58 |
| q-d1fa1701a0 | pivot step 11 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"3\" AND process.executable LIKE \"*python*\" \| KEEP @timestamp, process.executable, destination.ip, destination.port, _id, _ind… | 348 | F55 |
| q-3b60e98f60 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-3ea81f4cb7 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-5721c1c9cb | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-94ebc940df | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5y1od"} | None |  |
| q-93bf212dc0 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC92"} | None |  |
| q-0b0f85e6dc | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None |  |
| q-83b76d241b | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cri_p-"} | None |  |
| q-754bef6315 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-aae682b23d | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-3472bc3187 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSsN"} | None |  |
| q-74f7e8654d | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-70337a3583 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-498f4d4019 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNZ"} | None |  |
| q-711b98edaf | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hjk9tr"} | None |  |
| q-b7afc20419 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hTSlP6"} | None |  |
| q-ad781ca0e5 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE3lVE"} | None |  |
| q-228624308a | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YJ9aYA"} | None |  |
| q-50c5a1836d | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE3lWA"} | None |  |
| q-59b7037cc6 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qzXFri"} | None |  |
| q-50d0ed37a2 | pivot step 13 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None | F59 |
| q-06e195d022 | pivot step 13 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htvuyY"} | None | F60 |
| q-92c1b8e45a | pivot step 13 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7huwtP3"} | None | F61 |
| q-d59be4ca4b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-fb64687665 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-1df7408111 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-a95c6aae7d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-335f6c3cb4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-2782266949 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72YQ"} | None |  |
| q-46a5653fde | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72YQ"} | None |  |
| q-266f331051 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-9c4ffdaa43 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-7da8a58d53 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRapX"} | None |  |
| q-ff560968e0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-2d17645e14 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFDLy"} | None |  |
| q-e53df04041 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFDLy"} | None |  |
| q-7752d6346d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-c22faf4796 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVSlm"} | None |  |
| q-b58122cbf1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b7vVsn"} | None |  |
| q-1e4f848a5b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-1262a99558 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-a4701ebed9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-d0f5f75fb5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cjZNnV"} | None |  |
| q-a347614fbf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nVnj7M"} | None |  |
| q-bfa817825c | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCI"} | None |  |
| q-aaf927e814 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuAu"} | None |  |
| q-a9ba881fec | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFTIA"} | None |  |
| q-0374f9dd56 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNv3"} | None |  |
| q-8ef0262815 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-e3f5bfbe90 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNum"} | None |  |
| q-74073d5d8f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5y1oY"} | None |  |
| q-32878f2954 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns9wrd"} | None |  |
| q-5a21fe91e3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-a5d5efc406 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-2201bd106a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-6fe358b02c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-c7573e7c84 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-d3aea2175e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-2ae79c2613 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRapX"} | None |  |
| q-8cb987424a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yf"} | None |  |
| q-32711be682 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None |  |
| q-aa7aa13706 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None |  |
| q-f39937dd57 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitC"} | None |  |
| q-e56fe9bc9b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-130243350a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOx9"} | None |  |
| q-3ddc98b326 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-fd7efd2439 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-639b5f02ae | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuA_"} | None |  |
| q-75b25ba5f8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-46918dbcd2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-0019fc552c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-a3df551752 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-aae0e70b84 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-16501035be | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-1d3e540bd0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOhtev"} | None |  |
| q-b335b502b9 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuA-"} | None |  |
| q-7f2c1d1f91 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixAb0"} | None |  |
| q-12a9132385 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niwwaQ"} | None |  |
| q-96b6377bc8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niwwaQ"} | None |  |
| q-3c2a4b67f1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-df2a2fde74 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVsT"} | None |  |
| q-b7c1df28fb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-76414236ea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-0f030eb555 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-d578b908f7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-b44a61cfa7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-1616868eea | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-faee57b90c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bT"} | None |  |
| q-25096d9186 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-2b32d4336d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-2b4d217ea1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1br"} | None |  |
| q-e55b4148de | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YZ"} | None |  |
| q-59abcb1a71 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrG"} | None |  |
| q-21b474a5a1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-f841718e11 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuAv"} | None |  |
| q-7c0a940d31 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrG"} | None |  |
| q-d3f72e21d6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-fa20c8a3cb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-47150d23d4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-070ae34487 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-bfaeab390d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-3dc351c9d8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-655ae60e63 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-837ad9215f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-9bf8a15fd2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Zr"} | None |  |
| q-a98c672948 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-f64cd8ef54 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7habqTS"} | None |  |
| q-a2a740ef1d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-44b0db8949 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-6acd170690 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-25a1576249 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuI"} | None |  |
| q-bfe8f57704 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyU"} | None |  |
| q-626109c049 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyV"} | None |  |
| q-a0f2167f39 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cofd-n"} | None |  |
| q-0fe9a32eab | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4vE"} | None |  |
| q-6baf83cc55 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQPxjx"} | None |  |
| q-ed92460990 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQPxjx"} | None |  |
| q-d26f753266 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQPxjx"} | None |  |
| q-0293de9aeb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQPxjx"} | None |  |
| q-6bcb330c14 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQPxjx"} | None |  |
| q-db93fc6b7b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7habKTs"} | None |  |
| q-688c6a54d2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-c5c34e7ecd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0ZP57"} | None |  |
| q-204f2ef63b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-a28e38326b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy1EsG"} | None |  |
| q-f0f4c8c332 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-d7f7bf287a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-d6d8b4f47a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-7dba18751b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-7690e2c1eb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-735c11d78c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-25fdf46692 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-83c9992292 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None |  |
| q-8ed037c412 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None |  |
| q-d3a8608831 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-7c15e05a90 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-0de45dff3a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-873caa37c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrP"} | None |  |
| q-03b9b700a2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrP"} | None |  |
| q-7fac99204e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qzXFrk"} | None |  |
| q-6f3ebad8e0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-08ae34fc5c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-1112db5ecd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-1ff8d8898e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-0f223586ce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-82ef32e3c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-72454cda6f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-e74d92155e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-cd973d97cf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-0cbd90ed5d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-527596fa5d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-6e065f6f40 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0W8_"} | None |  |
| q-daf174d17d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0W8_"} | None |  |
| q-928f518b29 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGJOD"} | None |  |
| q-f752e0fdb8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq8Ga8"} | None |  |
| q-e573319fa9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nSlNDC"} | None |  |
| q-24115a5682 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-d8ab97a6cf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-5a97195eab | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuA9"} | None |  |
| q-e3fca9f92f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qyVUi_"} | None |  |
| q-2f50bbe842 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCQ"} | None |  |
| q-96c438dc70 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-f5d0be1026 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-1414d11944 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-be1d3ef065 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhF"} | None |  |
| q-c71b045131 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-c107c6cbd8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Zr"} | None |  |
| q-5f32dc538d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytuv"} | None |  |
| q-095a104d19 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7np7lpF"} | None |  |
| q-e6410f7823 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuBA"} | None |  |
| q-6e23a40e5f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCm"} | None |  |
| q-c2c809ac33 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVsT"} | None |  |
| q-997f765193 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytuv"} | None |  |
| q-b6347c7df9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72ZP"} | None |  |
| q-842bc4bd5c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72ZP"} | None |  |
| q-75c87ae764 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c93tyW"} | None |  |
| q-7322e02f97 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c93tyW"} | None |  |
| q-f82770d15b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_aFZ1"} | None |  |
| q-c219d0582c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qVdaFb"} | None |  |
| q-7b9371feec | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1a3"} | None |  |
| q-715ab93ddb | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qVdaEh"} | None |  |
| q-8cfdbf51ee | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_aFYa"} | None |  |
| q-375a3c0e9b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWWCli"} | None |  |
| q-af49046283 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbO"} | None |  |
| q-306ed61919 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_aFYW"} | None |  |
| q-ba48a6b32f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-af8e29ee27 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-84d0e541e4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVuD"} | None |  |
| q-dacbef4b87 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVuD"} | None |  |
| q-2ea781a588 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVuD"} | None |  |
| q-855195c875 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1ad"} | None |  |
| q-72da4e4b6d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qVdaE6"} | None |  |
| q-33ad01f013 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None |  |
| q-d1f2949fe0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-106ac0ffe9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-36cebdd72a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-9be73fd4d1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-044d22794a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-f248e05794 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-87d9674e30 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwewi"} | None |  |
| q-12d139aa73 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-49d23cc0d3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-4ce5c14874 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-794b51443d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5pu"} | None |  |
| q-1fbb0e0420 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-112d29c4c4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5ob"} | None |  |
| q-992343f6cd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72bs"} | None |  |
| q-5cbb96fb0c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlbp"} | None |  |
| q-8f74202da2 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlbx"} | None |  |
| q-2d6fe71a06 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72bs"} | None |  |
| q-37bc4bcbfa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytvM"} | None |  |
| q-ea663f6283 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlby"} | None |  |
| q-c204873b56 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bV"} | None |  |
| q-7f4a900876 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bT"} | None |  |
| q-bb11bb2489 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bU"} | None |  |
| q-625aa5c719 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nix9vF"} | None |  |
| q-64beb754ed | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-4e036f794e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-3978f9ef79 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-62e21bef54 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-5c1c9a36a4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-42061321b0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-17f5380064 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-f2525a700e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-0606d41702 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-8a56c64911 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-ea7b44dfdb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-a3781918e0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSsN"} | None |  |
| q-ed7834fac2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-a0ffbd06f2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-b11db73aae | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-0b2f5405a2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-a61125ef9b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-a8dfa8c09a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-4693e5dccc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-c026c9ba87 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-3bf72df5cc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5pb"} | None |  |
| q-50f29fbe78 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5pb"} | None |  |
| q-54f34d20c0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-8283a7745b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-85889564f0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-1fd8a76e4f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-aaf0458680 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5y1od"} | None |  |
| q-1ee1215305 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC92"} | None |  |
| q-126cb9fbe6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None |  |
| q-8173f2dc80 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cri_p-"} | None |  |
| q-b7e9d809c9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-5ab820435f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-aa22888f4b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSsN"} | None |  |
| q-784406eede | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-418930f729 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-9817847e8f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNZ"} | None |  |
| q-c468273c7d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hjk9tr"} | None |  |
| q-ef61fc5616 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hTSlP6"} | None |  |
| q-4f8891d9d6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE3lVE"} | None |  |
| q-e00bd63a9c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YJ9aYA"} | None |  |
| q-fc3420f0f2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE3lWA"} | None |  |
| q-f5fcceb5c3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qzXFri"} | None |  |
| q-a3f2a2b033 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-f73f6a8d4e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-0c930c9148 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqdH"} | None |  |
| q-06d2876f43 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htvuyY"} | None |  |
| q-5335a7a389 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htvuyY"} | None |  |
| q-67d9ec1cf9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htvuyT"} | None |  |
| q-d76d00bfbf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htvuxL"} | None |  |
| q-858bace4d4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7huwtP3"} | None |  |
| q-adee5b28e7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7huwtP3"} | None |  |
| q-7e90426590 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7huwtP3"} | None |  |

## Verification

Evidence items cited: 245; confirmed against the stored events: 245; rejected: 0. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 5 item(s) in 3 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
