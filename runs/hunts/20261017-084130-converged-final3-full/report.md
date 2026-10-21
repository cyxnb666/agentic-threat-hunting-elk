# Threat hunt report — 20261017-084130-converged-final3-full

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 5 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003.001 (F01, F02, F11, F15, F23, F31, F32, F33), I02 T1552.001 (F27, F52), I03 T1552.001 (F53), I04 T1552.004 (F26, F49, F51), I05 T1557.001 (F37)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-17T00:41:30+00:00 / 2026-10-17T00:51:17+00:00 (587.0 s) |
| LLM calls / tokens | 123 / {'prompt': 3190527, 'completion': 108879} |
| MCP tool calls | 1058 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003.001 | yes | malicious/high | F01, F02, F11, F15, F23, F31, F32, F33 | LSASS memory credential dumping via hidden PowerShell on scranton |
| I02 | T1552.001 | yes | malicious/high | F27, F52 | Plaintext credentials in PsExec command lines for lateral movement to NASHUA |
| I03 | T1552.001 | yes | malicious/high | F53 | Hardcoded WebDAV exfil credentials in Invoke-Exfil script |
| I04 | T1552.004 | yes | malicious/high | F26, F49, F51 | Get-PrivateKeys exports LocalMachine certificate private keys to .pfx on scranton |
| I05 | T1557.001 | yes | malicious/medium | F37 | Python relay/listener tooling on nashua with NTLM network logon |
| I06 | T1557.002 | yes | suspicious/low | F38 | Single responder MAC for most Zeek connections (possible L2 redirection) |
| I07 | out-of-scope:T1027 | no | malicious/high | F58 | csc.exe compiles attacker DLLs from PowerShell on scranton |
| I08 | out-of-scope:T1059 | no | malicious/high | F55 | Python interpreter dropped in Temp and launched via PsExec on nashua |
| I09 | out-of-scope:T1069 | no | suspicious/medium | F61 | accesschk.exe permission reconnaissance on scranton |
| I10 | out-of-scope:T1070 | no | malicious/high | F56 | SDelete anti-forensics wiping of payload and staged archives on scranton |
| I11 | out-of-scope:T1204 | no | malicious/high | F57 | Malicious .scr payload in ProgramData launched by explorer on scranton |
| I12 | out-of-scope:T1218 | no | suspicious/medium | F59 | hostui.exe LOLbin launched by PowerShell on scranton |
| I13 | out-of-scope:T1218 | no | suspicious/medium | F60 | sdclt.exe LOLbin launched by cmd.exe on scranton |
| I14 | out-of-scope:T1560 | no | suspicious/medium | F54 | Rar.exe password-protected staging and sdelete wiping on nashua |

## Findings

### F02 · malicious / high · T1003 · OS credential dumping activity via LSASS handle from malicious PowerShell

Evidence status: **verified**

The overarching OS Credential Dumping activity is present on scranton.dmevals.local: the compromised PowerShell loader (PID 2976, spawned by control.exe with hidden window and obfuscated payload) requested full-access handles to lsass.exe (0x1f3fff, 0x1fffff) and Security 4663 recorded 'Read from process memory' on lsass.exe by user pbeesly. No other credential-store dumping (SAM/NTDS/LSA secrets/DCSync) was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-0af7e930f6 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-0af7e930f6 | ok |
| 3 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKBk | q-2dd38c0cea | ok |

### F01 · malicious / high · T1003.001 · Malicious PowerShell reads LSASS memory with full-access handle on scranton

Evidence status: **verified**

On scranton.dmevals.local, a PowerShell process (PID 2976) launched by control.exe with a hidden window and an obfuscated bitmap-decoded IEX payload opened a handle to C:\windows\system32\lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff (full-access, dump-capable masks) at 2020-05-02T03:05:16Z. Windows Security event 4663 corroborates the same process (user pbeesly, logon 0x372E81) accessing lsass.exe with 'Read from process memory'. This is consistent with LSASS credential dumping by the APT29-style PowerShell framework (which also ran keystroke logging, screen capture and exfil functions).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-0af7e930f6 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-0af7e930f6 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-0af7e930f6 | ok |
| 4 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-60909e0635 | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | message | An attempt was made to access an object.    Subject:  	Security ID:		S-1-5-21-1830255721-3727074217-2423397540-1107  	Account Name:		pbeesly  	Account Domain:		… | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKBk | q-2dd38c0cea | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKBk | q-2dd38c0cea | ok |

### F15 · malicious / high · T1056 · Input capture family: LSASS credential access dominates; no keylogging/GUI/web capture

Evidence status: **verified**

Across the T1056 family, the only malicious input/credential-capture activity is API-level access to LSASS credential memory (T1056.004) by pbeesly via PowerShell on scranton and via wsmprovhost on nashua, alongside a PowerShell credential toolkit (Invoke-Discovery, Get-PrivateKeys exporting cert private keys). The high-volume Sysmon 10 process-access events are otherwise dominated by benign svchost.exe/backgroundTaskHost.exe/Explorer.EXE accesses with GrantedAccess 0x1000, and the 4656/4663 object accesses are dominated by routine registry reads (Session Manager\Environment, Control\Lsa, Winlogon). No keylogging, GUI input capture, or web portal capture was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-7583a48b3b | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-7583a48b3b | ok |
| 3 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQmt | q-d0b1a84959 | ok |
| 4 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTPA5kN | q-d0b1a84959 | ok |

### F11 · malicious / high · T1056.004 · PowerShell and wsmprovhost open LSASS with full access (credential API access) on scranton and nashua

Evidence status: **verified**

On 2020-05-02, user pbeesly on scranton.dmevals.local ran a PowerShell credential-access toolkit (script path C:\Program Files\SysinternalsSuite\readme.ps1) that included Invoke-Discovery and Get-PrivateKeys (exporting certificate private keys with password 'saribas'). At 03:05:16 PowerShell.exe (PID 2976) opened C:\windows\system32\lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff (PROCESS_ALL_ACCESS, including 'Read from process memory'), and the corresponding Security 4656 handle request confirms AccessMask 0x1f3fff against \Device\HarddiskVolume2\Windows\System32\lsass.exe. On nashua.dmevals.local at 03:09:29, wsmprovhost.exe (remote PowerShell, PID 0x1e28) as pbeesly requested AccessMask 0x1f3fff on lsass.exe. This is direct API-level access to LSASS credential memory, consistent with credential API hooking/dumping rather than normal system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-49499c32fa | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-49499c32fa | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-49499c32fa | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKB- | q-a781401a97 | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKA_ | q-a781401a97 | ok |
| 6 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FLV1 | q-a89d1cfe28 | ok |
| 7 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FLV1 | q-a89d1cfe28 | ok |
| 8 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FLV1 | q-a89d1cfe28 | ok |
| 9 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-b32b5fc80f | ok |
| 10 | 2020-05-02 03:04:03.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2M4 | q-484ab85b3c | ok |

### F23 · malicious / high · T1212 · PowerShell and remote WMI host processes opened lsass with full access (credential dumping primitive) during APT29-style intrusion

Evidence status: **verified**

On 2020-05-02, in an intrusion using the pbeesly account and SeaDuke tooling, PowerShell.exe (PID 2976) on scranton.dmevals.local opened lsass.exe (PID 736) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) at 03:05:16Z, and wsmprovhost.exe (PID 7720) on nashua.dmevals.local opened lsass.exe (PID 728) with GrantedAccess 0x1F3FFF at 03:09:29Z. These full-access handles to lsass are the standard primitive for reading credential material from LSASS memory, matching the T1212 credential-access hypothesis. The activity is part of a broader APT29-style chain: a Java(TM) Virtual Machine Support Service installed via javamtsup.exe on scranton, PsExec/PSEXESVC service installs on nashua, and PowerShell script blocks Invoke-SeaDukeStage -ComputerName NASHUA and Invoke-Command -ComputerName NASHUA. The remaining lsass accesses (svchost.exe 0x1000, Azure AntimalwareConfig/Telemetry 0x1400, wininit/csrss at boot) are normal system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-4804269d2d | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-4804269d2d | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-4804269d2d | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-4804269d2d | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-4804269d2d | ok |
| 6 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | process.command_line | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZJhF-L | q-0b1a8d50a9 | ok |
| 7 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | process.executable | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8TL | q-de605a0614 | ok |

### F27 · malicious / high · T1552.001 · Plaintext credentials embedded in PsExec command lines used for lateral movement

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly repeatedly invoked PsExec64.exe with the account password supplied in cleartext on the command line: "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe. Four such executions were observed between 2020-05-02T03:11:18Z and 03:14:42Z, targeting host NASHUA and launching C:\Windows\Temp\python.exe. The credential is stored in the process command line (recoverable from process listings/logs), matching unsecured credentials in files/command lines. Corroborating PowerShell script blocks on the same host (Invoke-Exfil) also embed a plaintext password ("MyCozyPassw0rd!") for a WebDAV share.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGglR | q-5e28989020 | ok |
| 2 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | host.name | scranton.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEF9 | q-87cbcc8db3 | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-3c9c649d6e | ok |

### F52 · malicious / high · T1552.001 · Plaintext credentials in PsExec command lines used for lateral movement to NASHUA

Evidence status: **verified**

On scranton.dmevals.local, powershell.exe launched PsExec64.exe four times (03:11-03:14) with the plaintext password 'Fl0nk3rt0n!T0by' for dmevals\pbeesly on \\NASHUA, executing C:\Windows\Temp\python.exe. This is credential material exposed in process command lines and used for lateral movement.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGglR | q-9e97de6448 | ok |

### F53 · malicious / high · T1552.001 · Hardcoded WebDAV exfil credentials in Invoke-Exfil PowerShell script

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran an Invoke-Exfil PowerShell script (loaded from C:\Program Files\SysinternalsSuite\psversion.ps1) that compresses the Downloads folder into OfficeSupplies.7z and copies it to a WebDAV share \\192.168.0.4\webdav using hardcoded plaintext credentials (user 'cozy', password 'MyCozyPassw0rd!'). The OfficeSupplies.7z archive was written at 03:08:35.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-f346ad2d63 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-aaeec36507 | ok |
| 3 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTWI7pZ | q-78881565ad | ok |

### F55 · malicious / high · T1552.001 · Python interpreter dropped in Temp and launched via PsExec on nashua

Evidence status: **verified**

On nashua.dmevals.local, C:\Windows\Temp\python.exe was launched by C:\Windows\PSEXESVC.exe (SYSTEM) after PsExec lateral movement from scranton using plaintext credentials; it spawned cmd.exe and powershell.exe. A Python interpreter dropped in the Temp folder and executed via PsExec is attacker tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\python.exe"  | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQmt | q-078b219231 | ok |
| 2 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQmt | q-078b219231 | ok |

### F56 · malicious / high · T1552.001 · SDelete anti-forensics wiping of payload and staged archives on scranton

Evidence status: **verified**

On scranton.dmevals.local, powershell.exe ran sdelete64.exe to securely wipe the malicious .scr payload, Draft.Zip and SysinternalsSuite.zip, destroying evidence of the intrusion and collected data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:03:14.693Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\Users\pbeesly\AppData\Roaming\Draft.Zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTneF2m | q-9e97de6448 | ok |
| 2 | 2020-05-02 03:03:33.984Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\Users\pbeesly\Downloads\SysinternalsSuite.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTmdl8v | q-9e97de6448 | ok |

### F57 · malicious / high · T1552.001 · Malicious .scr payload in C:\ProgramData\victim launched by explorer on scranton

Evidence status: **verified**

On scranton.dmevals.local, a suspicious .scr executable with a non-ASCII name in C:\ProgramData\victim was launched by explorer.exe (user pbeesly) and later wiped with sdelete64 — attacker payload on the compromised host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_psP | q-9e97de6448 | ok |
| 2 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\explorer.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_psP | q-9e97de6448 | ok |

### F58 · malicious / high · T1552.001 · csc.exe compiles attacker DLLs from PowerShell on scranton

Evidence status: **verified**

On scranton.dmevals.local, powershell.exe invoked the C# compiler csc.exe to compile attacker source into DLLs (0piklvia.dll, qkbkqqbs.dll) in the user Temp folder — on-disk payload compilation during the intrusion.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.cmdline" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQA6YzM | q-9e97de6448 | ok |
| 2 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQA6YzM | q-9e97de6448 | ok |

### F26 · malicious / high · T1552.004 · PowerShell Get-PrivateKeys harvests all machine certificates to .pfx files

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell script block (Event 4104, ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b, Path C:\Program Files\SysinternalsSuite\readme.ps1) defining function Get-PrivateKeys. It enumerates every certificate in cert:\LocalMachine recursively and exports each one with Export-PfxCertificate to a randomly named .pfx in the user's Downloads folder, protected by the hardcoded password "saribas". A matching Sysmon file-creation event confirms the exported key material: C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by powershell.exe at 2020-05-02T03:04:57Z. This is direct theft of private keys/certificates from the local machine store.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-4cfcc8d94c | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-ccbfb7d91c | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEF9 | q-87cbcc8db3 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEF9 | q-87cbcc8db3 | ok |

### F51 · malicious / high · T1552.004 · Get-PrivateKeys exports all LocalMachine certificates with private keys to .pfx files on scranton

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell script (loaded from C:\Program Files\SysinternalsSuite\readme.ps1) defining Get-PrivateKeys, which enumerates cert:\LocalMachine recursively and exports every certificate with a private key to a randomly-named .pfx in the user's Downloads folder, protected by the hardcoded password 'saribas'. A matching .pfx file (coyn5igj.3io.pfx) was written to C:\Users\pbeesly\Downloads by powershell.exe at 03:04:57, confirming execution.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-f346ad2d63 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-c34b7d46d7 | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEF9 | q-46ca0532bd | ok |

### F31 · malicious / high · T1555 · LSASS memory accessed with full-access masks by hidden PowerShell and PowerShell Remoting

Evidence status: **verified**

On scranton.dmevals.local a hidden PowerShell process (PID 2976, user DMEVALS\pbeesly, spawned by control.exe /name Microsoft.BackupAndRestoreCenter) opened lsass.exe with GrantedAccess 0x1F3FFF and 0x1FFFFF at 2020-05-02T03:05:16Z, the full-access masks typical of credential dumping from the LSASS credential store. On nashua.dmevals.local wsmprovhost.exe (PowerShell Remoting, PID 7720) opened lsass.exe with 0x1F3FFF at 2020-05-02T03:09:29Z with a call trace through PowerShell's Management module. The bulk of the 326 LSASS handle events (289 svchost.exe with 0x1000, plus Azure telemetry/antimalware with 0x1400) are benign system activity; the full-access PowerShell accesses are the malicious outliers.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-ea31b5ba07 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-ea31b5ba07 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-ea31b5ba07 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-ea31b5ba07 | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-ea31b5ba07 | ok |

### F32 · malicious / high · T1555.004 · Hidden PowerShell (control.exe LOLbin) dumping LSASS where Windows Credential Manager vaults reside

Evidence status: **verified**

The PowerShell process that opened LSASS with full access on scranton.dmevals.local was launched as PID 2976 at 2020-05-02T02:58:44Z by control.exe /name Microsoft.BackupAndRestoreCenter, with command line '"PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');...IEX([System.Text.Encoding]::ASCII.GetString($o[0..3932]))"' — a hidden, execution-policy-bypassed PowerShell decoding a steganographic payload from monkey.png and executing it in memory. This process then read LSASS memory (0x1F3FFF/0x1FFFFF), the store from which Windows Credential Manager / DPAPI vault secrets are extracted. No direct vault file or vault command-line artifacts were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-68ce82b4f9 | ok |
| 2 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-68ce82b4f9 | ok |
| 3 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | "C:\Windows\System32\control.exe"  /name Microsoft.BackupAndRestoreCenter | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-68ce82b4f9 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-4e2861ba65 | ok |

### F33 · malicious / high · T1556 · LSASS handle access with full access rights by PowerShell/WinRM — credential dumping, not auth-process modification

Evidence status: **verified**

On 2020-05-02, PowerShell.exe (PID 2976) on scranton.dmevals.local opened lsass.exe (PID 736) with GrantedAccess 0x1f3fff and 0x1fffff (PROCESS_ALL_ACCESS) at 03:05:16, and wsmprovhost.exe (PID 7720, WinRM remote PowerShell, parent svchost.exe) on nashua.dmevals.local opened lsass.exe (PID 728) with 0x1f3fff at 03:09:29. The wsmprovhost call trace runs through Microsoft.PowerShell.Commands.Management.ni.dll, i.e. a PowerShell cmdlet driving the LSASS access. This is credential theft from LSASS memory (T1003.001), not modification of the authentication process. The same user pbeesly was seen authenticating to nashua via WinRM/PSEXESVC and running an Invoke-Exfil script on scranton, consistent with an active intrusion. No T1556 modification artifacts (LSA registry, password filter, reversible encryption) were found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-cbfd68eee0 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-cbfd68eee0 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-cbfd68eee0 | ok |
| 4 | 2020-05-02 03:09:23.885Z | nashua.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\wsmprovhost.exe -Embedding | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTWIboY | q-eb4c7a2a76 | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-24d46b7b1e | ok |

### F37 · malicious / medium · T1557.001 · Python relay/listener tooling on nashua connecting to 192.168.0.4:8443, plus NTLM network logon

Evidence status: **verified**

On nashua.dmevals.local, C:\Windows\Temp\python.exe (user DMEVALS\pbeesly) was launched by C:\Windows\PSEXESVC.exe and made 348 outbound TCP connections to 192.168.0.4:8443 (source 10.0.1.6), a non-standard port consistent with an SMB-relay/name-resolution-poisoning listener. A single NTLM network logon (4624, LogonType 3, LogonProcessName NtLmSsp, NTLM V2) for pbeesly was recorded on scranton.dmevals.local from 172.18.39.2. Zeek shows SMB (445) and NBT-NS (137/138) traffic in the environment. Together these are consistent with T1557.001 relay/poisoning activity, though the Zeek window does not overlap the Windows window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:17:59.352Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO_tniJ | q-4b8050cb5b | ok |
| 2 | 2020-05-02 03:17:59.352Z | nashua.dmevals.local | windows.sysmon | destination.port | 8443 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO_tniJ | q-4b8050cb5b | ok |
| 3 | 2020-05-02 03:17:59.352Z | nashua.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO_tniJ | q-4b8050cb5b | ok |
| 4 | 2020-05-02 03:15:03.954Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPK66i5 | q-f8ed45b238 | ok |
| 5 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | NtLmSsp  | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn1FN5 | q-35088345c2 | ok |
| 6 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.AuthenticationPackageName | NTLM | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn1FN5 | q-35088345c2 | ok |

### F49 · malicious / high · T1649 · PowerShell Get-PrivateKeys exports all LocalMachine certificates with private keys to .pfx files

Evidence status: **verified**

On host scranton.dmevals.local, user pbeesly executed a PowerShell script block defining function Get-PrivateKeys (ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b, Path C:\Program Files\SysinternalsSuite\readme.ps1). The function enumerates every certificate under cert:\LocalMachine recursively, and for each certificate with a Thumbprint calls Export-PfxCertificate to write a password-protected .pfx (password 'saribas') into $env:USERPROFILE\Downloads with a random filename. This is direct theft of authentication certificates and their private keys. The export materialized on disk: Sysmon event 11 shows powershell.exe (PID 3876) creating C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx at 2020-05-02T03:04:57.460Z, matching the script's random-filename pattern. A follow-up script block Invoke-BeachCleanup (ScriptBlock ID 31f21f1d-9199-4d21-9ea8-...) deletes $env:USERPROFILE\Downloads\*.pfx (along with *.bmp, *.png and %APPDATA%\OfficeSupplies.7z), consistent with anti-forensic cleanup of the stolen certificate material. The activity is attributed to the apt29-powershell hunt source and mordorDataset tags.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-e9577e0ee0 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-e9577e0ee0 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-e9577e0ee0 | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-e9577e0ee0 | ok |
| 5 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | process.command_line | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRlVDe | q-f5fd2fecb8 | ok |
| 6 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEF9 | q-48eebca81f | ok |
| 7 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZLhp5O | q-f5fd2fecb8 | ok |

### F59 · suspicious / medium · T1552.001 · hostui.exe LOLbin launched by PowerShell on scranton

Evidence status: **verified**

On scranton.dmevals.local, hostui.exe was launched by powershell.exe during the intrusion — a legitimate Windows binary abused as a LOLbin.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\System32\hostui.exe"  | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItKT-VVW | q-9e97de6448 | ok |
| 2 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItKT-VVW | q-9e97de6448 | ok |

### F60 · suspicious / medium · T1552.001 · sdclt.exe LOLbin launched by cmd.exe on scranton

Evidence status: **verified**

On scranton.dmevals.local, sdclt.exe (a backup/UAC-bypass-capable LOLbin) was launched by cmd.exe during the intrusion and spawned control.exe — consistent with LOLbin abuse.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\sdclt.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB7l0w | q-9e97de6448 | ok |
| 2 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\cmd.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB7l0w | q-9e97de6448 | ok |

### F61 · suspicious / medium · T1552.001 · accesschk.exe permission reconnaissance launched by PowerShell on scranton

Evidence status: **verified**

On scranton.dmevals.local, Sysinternals accesschk.exe was launched by powershell.exe during the intrusion, used for permission reconnaissance of the compromised host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbkGg | q-9e97de6448 | ok |
| 2 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbkGg | q-9e97de6448 | ok |

### F54 · suspicious / medium · T1555.003 · Rar.exe used to password-protect and stage collected data on nashua

Evidence status: **verified**

On nashua.dmevals.local, C:\Windows\Temp\Rar.exe (dropped to the Temp folder, launched by powershell.exe) created a password-protected archive C:\Users\pbeesly\Desktop\working.zip from C:\Users\pbeesly\AppData\Roaming\working.zip using the password 'fGzq5yKw'. The archive and Rar.exe were then wiped with sdelete64.exe, consistent with staging collected credential/data files for exfiltration and anti-forensics.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTPA5kN | q-078b219231 | ok |
| 2 | 2020-05-02 03:17:18.030Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Users\pbeesly\AppData\Roaming\working.zip"  | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPJ5Bh7 | q-078b219231 | ok |

### F38 · suspicious / low · T1557.002 · Single responder MAC for most Zeek connections (possible L2 redirection)

Evidence status: **verified**

In the Zeek window, responder MAC 12:34:56:78:9a:bc appears for 559 of 613 conn records, answering for many different destination IPs (e.g. 10.0.1.6:55121, 10.0.0.4:123). A single MAC answering for the bulk of connections could reflect L2 redirection/ARP manipulation, but the MAC is a synthetic placeholder value and no Windows-side ARP cache or network-configuration evidence corroborates it; the Zeek window does not overlap the Windows datasets. Insufficient to confirm ARP cache poisoning.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:45:00.056Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrohb | q-4fff606656 | ok |
| 2 | 2020-04-30 00:45:00.056Z | simplerockbuild.simplerock.lan | zeek | zeek.orig_l2_addr | 00:0d:3a:4d:42:f2 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrohb | q-4fff606656 | ok |

### F03 · benign / medium · T1003.002 · No SAM/SECURITY registry hive dumping observed

Evidence status: **verified**

No evidence of SAM or SECURITY hive dumping: no reg save / SAM / SECURITY command lines in process creation (4688) or Sysmon event 2, and no 4663 object access to SAM/SECURITY registry keys. The only registry-key object accesses (4663) were generic 'Key' objects, not credential hives.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:03:38.000Z | newyork.dmevals.local | windows.security | win.ObjectType | Process | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOqAA | q-2dd38c0cea | ok |

### F04 · benign / medium · T1003.003 · No NTDS.dit / volume shadow copy activity observed

Evidence status: **verified**

No NTDS.dit access, ntdsutil, vssadmin or shadow-copy activity was found in Sysmon file-create (event 11), Sysmon event 2, Security 4688 process creation, or PowerShell 4104 script blocks. No domain-controller credential database dumping is present in the data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.ObjectType | %{19195a5b-6da0-11d0-afd3-00c04fd930c9} | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ6CoYO | q-66bca5768d | ok |

### F05 · benign / high · T1003.004 · LSA Secrets access is routine LOCAL SERVICE machine-account query

Evidence status: **verified**

The 4662 events reading Object Server LSA, Object Type SecretObject, Object Name Policy\Secrets\$MACHINE.ACC with Access Mask 0x2 ('Query secret value') are performed by the built-in NT AUTHORITY\LOCAL SERVICE account (S-1-5-19) on nashua, scranton and utica. This is normal machine-account secret access, not adversary LSA-secret dumping; no lsadump/secrets command lines or 4663/4656 accesses to SECURITY\Policy\Secrets were seen.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:02:59.000Z | nashua.dmevals.local | windows.security | win.ObjectName | Policy\Secrets\$MACHINE.ACC | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaEO1dd | q-66bca5768d | ok |
| 2 | 2020-05-02 03:02:59.000Z | nashua.dmevals.local | windows.security | user.name | LOCAL SERVICE | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaEO1dd | q-66bca5768d | ok |
| 3 | 2020-05-02 03:02:59.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaEO1dd | q-66bca5768d | ok |

### F06 · benign / medium · T1003.005 · No cached domain credential (DCC2) dumping observed

Evidence status: **verified**

No 4663/4656 object access to SECURITY or Cache registry keys and no PowerShell 4104 script blocks referencing cache/dcc2/mimikatz were found. No cached domain credential theft is present in the data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:03.000Z | nashua.dmevals.local | windows.security | win.ObjectName | Policy\Secrets\$MACHINE.ACC | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVq1j6z | q-66bca5768d | ok |

### F07 · benign / medium · T1003.006 · No DCSync / directory replication activity observed

Evidence status: **verified**

No Security event 4929 (directory service replication) exists, and no process creation or PowerShell script blocks referencing drsuapi/lsadump/dcsync/Get-ADReplAccount were found. The single 4662 DS object access (newyork, NEWYORK$ machine account, Control Access) is not a replication request. No DCSync is present.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ6CoYO | q-66bca5768d | ok |

### F08 · benign / high · T1040 · netsh trace capture on scranton.dmevals.local is Azure Network Watcher agent activity, not adversary sniffing

Evidence status: **verified**

The only packet-capture-looking activity in the environment is `netsh.exe trace start capture=yes` (and the matching `trace stop`) on scranton.dmevals.local at 2020-05-02T03:19:17Z / 03:19:24Z. Both invocations were spawned by the Microsoft Azure Network Watcher agent (parent image C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe /service) running as NT AUTHORITY\SYSTEM, writing to a TEMP .etl file. The netsh.exe binary is the Microsoft-signed system binary (Company: Microsoft Corporation, OriginalFileName: netsh.exe, FileVersion 10.0.18362.1). This is the documented Azure Network Watcher packet-capture feature, not an adversary capturing traffic. The same two events appear in windows.security 4688 with the same parent. No Npcap/WinPcap/dumpcap/Wireshark binaries, drivers, files or registry keys were found anywhere in sysmon or security.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPM8kte | q-b41668d451 | ok |
| 2 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPM8kte | q-b41668d451 | ok |
| 3 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | win.Company | Microsoft Corporation | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPM8kte | q-bd558bbce7 | ok |
| 4 | 2020-05-02 03:19:24.835Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPE0PdZ | q-b41668d451 | ok |
| 5 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVt4o2y | q-3ad020fc61 | ok |

### F09 · benign / high · T1040 · No packet-capture driver or sniffing tooling installed; 7045 services are PsExec and a Java service

Evidence status: **verified**

The five service-install (7045) events in windows.other are four PSEXESVC installs on nashua.dmevals.local (ImagePath %SystemRoot%\PSEXESVC.exe, demand start, user pbeesly) and one 'Java(TM) Virtual Machine Support Service' on scranton.dmevals.local (C:\Windows\System32\javamtsup.exe, auto start, user pbeesly). None is a packet-capture driver such as Npcap/WinPcap/NPF. A targeted search for npcap/winpcap/dumpcap/Wireshark in process command lines, file paths and registry paths returned zero hits, and a search for pcap/sniff/promisc in security process command lines and service names returned zero hits. No evidence of a sniffer being installed or run.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrYMQT | q-a96d5a5eec | ok |
| 2 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | win.ServiceName | Java(TM) Virtual Machine Support Service | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8TL | q-a96d5a5eec | ok |
| 3 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | win.ImagePath | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8TL | q-a96d5a5eec | ok |

### F10 · benign / medium · T1040 · Zeek capture window shows no sniffing-related or anomalous protocol activity

Evidence status: **verified**

The zeek dataset (2020-04-30, a window that does not overlap the Windows host data) contains only normal protocol logs: conn, files, ssl, x509, dce_rpc, http, dns, kerberos, smb_files, smb_mapping, dpd, weird, notice and pe. The 12 'weird' and 2 'notice' events are SSL::Invalid_Server_Cert (self-signed certificate) notices and generic protocol anomalies, none indicating packet capture or promiscuous-mode sniffing. No sniffing tooling or capture artifacts are visible in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:15:18.392Z | simplerockbuild.simplerock.lan | zeek | zeek.note | SSL::Invalid_Server_Cert | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrIjg | q-79cf31527b | ok |
| 2 | 2020-04-30 00:15:18.392Z | simplerockbuild.simplerock.lan | zeek | zeek.msg | SSL certificate validation failed with (self signed certificate) | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrIjg | q-79cf31527b | ok |

### F12 · benign / medium · T1056.001 · No keylogging evidence found

Evidence status: **verified**

Searches for keylogging indicators were negative: no PowerShell script blocks referencing GetAsyncKeyState/SetWindowsHookEx/RegisterHotKey/keylog (C069 zero hits), no keyboard/hook registry keys beyond default Windows keyboard-layout and device-enumeration entries (C066), and no keylogger service installed (7045 services were only PSEXESVC and Java Virtual Machine Support Service, C068). The keyboard-related registry writes observed are standard Windows CTF/KeyboardLayout and TERMINPUT_BUS device entries, not attacker keylogging.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_JuD | q-7583a48b3b | ok |

### F13 · benign / medium · T1056.002 · No GUI input capture / fake credential prompt evidence

Evidence status: **verified**

The only process creations referencing credential/prompt/consent were three legitimate C:\Windows\System32\consent.exe executions (C071), which is the standard Windows UAC consent UI, not a spoofed credential prompt. No fake credential-prompt executables were observed among 4688 process creations (C073). The PowerShell script blocks matching 'credential' were benign Microsoft module resource strings (MSFT_ScriptResourceStrings.psd1) and the Get-PrivateKeys function, not GUI input capture.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | win.ScriptBlockText | # Localized	09/15/2018 04:54 AM (GMT)	303:6.40.10614 	MSFT_ScriptResourceStrings.psd1  # Localized MSFT_ScriptResourceStrings.psd1    ConvertFrom-StringData @' … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSmWPy | q-57626a0236 | ok |

### F14 · benign / medium · T1056.003 · No web portal capture evidence

Evidence status: **verified**

No web-portal credential capture was observed. Zeek HTTP activity (62 requests) was limited to WebDAV paths (/webdav/OfficeSupplies.7z, /webdav/python.exe, /webdav/), and no IIS/w3wp/appcmd process creations or wwwroot/inetpub/login file or object accesses were found (C076, C077, C078 zero hits). The PowerShell script blocks matching 'login/password' were file-collection globs (*pass*, *login*) used for archiving user documents, not web login capture.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZWqdCw | q-57626a0236 | ok |

### F16 · benign / high · T1110 · No brute-force authentication activity observed; credential theft via PowerShell instead

Evidence status: **verified**

Across the whole windows.security window (2020-05-02T02:55:25Z..03:28:09Z) there are zero event.code 4625 failed-logon events (count query returned total 0). Logon activity is only successful 4624/4634 for machine accounts (NEWYORK$, SCRANTON$, NASHUA$, UTICA$, WEC$) and user pbeesly, with no repeated failures. The WMI 5857/5858/5860 events on newyork.dmevals.local are routine RSOP_ExtensionStatus DeleteInstance operations by NT AUTHORITY\SYSTEM (ClientProcessId 1588), not scripted authentication. No brute-force tooling (hydra/ncrack/hashcat/john) appears in the sysmon process stacks. The genuine malicious activity in this window is credential theft/exfiltration, not brute force.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8Rl | q-bfd403176e | ok |
| 2 | 2020-05-02 03:20:46.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn0lPw | q-5120470c05 | ok |

### F17 · benign / high · T1110.001 · No password-guessing attempts; PowerShell scripts steal credentials rather than guess them

Evidence status: **verified**

No 4625 failed logons exist (total 0), so there is no password guessing. The PowerShell 4104 scripts that matched *Password*/*Credential* are credential-theft and exfiltration tooling, not guessing: on scranton.dmevals.local user pbeesly ran Get-PrivateKeys (exports all LocalMachine certificates to .pfx using a hardcoded password 'saribas') and Invoke-Exfil (7-Zip archives Downloads with password 'lolol' and copies to a WebDAV share using hardcoded creds cozy/MyCozyPassw0rd!). These are T1552/T1041 behaviours, not T1110.001. The PsExec64.exe command line carries a plaintext password (-p Fl0nk3rt0n!T0by) for lateral movement, again credential use, not guessing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-6e6b90e4ed | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-267146854f | ok |
| 3 | 2020-05-02 03:14:42.601Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPDyDoS | q-f66b690ca7 | ok |

### F18 · benign / high · T1110.002 · No password-cracking tooling or hash-dump artifacts observed

Evidence status: **NOT verified (1/2 evidence items)** — excluded from the verdict

No hashcat/john/wordlist command lines exist (C104 zero hits). The sysmon process stacks show no cracking binaries. LSASS handle access (event.code 10, TargetImage lsass.exe) is dominated by svchost.exe with GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION, 286 events) plus Azure antimalware/telemetry agents at 0x1400 — normal system behaviour, not credential dumping for offline cracking. File-creation stacks (event.code 11) show only prefetch files, DSC caches and PSEXESVC.exe, no .pot/.hash/.pfx cracking output. The only certificate export (.pfx) is the Get-PrivateKeys theft script, which is credential access, not cracking.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:24:18.178Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOYDnci | q-aaa37afbd5 | ok |
| 2 | 2020-05-02 03:12:25.384Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | None | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUGBVXT | q-f66b690ca7 | FAILED: field win.TargetFilename not in the event |

### F19 · benign / high · T1110.003 · No password-spraying pattern; no failed logons at all

Evidence status: **verified**

Password spraying requires many failed authentications across accounts. The security dataset contains zero 4625 events (total 0), and the 4624/4634 breakdown shows only successful machine-account and pbeesly logons with no burst of failures. There is no evidence of spraying.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn0lPw | q-5120470c05 | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonType | 10 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn0lP2 | q-5120470c05 | ok |

### F20 · benign / high · T1110.004 · No credential-stuffing activity; only successful logons present

Evidence status: **verified**

Credential stuffing would produce repeated failed logons using leaked credential pairs. No 4625 events exist (total 0) and no source.ip values are associated with failed authentication. The observed logons are successful (4624) for machine accounts and pbeesly. No stuffing observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn0lPw | q-5120470c05 | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | event.code | 4624 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn0lP2 | q-5120470c05 | ok |

### F21 · benign / high · T1111 · No MFA/smartcard interception artifacts; only legitimate Microsoft smartcard provider and OS credential-service registration

Evidence status: **verified**

Hunting for T1111 (Multi-Factor Authentication Interception) across windows.sysmon, windows.security, windows.powershell and windows.other on 2020-05-02 found no interception tooling. The only smartcard-related image load is the Microsoft-signed SmartcardCredentialProvider.dll loaded by LogonUI.exe on scranton.dmevals.local (Sysmon 7), which is the standard Windows smartcard credential provider. All registry writes touching 'Credential'/'Ngc' keys are routine service registration by services.exe/svchost.exe (CredentialEnrollmentManagerUserSvc, NgcSvc, NgcCtnrSvc, CredentialGuard). The 4648 explicit-credential logons are pbeesly authenticating to NASHUA via PsExec (lateral movement), not MFA interception. No fake credential provider, no interception DLL, no MFA-related process or file was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:21.087Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\SmartcardCredentialProvider.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO5lCpc | q-64d7bb7b25 | ok |
| 2 | 2020-05-02 03:19:21.087Z | scranton.dmevals.local | windows.sysmon | win.Signature | Microsoft Windows | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO5lCpc | q-64d7bb7b25 | ok |
| 3 | 2020-05-02 03:19:21.087Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\LogonUI.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO5lCpc | q-64d7bb7b25 | ok |
| 4 | 2020-05-02 03:20:48.264Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\System\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc_13619b\ImagePath | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOxeHN4 | q-532e518bc5 | ok |
| 5 | 2020-05-02 03:20:48.264Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\services.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOxeHN4 | q-532e518bc5 | ok |
| 6 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-80df873020 | ok |
| 7 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-80df873020 | ok |

### F22 · benign / high · T1187 · No forced-authentication (T1187) artifacts; SMB traffic is normal domain/GPO and PsExec lateral movement

Evidence status: **verified**

Hunting for T1187 forced authentication across windows.security, windows.sysmon, windows.other and windows.powershell found no coercion artifacts. All outbound SMB (445/139) connections in windows.sysmon originate from process.executable 'System' (the kernel SMB client) to the domain controller 10.0.0.4 or link-local IPv6 fe80::e40c:95b6:b0a7:6429, consistent with normal domain/GPO traffic rather than an attacker-controlled SMB/WebDAV listener. Share access (5140/5145) is dominated by machine accounts (SCRANTON$, NEWYORK$, NASHUA$, UTICA$, WEC$) reading SYSVOL GPO paths, plus user pbeesly from 10.0.1.4 accessing ADMIN$/IPC$ with PSEXESVC.exe, svcctl and samr — that is PsExec-style lateral movement (T1021.002/T1569.002), not forced authentication. The only .lnk files created (Sysmon 11) are benign Explorer 'Recent' shortcuts and a hostui.lnk in the StartUp folder written by powershell.exe (persistence), not .scf/.searchconnector-ms/WebDAV coercion files. No WebDAV/NTLM coercion script blocks were found (check C135 returned zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqgghU | q-09b02ce989 | ok |
| 2 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.0.4 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqgghU | q-09b02ce989 | ok |
| 3 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | destination.port | 445 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqgghU | q-09b02ce989 | ok |
| 4 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaFQQtn | q-cbc722fc77 | ok |
| 5 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\SYSVOL | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaFQQtn | q-cbc722fc77 | ok |
| 6 | 2020-05-02 03:11:18.000Z | nashua.dmevals.local | windows.security | win.RelativeTargetName | PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ef_q | q-0c8294e2ee | ok |
| 7 | 2020-05-02 03:11:18.000Z | nashua.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ef_q | q-0c8294e2ee | ok |
| 8 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | process.executable | %SystemRoot%\PSEXESVC.exe | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrYMQT | q-e308d8ec44 | ok |
| 9 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTmcl_4 | q-4dc369b6d1 | ok |

### F24 · benign / medium · T1212 · Kerberos service-ticket requests by pbeesly for host SPNs (normal authentication, not exploitation)

Evidence status: **verified**

The 4769 Kerberos service-ticket events for pbeesly@DMEVALS.LOCAL requesting SPNs such as NEWYORK$ and NASHUA$ (client addresses 10.0.1.4/10.0.1.6) are ordinary Kerberos authentication traffic generated by the account's remote activity, not evidence of ticket-forging or exploitation for credential access. They are consistent with the same intrusion's lateral movement but do not themselves demonstrate T1212 exploitation.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FbW6 | q-38109cb27e | ok |
| 2 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | message | A Kerberos service ticket was requested.    Account Information:  	Account Name:		pbeesly@DMEVALS.LOCAL  	Account Domain:		DMEVALS.LOCAL  	Logon GUID:		{b7617a6… | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FbW6 | q-38109cb27e | ok |

### F25 · benign / high · T1539 · No web session cookie theft observed; browser accesses are benign shell/COM activity

Evidence status: **verified**

Across windows.sysmon, windows.security, windows.powershell and windows.other (2020-05-02 02:55-03:28Z) there is no evidence of web session cookie theft. Searches for browser cookie stores (Cookies, Login Data, WebCache, Local State, Network\Cookies) in file-creation (Sysmon 11), file-creation-time (Sysmon 2), process command lines (Sysmon 1) and PowerShell scriptblocks (4104) returned zero hits. The only browser process accesses (Sysmon 10) target MicrosoftEdge.exe / MicrosoftEdgeCP.exe from C:\windows\Explorer.EXE and C:\windows\system32\svchost.exe with low granted access (0x2000/0x3000), consistent with normal Windows shell/COM interaction rather than memory scraping of session cookies. The genuine malicious activity on these hosts is a credential-access/lateral-movement campaign (PsExec64 with a cleartext password to \\NASHUA launching C:\Windows\Temp\python.exe, plus sdelete64 cleanup), which does not match T1539.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:59.199Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\Windows\System32\MicrosoftEdgeCP.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_Zu5 | q-25936d92e2 | ok |
| 2 | 2020-05-02 02:55:59.199Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\Explorer.EXE | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_Zu5 | q-25936d92e2 | ok |
| 3 | 2020-05-02 02:55:59.199Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x2000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_Zu5 | q-25936d92e2 | ok |
| 4 | 2020-05-02 02:57:28.777Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQC8TKL | q-25936d92e2 | ok |
| 5 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGglR | q-3c680dea7b | ok |
| 6 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTpgCep | q-3c680dea7b | ok |

### F29 · benign / medium · T1552.002 · Registry credential-store access not observed

Evidence status: **verified**

Sysmon registry value-set events touching credential-related keys (HKLM\SECURITY\Cache\NL$1) were written by C:\windows\system32\lsass.exe on nashua.dmevals.local and scranton.dmevals.local, consistent with normal OS cached-credential maintenance. No reg query/save/export of SAM/SECURITY/LSA was observed (C164 zero hits) and no 4663 access to SAM/SECURITY/LSA objects (C165 zero hits). No evidence of adversary registry credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | registry.path | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQnT | q-f2f02bf2b2 | ok |
| 2 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQnT | q-f2f02bf2b2 | ok |

### F30 · benign / medium · T1552.003 · Shell history access not observed

Evidence status: **verified**

All shell-history checks (ConsoleHost_history, PSReadLine, history) across windows.powershell, windows.sysmon and windows.security returned zero hits (C168-C171). No evidence of adversary reading shell history for credentials.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:03.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Discovery {     $DiscoveryInfo =@()     $CurrentDir = Get-Location      $DiscoveryInfo += [PSCustomObject]@{                 CurrentDirectory = … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2M4 | q-eaa0948789 | ok |

### F28 · benign / high · T1552.006 · Group Policy DataStore/SYSVOL file creation is normal GPO processing

Evidence status: **verified**

Sysmon file-creation events for C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\... (gpt.ini, Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf) on scranton.dmevals.local and nashua.dmevals.local were all created by C:\windows\system32\svchost.exe (SYSTEM) as part of routine Group Policy refresh. No Groups.xml, cpassword, or gpprefdecrypt activity was observed; the GPP-preference credential checks returned zero hits. This is expected OS behaviour, not adversary collection of GPP cpassword material.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.091Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.in… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqhAkt | q-c3aecca811 | ok |
| 2 | 2020-05-02 03:01:43.091Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqhAkt | q-c3aecca811 | ok |

### F34 · benign / medium · T1556.001 · No domain-controller authentication modification observed

Evidence status: **verified**

The LSASS handle-access hits on the DCs (scranton, newyork, utica, nashua) are dominated by svchost.exe (289 of 326) with GrantedAccess 0x1000, plus AntimalwareConfig.exe and WindowsAzureTelemetryService.exe — normal security/telemetry processes. The rare full-access opens by PowerShell/wsmprovhost are memory reads for credential theft, not patching of DC authentication. No service installation targeting lsass/cryptdll (event 7045) and no LSASS image-load of unsigned DLLs were found; the cryptdll/samlib/samcli image loads are all Microsoft-signed system DLLs loaded by SearchProtocolHost, WmiPrvSE, svchost, dsregcmd and powershell.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_JuD | q-667a9edb75 | ok |
| 2 | 2020-05-02 03:01:36.915Z | newyork.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\cryptdll.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqhQkl | q-2528224efc | ok |

### F35 · benign / high · T1556.002 · No password filter DLL registration or drop observed

Evidence status: **verified**

No registry modification of the LSA 'Notification Packages' value was found (event 4657 query returned zero hits), no PowerShell script referencing Notification Packages or PasswordFilter (4104 query zero hits), no service installation with a .dll ImagePath (7045 query zero hits), and no DLL file creation in System32/SysWOW64 (Sysmon event 11 query returned zero hits). The only registry writes seen are benign ContentDeliveryManager/RuntimeBroker AppContainer cache paths under the pbeesly user hive.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:59:17.458Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\S-1-5-21-1830255721-3727074217-2423397540-1107_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.windows.conte… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItT_4QtO | q-65d15711dc | ok |

### F36 · benign / medium · T1556.008 · No network provider DLL registration observed

Evidence status: **verified**

No evidence of a network provider DLL being registered: no service installation with a .dll ImagePath (7045 query zero hits), no DLL file creation in System32/SysWOW64 (Sysmon event 11 zero hits), and no LSA registry modification (4657 query zero hits). The only network-related activity is the Invoke-Exfil script mapping a WebDAV PSDrive, which is data staging/exfiltration, not authentication-process modification.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-24d46b7b1e | ok |

### F39 · benign / medium · T1557.003 · No DHCP spoofing activity observed

Evidence status: **verified**

No DHCP traffic (UDP 67/68) was found in Zeek or Windows security 5156 events, no DHCP server events (1341/1342/1020/1063) in windows.other, and no DHCP/netsh-interface command lines in PowerShell. No evidence of DHCP spoofing in any dataset.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:45:00.056Z | simplerockbuild.simplerock.lan | zeek | destination.port | 55121 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrohb | q-4fff606656 | ok |

### F40 · benign / high · T1558 · No Kerberos ticket theft/forgery observed; credential access present is LSASS memory dumping (T1003)

Evidence status: **verified**

Across windows.security, windows.sysmon, windows.powershell and zeek there is no evidence of Kerberos ticket theft or forgery. All TGS/AS ticket requests in windows.security (4769/4768) and all Zeek kerberos records use AES256 (0x12 / aes256-cts-hmac-sha1-96) only, with no RC4 (0x17) downgrade, no anomalous SPN enumeration and no AS-REQ without preauth. The 4672 special-privilege logons are all normal machine/system accounts (NEWYORK$, SYSTEM, pbeesly, SCRANTON$). The only credential-access activity found is LSASS process-memory access by PowerShell.exe (PID 2976) on scranton.dmevals.local with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) at 2020-05-02T03:05:16, which is credential dumping (T1003), not a T1558 technique.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKC- | q-fe8d1b3881 | ok |
| 2 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ef_w | q-fe8d1b3881 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-eb6ebc062f | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-eb6ebc062f | ok |
| 5 | 2020-04-30 00:24:19.119Z | simplerockbuild.simplerock.lan | zeek | zeek.cipher | aes256-cts-hmac-sha1-96 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrIjh | q-a12e2791a4 | ok |

### F41 · benign / high · T1558.001 · No Golden Ticket activity: no RC4 TGS, no anomalous 4672 privilege logons

Evidence status: **verified**

Golden ticket forging would show RC4 (0x17) TGS requests and/or special-privilege (4672) logons for accounts that should not hold them. All 28 4769 events use TicketEncryptionType 0x12 (AES256) for pbeesly@DMEVALS.LOCAL and SCRANTON$@DMEVALS.LOCAL only, and the 212 4672 events are all for legitimate machine/system accounts (NEWYORK$ 123, SYSTEM 59, pbeesly 19, SCRANTON$ 4, DWM-1/2, NASHUA$, NETWORK SERVICE, LOCAL SERVICE). No forged-ticket indicators.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKC- | q-fe8d1b3881 | ok |
| 2 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKXhpM | q-d2f149f422 | ok |

### F42 · benign / high · T1558.002 · No Silver Ticket activity observed

Evidence status: **verified**

Silver ticket forging would produce service-ticket (4769) requests with RC4 encryption or for services/accounts not normally accessed. All 4769 events use AES256 (0x12) and target only pbeesly@DMEVALS.LOCAL and SCRANTON$@DMEVALS.LOCAL for services krbtgt, NEWYORK$, NASHUA$, SCRANTON$ and WEC$ — normal machine/service account access. No RC4 service tickets and no anomalous service targets.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:14.000Z | newyork.dmevals.local | windows.security | win.ServiceName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV3-aUJ | q-fe8d1b3881 | ok |
| 2 | 2020-05-02 03:19:14.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV3-aUJ | q-fe8d1b3881 | ok |

### F43 · benign / high · T1558.003 · No Kerberoasting: all service tickets AES256, no RC4 downgrade

Evidence status: **verified**

Kerberoasting requires requesting service tickets with weak RC4 (0x17) encryption to crack offline. Every 4769 TGS request in windows.security uses TicketEncryptionType 0x12 (AES256), and every Zeek kerberos TGS record uses aes256-cts-hmac-sha1-96. No RC4 service tickets and no SPN enumeration tooling (no setspn/GetUserSPNs/Rubeus/Invoke-Kerberoast in PowerShell command lines).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOaA_ | q-fe8d1b3881 | ok |
| 2 | 2020-04-30 00:24:19.122Z | simplerockbuild.simplerock.lan | zeek | zeek.cipher | aes256-cts-hmac-sha1-96 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrIji | q-a12e2791a4 | ok |

### F44 · benign / high · T1558.004 · No AS-REP Roasting: all AS-REQs have preauthentication enabled

Evidence status: **verified**

AS-REP roasting requires accounts with Kerberos preauthentication disabled (PreAuthType 0). All 4768 AS-REQ events in windows.security have win.PreAuthType 2 (preauth enabled) for pbeesly and SCRANTON$, and all Zeek AS requests to krbtgt/DMEVALS.LOCAL use aes256-cts-hmac-sha1-96. No preauth-disabled accounts and no AS-REP roasting tooling (no GetNPUsers/asreproast/Rubeus) in PowerShell command lines.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ef_w | q-fe8d1b3881 | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV3-aXJ | q-fe8d1b3881 | ok |

### F45 · benign / high · T1606 · No web-credential forging; only benign WebDAV cookie handling and PsExec credential use

Evidence status: **verified**

Across windows.security, windows.sysmon, windows.powershell and windows.other there is no evidence of forged web credentials. The only cookie-related activity is the legitimate Windows WebDAV client: on scranton.dmevals.local, rundll32.exe running davclnt.dll,DavSetCookie for http://192.168.0.4/webdav, spawned by the WebClient service (svchost.exe -k LocalService -p -s WebClient) under user pbeesly. A single INetCookies file was created by svchost in a ServiceProfiles path (normal OS behavior). The lone PowerShell 4104 'cookie/token' hit is a benign Sysinternals readme.ps1 script (Get-AttributesMask). The 4648 explicit-credential logons are PsExec (C:\Windows\PSEXESVC.exe) lateral movement by pbeesly, i.e. credential use, not forging. No SAML/JWT/ADFS artifacts anywhere.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVHe6C | q-d496ae87c2 | ok |
| 2 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | C:\windows\system32\svchost.exe -k LocalService -p -s WebClient | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVHe6C | q-270767b06b | ok |
| 3 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-17ffbe94f3 | ok |
| 4 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRllBR | q-23b7bfa0c5 | ok |
| 5 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-e1b3c61600 | ok |

### F46 · benign / high · T1606.001 · Web cookie activity is legitimate WebDAV client and OS INetCookies, not forging

Evidence status: **verified**

The only cookie-related events are the Windows WebDAV client setting an auth cookie (rundll32.exe davclnt.dll,DavSetCookie for http://192.168.0.4/webdav, parent svchost WebClient service) on scranton.dmevals.local as pbeesly, and a single INetCookies file created by svchost under a ServiceProfiles package path. No browser cookie theft, cookie-file tampering, or cookie-forging tooling was observed. The PowerShell 4104 hit matching 'cookie/session' is a benign Sysinternals readme.ps1 script.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVHe6C | q-d496ae87c2 | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-17ffbe94f3 | ok |
| 3 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRllBR | q-23b7bfa0c5 | ok |

### F47 · benign / high · T1606.002 · No SAML token forging artifacts observed

Evidence status: **verified**

No SAML/Assertion/ADFS/JWT artifacts were found in any dataset. Searches for SAML, Assertion, NotOnOrAfter, ADFS, token and cert in PowerShell script blocks, windows.other messages, and sysmon process command lines returned zero hits. The zeek TLS server_name stack shows only 192.168.0.4 (no SSO/ADFS endpoint). No evidence of SAML token forging.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVHe6C | q-d496ae87c2 | ok |

### F48 · benign / high · T1621 · No MFA request generation activity; authentication events are normal Windows/RDP logons

Evidence status: **verified**

Hunting for T1621 (Multi-Factor Authentication Request Generation) across windows.other, windows.powershell, windows.security and windows.sysmon found no MFA tooling, no repeated authentication-prompt generation, and no identity-provider abuse. The only authentication-related events are ordinary Windows behaviour: an RDP logon by user pbeesly on scranton.dmevals.local (TerminalServices events 1149/21 from source 172.18.39.2), an NTLM-in-use informational event (6038), and a Credential Guard configuration event (14). PowerShell 4104 script blocks matching auth keywords are all benign Microsoft module manifests (DSC xStorage, Operation.Validation, 7-Zip). DNS/network activity to login.live.com and Microsoft/Azure CDN IPs originates from svchost.exe, backgroundTaskHost.exe and BackgroundTransferHost.exe (normal OS telemetry). No 4625 failed logons and no MFA/authenticator/OTP processes or command lines were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:42.000Z | scranton.dmevals.local | windows.other | message | Remote Desktop Services: User authentication succeeded:    User: pbeesly  Domain: dmevals  Source Network Address: 172.18.39.2 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8RI | q-d0178f5fe8 | ok |
| 2 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.other | message | Microsoft Windows Server has detected that NTLM authentication is presently being used between clients and this server. This event occurs once per boot of the s… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8RH | q-120a8602a0 | ok |
| 3 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8R_ | q-120a8602a0 | ok |
| 4 | 2020-05-02 03:05:31.948Z | scranton.dmevals.local | windows.sysmon | message | Dns query:  RuleName: -  UtcTime: 2020-05-02 03:05:31.948  ProcessGuid: {47ab858c-e37a-5eac-e103-000000000400}  ProcessId: 8396  QueryName: login.live.com  Quer… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItThXQrv | q-186881bdc4 | ok |
| 5 | 2020-05-02 02:59:16.747Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\backgroundTaskHost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItT-3yn1 | q-fc6b9a2a55 | ok |
| 6 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | process.command_line | #  # Module manifest for module 'xStorage'  #  # Generated on: 6/14/2015  #    @{    # Script module or binary module file associated with this manifest.  # Roo… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSmmMy | q-84165c5c05 | ok |

### F50 · benign / medium · T1649 · Certificate store registry modifications (4657) are benign OS/Sysmon activity

Evidence status: **verified**

The 4657 registry-value-modification hits touching certificate paths are not attacker certificate theft. The single SystemCertificates hit is on nashua.dmevals.local where the modifying process is C:\Windows\Sysmon.exe (PID 0xd64) under the machine account NASHUA$ (S-1-5-18, logon 0x3E7), modifying the ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 Blob — normal certificate-store maintenance by a system process. The remaining 4657 hits are wevtutil.exe (SCRANTON$) editing WMI Autologger EventLog-Application keys, unrelated to certificates. The Sysmon registry-set (event 13) hits under SystemCertificates/Cryptography are likewise routine certificate-store and CryptoAPI symbolic-link writes. None of these show an adversary exporting or forging authentication certificates.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ6CoZN | q-7982ebad0c | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ6CoZN | q-7982ebad0c | ok |
| 3 | 2020-05-02 03:19:16.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\wevtutil.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVt5I2Y | q-a2d6511705 | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Legitimate Microsoft Store Skype app self-restarting; no credential access or unusual child processes. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | Python interpreter dropped in C:\Windows\Temp and launched by PSEXESVC.exe (SYSTEM) after PsExec lateral movement from scranton with plaintext creds; spawned cm… |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Rar.exe dropped to Temp and run by powershell.exe to create a password-protected archive of collected data, then wiped with sdelete64 — staging/anti-forensics. |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | SDelete run from Temp by cmd.exe to securely delete the staged archive and Rar.exe, destroying evidence of collection. |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Standard Azure guest agent log collection utility, parented by WaAppAgent.exe. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher agent, standard cloud VM monitoring component. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure IaaS Antimalware configuration utility, standard cloud component. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure Custom Script Extension handler, standard VM extension. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure AD domain-join extension, standard VM provisioning component. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler, legitimate updater component. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler (64-bit), legitimate updater component. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Google Update service, legitimate software updater. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Sysinternals accessChk launched by powershell.exe during the intrusion; used for permission reconnaissance of the compromised host. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | PsExec64 run by powershell.exe with plaintext credentials to move laterally to \\NASHUA and launch python.exe — attacker lateral movement. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | SDelete run by powershell.exe to wipe the malicious .scr payload, Draft.Zip, SysinternalsSuite.zip and staged archives — anti-forensics. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Windows Defender antimalware service, legitimate. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Windows Defender network inspection service, legitimate. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Suspicious .scr executable in C:\ProgramData\victim with a non-ASCII name, launched by explorer.exe and later wiped with sdelete — attacker payload. |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | C# compiler invoked by powershell.exe compiling attacker source into DLLs (0piklvia.dll, qkbkqqbs.dll) in the user Temp folder — in-memory/on-disk payload compi… |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | hostui.exe launched by powershell.exe; a legitimate binary abused as a LOLbin during the intrusion. |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | sdclt.exe (backup/UAC-bypass-capable LOLbin) launched by cmd.exe during the intrusion, spawning control.exe. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent firewall tool, standard cloud component. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent volume discovery utility, standard cloud component. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure guest agent service, standard cloud component. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | 1 | C:\Windows\System32\services.exe | benign | Azure telemetry service, standard cloud component. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\WaAppAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure Windows Azure Agent, standard cloud component. |
| scranton.dmevals.local | C:\WindowsAzure\SecAgent\WaSecAgentProv.exe | 2 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure security agent provider, standard cloud component. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\Plugins\VFPl… | 1 | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | benign | Azure network agent plugin, standard cloud component. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | 1 | C:\Windows\System32\services.exe | benign | Azure network agent service, standard cloud component. |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | Malicious PowerShell (PID 2976, spawned by control.exe with hidden window and obfuscated bitmap-decoded IEX payload) opened full-access handles to lsass.exe (0x1f3fff, 0x1fffff) and Security 4663 recorded 'Read from proc… |
| T1003.001 LSASS Memory | malicious | Sysmon event 10 shows PowerShell.exe (PID 2976) accessing lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff; Security 4663 confirms 'Read from process memory' on lsass.exe by the same process/user. |
| T1003.002 Security Account Manager | not_observed | No reg save/SAM/SECURITY command lines, no Sysmon event 2 hive access, and no 4663 access to SAM/SECURITY registry keys. |
| T1003.003 NTDS | not_observed | No NTDS.dit file access, ntdsutil/vssadmin/shadow-copy activity in Sysmon, Security 4688 or PowerShell 4104 logs. |
| T1003.004 LSA Secrets | benign | The only LSA secret reads (4662, Policy\Secrets\$MACHINE.ACC, mask 0x2) are routine queries by NT AUTHORITY\LOCAL SERVICE, not adversary LSA-secret dumping. |
| T1003.005 Cached Domain Credentials | not_observed | No 4663/4656 access to SECURITY/Cache registry keys and no PowerShell script blocks referencing cache/dcc2/mimikatz. |
| T1003.006 DCSync | not_observed | No Security 4929 replication events and no drsuapi/lsadump/dcsync/Get-ADReplAccount references in process creation or PowerShell logs. |
| T1040 Network Sniffing | benign | The only capture-like activity is Microsoft Azure Network Watcher's netsh trace start/stop on scranton.dmevals.local, spawned by NetworkWatcherAgent.exe /service as SYSTEM using the signed Microsoft netsh.exe. No Npcap/W… |
| T1056 Input Capture | malicious | LSASS credential-memory access (0x1f3fff/0x1fffff) by pbeesly via PowerShell on scranton and wsmprovhost on nashua, plus a PowerShell credential toolkit (Invoke-Discovery, Get-PrivateKeys). |
| T1056.001 Keylogging | not_observed | No keylogging indicators: no GetAsyncKeyState/SetWindowsHookEx/RegisterHotKey script blocks, no hook/keylogger registry keys, no keylogger service installed. |
| T1056.002 GUI Input Capture | not_observed | Only legitimate consent.exe UAC prompts; no fake credential-prompt executables or GUI input capture observed. |
| T1056.003 Web Portal Capture | not_observed | No IIS/w3wp/appcmd processes, no wwwroot/inetpub/login file or object access; Zeek HTTP limited to WebDAV file transfers. |
| T1056.004 Credential API Hooking | malicious | PowerShell.exe (scranton) and wsmprovhost.exe (nashua) opened lsass.exe with AccessMask 0x1f3fff/0x1fffff including 'Read from process memory', consistent with credential API access/hooking. |
| T1110 Brute Force | not_observed | Zero 4625 failed-logon events in windows.security (count total 0); no brute-force tooling in sysmon process stacks. WMI 5857/5858 hits are routine RSOP DeleteInstance by SYSTEM. |
| T1110.001 Password Guessing | not_observed | No failed logons and no guessing tools. PowerShell 4104 hits are credential theft/exfil scripts (Get-PrivateKeys, Invoke-Exfil) and PsExec with a plaintext password, i.e. credential use, not guessing. |
| T1110.002 Password Cracking | not_observed | No hashcat/john/wordlist command lines (C104 zero hits); LSASS access is svchost.exe 0x1000 (normal); no cracking output files. |
| T1110.003 Password Spraying | not_observed | No 4625 events and no burst of failed authentications across accounts; only successful 4624/4634 logons. |
| T1110.004 Credential Stuffing | not_observed | No failed logons and no source.ip tied to authentication failures; only successful logons present. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA/smartcard interception activity found. The only smartcard artifact is the Microsoft-signed SmartcardCredentialProvider.dll loaded by LogonUI.exe (legitimate Windows component). All 'Credential'/'Ngc' registry writ… |
| T1187 Forced Authentication | not_observed | No forced-authentication artifacts found. Outbound SMB (445/139) is exclusively from process.executable 'System' to the DC 10.0.0.4 / link-local IPv6, i.e. normal domain/GPO traffic; share access is machine-account SYSVO… |
| T1212 Exploitation for Credential Access | malicious | PowerShell.exe on scranton opened lsass with GrantedAccess 0x1FFFFF and wsmprovhost.exe on nashua opened lsass with 0x1F3FFF — full-access handles to LSASS memory, the credential-dumping primitive, within an APT29-style … |
| T1539 Steal Web Session Cookie | not_observed | No browser cookie store was accessed, copied or exfiltrated. Queries for cookie/Login Data/WebCache/Local State filenames in Sysmon file-create (11), file-create-time (2), process command lines (1) and PowerShell 4104 sc… |
| T1552 Unsecured Credentials | malicious | Unsecured credentials observed: plaintext password in PsExec command line and hardcoded passwords in PowerShell scripts on scranton.dmevals.local. |
| T1552.001 Credentials In Files | malicious | Plaintext credentials in PsExec command lines (Fl0nk3rt0n!T0by) and hardcoded WebDAV exfil credentials (MyCozyPassw0rd!) in PowerShell scripts. |
| T1552.002 Credentials in Registry | not_observed | No reg query/save/export of SAM/SECURITY/LSA and no 4663 access to credential hives; only routine lsass.exe cached-credential writes. |
| T1552.003 Shell History | not_observed | All ConsoleHost_history/PSReadLine/history checks returned zero hits across powershell, sysmon and security datasets. |
| T1552.004 Private Keys | malicious | Get-PrivateKeys script exported all LocalMachine certificates with private keys to .pfx files on scranton; a .pfx was written to Downloads. |
| T1552.006 Group Policy Preferences | benign | SYSVOL/GroupPolicy DataStore file creations were routine svchost.exe GPO processing; no Groups.xml/cpassword activity. |
| T1555 Credentials from Password Stores | malicious | Hidden PowerShell (PID 2976, spawned by control.exe) opened lsass.exe with 0x1F3FFF/0x1FFFFF on scranton, and wsmprovhost.exe opened lsass.exe with 0x1F3FFF on nashua — full-access LSASS reads consistent with credential-… |
| T1555.003 Credentials from Web Browsers | suspicious | Rar.exe used to password-protect staged data on nashua, then wiped with sdelete; consistent with credential/data staging though no browser store access observed. |
| T1555.004 Windows Credential Manager | malicious | The LSASS-dumping PowerShell was launched via control.exe LOLbin with a hidden, EP-bypass command line decoding a steganographic payload from monkey.png; LSASS is the memory store for Windows Credential Manager/DPAPI vau… |
| T1555.005 Password Managers | not_observed | No password-manager (1Password/KeePass/LastPass/Bitwarden/kdbx) file, process or script artifacts found in any dataset. |
| T1556 Modify Authentication Process | suspicious | LSASS was opened with full access (0x1fffff/0x1f3fff) by PowerShell.exe on scranton and wsmprovhost.exe on nashua, indicating credential theft from the authentication process; however this is memory access (T1003.001), n… |
| T1556.001 Domain Controller Authentication | not_observed | No DC authentication patching: LSASS access is dominated by svchost/antimalware/telemetry with 0x1000, and no unsigned DLL loads into LSASS or lsass/cryptdll service installs were found. |
| T1556.002 Password Filter DLL | not_observed | No Notification Packages registry change, no PasswordFilter script, no .dll service install, no DLL drop into System32/SysWOW64. |
| T1556.005 Reversible Encryption | not_observed | No reversible-encryption references in scripts, command lines, service installs, or account-policy events (4739 zero hits). |
| T1556.006 Multi-Factor Authentication | not_observed | No account-policy change (4739) and no AD authentication policy cmdlets observed. |
| T1556.007 Hybrid Identity | not_observed | No directory-service object modification events (5136/5137/5141 zero hits). |
| T1556.008 Network Provider DLL | not_observed | No network provider DLL registration or LSA registry modification observed. |
| T1557 Adversary-in-the-Middle | suspicious | Relay-style python tooling and NTLM network logon observed, but no single dataset shows a complete AiTM chain; Zeek and Windows windows do not overlap. |
| T1557.001 Name Resolution Poisoning and SMB Relay | malicious | C:\Windows\Temp\python.exe spawned by PSEXESVC.exe on nashua made 348 connections to 192.168.0.4:8443, with an NTLM network logon for pbeesly and SMB/NBT-NS traffic present. |
| T1557.002 ARP Cache Poisoning | suspicious | One responder MAC dominates Zeek conn records, but no corroborating ARP-cache evidence on Windows hosts. |
| T1557.003 DHCP Spoofing | not_observed | No DHCP (67/68) traffic, DHCP server events, or DHCP/netsh command lines in any dataset. |
| T1558 Steal or Forge Kerberos Tickets | not_observed | No Kerberos ticket theft/forgery indicators in any dataset. All ticket requests use AES256 (0x12), no RC4 downgrade, no anomalous SPN or privilege logons. The credential access present (LSASS access 0x1FFFFF by PowerShel… |
| T1558.001 Golden Ticket | not_observed | No RC4 TGS requests and no anomalous 4672 special-privilege logons; all 4672 events are legitimate machine/system accounts (NEWYORK$, SYSTEM, pbeesly, SCRANTON$). |
| T1558.002 Silver Ticket | not_observed | All 4769 service-ticket requests use AES256 (0x12) and target only normal machine/service accounts (krbtgt, NEWYORK$, NASHUA$, SCRANTON$, WEC$); no forged silver-ticket indicators. |
| T1558.003 Kerberoasting | not_observed | Every TGS request (windows.security 4769 and Zeek kerberos) uses AES256; no RC4 (0x17) service tickets and no SPN-enumeration/kerberoasting tooling in PowerShell command lines. |
| T1558.004 AS-REP Roasting | not_observed | All 4768 AS-REQ events have win.PreAuthType 2 (preauth enabled); no preauth-disabled accounts and no AS-REP roasting tooling observed. |
| T1606 Forge Web Credentials | benign | Only cookie-related activity is the legitimate Windows WebDAV client (davclnt.dll,DavSetCookie via WebClient svchost) and an OS INetCookies file; the PowerShell 'cookie/token' hit is a benign Sysinternals readme.ps1. No … |
| T1606.001 Web Cookies | benign | Web cookie events are normal WebDAV client cookie setting and OS INetCookies creation by svchost; no browser cookie theft or cookie forging observed. |
| T1606.002 SAML Tokens | not_observed | Zero hits for SAML/Assertion/ADFS/JWT/NotOnOrAfter across powershell, windows.other and sysmon; zeek TLS server_name shows only 192.168.0.4, no SSO/ADFS endpoint. |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | No MFA request generation activity found. Searches for MFA/2FA/Authenticator/OTP keywords in windows.other messages, PowerShell 4104 script blocks, sysmon process command lines and process executables returned no MFA too… |
| T1649 Steal or Forge Authentication Certificates | malicious | Certificate theft via Get-PrivateKeys exporting LocalMachine certs with private keys to .pfx files on scranton. |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 5 hits | 0 hits | 5344 hits | 773 hits | 2140 hits |
| T1003.001 LSASS Memory | 5 hits | 0 hits | 103 hits | 653 hits | 2140 hits |
| T1003.002 Security Account Manager | 5 hits | 0 hits | 0 hits | 10 hits | 2140 hits |
| T1003.003 NTDS | 5 hits | 0 hits | 0 hits | 0 hits | 2140 hits |
| T1003.004 LSA Secrets | 5 hits | 0 hits | 143 hits | 327 hits | 2140 hits |
| T1003.005 Cached Domain Credentials | 5 hits | 0 hits | 143 hits | 330 hits | 2140 hits |
| T1003.006 DCSync | 216 hits | 0 hits | 14 hits | 0 hits | n/a |
| T1040 Network Sniffing | 5 hits | 0 hits | 2 hits | 9 hits | 2140 hits |
| T1056 Input Capture | 216 hits | 0 hits | 21811 hits | 78566 hits | n/a |
| T1056.001 Keylogging | 5 hits | 0 hits | 10977 hits | 39309 hits | 2140 hits |
| T1056.002 GUI Input Capture | 216 hits | 3 hits | 460 hits | 3 hits | 2140 hits |
| T1056.003 Web Portal Capture | n/a | 4 hits | 0 hits | 0 hits | 62 hits |
| T1056.004 Credential API Hooking | 5 hits | 3 hits | 19 hits | 60289 hits | n/a |
| T1110 Brute Force | 88 hits | 4 hits | 0 hits | 447 hits | n/a |
| T1110.001 Password Guessing | 5 hits | 4 hits | 0 hits | 447 hits | n/a |
| T1110.002 Password Cracking | 5 hits | 2 hits | 10977 hits | 41379 hits | n/a |
| T1110.003 Password Spraying | 85 hits | 19 hits | 15 hits | 447 hits | n/a |
| T1110.004 Credential Stuffing | 5 hits | 4 hits | 0 hits | 447 hits | n/a |
| T1111 Multi-Factor Authentication Interception | 5 hits | 3 hits | 312 hits | 39294 hits | n/a |
| T1187 Forced Authentication | 5 hits | 0 hits | 11140 hits | 1715 hits | 50 hits |
| T1212 Exploitation for Credential Access | 5 hits | 16 hits | 42 hits | 39730 hits | 613 hits |
| T1539 Steal Web Session Cookie | 5 hits | 0 hits | 460 hits | 41141 hits | 62 hits |
| T1552 Unsecured Credentials | 5 hits | 4 hits | 460 hits | 19190 hits | 448 hits |
| T1552.001 Credentials In Files | 5 hits | 1 hits | 312 hits | 2096 hits | 448 hits |
| T1552.002 Credentials in Registry | 5 hits | 0 hits | 0 hits | 16 hits | n/a |
| T1552.003 Shell History | n/a | 0 hits | 0 hits | 0 hits | n/a |
| T1552.004 Private Keys | 5 hits | 1 hits | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | 0 hits | 0 hits | 0 hits | 18 hits | n/a |
| T1555 Credentials from Password Stores | 1 hits | 0 hits | 6 hits | 797 hits | n/a |
| T1555.003 Credentials from Web Browsers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1555.004 Windows Credential Manager | 0 hits | 3 hits | 0 hits | 326 hits | n/a |
| T1555.005 Password Managers | 0 hits | 0 hits | 0 hits | 326 hits | n/a |
| T1556 Modify Authentication Process | 0 hits | 0 hits | 0 hits | 401 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | 0 hits | 213 hits | 359 hits | n/a |
| T1556.002 Password Filter DLL | 0 hits | 0 hits | 0 hits | 37 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556.006 Multi-Factor Authentication | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556.007 Hybrid Identity | 0 hits | 0 hits | 297 hits | 20259 hits | n/a |
| T1556.008 Network Provider DLL | 5 hits | 0 hits | 72 hits | 1088 hits | n/a |
| T1557 Adversary-in-the-Middle | 0 hits | 0 hits | 21954 hits | 1310 hits | 1226 hits |
| T1557.001 Name Resolution Poisoning and SMB Relay | 5 hits | 0 hits | 241 hits | 155 hits | 125 hits |
| T1557.002 ARP Cache Poisoning | 0 hits | 0 hits | 10977 hits | 1310 hits | 1226 hits |
| T1557.003 DHCP Spoofing | 0 hits | 0 hits | 0 hits | 81 hits | 0 hits |
| T1558 Steal or Forge Kerberos Tickets | 17 hits | 0 hits | 787 hits | 652 hits | 35 hits |
| T1558.001 Golden Ticket | 9 hits | 0 hits | 240 hits | 326 hits | 35 hits |
| T1558.002 Silver Ticket | 9 hits | 0 hits | 240 hits | 326 hits | 35 hits |
| T1558.003 Kerberoasting | 9 hits | 0 hits | 552 hits | 326 hits | 35 hits |
| T1558.004 AS-REP Roasting | 9 hits | 0 hits | 14 hits | 0 hits | 35 hits |
| T1606 Forge Web Credentials | 0 hits | 1 hits | 297 hits | 39283 hits | 378 hits |
| T1606.001 Web Cookies | 0 hits | 1 hits | 312 hits | 1 hits | 0 hits |
| T1606.002 SAML Tokens | 0 hits | 0 hits | 312 hits | 0 hits | 378 hits |
| T1621 Multi-Factor Authentication Request Generatio… | 2 hits | 0 hits | 0 hits | 1229 hits | 613 hits |
| T1649 Steal or Forge Authentication Certificates | 0 hits | 1 hits | 86 hits | 25 hits | 378 hits |

Cells: 265, gaps: 0.

## Queries

Every MCP tool call of this run (1058), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-1ff379348a | scope | list_data_sources | {} | None |  |
| q-ef744322a7 | scope | get_registry | {} | None |  |
| q-cc05e7a185 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-e5e7e73790 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-a35bd7a0ae | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-a3b957c26c | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-a6618a34a2 | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-b3bdf7fead | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-67b8f1c978 | check C002 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-bdc34023b0 | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5337 |  |
| q-5e74ec2e20 | check C004 | search | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 7 |  |
| q-f5377a17eb | check C005 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*lsass* OR *mimikatz* OR *sekurlsa* OR *DumpCreds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 0 |  |
| q-6220cce7fd | check C006 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-781c3c48c8 | check C007 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-bf8ca29533 | check C008 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-5035cb8b4e | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-9398f5a734 | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*procdump* OR process.command_line:*comsvcs*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 1 |  |
| q-beb5a8eca1 | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 0 |  |
| q-65002e9dd5 | check C012 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line… | 0 |  |
| q-85aa67b2fc | check C013 | search | {"dataset": "windows.security", "query": "event.code:4673 AND win.ProcessName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 103 |  |
| q-2f206dc901 | check C014 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*lsass* OR *MiniDump* OR *sekurlsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 0 |  |
| q-2aeba8aed1 | check C015 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-f5853f4d28 | check C016 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-a586258805 | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*SAM* OR file.path:*SECURITY* OR file.path:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 3 |  |
| q-6bc43bab0d | check C018 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*SAM* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execut… | 7 |  |
| q-c48f6a519e | check C019 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (process.command_line:*reg* OR process.command_line:*save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proce… | 0 |  |
| q-71a326a8b3 | check C020 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*reg save* OR process.command_line:*SAM* OR process.command_line:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-d38db39b2f | check C021 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 0 |  |
| q-968b666dd4 | check C022 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*reg save* OR *SAM* OR *SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-635de880ad | check C023 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-2612756e55 | check C024 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-14c032211b | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 0 |  |
| q-490ac06d56 | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND file.path:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-cbae53a83c | check C027 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*ntdsutil*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-b325d315f6 | check C028 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-117bec4292 | check C029 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*ntds* OR *vssadmin* OR *ntdsutil* OR *shadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 0 |  |
| q-7599737b69 | check C030 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-b34c47207c | check C031 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-a53a398b47 | check C032 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-e3e08f9e16 | check C033 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*secrets* OR process.command_line:*lsadump* OR process.command_line:*reg save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.d… | 0 |  |
| q-493b410a24 | check C034 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*Policy*Secrets*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 0 |  |
| q-d0b376cdd8 | check C035 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*Secrets*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-9efcaf2f6c | check C036 | search | {"dataset": "windows.security", "query": "event.code:4670", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 143 |  |
| q-984dc3337a | check C037 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*lsadump* OR *secrets* OR *SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", … | 0 |  |
| q-b3e11d7d0e | check C038 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-a7ccdd8072 | check C039 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-5f02341699 | check C040 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-2ef6e64594 | check C041 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*dcc* OR process.command_line:*mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset… | 4 |  |
| q-29a0872931 | check C042 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*Cache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-f32ad0797c | check C043 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*Cache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-cc622f4f31 | check C044 | search | {"dataset": "windows.security", "query": "event.code:4670", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 143 |  |
| q-d9b06a217d | check C045 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*cache* OR *dcc2* OR *mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-6e475fd45d | check C046 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-25880e46c4 | check C047 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-bf1aa81ba0 | check C048 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-915a07c7b5 | check C049 | aggregate | {"dataset": "windows.security", "field": "win.Properties", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-eebb227350 | check C050 | count | {"dataset": "windows.security", "query": "event.code:4929", "time_from": null, "time_to": null} | 0 |  |
| q-f033b3e1b7 | check C051 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-84151b330f | check C052 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*DCSync* OR win.ScriptBlockText:*drsuapi* OR win.ScriptBlockText:*Get-ADReplAccount*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.nam… | 0 |  |
| q-f3aaa3abe9 | check C053 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-0d119d09a8 | check C054 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*pcap* OR process.command_line:*windump* OR process.command_line:*tshark* OR process.command_line:*netsh* OR process.command_line:*promisc*)", "t… | 2 |  |
| q-1bf3bf8d89 | check C055 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*pcap* OR process.command_line:*windump* OR process.command_line:*tshark* OR process.command_line:*promisc* OR process.command_line:*netsh trace*)", "… | 9 |  |
| q-5f70555b79 | check C056 | aggregate | {"dataset": "windows.other", "field": "win.ServiceName", "query": "event.code:7045", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5 |  |
| q-246c6b9470 | check C057 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*pcap* OR win.ScriptBlockText:*promiscuous* OR win.ScriptBlockText:*netsh trace*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-a3ef4d212c | check C058 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-8df968b556 | check C059 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-65bdfe739b | check C060 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-9946125ab4 | check C061 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-c8bc904fc6 | check C062 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4656 OR event.code:4663", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10834 |  |
| q-e3c54d1a8e | check C063 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*SetWindowsHookEx* OR win.ScriptBlockText:*keylog*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obse… | 0 |  |
| q-b00c06ddaf | check C064 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-f044e1797b | check C065 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-b8806cb90e | check C066 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*WindowsHook*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 26 |  |
| q-8d2885a386 | check C067 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-16aa9d34cd | check C068 | aggregate | {"dataset": "windows.other", "field": "win.ServiceName", "query": "event.code:7045", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5 |  |
| q-a098c1d3c3 | check C069 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*SetWindowsHookEx* OR win.ScriptBlockText:*RegisterHotKey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 0 |  |
| q-b0aac52b21 | check C070 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-948bdf0f1a | check C071 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3 |  |
| q-f1a0332c55 | check C072 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*PromptForCredential* OR win.ScriptBlockText:*Get-Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 3 |  |
| q-875b92cd9d | check C073 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-c28a908f23 | check C074 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-1667eea025 | check C075 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-ed3324d960 | check C076 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*login* OR file.path:*portal* OR file.path:*wwwroot* OR file.path:*inetpub*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-5b48923640 | check C077 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*iis* OR process.command_line:*w3wp* OR process.command_line:*appcmd*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-fecefa9d59 | check C078 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*wwwroot* OR win.ObjectName:*inetpub* OR win.ObjectName:*login*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-57626a0236 | check C079 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*login* OR win.ScriptBlockText:*credential* OR win.ScriptBlockText:*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 4 | F13, F14 |
| q-dc74071671 | check C080 | aggregate | {"dataset": "zeek", "field": "url.original", "query": "event.action:http", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 62 |  |
| q-b229f3429d | check C081 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-0cfc217b84 | check C082 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-c7236c79b4 | check C083 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-3c0326dcab | check C084 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-ea65c54800 | check C085 | search | {"dataset": "windows.sysmon", "query": "event.code:8", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 95 |  |
| q-f591979c73 | check C086 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND win.ObjectType:Process", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-fbb0709d2d | check C087 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 6 |  |
| q-ec832b4cae | check C088 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*lsass* OR *MiniDump* OR *Get-Process*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 3 |  |
| q-8c71d11628 | check C089 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-2f85271a22 | check C090 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-cd38e7a0f1 | check C091 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e53f24b08e | check C092 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-d7b0ad2f32 | check C093 | search | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-bfd403176e | check C094 | search | {"dataset": "windows.other", "query": "event.code:5857 OR event.code:5858 OR event.code:5860", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 88 | F16 |
| q-83b9cb9a92 | check C095 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*Credential* OR *Password* OR *Login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 4 |  |
| q-45438050bf | check C096 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-2704761735 | check C097 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-7309fd28de | check C098 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-6110b62f44 | check C099 | search | {"dataset": "windows.security", "query": "event.code:4625 AND win.LogonType:3", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 0 |  |
| q-e0913f7c7e | check C100 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*Password* OR *Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 4 |  |
| q-5cfecb0328 | check C101 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-f66e176615 | check C102 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-caa4328ab6 | check C103 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-e3497dabc3 | check C104 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:(*hashcat* OR *john* OR *--format* OR *wordlist*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.na… | 0 |  |
| q-cf2fc98d41 | check C105 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-6969bce7c7 | check C106 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-75a54c7e59 | check C107 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-2409e1fad5 | check C108 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 0 |  |
| q-b57d4e9019 | check C109 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*hashcat* OR *john* OR *ConvertTo-SecureString* OR *Get-Content*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 2 |  |
| q-6b10097892 | check C110 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-8a38f6d83b | check C111 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-32d9b706da | check C112 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-bae4cb14bb | check C113 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-cdad9c3dcd | check C114 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-c662a350e0 | check C115 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*Password* OR *Credential* OR *Invoke-*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 19 |  |
| q-3c40006d1e | check C116 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-254f6c3e64 | check C117 | search | {"dataset": "windows.other", "query": "event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 85 |  |
| q-d0d0de77e6 | check C118 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-5e1e0e7d8d | check C119 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-aef0235d8d | check C120 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-964a14ce93 | check C121 | search | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-e0666caeee | check C122 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*Credential* OR *Password* OR *Login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 4 |  |
| q-0674378bc7 | check C123 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-76aa9ad88d | check C124 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-0579bd5d57 | check C125 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-d2e38bd9f8 | check C126 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 15 |  |
| q-3fce60157d | check C127 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 39283 |  |
| q-ab5aa66ee8 | check C128 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND registry.path:*Credential*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 11 |  |
| q-07dc7e9336 | check C129 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*Credential* OR *Smartcard* OR *MFA*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", … | 3 |  |
| q-540773d2a2 | check C130 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-b410e13dc0 | check C131 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 10977 |  |
| q-9690ef580c | check C132 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 163 |  |
| q-5abfc78713 | check C133 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 1649 |  |
| q-9b9e045cee | check C134 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 66 |  |
| q-5fd4fa785d | check C135 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*WebDAV* OR *NTLM* OR *\\\\\\\\)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-9b63ea1fcf | check C136 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-95a0e05ca3 | check C137 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 50 |  |
| q-c12720bb04 | check C138 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 42 |  |
| q-e2628d7179 | check C139 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 39283 |  |
| q-900682f43c | check C140 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 447 |  |
| q-9e5cf6b910 | check C141 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*Invoke-* OR *Exploit* OR *SeDebugPrivilege*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user… | 16 |  |
| q-122ec4c5e4 | check C142 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-169832477c | check C143 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 613 |  |
| q-c0c867851f | check C144 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 460 |  |
| q-abc8e80a8e | check C145 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 1649 |  |
| q-0dec28b8d5 | check C146 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 39283 |  |
| q-105ef26cbe | check C147 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:2", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 209 |  |
| q-418c2f05c3 | check C148 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*Cookies* OR *Login Data* OR *sqlite*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-aba615c193 | check C149 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-eba67e94dd | check C150 | aggregate | {"dataset": "zeek", "field": "http.request.method", "query": "event.action:http", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 62 |  |
| q-1f5baa6ec2 | check C151 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 460 |  |
| q-e1f0ac1ee3 | check C152 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 1649 |  |
| q-54cae024aa | check C153 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 OR event.code:14", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 17541 |  |
| q-4cfcc8d94c | check C154 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*password* OR *credential* OR *ConvertTo-SecureString*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 4 | F26 |
| q-59aa0a73c8 | check C155 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-969af63d3e | check C156 | aggregate | {"dataset": "zeek", "field": "file.path", "query": "event.action:files", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 448 |  |
| q-fb3a98943d | check C157 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 312 |  |
| q-f819e54b0f | check C158 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 447 |  |
| q-5d19c58489 | check C159 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 1649 |  |
| q-95be76bbdc | check C160 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*Get-Content* OR *Select-String* OR *unattend*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 1 |  |
| q-6bc3a551dc | check C161 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-4e80c0aa4c | check C162 | aggregate | {"dataset": "zeek", "field": "file.path", "query": "event.action:files", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 448 |  |
| q-d9e870a50c | check C163 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*SAM* OR registry.path:*SECURITY* OR registry.path:*LSA* OR registry.path:*Control\\\\Set\\\\Control\\\\Lsa* OR registry.path:*Winlogon* OR registry.path:*Vault*… | 16 |  |
| q-b4490ba2c7 | check C164 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg*query* OR process.command_line:*reg*save* OR process.command_line:*reg*export*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 0 |  |
| q-0cd5ba9029 | check C165 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*LSA*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-abfab7cbb3 | check C166 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*reg*query* OR win.ScriptBlockText:*reg*export* OR win.ScriptBlockText:*Get-ItemProperty*HKLM*SAM* OR win.ScriptBlockText:*Lsa*Secrets*)", "time_from": null, "time_to": null, … | 0 |  |
| q-34ebcf5885 | check C167 | search | {"dataset": "windows.other", "query": "win.HiveName:* OR win.KeyName:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 5 |  |
| q-ed08d4efa8 | check C168 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ConsoleHost_history* OR win.ScriptBlockText:*PSReadLine* OR win.ScriptBlockText:*history*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observ… | 0 |  |
| q-f17d37b552 | check C169 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ConsoleHost_history* OR process.command_line:*PSReadLine* OR process.command_line:*history*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.n… | 0 |  |
| q-804cf3e95d | check C170 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ConsoleHost_history* OR file.path:*PSReadLine*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-b0f2151181 | check C171 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*ConsoleHost_history* OR win.ObjectName:*PSReadLine*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "use… | 0 |  |
| q-03f1ca1845 | check C172 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*.key OR file.path:*.pgp OR file.path:*.gpg OR file.path:*.ppk OR file.path:*.p12 OR file.path:*.pem OR file.path:*.pfx OR file.path:*.cer OR file.path:*.p7b OR file.pat… | 1 |  |
| q-ab6c5cef77 | check C173 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*.pem OR process.command_line:*.pfx OR process.command_line:*.p12 OR process.command_line:*.key OR process.command_line:*.ppk)", "time_from": null, "time_to": null, "fields": ["@tim… | 0 |  |
| q-c55107bdf9 | check C174 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:5145 AND (win.ObjectName:*.key OR win.ObjectName:*.pem OR win.ObjectName:*.pfx OR win.ObjectName:*.p12 OR win.ObjectName:*.ppk OR win.ObjectName:*.cer)", "time_from": null, "time_t… | 0 |  |
| q-9fdbf8e9db | check C175 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*.pem OR win.ScriptBlockText:*.pfx OR win.ScriptBlockText:*.p12 OR win.ScriptBlockText:*.ppk OR win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*Import-PfxC… | 1 |  |
| q-11963fc739 | check C176 | search | {"dataset": "windows.other", "query": "win.FileName:* OR win.ImagePath:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 5 |  |
| q-947cf1b667 | check C177 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Groups.xml* OR win.ScriptBlockText:*gpprefdecrypt* OR win.ScriptBlockText:*cpassword* OR win.ScriptBlockText:*SYSVOL* OR win.ScriptBlockText:*AES*)", "time_from": null, "time… | 0 |  |
| q-12f81a2a56 | check C178 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Groups.xml* OR process.command_line:*cpassword* OR process.command_line:*gpprefdecrypt* OR process.command_line:*SYSVOL*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-b8435bfe20 | check C179 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:5145 AND (win.ObjectName:*SYSVOL* OR win.ObjectName:*Groups.xml* OR win.ObjectName:*Policies*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-cc72e3d493 | check C180 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*Groups.xml* OR file.path:*SYSVOL* OR file.path:*Policies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 18 |  |
| q-7a79dce97a | check C181 | search | {"dataset": "windows.other", "query": "win.Message:*SYSVOL* OR win.Message:*Groups.xml* OR win.Message:*cpassword*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 0 |  |
| q-04a995b312 | check C182 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon* OR win.TargetImage:*Credential* OR win.TargetImage:*Vault*)", "time_from": null, "time_to": null, "size": 50, "sub_fiel… | 470 |  |
| q-0e2ba5164e | check C183 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-63052727c2 | check C184 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*procdump* OR process.command_line:*mimikatz* OR process.command_line:*sekurlsa* OR process.command_line:*comsvcs*MiniDump*)", "time_from": null, "ti… | 1 |  |
| q-079345cd68 | check C185 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*Vault* OR win.ObjectName:*Credential*)", "time_from": null, "time_to": null… | 6 |  |
| q-f5812e401a | check C186 | aggregate | {"dataset": "windows.security", "field": "win.TargetProcessName", "query": "event.code:4656 AND (win.TargetProcessName:*lsass* OR win.TargetProcessName:*winlogon*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-8ad0f1f9a3 | check C187 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*DumpCreds*)", "time_from": null, "… | 0 |  |
| q-14d63739a6 | check C188 | search | {"dataset": "windows.other", "query": "win.Message:*lsass* OR win.Message:*MiniDump* OR win.Message:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 1 |  |
| q-fe1a9bcadf | check C189 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Login Data* OR file.path:*logins.json* OR file.path:*key4.db* OR file.path:*key3.db* OR file.path:*signons.sqlite* OR file.path:*Cookies*)", "time_from": null, "time_to… | 0 |  |
| q-5060bd2420 | check C190 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Login Data* OR process.command_line:*logins.json* OR process.command_line:*key4.db* OR process.command_line:*Cookies*)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 0 |  |
| q-02db3f6ac7 | check C191 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Login Data* OR win.ObjectName:*logins.json* OR win.ObjectName:*key4.db* OR win.ObjectName:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "su… | 0 |  |
| q-33411fba29 | check C192 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*logins.json* OR win.ScriptBlockText:*key4.db* OR win.ScriptBlockText:*CryptUnprotectData* OR win.ScriptBlockText:*sqlite*)", "time_from": … | 0 |  |
| q-d090c9f296 | check C193 | search | {"dataset": "windows.other", "query": "win.Message:*Login Data* OR win.Message:*logins.json* OR win.Message:*key4.db*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-3c1a7ccf86 | check C194 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-1e818c6796 | check C195 | search | {"dataset": "windows.sysmon", "query": "event.code:15 AND file.path:*Credentials*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 0 |  |
| q-0b69aad703 | check C196 | search | {"dataset": "windows.security", "query": "event.code:4688 AND process.command_line:*vault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 0 |  |
| q-459a42f375 | check C197 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 3 |  |
| q-b0888b9bb9 | check C198 | search | {"dataset": "windows.other", "query": "event.code:7045 AND win.ImagePath:*vault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-a4ced26724 | check C199 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-1b8d50f9ba | check C200 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*1Password* OR file.path:*KeePass* OR file.path:*LastPass* OR file.path:*Bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 0 |  |
| q-0790b81480 | check C201 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-7f9903dc08 | check C202 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*KeePass* OR win.ScriptBlockText:*kdbx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 0 |  |
| q-f995c76331 | check C203 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*keepass* OR win.ImagePath:*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 0 |  |
| q-667a9edb75 | check C204 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 | F34 |
| q-2528224efc | check C205 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*wdigest*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 75 | F34 |
| q-5db8fbe5c6 | check C206 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*cryptdll* OR win.ObjectName:*wdigest* OR win.ObjectName:*Security Packages*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "o… | 0 |  |
| q-b707dd829f | check C207 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*wdigest* OR win.ScriptBlockText:*Security Packages*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name… | 0 |  |
| q-ae051f1832 | check C208 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*lsass* OR win.ImagePath:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exe… | 0 |  |
| q-8f3474f7cb | check C209 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-109c6e5a96 | check C210 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-2c5bf246a5 | check C211 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3 AND win.TargetUserName:*$", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 198 |  |
| q-fb15a65add | check C212 | search | {"dataset": "windows.security", "query": "event.code:4648 AND win.TargetUserName:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 15 |  |
| q-4f03c65194 | check C213 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*lsass* OR win.ImagePath:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exe… | 0 |  |
| q-6f87abb486 | check C214 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.na… | 0 |  |
| q-231624103a | check C215 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*System32* OR file.path:*SysWOW64*) AND file.path:*.dll", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 0 |  |
| q-8bcfa4de39 | check C216 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*msv1_0* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 37 |  |
| q-f11aa8df19 | check C217 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*Notification Packages*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", … | 0 |  |
| q-eba91de290 | check C218 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Notification Packages* OR win.ScriptBlockText:*PasswordFilter*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", … | 0 |  |
| q-f8007d05c0 | check C219 | search | {"dataset": "windows.other", "query": "event.code:7045 AND win.ImagePath:*.dll", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 0 |  |
| q-7b1cb777fe | check C220 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*AllowReversiblePasswordEncryption* OR win.ScriptBlockText:*ReversibleEncryption*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name",… | 0 |  |
| q-b774998a7e | check C221 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND win.Payload:*Reversible*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.com… | 0 |  |
| q-6b58d9619b | check C222 | search | {"dataset": "windows.security", "query": "event.code:4739 AND win.ChangeType:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 0 |  |
| q-92019fb9e6 | check C223 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*AllowReversiblePasswordEncryption*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset… | 0 |  |
| q-ddd1385565 | check C224 | search | {"dataset": "windows.other", "query": "event.code:7045 AND win.ImagePath:*Reversible*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 0 |  |
| q-b7a24dc0f9 | check C225 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adaccount*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(pr… | ERROR |  |
| q-77f1e6cfce | check C225 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adaccount*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(pr… | ERROR |  |
| q-d44869aca8 | check C226 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-af2bbefe6b | check C227 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4739", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-afb1c88fe9 | check C228 | search | {"dataset": "windows.other", "query": "event.code:4739 OR event.code:4738 OR event.code:4662", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-71ef4c48c2 | check C229 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Set-ADUser* OR process.command_line:*Set-ADAuthenticationPolicy* OR process.command_line:*dsacls* OR process.command_line:*ntdsutil*)", "time_from": … | 0 |  |
| q-23c8be740b | check C230 | count | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null} | 0 |  |
| q-754a574a98 | check C231 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:5136", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-34cd59666b | check C232 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-d721a11ef8 | check C233 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-34c77ce62c | check C234 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aad*\" OR TO_LOWER(win.ScriptBlockText) L… | ERROR |  |
| q-a910765c93 | check C234 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aad*\" OR TO_LOWER(win.ScriptBlockText) L… | ERROR |  |
| q-642eee178c | check C235 | search | {"dataset": "windows.other", "query": "event.code:5136 OR event.code:5137 OR event.code:5141", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-344f63a083 | check C236 | count | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null} | 36 |  |
| q-3138f1be33 | check C237 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 36 |  |
| q-c50e2eb32b | check C238 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*NetworkProvider* OR registry.path:*Winlogon* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20 |  |
| q-212f1793b4 | check C239 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.dll OR win.TargetFilename:*System32*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 453 |  |
| q-eaf2eafe93 | check C240 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 470 |  |
| q-c9ebec1ae2 | check C241 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*np*.dll OR win.ImageLoaded:*provider*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 145 |  |
| q-646bb84263 | check C242 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*winlogon*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credential*\" \| KEEP @timestamp, host.name,… | ERROR |  |
| q-bc85199921 | check C242 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*winlogon*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credential*\" \| KEEP @timestamp, host.name,… | ERROR |  |
| q-d9441bfd63 | check C243 | search | {"dataset": "windows.other", "query": "event.code:4657 OR event.code:4697 OR event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 5 |  |
| q-d6156cbe5a | check C244 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-0f7592cd66 | check C245 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-906099b2a2 | check C246 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-1189d02644 | check C247 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-826ef822e5 | check C248 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mitm*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*spoof*… | ERROR |  |
| q-b5ce624a6d | check C248 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mitm*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*spoof*… | ERROR |  |
| q-8a3772ef65 | check C249 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4670 OR event.code:4656 OR event.code:5156", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.ex… | 0 |  |
| q-50c1288e1e | check C250 | aggregate | {"dataset": "zeek", "field": "zeek.conn_state", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-983e7b43dd | check C251 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-c71152a8c5 | check C252 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:5355 OR destination.port:137 OR destination.port:138 OR destination.port:445)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 55 |  |
| q-7c18a49412 | check C253 | aggregate | {"dataset": "zeek", "field": "source.ip", "query": "event.action:conn AND (destination.port:5355 OR destination.port:137 OR destination.port:445)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 47 |  |
| q-1615588f8e | check C254 | aggregate | {"dataset": "zeek", "field": "zeek.name", "query": "event.action:smb_files OR event.action:smb_mapping", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 23 |  |
| q-c6d443144c | check C255 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-d4a27f32e4 | check C256 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 218 |  |
| q-95268ebde1 | check C257 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-cff13a7176 | check C258 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:3 AND (destination.port:445 OR destination.port:5355 OR destination.port:137)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 74 |  |
| q-8d46964180 | check C259 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*enablemulticast*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*nbt-ns*\" OR TO_LOWER(win.ScriptBlockText) LIKE… | ERROR |  |
| q-6270ef1ac4 | check C259 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*enablemulticast*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*nbt-ns*\" OR TO_LOWER(win.ScriptBlockText) LIKE… | ERROR |  |
| q-baf06fa8bf | check C260 | search | {"dataset": "windows.other", "query": "event.code:4697 OR event.code:7045 OR event.code:4657", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 5 |  |
| q-11ae0b837f | check C261 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-35936bc886 | check C262 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-d95b6f0f33 | check C263 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-c113f32fa0 | check C264 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*netsh interface*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-netneighbor*\" OR TO_LOWER(win.ScriptBlockTex… | ERROR |  |
| q-dbc06b6f11 | check C264 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*netsh interface*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-netneighbor*\" OR TO_LOWER(win.ScriptBlockTex… | ERROR |  |
| q-7a4ee97b99 | check C265 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4670 OR event.code:4656 OR event.code:5156", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.ex… | 0 |  |
| q-f2c31d3ab6 | check C266 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-ec0e04db55 | check C267 | aggregate | {"dataset": "zeek", "field": "zeek.resp_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-afbe59d8a7 | check C268 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-fc88f6db1e | check C269 | search | {"dataset": "windows.security", "query": "event.code:5156 AND network.transport:udp AND destination.port:(67 OR 68)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-5c739a465c | check C270 | search | {"dataset": "windows.sysmon", "query": "event.code:22 AND dns.question.name:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 81 |  |
| q-1196e34900 | check C271 | search | {"dataset": "windows.powershell", "query": "process.command_line:(*dhcp* OR *DhcpServer* OR *New-DhcpServer* OR *netsh*interface*ip*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "u… | 0 |  |
| q-023f56c275 | check C272 | search | {"dataset": "zeek", "query": "event.action:conn AND network.transport:udp AND destination.port:(67 OR 68)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 0 |  |
| q-4bba20ba93 | check C273 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:(4672 OR 4634 OR 4769 OR 4768 OR 4624)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 787 |  |
| q-6fb4ff8a7d | check C274 | search | {"dataset": "windows.security", "query": "event.code:4769 AND win.TicketEncryptionType:0x17", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-fccf9c2d85 | check C275 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-cb7374dd22 | check C276 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-7d2c42c7f0 | check C277 | search | {"dataset": "windows.powershell", "query": "process.command_line:(*Invoke-Mimikatz* OR *sekurlsa* OR *kerberos* OR *klist* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", … | 0 |  |
| q-911ed0a44b | check C278 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040 OR 7036)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 17 |  |
| q-a12e2791a4 | check C279 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 | F40, F43 |
| q-f1f31fa18d | check C280 | search | {"dataset": "windows.security", "query": "event.code:4769 AND win.TicketEncryptionType:0x17", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-810803257d | check C281 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-d2f149f422 | check C282 | search | {"dataset": "windows.security", "query": "event.code:4672", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 212 | F41 |
| q-9c952dfa24 | check C283 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-cea4d76942 | check C284 | search | {"dataset": "windows.powershell", "query": "process.command_line:(*golden* OR *krbtgt* OR *Rubeus* OR *Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 0 |  |
| q-234588351d | check C285 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-3e263fff7b | check C286 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-c6821ba029 | check C287 | search | {"dataset": "windows.security", "query": "event.code:4769 AND win.TicketEncryptionType:0x17", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-209d82a017 | check C288 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-bb843fa969 | check C289 | search | {"dataset": "windows.security", "query": "event.code:4672", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 212 |  |
| q-08245d75c2 | check C290 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-8419b82891 | check C291 | search | {"dataset": "windows.powershell", "query": "process.command_line:(*silver* OR *Rubeus* OR *Mimikatz* OR *kerberoast*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-00e71a73fd | check C292 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-22d38f80e0 | check C293 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-005cb0d319 | check C294 | search | {"dataset": "windows.security", "query": "event.code:4769 AND win.TicketEncryptionType:0x17", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-428d8eeed0 | check C295 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-367e7c501d | check C296 | search | {"dataset": "windows.security", "query": "event.code:(4624 OR 4648 OR 4672)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 524 |  |
| q-faa7accc22 | check C297 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-7aac65efef | check C298 | search | {"dataset": "windows.powershell", "query": "process.command_line:(*kerberoast* OR *Invoke-Kerberoast* OR *Rubeus* OR *GetUserSPNs* OR *setspn*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 0 |  |
| q-d1f503464d | check C299 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-d45acb779b | check C300 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-6af2131d91 | check C301 | search | {"dataset": "windows.security", "query": "event.code:4768 AND win.PreAuthType:0", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line… | 0 |  |
| q-49961c78c0 | check C302 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-6d451b1fe0 | check C303 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:(*asreproast* OR *GetNPUsers* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-11079f94b5 | check C304 | search | {"dataset": "windows.powershell", "query": "process.command_line:(*asreproast* OR *GetNPUsers* OR *Rubeus* OR *preauth*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-26d53155ca | check C305 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-f87d963216 | check C306 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-6844cc1510 | check C307 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-dba1322be9 | check C308 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:8", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-969d906cfc | check C309 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-1c625ecb7b | check C310 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cookie* OR win.ScriptBlockText:*token* OR win.ScriptBlockText:*SAML* OR win.ScriptBlockText:*jwt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name",… | 1 |  |
| q-5d4e958390 | check C311 | search | {"dataset": "windows.other", "query": "message:*token* OR message:*cookie* OR message:*SAML*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-657aa41a9c | check C312 | aggregate | {"dataset": "zeek", "field": "zeek.server_name", "query": "event.action:ssl", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 378 |  |
| q-2611339844 | check C313 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-11af6b947f | check C314 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-de9618adb9 | check C315 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Cookie* OR file.path:*cookie*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-e37c40425a | check C316 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cookie* OR win.ScriptBlockText:*Set-Cookie* OR win.ScriptBlockText:*session*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 1 |  |
| q-f2472959a1 | check C317 | search | {"dataset": "windows.other", "query": "message:*cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destina… | 0 |  |
| q-e0d2627642 | check C318 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*cookie* OR url.original:*session*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable",… | 0 |  |
| q-1e9531e197 | check C319 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-409971e107 | check C320 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-c3d6d06d37 | check C321 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SAML* OR win.ScriptBlockText:*NotOnOrAfter* OR win.ScriptBlockText:*Assertion*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 0 |  |
| q-3c4e7e8b08 | check C322 | search | {"dataset": "windows.other", "query": "message:*SAML* OR message:*Assertion* OR message:*ADFS*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proce… | 0 |  |
| q-6ad8d65987 | check C323 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*SAML* OR process.command_line:*token* OR process.command_line:*cert*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-5a191dce3b | check C324 | aggregate | {"dataset": "zeek", "field": "zeek.server_name", "query": "event.action:ssl", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 378 |  |
| q-6d4f342a3c | check C325 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-21435d6fe8 | check C326 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-760c75a84d | check C327 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MFA* OR win.ScriptBlockText:*2FA* OR win.ScriptBlockText:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-a7686c1934 | check C328 | search | {"dataset": "windows.other", "query": "message:*MFA* OR message:*multi-factor* OR message:*authentication*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-53b34ac9dd | check C329 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-bb17278449 | check C330 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-a2d6511705 | check C331 | search | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 36 | F50 |
| q-98bf13ad0e | check C332 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-56f1b094b5 | check C333 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-aa1f3772bf | check C334 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Certificate* OR registry.path:*Crypto* OR registry.path:*Crypt*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 25 |  |
| q-44c2465e20 | check C335 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*certutil* OR win.ScriptBlockText:*Certificate*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 1 |  |
| q-4d9ea74885 | check C336 | search | {"dataset": "windows.other", "query": "message:*certificate* OR message:*Certificate*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 0 |  |
| q-142667cffb | check C337 | aggregate | {"dataset": "zeek", "field": "zeek.certificate_subject", "query": "event.action:x509", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 378 |  |
| q-0af7e930f6 | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F01, F02 |
| q-c3824a1ebb | triage T1003 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" \| STATS cnt = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT cnt DESC"} | ERROR |  |
| q-219ea89fbb | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-a47b2cd1aa | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-7708228d52 | triage T1003 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*… | 0 |  |
| q-60909e0635 | triage T1003 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.pid:2976", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executable", "process.parent.command_line", "use… | 1 | F01 |
| q-bb2d66044f | triage T1003 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*dump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credential*\"… | 5 |  |
| q-a5b48f48dd | triage T1003 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-3253c16ff9 | triage T1003 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, win.ScriptBlockText, _id, _index \| LIMIT 30"} | 30 |  |
| q-2dd38c0cea | triage T1003 step 5 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectType:Process", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.ProcessName", "win.SubjectUserName", "win.AccessMask", "win.AccessList", "me… | 6 | F01, F02, F03 |
| q-0e3df99d52 | triage T1003 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND process.executable LIKE \"*PowerShell*\" \| KEEP @timestamp, host.name, process.executable, win.GrantedAccess, win.SourcePro… | 4 |  |
| q-06b21dcad3 | triage T1003 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKBk"} | None |  |
| q-66bca5768d | triage T1003 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4662\" \| KEEP @timestamp, host.name, win.ObjectName, win.ObjectType, win.AccessMask, win.SubjectUserName, _id, _index"} | 7 | F04, F05, F06, F07 |
| q-7148535d8e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-3f6055b006 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-73c350be62 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-72d9ae86b6 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-0e25d94463 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKBk"} | None |  |
| q-366b6e0aad | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKBk"} | None |  |
| q-eeade06a0a | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-17545ecfbe | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-66eb3fc244 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKBk"} | None |  |
| q-b5f9162f38 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOqAA"} | None |  |
| q-6b26fff8dd | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoYO"} | None |  |
| q-fa9960f52b | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaEO1dd"} | None |  |
| q-a991eabc71 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaEO1dd"} | None |  |
| q-58ae7b009c | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaEO1dd"} | None |  |
| q-b9f7bb8842 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVq1j6z"} | None |  |
| q-fa551c0ba1 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoYO"} | None |  |
| q-b41668d451 | triage T1040 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*pcap* OR process.command_line:*windump* OR process.command_line:*tshark* OR process.command_line:*promisc* OR process.command_line:*netsh trace*)", "time_from": null, "time_to": nu… | 9 | F08 |
| q-3ad020fc61 | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pcap* OR process.command_line:*windump* OR process.command_line:*tshark* OR process.command_line:*netsh* OR process.command_line:*promisc*)", "time_from": null, "time_to": nul… | 2 | F08 |
| q-a96d5a5eec | triage T1040 step 2 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ServiceName", "win.ImagePath", "win.ServiceType", "win.StartType", "user.name"], "size": 20, "sort": "asc"} | 5 | F09 |
| q-79cf31527b | triage T1040 step 2 | search | {"dataset": "zeek", "query": "event.action:notice OR event.action:weird", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "source.ip", "destination.ip", "destination.port", "network.transport", "zeek.service", "zeek.note", "zeek.ms… | 14 | F10 |
| q-bd558bbce7 | triage T1040 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None | F08 |
| q-624931a4d2 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "(process.command_line:*npcap* OR process.command_line:*winpcap* OR file.path:*npcap* OR file.path:*winpcap* OR registry.path:*npcap* OR registry.path:*winpcap* OR process.command_line:*dumpcap* OR process.command_line:*W… | 0 |  |
| q-a09a84d6d3 | triage T1040 step 4 | search | {"dataset": "windows.sysmon", "query": "(process.command_line:*capture* OR process.command_line:*sniff* OR win.TargetFilename:*pcap* OR win.ImageLoaded:*pcap* OR win.ImageLoaded:*npf* OR process.command_line:*raw* OR process.command_line:*promisc*)", "time_fro… | 2 |  |
| q-1e4a13ad8b | triage T1040 step 4 | search | {"dataset": "windows.security", "query": "(process.command_line:*pcap* OR process.command_line:*sniff* OR process.command_line:*promisc* OR win.ServiceName:*pcap* OR win.ServiceName:*npf* OR win.ImagePath:*pcap*)", "time_from": null, "time_to": null, "fields":… | 0 |  |
| q-dafdc1f8d8 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-06d768547a | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-b9785e23a9 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-e8f62dd593 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPE0PdZ"} | None |  |
| q-f1c29afbd0 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt4o2y"} | None |  |
| q-e4e78ba196 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-743c87eef7 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-f3cede722d | triage T1040 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-d44304381d | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjg"} | None |  |
| q-65552b612a | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjg"} | None |  |
| q-7583a48b3b | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass.exe*\" \| KEEP @timestamp, host.name, process.executable, process.command_line, win.TargetImage, win.GrantedAccess, user.name, _id,… | 50 | F12, F15 |
| q-d0b1a84959 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*python*\" OR process.executable LIKE \"*Temp*\") \| KEEP @timestamp, host.name, process.executable, process.command_line, process.pare… | 9 | F15 |
| q-49499c32fa | triage T1056 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None | F11 |
| q-a5c0287c38 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _i… | 20 |  |
| q-08032273e4 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _i… | 20 |  |
| q-34c0ce4b46 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4656\" AND win.ObjectName LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.ObjectName, win.AccessMask, win.GrantedAccess, user.name, _id, _index … | ERROR |  |
| q-a781401a97 | triage T1056 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4656\" AND win.ObjectName LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.ObjectName, win.AccessMask, user.name, _id, _index \| SORT @timestamp … | 13 | F11 |
| q-484ab85b3c | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2M4"} | None | F11 |
| q-a89d1cfe28 | triage T1056 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None | F11 |
| q-b32b5fc80f | triage T1056 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None | F11 |
| q-bc6c2b65d2 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-ab36046181 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-49c62ffd77 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-4eaf05859f | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-0dbbf5a2e3 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-28ae0315ee | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-97c0eabb75 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-3feb16a3b9 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-36e56dc934 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-e17b745344 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2M4"} | None |  |
| q-53f0c82803 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-36a562271f | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSmWPy"} | None |  |
| q-a4e2abfc43 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqdCw"} | None |  |
| q-4caefe3472 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-ae671ceb83 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-9ef4004ca5 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-39e3b41095 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTPA5kN"} | None |  |
| q-f66b690ca7 | triage T1110 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.command_line LIKE \"*PsExec*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.command_line, _id, _inde… | 4 | F17, F18 |
| q-a893b6883f | triage T1110 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" OR event.code == \"4625\" OR event.code == \"4634\" \| STATS c = COUNT(*) BY event.code, win.LogonType, win.TargetUserName \| SORT c DESC \| LIMIT 50"} | 26 |  |
| q-6e6b90e4ed | triage T1110 step 2 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None | F17 |
| q-267146854f | triage T1110 step 2 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None | F17 |
| q-4f49b05c4f | triage T1110 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*python*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.command_line, _id, _index"… | 5 |  |
| q-45f0f658a7 | triage T1110 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| STATS c = COUNT(*) BY win.SourceImage, win.GrantedAccess \| SORT c DESC \| LIMIT 20"} | 15 |  |
| q-a12bddc17b | triage T1110 step 3 | count | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null} | 0 |  |
| q-70758632a6 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-9d60b0dd55 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "q-a12bddc17b"} | ERROR |  |
| q-bc533bdc5a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-e9d1b9aa94 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-de72f08a1f | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPDyDoS"} | None |  |
| q-468a42339a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "q-45f0f658a7"} | ERROR |  |
| q-fd265c0502 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "q-cf2fc98d41"} | ERROR |  |
| q-7e6cefced5 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "q-a12bddc17b"} | ERROR |  |
| q-1062a2767f | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "q-a893b6883f"} | ERROR |  |
| q-4ac394ecf0 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "q-a12bddc17b"} | ERROR |  |
| q-b6d5bb0fe9 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "q-a893b6883f"} | ERROR |  |
| q-5120470c05 | triage T1110 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.TargetUserName == \"pbeesly\" \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.LogonType, _id, _index \| LIMIT 3"} | 3 | F16, F19, F20 |
| q-aaa37afbd5 | triage T1110 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.SourceImage LIKE \"*svchost*\" \| KEEP @timestamp, host.name, event.code, win.SourceImage, win.TargetImage, win.GrantedA… | 3 | F18 |
| q-9089e68eed | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-e8aaafd017 | triage T1111 step 1 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 2 |  |
| q-abb0e55ba2 | triage T1111 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-f977f68165 | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.TargetImage", "win.GrantedAccess", "win… | 2 |  |
| q-07b6f1bdc7 | triage T1111 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.IpAddress", "win.Workstation", "win.LogonProcessName", "win.AuthenticationPack… | 2 |  |
| q-630b2c12e8 | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*smartcard* OR file.path:*SmartCard* OR file.path:*MFA* OR file.path:*mfa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "file.path", "process.executable"], "si… | 0 |  |
| q-532e518bc5 | triage T1111 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Smartcard* OR registry.path:*ScPolicy* OR registry.path:*Credential* OR registry.path:*Ngc* OR registry.path:*Pin* OR registry.path:*Biometric*)", "time_from": null, "time_to": null, "fi… | 15 | F21 |
| q-80df873020 | triage T1111 step 3 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.SubjectUserName", "win.ProcessName", "win.IpAddress", "win.TargetServerName"], "size": 20, "sort": … | 15 | F21 |
| q-3188aba896 | triage T1111 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*smartcard* OR process.command_line:*SmartCard* OR process.command_line:*MFA* OR process.command_line:*CredentialProvider* OR process.command_line:*Ngc* OR process.command_line:*pin… | 2 |  |
| q-64d7bb7b25 | triage T1111 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*CredentialProvider* OR win.ImageLoaded:*Smartcard* OR win.ImageLoaded:*Ngc* OR win.ImageLoaded:*MFA* OR win.ImageLoaded:*Intercept*)", "time_from": null, "time_to": null, "fields": ["@t… | 2 | F21 |
| q-ad67018265 | triage T1111 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND NOT process.executable:*svchost* AND NOT process.executable:*Antimalware* AND NOT process.executable:*Telemetry*", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 9 |  |
| q-8131ee6afd | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO5lCpc"} | None |  |
| q-0cc2d9cd58 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO5lCpc"} | None |  |
| q-7cc90d434e | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO5lCpc"} | None |  |
| q-276effca31 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOxeHN4"} | None |  |
| q-295e3acd34 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOxeHN4"} | None |  |
| q-bcb8c7aafd | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-ba68d317c8 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-e308d8ec44 | triage T1187 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None | F22 |
| q-09b02ce989 | triage T1187 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "destination.ip", "destination.port", "user.name", "win.So… | 66 | F22 |
| q-cbc722fc77 | triage T1187 step 2 | search | {"dataset": "windows.security", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ShareName", "win.SubjectUserName", "win.IpAddress", "win.ObjectName", "win.AccessMask", … | 163 | F22 |
| q-24dd84605d | triage T1187 step 2 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 163 |  |
| q-0c8294e2ee | triage T1187 step 3 | search | {"dataset": "windows.security", "query": "(event.code:5140 OR event.code:5145) AND win.SubjectUserName:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ShareName", "win.SubjectUserName", "win.IpAddress", "w… | 59 | F22 |
| q-92e3c4310f | triage T1187 step 3 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "(event.code:5140 OR event.code:5145) AND win.SubjectUserName:pbeesly", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 59 |  |
| q-4dc369b6d1 | triage T1187 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*.lnk\" OR TO_LOWER(win.TargetFilename) LIKE \"*.scf\" OR TO_LOWER(win.TargetFilename) LIKE \"*.url\" OR TO_LOWER(win.Target… | 3 | F22 |
| q-713095e3a6 | triage T1187 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 139) \| KEEP @timestamp, host.name, process.executable, destination.ip, destination.port, win.SourceIp, _id, _inde… | 40 |  |
| q-864238810f | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-4d11f3a6c9 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-4a33dfa9b0 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-d2f106f41f | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQtn"} | None |  |
| q-c38df3e80d | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQtn"} | None |  |
| q-af9966aa54 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_q"} | None |  |
| q-8999a59506 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_q"} | None |  |
| q-ea78fcaa9b | triage T1187 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-196640ecd9 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTmcl_4"} | None |  |
| q-546bc9a725 | triage T1212 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-5be84c5b5f | triage T1212 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZJhF-L"} | None |  |
| q-5529ed1850 | triage T1212 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZKhD3z"} | None |  |
| q-de605a0614 | triage T1212 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None | F23 |
| q-b5532bd609 | triage T1212 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*SeaDuke* OR *Credential* OR *lsass* OR *Mimikatz* OR *Dump* OR *Get-Credential* OR *keytab* OR *Kerberos*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 4 |  |
| q-00caecbedb | triage T1212 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, _id, _index \| LIMIT 50"} | 50 |  |
| q-4804269d2d | triage T1212 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND process.executable NOT LIKE \"*svchost*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAcc… | 37 | F23 |
| q-0b1a8d50a9 | triage T1212 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:*SeaDuke*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proces… | 1 | F23 |
| q-38109cb27e | triage T1212 step 3 | search | {"dataset": "windows.security", "query": "event.code:4769 AND win.TargetUserName:*pbeesly*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 15 | F24 |
| q-85d95751f3 | triage T1212 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-5d8daf5b7c | triage T1212 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-77a21cb8e6 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b15162f364 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-9b2b634bf0 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-bdb54d610c | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-d46efc0cd1 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-5d990d0b68 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZJhF-L"} | None |  |
| q-0554aac2bd | triage T1212 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-cb37f3e6c9 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-52ceae3f99 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-87d13b627a | triage T1539 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:(*Cookies* OR *Login\\\\ Data* OR *WebCache* OR *History* OR *Network\\\\ Cookies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-d0c4d0f732 | triage T1539 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:(*Cookies* OR *Login\\\\ Data* OR *sqlite* OR *cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "u… | 0 |  |
| q-3c680dea7b | triage T1539 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:(*python.exe OR *PsExec64.exe OR *sdelete64.exe OR *PSEXESVC.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 19 | F25 |
| q-08042cd23b | triage T1539 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*cookie* OR *Cookie* OR *session* OR *browser* OR *chrome* OR *edge* OR *firefox*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name",… | 1 |  |
| q-285b4239ef | triage T1539 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-8f7ac9695b | triage T1539 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:(*victim* OR *cod* OR *Draft* OR *Temp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 184 |  |
| q-25936d92e2 | triage T1539 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:(*chrome.exe OR *msedge.exe OR *firefox.exe OR *iexplore.exe OR *MicrosoftEdge.exe OR *MicrosoftEdgeCP.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "o… | 328 | F25 |
| q-e04e1ebead | triage T1539 step 4 | search | {"dataset": "windows.sysmon", "query": "win.TargetFilename:(*Cookies* OR *Login\\\\ Data* OR *WebCache* OR *Local\\\\ State* OR *Network\\\\ Cookies*) OR registry.path:(*Cookies* OR *Login\\\\ Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp… | 0 |  |
| q-4ccce40965 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_Zu5"} | None |  |
| q-7efb030e37 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_Zu5"} | None |  |
| q-61c2400242 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_Zu5"} | None |  |
| q-f63af833f1 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQC8TKL"} | None |  |
| q-ed4d2f8438 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-5cdf1c7816 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTpgCep"} | None |  |
| q-ccbfb7d91c | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None | F26 |
| q-3c9c649d6e | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None | F27 |
| q-eaa0948789 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2M4"} | None | F30 |
| q-801995bb2d | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhAkj"} | None |  |
| q-5e28989020 | triage T1552 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:*PsExec64*", "time_from": null, "time_to": null, "fields": ["process.command_line", "process.executable", "host.name", "user.name", "@timestamp"], "size": 10, "sort": "asc"} | 4 | F27 |
| q-87cbcc8db3 | triage T1552 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*.pfx", "time_from": null, "time_to": null, "fields": ["file.path", "process.executable", "host.name", "user.name", "@timestamp"], "size": 10, "sort": "asc"} | 1 | F26, F27 |
| q-c3aecca811 | triage T1552 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*Groups.xml* OR file.path:*SYSVOL* OR file.path:*Policies*)", "time_from": null, "time_to": null, "fields": ["file.path", "process.executable", "host.name", "@timestamp"], "size": 20, "sort":… | 18 | F28 |
| q-a6793c29c7 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-173d0838f1 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-402ccc4d49 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-83a1b7ddfa | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-62eb26d979 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-808d522d27 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-aaf7b6388e | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-2eb17bbe45 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhAkt"} | None |  |
| q-2e9db62ac6 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhAkt"} | None |  |
| q-30640b33a9 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhAkj"} | None |  |
| q-96454cde62 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2M4"} | None |  |
| q-f2f02bf2b2 | triage T1552 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*NL$1*", "time_from": null, "time_to": null, "fields": ["registry.path", "process.executable", "host.name", "@timestamp"], "size": 5, "sort": "asc"} | 5 | F29 |
| q-aa830397ba | triage T1555 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-8ccb108134 | triage T1555 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass* AND NOT win.GrantedAccess:0x1000", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 33 |  |
| q-c992d45ff1 | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-ea31b5ba07 | triage T1555 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND NOT win.GrantedAccess:0x1000", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.GrantedAccess", "win.CallTrace", "user.nam… | 33 | F31 |
| q-bb7d3018f2 | triage T1555 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.GrantedAccess", "win.CallTrace", "user.… | 2 |  |
| q-4e2861ba65 | triage T1555 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None | F32 |
| q-11d0e4ef54 | triage T1555 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-68ce82b4f9 | triage T1555 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.pid:2976", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executable", "process.parent.command_line", "use… | 1 | F32 |
| q-ed1a0773e1 | triage T1555 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*DumpCred* OR win.ScriptBlockText:*Get-Process*lsass*)", "time_from": null, … | 0 |  |
| q-2b9ce4ff76 | triage T1555 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-493a841bfa | triage T1555 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-104324a11a | triage T1555 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key4.db*\" OR TO_LOWER(file.path) LIKE \"*kee… | ERROR |  |
| q-f1a8cb0cc7 | triage T1555 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*vault*\" OR TO_LOWER(process.command_line) LIKE \"*credential*\" OR TO_LOWER(process.command_line) LIKE \"*dpapi*\" OR TO_LOWE… | ERROR |  |
| q-a378715147 | triage T1555 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key4.db*\" OR TO_LOWER(file.path) LIKE \"… | 0 |  |
| q-47bcbd6c92 | triage T1555 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*vault*\" OR TO_LOWER(process.command_line) LIKE \"*credential*\" OR TO_LOWER(process.command_line) LIKE \"*dpapi*\" OR TO_… | 0 |  |
| q-5df70637c5 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-5c23049f4d | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-c99863c154 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-554b6b673b | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-a0fbfad2c4 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-416d42b9b6 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-3604b40e6d | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-37cae20c53 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-bbdde88ff0 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-49e638eb3b | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "q-a378715147"} | ERROR |  |
| q-bd0755f65c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "q-47bcbd6c92"} | ERROR |  |
| q-c86344e42f | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-8a66c35201 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-cbfd68eee0 | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F33 |
| q-e6714ef6d8 | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.GrantedAccess",… | 2 |  |
| q-88d354f22d | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-764c680eca | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-7de0dcb0a9 | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-24d46b7b1e | triage T1556 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Dump* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*se… | 3 | F33, F36 |
| q-e1ac1dd6cc | triage T1556 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*sekurlsa* OR process.command_line:*DumpCred* OR process.command_line:*comsvcs*)", "time_from": null, "time_to": n… | 1 |  |
| q-eb635c70ae | triage T1556 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-0e870de22e | triage T1556 step 5 | search | {"dataset": "windows.security", "query": "event.code:4624 AND (win.LogonType:3 OR win.LogonType:9 OR win.LogonType:10)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.LogonType", "win.LogonProcessName", "win.Target… | 220 |  |
| q-9888ff8013 | triage T1556 step 6 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.TargetUserName:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.TargetUserName", "win.LogonType", "win.IpAddress", "win.ProcessName", "event.… | 30 |  |
| q-eb4c7a2a76 | triage T1556 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*wsmprovhost*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executable"], "size… | 1 | F33 |
| q-65d15711dc | triage T1556 step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Control\\\\Lsa* OR registry.path:*Notification* OR registry.path:*WDigest* OR registry.path:*Security Packages*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 293 | F35 |
| q-e23b1ae276 | triage T1556 step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*System32* OR file.path:*SysWOW64*) AND file.path:*.dll", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "file.path", "event.code… | 0 |  |
| q-75feda5dc3 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-825dc641af | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-69396ae9f8 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-bdd980c650 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWIboY"} | None |  |
| q-679edcf9bb | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-fcc8942962 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-1fa950aea3 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhQkl"} | None |  |
| q-197c4e17e9 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT_4QtO"} | None |  |
| q-57e3b93092 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-907259854d | triage T1557 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_ZtM"} | None |  |
| q-e4c7960679 | triage T1557 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND process.executable LIKE \"*python*\" \| KEEP @timestamp, host.name, process.executable, process.command_line, destination.ip, destination.port, user.name, _id, _i… | 20 |  |
| q-d05838de4c | triage T1557 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 5355 OR destination.port == 137 OR destination.port == 138) \| KEEP @timestamp, host.name, process.executable, des… | 30 |  |
| q-fe5d41748c | triage T1557 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*scr*\" OR process.executable LIKE \"*victim*\") \| KEEP @timestamp, host.name, process.executable, process.command_line, process.paren… | 2 |  |
| q-f8ed45b238 | triage T1557 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*python*\" \| KEEP @timestamp, host.name, process.executable, process.command_line, process.parent.executable, user.name, _id, _index \|… | 5 | F37 |
| q-0fd3a1e78f | triage T1557 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" AND win.LogonProcessName LIKE \"*NtLm*\" \| KEEP @timestamp, host.name, win.LogonProcessName, win.TargetUserName, win.IpAddress, win.W… | 1 |  |
| q-e3943de916 | triage T1557 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND process.executable LIKE \"*python*\" \| STATS c = COUNT(*) BY destination.ip, destination.port, host.name \| LIMIT 20"} | 1 |  |
| q-7d7478afc6 | triage T1557 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"22\" AND process.executable LIKE \"*scr*\" \| KEEP @timestamp, host.name, process.executable, dns.question.name, win.QueryResults, _id, _index \| LIMIT 20"} | 3 |  |
| q-35088345c2 | triage T1557 step 3 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FN5"} | None | F37 |
| q-4b8050cb5b | triage T1557 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO_tniJ"} | None | F37 |
| q-75b9151441 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO_tniJ"} | None |  |
| q-9910e427d5 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO_tniJ"} | None |  |
| q-98f6368d0a | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO_tniJ"} | None |  |
| q-51d3583ed7 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK66i5"} | None |  |
| q-cd865fa331 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FN5"} | None |  |
| q-cbf89f1173 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FN5"} | None |  |
| q-59069e60c1 | triage T1557 verify | get_event | {"index": "zeek", "id": "q-ec0e04db55"} | ERROR |  |
| q-0aed06c545 | triage T1557 verify | get_event | {"index": "zeek", "id": "q-f2c31d3ab6"} | ERROR |  |
| q-181151f95a | triage T1557 verify | get_event | {"index": "zeek", "id": "q-983e7b43dd"} | ERROR |  |
| q-4fff606656 | triage T1557 step 5 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.orig_l2_addr, zeek.resp_l2_addr, _id, _index \| LIMIT 10"} | 10 | F38, F39 |
| q-986d1db687 | triage T1558 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess != \"0x1000\" \| KEEP @timestamp, host.name, process.executable, win.SourceImage, win.GrantedAccess, win.Targe… | ERROR |  |
| q-7337bb6b6d | triage T1558 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4769 OR event.code == 4768 \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.TicketEncryptionType, win.PreAuthType, win.IpAddress, win.ServiceName, win.S… | ERROR |  |
| q-a518cd87b6 | triage T1558 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess != \"0x1000\" \| KEEP @timestamp, host.name, process.executable, win.SourceImage, win.GrantedAccess, win.T… | 33 |  |
| q-fe8d1b3881 | triage T1558 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" OR event.code == \"4768\" \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.TicketEncryptionType, win.PreAuthType, win.IpAddress, win.ServiceNam… | 42 | F40, F41, F42, F43, F44 |
| q-0bd7bba865 | triage T1558 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND process.executable LIKE \"*PowerShell*\" \| KEEP @timestamp, host.name, process.executable, win.SourceImage, win.GrantedAcce… | 4 |  |
| q-a81fc5d24b | triage T1558 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" OR event.code == \"4103\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" OR TO_LOWER(win.ScriptBl… | 16 |  |
| q-eb6ebc062f | triage T1558 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None | F40 |
| q-f355d2ec20 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T03:04:50\" AND @timestamp <= \"2020-05-02T03:06:00\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, event.code, win.ScriptBlockText, proce… | 249 |  |
| q-fae838b29e | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" \| STATS cnt = COUNT(*) BY win.TicketEncryptionType, win.TargetUserName \| SORT cnt DESC"} | 2 |  |
| q-6298b8186e | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" \| STATS cnt = COUNT(*) BY user.name \| SORT cnt DESC"} | 9 |  |
| q-5f8863990f | triage T1558 step 6 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"kerberos\" \| STATS cnt = COUNT(*) BY zeek.cipher, zeek.request_type, zeek.service \| SORT cnt DESC"} | 10 |  |
| q-3b7670d2b8 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-d18edfefed | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-e5c2088b53 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b5b5f40d7a | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-7fe0a30206 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjh"} | None |  |
| q-985fed68ea | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-9fc7515b48 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpM"} | None |  |
| q-550290f30e | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUJ"} | None |  |
| q-eea1ca5835 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUJ"} | None |  |
| q-9e685ba592 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOaA_"} | None |  |
| q-3904c24e24 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIji"} | None |  |
| q-35f4897b8d | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-bc952ed34a | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXJ"} | None |  |
| q-c0a8b50335 | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-e1b3c61600 | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None | F45 |
| q-88565999f0 | triage T1606 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| STATS c = COUNT(*) BY win.SourceImage, host.name \| SORT c DESC \| LIMIT 30"} | 12 |  |
| q-17ffbe94f3 | triage T1606 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND file.path LIKE \"*Cookie*\" \| KEEP @timestamp, host.name, file.path, process.executable, user.name, _id, _index"} | 1 | F45, F46 |
| q-d496ae87c2 | triage T1606 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*cookie*\" OR process.command_line LIKE \"*Cookie*\" OR process.command_line LIKE \"*SAML*\" OR process.command_line LIKE \"*jwt*\" O… | 5 | F45, F46, F47 |
| q-23b7bfa0c5 | triage T1606 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*cookie*\" OR win.ScriptBlockText LIKE \"*Cookie*\" OR win.ScriptBlockText LIKE \"*SAML*\" OR win.ScriptBlockText LIKE \"*jwt*\… | 1 | F45, F46 |
| q-270767b06b | triage T1606 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None | F45 |
| q-9a2e43cf25 | triage T1606 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*rundll32*\" \| KEEP @timestamp, host.name, process.executable, process.command_line, process.parent.executable, process.parent.command_… | 7 |  |
| q-c308963dc4 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-1b5c951704 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-3fd44e7929 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-51ab447d4c | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-1ef1a889bb | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-968e2c7837 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-0ad9c11afe | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-a8994f7abb | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-9f52641211 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-d0178f5fe8 | triage T1621 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RI"} | None | F48 |
| q-57f939835f | triage T1621 step 1 | search | {"dataset": "windows.other", "query": "message:*MFA* OR message:*multi-factor* OR message:*Authenticator* OR message:*one-time* OR message:*verification*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 0 |  |
| q-92f27eb8fd | triage T1621 step 1 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*MFA* OR win.ScriptBlockText:*Authenticator* OR win.ScriptBlockText:*OneTime* OR win.ScriptBlockText:*verification* OR win.ScriptBlockText:*2FA*", "time_from": null, "time_to": null, "fields": ["@… | 0 |  |
| q-c6f0c903e3 | triage T1621 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND (win.LogonType:10 OR win.LogonType:3)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.LogonType", "win.IpAddress", "win.Workstation"], "size": … | 220 |  |
| q-9f4c87bc64 | triage T1621 step 2 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "message:*authentication* OR message:*logon* OR message:*credential*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 6 |  |
| q-84165c5c05 | triage T1621 step 2 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*Connect* OR win.ScriptBlockText:*Token* OR win.ScriptBlockText:*Login* OR win.ScriptBlockText:*Auth*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 13 | F48 |
| q-120a8602a0 | triage T1621 step 3 | search | {"dataset": "windows.other", "query": "event.code:1149 OR event.code:6038 OR event.code:7001 OR event.code:8013 OR event.code:14 OR event.code:21", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "message", "user.name"],… | 6 | F48 |
| q-186881bdc4 | triage T1621 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:22 AND (dns.question.name:*mfa* OR dns.question.name:*okta* OR dns.question.name:*duo* OR dns.question.name:*auth* OR dns.question.name:*login* OR dns.question.name:*verify*)", "time_from": null, "time_to": nu… | 2 | F48 |
| q-364717f1a5 | triage T1621 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*MFA* OR process.command_line:*Authenticator* OR process.command_line:*2FA* OR process.command_line:*OneTime* OR process.command_line:*verification*)", "time_from": null, "time_to":… | 0 |  |
| q-fc6b9a2a55 | triage T1621 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.ip:52.167.250.154 OR destination.ip:168.61.186.235 OR destination.ip:23.4.15.75 OR destination.ip:23.56.173.48)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "p… | 23 | F48 |
| q-82bc3bdad4 | triage T1621 step 4 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*MFA* OR process.command_line:*Authenticator* OR process.command_line:*2FA* OR process.command_line:*OneTime* OR process.command_line:*otp*)", "time_from": null, "time_to": nul… | 0 |  |
| q-769ea8ba87 | triage T1621 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*Authenticator* OR process.executable:*MFA* OR process.executable:*otp* OR process.executable:*duo* OR process.executable:*okta*)", "time_from": null, "time_to": null, "fields": ["@ti… | 0 |  |
| q-9637dcae6c | triage T1621 step 5 | count | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null} | 0 |  |
| q-ffb36b9458 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RI"} | None |  |
| q-f82643a91a | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RH"} | None |  |
| q-da8d55fe76 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-f3ffecc9eb | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThXQrv"} | None |  |
| q-764f472657 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT-3yn1"} | None |  |
| q-da446bf674 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSmmMy"} | None |  |
| q-e9577e0ee0 | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None | F49 |
| q-ebc9f36efe | triage T1649 step 1 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*pfx* OR win.ScriptBlockText:*PrivateKey* OR win.ScriptBlockText:*cert:\\\\* OR win.ScriptBlockText:*Export* OR win.ScriptBlockText:*ConvertTo-SecureString*)", "time_from": nu… | ERROR |  |
| q-f5fd2fecb8 | triage T1649 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*pfx* OR win.ScriptBlockText:*PrivateKey* OR win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*Get-PrivateKeys*)", "time_from": null, "time_to": null, "field… | 3 | F49 |
| q-4ad3bf5d44 | triage T1649 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*Downloads* OR file.path:*.pfx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable",… | 314 |  |
| q-48eebca81f | triage T1649 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*.pfx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 1 | F49 |
| q-7982ebad0c | triage T1649 step 3 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None | F50 |
| q-9e9cf278af | triage T1649 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*coyn5igj*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 1 |  |
| q-1abbf3dd3c | triage T1649 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*pfx* OR process.command_line:*Get-PrivateKeys* OR process.command_line:*certutil*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-9f4d3bd10f | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-f0eaffcfc4 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-fb0ca6d7ba | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-8697b8637d | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-a06bc97057 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlVDe"} | None |  |
| q-917f10ea8e | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-f2725652d6 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhp5O"} | None |  |
| q-7debbfe797 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-a74694613b | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-b5cecf2761 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt5I2Y"} | None |  |
| q-828841fb25 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-fe723fc44d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-26b8c0242f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-6ba7ad103a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-40dd8cb1d2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKBk"} | None |  |
| q-011e70f0ac | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKBk"} | None |  |
| q-4ae1771d01 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-0435db4ed2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-ee8d3e1086 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKBk"} | None |  |
| q-6021082927 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOqAA"} | None |  |
| q-375f74db61 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoYO"} | None |  |
| q-117542ae53 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaEO1dd"} | None |  |
| q-6620b92c8d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaEO1dd"} | None |  |
| q-ace4fbbcfe | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaEO1dd"} | None |  |
| q-fd8b632dda | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVq1j6z"} | None |  |
| q-560117acf2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoYO"} | None |  |
| q-da60acd102 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-241319676c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-ebee175d4f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-d47f8d66f7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPE0PdZ"} | None |  |
| q-dcadec4e55 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt4o2y"} | None |  |
| q-7ee22ceecf | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-8eae6db1c2 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-539005c024 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-47bca15a95 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjg"} | None |  |
| q-0bcb6e724d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjg"} | None |  |
| q-6bcca573c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-ce1c23a710 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-8b3975230a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-51723b0cf9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-23dc1678f3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-8ec2d9b031 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-ce2e6a97f7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-3266b5c576 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-ba686e7c9a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-75e0f56a35 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2M4"} | None |  |
| q-a3bdac3918 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-5c22b32432 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSmWPy"} | None |  |
| q-d0fdeb2ff7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqdCw"} | None |  |
| q-a8861a0862 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-cbef8b7927 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-55af8903bd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-b829a5ac85 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTPA5kN"} | None |  |
| q-74f6ec14cb | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-0647fc960f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lPw"} | None |  |
| q-fe6804fac6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-d610a1fc3f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-015f8baaad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPDyDoS"} | None |  |
| q-063806f5e6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOYDnci"} | None |  |
| q-a72cdd97a5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUGBVXT"} | None |  |
| q-8a78734d97 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lPw"} | None |  |
| q-f762cf2bfb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP2"} | None |  |
| q-1ee0e40c88 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lPw"} | None |  |
| q-b05999d5ab | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP2"} | None |  |
| q-0029f5b927 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO5lCpc"} | None |  |
| q-9948cf7dba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO5lCpc"} | None |  |
| q-35ab827988 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO5lCpc"} | None |  |
| q-c68466fa3d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOxeHN4"} | None |  |
| q-afa6c6709e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOxeHN4"} | None |  |
| q-94225edca6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-54c1ff997f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-ff6808c730 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-1352b7a18a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-74f8c3a29e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-2e3dbf4e72 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQtn"} | None |  |
| q-0e34f493fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQtn"} | None |  |
| q-5a763d1d25 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_q"} | None |  |
| q-cfe2014b0c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_q"} | None |  |
| q-a26e5f44aa | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-860a4cdcc3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTmcl_4"} | None |  |
| q-91220ef9b4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-88ed654c37 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b851c4e57a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-907c501645 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-02722943c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-c47d94c0b2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZJhF-L"} | None |  |
| q-e4a4864d7a | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-d07ea4ac6e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-1da0e59ba6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-ca5f747a51 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_Zu5"} | None |  |
| q-8832b60b05 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_Zu5"} | None |  |
| q-498f86cdc7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_Zu5"} | None |  |
| q-2a967bbb1e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQC8TKL"} | None |  |
| q-d3642acc5c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-fb087645e1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTpgCep"} | None |  |
| q-ed376b9067 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-e0b3013df9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-6786df7aad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-54fedb95f9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-43e3e96741 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-455e794da3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-4c95b30523 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-e313b319e8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhAkt"} | None |  |
| q-f0ef2863d6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhAkt"} | None |  |
| q-b04d42ac87 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-b7a8eb2000 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-72999f0c1c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2M4"} | None |  |
| q-a83a5e4a5c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-7dc37d9627 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-95d530546a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-3f5b85a976 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-739efa08c6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-48f32576c9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-ee32d599e9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-4471a1b3d2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-1593eba746 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-b921ec3614 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-6c6ad14a73 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-5f78fc5b5b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-fdabff5888 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWIboY"} | None |  |
| q-c1b071e918 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-1429760dc8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-5774549379 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhQkl"} | None |  |
| q-5cbeca2e53 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT_4QtO"} | None |  |
| q-a9e22596dc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-101b3d9925 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO_tniJ"} | None |  |
| q-3b81564ea6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO_tniJ"} | None |  |
| q-31cd592172 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO_tniJ"} | None |  |
| q-1d94a822e6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK66i5"} | None |  |
| q-ac9460159f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FN5"} | None |  |
| q-ce690507c6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FN5"} | None |  |
| q-278f6db211 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrohb"} | None |  |
| q-21ce3fea0f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrohb"} | None |  |
| q-1e9ccd6762 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrohb"} | None |  |
| q-946cd55e64 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-6af4433629 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-f968cac407 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b1e758f2ce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-da6591fc64 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjh"} | None |  |
| q-4f0d857f3b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-a701d13e7b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpM"} | None |  |
| q-9078196ec6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUJ"} | None |  |
| q-ec0877c53f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUJ"} | None |  |
| q-910e468c66 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOaA_"} | None |  |
| q-9ed22438c1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIji"} | None |  |
| q-46fcda9e9b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-f7201765c8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXJ"} | None |  |
| q-961cf35577 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-967807cf50 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-c531c9261e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-f532f947bc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-c213e4f8a8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-a20c013d4c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-a597ea38b1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-26e4aba648 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-9dd2360894 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-08a5a3a39c | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RI"} | None |  |
| q-29f298f1ab | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RH"} | None |  |
| q-61a9925267 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-6d1c18734e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThXQrv"} | None |  |
| q-eeb0e7ee6d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT-3yn1"} | None |  |
| q-2888d06dbb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSmmMy"} | None |  |
| q-2ee491a210 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-09182c7e76 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-b20f704841 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-ef02f25f47 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-2bca9c5521 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlVDe"} | None |  |
| q-4e4efacad3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-3da18d65ca | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhp5O"} | None |  |
| q-07efd9a98f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-c48b12e783 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-fc7eb66e23 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt5I2Y"} | None |  |
| q-cf26575b6e | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:32:59.352000+00:00", "size": 100, "sub_field": "process.pare… | 61 |  |
| q-a938609d2c | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:32:59.352000+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-1eadc31967 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:32:59.352000+00:00", "size": 100, "sub_field": "process… | 63 |  |
| q-3f6994db3f | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:32:59.352000+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-d498db8710 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:35:41+00:00", "size": 100, "sub_field": "process.parent.ex… | 359 |  |
| q-2fe6b018d2 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:35:41+00:00", "size": 100, "sub_field": "process.executable"} | 1276 |  |
| q-fda0e80f24 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:35:41+00:00", "size": 100, "sub_field": "process.pare… | 370 |  |
| q-d376b32776 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:35:41+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-9e97de6448 | pivot step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\" AND (process.executable:*SysinternalsSuite* OR process.executable:*csc.exe OR process.executable:*cod.3aka3* OR process.executable:*hostui* OR process.executable:*sdc… | 15 | F52, F56, F57, F58, F59, F60, F61 |
| q-078b219231 | pivot step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\" AND (process.executable:*python* OR process.executable:*Rar.exe OR process.executable:*sdelete* OR process.executable:*PSEXESVC*)", "time_from": null, "time_to": null, … | 13 | F54, F55 |
| q-12d80d71a8 | pivot step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.file.script_block_text:*lsass* OR powershell.file.script_block_text:*PrivateKey* OR powershell.file.script_block_text:*Credential* OR powershell.file.script_block_text:*vault* OR power… | 0 |  |
| q-46ca0532bd | pivot step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*.pfx OR file.path:*.zip OR file.path:*.rar OR file.path:*Credential* OR file.path:*vault* OR file.path:*Draft* OR file.path:*working*)", "time_from": null, "time_to": null, "fields": ["host.… | 5 | F51 |
| q-6ee04cbd7f | pivot step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:\"scranton.dmevals.local\"", "time_from": null, "time_to": null, "fields": ["host.name", "event.code", "powershell.file.script_block_text", "@timestamp"], "size": 30, "sort": "asc"} | 146 |  |
| q-a3a8e5decc | pivot step 3 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663) AND (object.name:*lsass* OR object.name:*SAM* OR object.name:*SECURITY* OR object.name:*vault* OR object.name:*Credential*)", "time_from": null, "time_to": null, "fields": ["host.name", "event… | 0 |  |
| q-8ebc14f58a | pivot step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqdCz"} | None |  |
| q-a36fbcf47b | pivot step 4 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-0831ee2bb8 | pivot step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*PrivateKey* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*vault* OR win.ScriptBlockText:*password* OR win.ScriptBlockText:*Get-Ch… | 53 |  |
| q-f346ad2d63 | pivot step 6 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND user.name:\"pbeesly\" AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*PrivateKey* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*vault* OR win.ScriptBlockText:*Export-PfxCert… | 3 | F51, F53 |
| q-c34b7d46d7 | pivot step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None | F51 |
| q-aaeec36507 | pivot step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None | F53 |
| q-fd2730cd7a | pivot step 8 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg*save* OR process.command_line:*SAM* OR process.command_line:*SECURITY* OR process.command_line:*ntds* OR process.command_line:*sekurlsa* OR process.command_line:*procdump* OR p… | 0 |  |
| q-78881565ad | pivot step 8 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*.dmp OR file.path:*.7z OR file.path:*OfficeSupplies* OR file.path:*readme.ps1 OR file.path:*psversion*)", "time_from": null, "time_to": null, "fields": ["host.name", "file.path", "process.ex… | 7 | F53 |
| q-e13beb02fa | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-b3679d2b7c | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-c43b88817e | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-5425cf79d9 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-eac98a9acc | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-b7a1b572ac | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-479d183f5f | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWI7pZ"} | None |  |
| q-b59dc9b992 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTPA5kN"} | None |  |
| q-7c1e912085 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPJ5Bh7"} | None |  |
| q-e4cfb2c17d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-3a5aefc114 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-e302b78fb1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-223180d5ec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-d36c2eb4e6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKBk"} | None |  |
| q-964ff2ee72 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKBk"} | None |  |
| q-29fe00a86a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-96d65efef6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-567665c321 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKBk"} | None |  |
| q-a9646f415b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOqAA"} | None |  |
| q-ecc7368e33 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoYO"} | None |  |
| q-f86cf911a8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaEO1dd"} | None |  |
| q-15b353ad65 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaEO1dd"} | None |  |
| q-0e35a6e752 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaEO1dd"} | None |  |
| q-e4381c1635 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVq1j6z"} | None |  |
| q-9e2d7510de | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoYO"} | None |  |
| q-c8a5be4de6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-aa1126f567 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-089a90f281 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-1a0a591e08 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPE0PdZ"} | None |  |
| q-b43a67b799 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt4o2y"} | None |  |
| q-12681bc69e | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-7f7dff16fd | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-902fdf36cb | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-4f54b194e6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjg"} | None |  |
| q-30fd2b07b0 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjg"} | None |  |
| q-483cd35e2f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-3315a82e5f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-90d44f09d5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-8baf37698c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-925b2876a7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-a1a0f71698 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-a417d4e8c9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-0c71411a60 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-ccf3ae3855 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-b8b327b8b8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2M4"} | None |  |
| q-c4e3fc55d6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-c282108144 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSmWPy"} | None |  |
| q-7c0ea63757 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqdCw"} | None |  |
| q-331770dc60 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-add79b3a40 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-fcb326c476 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-34c6524c31 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTPA5kN"} | None |  |
| q-043d9d650a | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-d02117eb0a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lPw"} | None |  |
| q-294c4dda66 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-33f257a21f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-c3fcc27ca9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPDyDoS"} | None |  |
| q-29fbb943f7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOYDnci"} | None |  |
| q-2c2c7d9e57 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUGBVXT"} | None |  |
| q-851d497528 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lPw"} | None |  |
| q-5f0fcae89b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP2"} | None |  |
| q-c3771d3c97 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lPw"} | None |  |
| q-b6e0935456 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP2"} | None |  |
| q-b782a64c4d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO5lCpc"} | None |  |
| q-31aea159c0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO5lCpc"} | None |  |
| q-beefe812f9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO5lCpc"} | None |  |
| q-2072ee6540 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOxeHN4"} | None |  |
| q-0cb8ec6c06 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOxeHN4"} | None |  |
| q-8db773e549 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-fa5aa5e2f8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-d2ce48eea8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-f99bc76eca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-aa6e742b4c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-efb1f50806 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQtn"} | None |  |
| q-bd0f0d5cb6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQtn"} | None |  |
| q-b8ba7148a0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_q"} | None |  |
| q-b246baae47 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_q"} | None |  |
| q-0f96f4d316 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-0203a14d89 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTmcl_4"} | None |  |
| q-345b7e4b0d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-7dac9c64e9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-45f98bd23d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-4fb7a33387 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-e1a69e9677 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-0530a6446e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZJhF-L"} | None |  |
| q-feaad7068b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-bcec6f51be | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-d540b9a02f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-f2445387af | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_Zu5"} | None |  |
| q-a9bac00a72 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_Zu5"} | None |  |
| q-d1bf408549 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_Zu5"} | None |  |
| q-b0ac346937 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQC8TKL"} | None |  |
| q-af48bdc7fe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-d339b22b04 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTpgCep"} | None |  |
| q-40b4451489 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-cb07c5dd65 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-85ca37a2b3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-b91a1e970a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-4667fefe3d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-c976a86440 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-d92d6a6fa8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-dd68aa2173 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhAkt"} | None |  |
| q-1ca8231294 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhAkt"} | None |  |
| q-1e9c73a9a4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-2831e498a7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-5ebd7a6f1b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2M4"} | None |  |
| q-d67d8829e5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-8671e852f9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-789531efec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-f3ff0e0a07 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-0f69bb4334 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-f314d50d69 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-fa1dab05c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-ca2d57731a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-c5bd0d32df | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-c800f3fd49 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-331cfe2c54 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-a20ec424ba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-8734c2e419 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWIboY"} | None |  |
| q-7769cf1f3a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-d4c9436233 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-392afdda34 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhQkl"} | None |  |
| q-64857bc6a2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT_4QtO"} | None |  |
| q-bd31d5587b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-a819c0b029 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO_tniJ"} | None |  |
| q-088ce950a4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO_tniJ"} | None |  |
| q-cfc418e73e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO_tniJ"} | None |  |
| q-2bf60b22de | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK66i5"} | None |  |
| q-c1dbc8af5a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FN5"} | None |  |
| q-1954711398 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FN5"} | None |  |
| q-101e6e1e0e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrohb"} | None |  |
| q-251b1d670f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrohb"} | None |  |
| q-c2a79ab266 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrohb"} | None |  |
| q-1cdd576643 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-d6f68d9866 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-5657060ba5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-3cc88f463c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-c5446946a5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjh"} | None |  |
| q-502e5d66a7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-ef08498ced | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpM"} | None |  |
| q-0cf4bd46b3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUJ"} | None |  |
| q-0c32651d5e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUJ"} | None |  |
| q-3e2582f91d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOaA_"} | None |  |
| q-43e1aa07a6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIji"} | None |  |
| q-8673c8c1d0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-319b24ea55 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXJ"} | None |  |
| q-cd4359cfd6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-e583b4eae5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-1b14c7627c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-a2a64a33e5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-2b6ce46efb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-ad454c78ac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-74d44df287 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-772c1fb300 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-9bc21e290c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-714632d536 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RI"} | None |  |
| q-9e528b655f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RH"} | None |  |
| q-18257cb529 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-8535715f35 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThXQrv"} | None |  |
| q-21803fe770 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT-3yn1"} | None |  |
| q-757438a86a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSmmMy"} | None |  |
| q-906d7486b0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-8c2fe03872 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-777eeaab40 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-c9b4b286f9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-7287e8a327 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlVDe"} | None |  |
| q-7f7a5c918e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-b099c9302d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhp5O"} | None |  |
| q-3ac7b5fdf7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-9eea76ec80 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-35a9776d8f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt5I2Y"} | None |  |
| q-8894dd88a9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-27426eff88 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-db5a26399d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-73e29ace45 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-9e454afffc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-eae1cf2da7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-3158ea0d3e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWI7pZ"} | None |  |
| q-dbaa8c0c93 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTPA5kN"} | None |  |
| q-9096896c4c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPJ5Bh7"} | None |  |
| q-1b94ce8676 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-9102a9a2a2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-7ae5382f73 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTneF2m"} | None |  |
| q-96d966a7ea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTmdl8v"} | None |  |
| q-9be848532e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-b525b7b9c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-1a41d560e0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQA6YzM"} | None |  |
| q-b28458b2cc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQA6YzM"} | None |  |
| q-b47299f5de | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-VVW"} | None |  |
| q-ff22c15f06 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-VVW"} | None |  |
| q-270cd32de2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB7l0w"} | None |  |
| q-8a5cf05202 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB7l0w"} | None |  |
| q-ccec75db1d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGg"} | None |  |
| q-7c83767d16 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGg"} | None |  |

## Verification

Evidence items cited: 185; confirmed against the stored events: 184; rejected: 1. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 15 item(s) in 5 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
