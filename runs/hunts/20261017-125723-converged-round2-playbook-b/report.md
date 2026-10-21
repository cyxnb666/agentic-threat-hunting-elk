# Threat hunt report — 20261017-125723-converged-round2-playbook-b

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 8 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003.001 (F01, F10, F11, F17, F23, F32, F34, F36, F47, F59, F63), I02 T1056.001 (F57, F58), I03 T1187 (F21), I04 T1539 (F25), I05 T1552 (F29, F62), I06 T1552.001 (F28, F60), I07 T1552.004 (F27, F37, F56, F61), I08 T1649 (F52)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-17T04:57:23+00:00 / 2026-10-17T05:06:08+00:00 (524.9 s) |
| LLM calls / tokens | 165 / {'prompt': 5160678, 'completion': 105958} |
| MCP tool calls | 1340 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003.001 | yes | malicious/high | F01, F10, F11, F17, F23, F32, F34, F36, F47, F59, F63 | LSASS memory access with full-access masks by PowerShell on scranton and wsmprovhost on nashua |
| I02 | T1056.001 | yes | malicious/high | F57, F58 | Keylogging and clipboard capture on scranton |
| I03 | T1187 | yes | malicious/high | F21 | Forced authentication via WebDAV/UNC coercion from scranton to 192.168.0.4 |
| I04 | T1539 | yes | malicious/medium | F25 | Hidden PowerShell stager opened Microsoft Edge processes with PROCESS_ALL_ACCESS |
| I05 | T1552 | yes | malicious/high | F29, F62 | Unsecured credentials staged and exfiltrated via Invoke-Exfil on scranton |
| I06 | T1552.001 | yes | malicious/high | F28, F60 | Credential-hunting file collection and plaintext credential use |
| I07 | T1552.004 | yes | malicious/high | F27, F37, F56, F61 | Get-PrivateKeys exported LocalMachine certificate private keys to .pfx on scranton |
| I08 | T1649 | yes | malicious/high | F52 | Credential/certificate theft tooling staged on scranton with no web-credential forging observed |
| I09 | out-of-scope:T1036 | no | suspicious/low | F66, F67 | Low-confidence hostui.exe and sdclt.exe process anomalies on scranton |
| I10 | out-of-scope:T1071 | no | suspicious/medium | F09 | Attacker python.exe on nashua as C2/exfil client |
| I11 | out-of-scope:T1569 | no | malicious/high | F07, F64 | Sysinternals credential-access toolchain, PsExec lateral movement and anti-forensic cleanup by pbeesly |

## Findings

### F07 · malicious / high · T1003 · Credential-access toolchain staged by pbeesly: Sysinternals, accesschk, private-key export, PsExec to NASHUA, packed python.exe, Rar archive

Evidence status: **verified**

On scranton.dmevals.local pbeesly expanded SysinternalsSuite.zip into C:\Program Files\SysinternalsSuite, ran accesschk.exe, defined and invoked a Get-PrivateKeys function that exports every LocalMachine certificate to a random .pfx in Downloads, and used sdelete64.exe to wipe artifacts (C:\programdata\victim\???cod.3aka3.scr, Draft.Zip, SysinternalsSuite.zip). From 03:11:18 to 03:14:42 UTC pbeesly launched PsExec64.exe four times against \\NASHUA with the cleartext password Fl0nk3rt0n!T0by to run C:\Windows\Temp\python.exe. On nashua.dmevals.local PSEXESVC.exe spawned that python.exe (PyInstaller bundle unpacking _ssl.pyd, pywintypes27.dll, _hashlib.pyd into _MEI29522), which made hundreds of outbound connections to 192.168.0.4:8443, spawned cmd.exe, and Rar.exe created a password-protected archive C:\Users\pbeesly\Desktop\working.zip; sdelete64.exe then wiped Rar.exe and working.zip. This is a hands-on credential-theft and exfiltration chain, and it is the context for the LSASS memory reads reported under T1003.001.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-9fe19b7e28 | ok |
| 2 | 2020-05-02 03:04:34.000Z | scranton.dmevals.local | windows.powershell | process.command_line | &amp; "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQDVp3 | q-9fe19b7e28 | ok |
| 3 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ioON3 | q-4696e5ed2d | ok |
| 4 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2in-NH | q-faf858b0bc | ok |
| 5 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.port | 8443 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2bgjeM | q-66b878f09f | ok |
| 6 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2Ze6tB | q-bcfec6c8a7 | ok |
| 7 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL69HSbI | q-4696e5ed2d | ok |

### F64 · malicious / high · T1003 · Sysinternals credential-access toolchain executed by pbeesly

Evidence status: **verified**

PsExec64 with cleartext creds launched python.exe on NASHUA; sdelete64 wiped the victim payload and archives.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ioON3 | q-09135d5471 | ok |
| 2 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL69HSbI | q-09135d5471 | ok |

### F01 · malicious / high · T1003.001 · pbeesly PowerShell requests full-access handle to LSASS on scranton and nashua

Evidence status: **verified**

On 2020-05-02 at 03:05:16 UTC the account pbeesly (DMEVALS, SID ...-1107) running C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe on scranton.dmevals.local requested a handle to \Device\HarddiskVolume2\Windows\System32\lsass.exe with AccessMask 0x1FFFFF, which the audit message expands to 'Read from process memory' / 'Write to process memory' / 'Duplicate handle into or out of process' — the classic LSASS memory-read pattern used by dumping tools. A second handle with 0x1F3FFF was requested in the same second, and Sysmon corroborates the same source image (PowerShell.exe) opening lsass with GrantedAccess 0x1f3fff and 0x1fffff at 03:05:16. At 03:09:29 UTC the same user, via wsmprovhost.exe (WinRM) on nashua.dmevals.local, again opened lsass with 0x1F3FFF (Sysmon GrantedAccess 0x1f3fff). This is preceded by pbeesly unpacking SysinternalsSuite, running accesschk.exe, and a PowerShell 'Get-PrivateKeys' function that exports certificates to .pfx files, i.e. an active credential-theft toolchain. The only other LSASS opens in the window are svchost/wininit/csrss/AntimalwareConfig/CollectGuestLogs with 0x1000/0x1400/0x101001 masks, which are normal.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9MpvMw | q-546fc3b995 | ok |
| 2 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9MpvMw | q-546fc3b995 | ok |
| 3 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | user.name | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9MpvMw | q-546fc3b995 | ok |
| 4 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9VzibT | q-546fc3b995 | ok |
| 5 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9VzibT | q-546fc3b995 | ok |
| 6 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-a788e744ce | ok |
| 7 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-a788e744ce | ok |
| 8 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-a788e744ce | ok |
| 9 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-9fe19b7e28 | ok |

### F63 · malicious / high · T1003.001 · LSASS handle 0x1f3fff from WinRM host on nashua

Evidence status: **verified**

New host evidence: nashua shows a full-access LSASS open by wsmprovhost.exe with a PowerShell Management-module call trace.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-b1afd86234 | ok |

### F11 · malicious / high · T1056 · Lateral movement to nashua: wsmprovhost and dropped python.exe open LSASS with full access

Evidence status: **verified**

On nashua.dmevals.local, pbeesly's remote PowerShell session (wsmprovhost.exe, started 03:09:23Z) opened lsass.exe with GrantedAccess 0x1f3fff at 03:09:29Z, and the security log records the same handle request with AccessMask 0x1f3fff. Shortly after, PSEXESVC.exe launched C:\Windows\Temp\python.exe (03:11:40Z), which opened powershell.exe, cmd.exe and itself with 0x1fffff. The same session enumerated processes with Get-Process -IncludeUserName and then staged data with Rar.exe into working.zip. This is credential-access tooling deployed over the lateral-movement channel.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-320d9ff97f | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-320d9ff97f | ok |
| 3 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9VzibT | q-40814c6b5b | ok |
| 4 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\python.exe"  | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2in-NH | q-2154f1d466 | ok |
| 5 | 2020-05-02 03:15:48.656Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2bgTcg | q-d1fa16b8d4 | ok |
| 6 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAMA2AH | q-f6339477d0 | ok |

### F57 · malicious / high · T1056.001 · pbeesly ran Get-Keystrokes keylogger job on scranton

Evidence status: **verified**

On scranton pbeesly ran Get-Keystrokes, slept 15s and viewed the Keystrokes job after an AV-enumeration function.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQDFlH | q-6b17567544 | ok |
| 2 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Keystroke-Check {     Get-Process \| Where-Object { $_.ProcessName -Eq "avp" -or $_.ProcessName -Eq "acs" -or $_.ProcessName -Eq "outpost" -or $_.Proce… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1lL | q-9398fd5190 | ok |

### F58 · malicious / medium · T1056.002 · pbeesly read clipboard on scranton

Evidence status: **verified**

On scranton pbeesly executed Get-Clipboard between screenshot and keystroke collection.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:42.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Clipboard | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQDFlE | q-9398fd5190 | ok |

### F10 · malicious / high · T1056.004 · pbeesly PowerShell opens LSASS with full access (0x1fffff/0x1f3fff) on scranton after obfuscated shellcode loader

Evidence status: **verified**

On scranton.dmevals.local the user pbeesly ran an interactive PowerShell session (PID 2976) that first executed an obfuscated Add-Type/VirtualAlloc/CreateThread shellcode loader (script block 1b1697b2-39d8-4a6b-91ef-65ad303664d0, 2020-05-02T02:58:45Z) and a steganographic IEX loader from monkey.png, then at 03:05:16Z opened a handle to C:\windows\system32\lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff (PROCESS_ALL_ACCESS) — the access pattern used to read LSASS memory for credential extraction. The same session also ran csc.exe compilation, accesschk.exe, sdelete64.exe and WebDAV/rundll32 davclnt activity. This is attacker credential-API access to LSASS, not normal system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-ef1a83986f | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-8124962722 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-ef1a83986f | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9MpvMw | q-40814c6b5b | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Qtr32 | q-40814c6b5b | ok |
| 6 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $cFIrwwpZzGzU = @"  [DllImport("kernel32.dll")]  public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWIxa2 | q-d8354f87f2 | ok |

### F65 · malicious / high · T1056.004 · csc.exe compiled in-memory loader DLLs on scranton

Evidence status: **NOT verified (1/2 evidence items)** — excluded from the verdict

csc.exe compiled attacker C# from PowerShell temp dirs into DLLs on scranton.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 |  | None | None | process.command_line | /noconfig /fullpaths @"C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.cmdline" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2VhsbT | q-09135d5471 | FAILED: cited query did not return this event; event not found |
| 2 | 2020-05-02 02:58:45.292Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7VhsbV | q-76eb1ac43b | ok |

### F17 · malicious / high · T1110.002 · LSASS memory accessed with PROCESS_ALL_ACCESS by PowerShell on scranton, followed by obfuscated shellcode loader and encrypted archive staging

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:05:16.654Z, C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe (PID 2976, thread 992) opened C:\windows\system32\lsass.exe (PID 736) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) — the classic handle used to read LSASS memory for credential extraction; a second handle with 0x1f3fff was opened 31 ms earlier. Of 326 LSASS handle events, only these PowerShell ones and system processes (wininit/csrss) requested full access; the rest were svchost 0x1000 and AV/telemetry 0x1400. At 23:21:29 local the same host logged PowerShell 4104 script block bc19aae2-d1f9-49b2-b718-192531ae928f under user pbeesly containing an obfuscated reflective loader (GetModuleHandle/GetProcAddress via Microsoft.Win32.UnsafeNativeMethods, ReflectedDelegate dynamic assembly, base64 byte array) — in-memory shellcode execution consistent with a credential-dumping payload. Staging followed: PowerShell created C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z at 03:08:35 on scranton, and on nashua.dmevals.local Rar.exe created a password-protected archive ("a -hpfGzq5yKw ... working.zip") at 03:16:19, after which sdelete64.exe was run against Rar.exe at 03:16:52 to remove tooling. This is credential access/collection, not offline password cracking — no cracking tooling, wordlists or potfiles were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-872025836f | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-872025836f | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-872025836f | ok |
| 4 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockId | bc19aae2-d1f9-49b2-b718-192531ae928f | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWJWyf | q-92cb41666f | ok |
| 5 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2lq7zj | q-1730068d6f | ok |
| 6 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2Ze6tB | q-8d3378c8a1 | ok |
| 7 | 2020-05-02 03:16:52.456Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2WaNu5 | q-8d3378c8a1 | ok |

### F21 · malicious / high · T1187 · Forced authentication via WebDAV/UNC coercion from scranton.dmevals.local to 192.168.0.4

Evidence status: **verified**

On 2020-04-30 (Zeek window) host 10.0.1.4 (scranton) attempted SMB to 192.168.0.4 on TCP 445 and 139 and was rejected (conn_state REJ, 0 bytes) repeatedly between 00:32:14 and 00:32:18, then fell back to HTTP port 80 and issued WebDAV requests with User-Agent 'Microsoft-WebDAV-MiniRedir/10.0.18362' (OPTIONS /, OPTIONS /webdav, PROPFIND /webdav, PROPFIND /webdav/OfficeSupplies.7z, PROPFIND /webdav/python.exe) at 00:32:18-00:32:21 and again at 00:35:25. The server answered 401 Unauthorized, i.e. the client was being induced to authenticate to an attacker-controlled listener — the classic forced-authentication pattern (SMB blocked, WebDAV fallback). The same destination 192.168.0.4 is contacted in the Windows window: on scranton.dmevals.local, powershell.exe running as DMEVALS\pbeesly connected outbound to 192.168.0.4:80 at 2020-05-02T03:08:47.769Z, followed by svchost.exe (LOCAL SERVICE) connections to 192.168.0.4:80 at 03:08:50.904Z, 03:08:50.988Z and 03:10:23.020-03:10:23.187Z — the WebDAV client stack (svchost/WebClient) authenticating to the remote host. This activity occurs on a host where pbeesly also ran a hidden PowerShell IEX stager, csc.exe compilation, sdclt.exe and sdelete64.exe anti-forensics, so the coercion is part of an active intrusion rather than benign file-share use. Note the Zeek and Windows windows do not overlap, so the two are correlated by host/address, not by time.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | zeek.user_agent | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5I | q-5a264789a7 | ok |
| 2 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | zeek.uri | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5I | q-5a264789a7 | ok |
| 3 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 401 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5I | q-5a264789a7 | ok |
| 4 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | zeek.conn_state | REJ | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA0a | q-a687cf7d59 | ok |
| 5 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | destination.port | 445 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA0a | q-a687cf7d59 | ok |
| 6 | 2020-04-30 00:32:15.992Z | simplerockbuild.simplerock.lan | zeek | destination.port | 139 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA7g | q-a687cf7d59 | ok |
| 7 | 2020-04-30 00:35:25.615Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/python.exe | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA0j | q-a7d6f5c891 | ok |
| 8 | 2020-05-02 03:08:47.769Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2lq7yE | q-a79240a76a | ok |
| 9 | 2020-05-02 03:08:47.769Z | scranton.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2lq7yE | q-a79240a76a | ok |
| 10 | 2020-05-02 03:08:50.904Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kqttk | q-3077e5d41c | ok |
| 11 | 2020-05-02 03:08:50.904Z | scranton.dmevals.local | windows.sysmon | destination.port | 80 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kqttk | q-3077e5d41c | ok |

### F23 · malicious / high · T1212 · PowerShell and PowerShell-remoting host opened LSASS with full-access masks on scranton and nashua during a hands-on-keyboard intrusion

Evidence status: **verified**

On 2020-05-02 between 03:05 and 03:10 UTC, user pbeesly's activity on scranton.dmevals.local escalated from discovery/persistence/screen-capture/exfil script blocks (Invoke-Discovery 03:04:03, Invoke-Persistence 03:04:15 and 03:04:23, Invoke-ScreenCapture 03:05:53, Invoke-Exfil 03:08:02, Invoke-BeachCleanup 03:08:51) to credential access. At 03:05:16 PowerShell.exe (PID 2976) opened C:\windows\system32\lsass.exe (PID 736) with GrantedAccess 0x1f3fff and then 0x1fffff, with a CallTrace ending in an UNKNOWN module (ntdll.dll+9c584\|KERNELBASE.dll+2732e\|UNKNOWN(...)) - the pattern of an in-memory credential-dumping tool rather than a signed Windows component. At 03:09:23 scranton ran 'Invoke-Command -ComputerName NASHUA' and at 03:10:22 'Invoke-SeaDukeStage -ComputerName NASHUA'; wsmprovhost.exe (PID 7720) spawned on nashua.dmevals.local at 03:09:23 and at 03:09:29 opened nashua's lsass.exe (PID 728) with GrantedAccess 0x1f3fff, its CallTrace running through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll - the LSASS handle was taken from inside a PowerShell remoting session, not by an OS component. These are the only LSASS accesses in the dataset with these masks from PowerShell/wsmprovhost; all other LSASS access (svchost.exe 0x1000, Azure telemetry/antimalware 0x1000/0x1400, wininit/csrss at boot 03:19:09) is normal system behaviour. The Kerberos 4768/4769 events (14/28, all Status 0x0, RC4-HMAC 0x12, only on newyork) show no roasting/exploitation pattern and are benign background authentication; the zeek notices/weirds are from a non-overlapping 2020-04-30 window and show no exploit signature.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-3e88524b13 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-3e88524b13 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-3e88524b13 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-b426b40c32 | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-c41d49d1ea | ok |
| 6 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-c41d49d1ea | ok |
| 7 | 2020-05-02 03:09:23.885Z | nashua.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\wsmprovhost.exe -Embedding | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kqds5 | q-3438a67bd7 | ok |
| 8 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAOAxHj | q-bf32b1a1aa | ok |
| 9 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAOBExi | q-60c98a6127 | ok |
| 10 | 2020-05-02 03:04:03.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Discovery | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQDFmw | q-bf32b1a1aa | ok |
| 11 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-bf32b1a1aa | ok |
| 12 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7ViMbT | q-3438a67bd7 | ok |

### F25 · malicious / medium · T1539 · Hidden PowerShell stager on scranton.dmevals.local opened Microsoft Edge processes with PROCESS_ALL_ACCESS (0x1fffff) — consistent with in-memory browser session-cookie theft

Evidence status: **verified**

On scranton.dmevals.local, user DMEVALS\pbeesly ran a hidden, execution-policy-bypassing PowerShell stager ("PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');...IEX([System.Text.Encoding]::ASCII.GetString($o[0..3932]))") that decoded and executed a payload from a bitmap file. Child PowerShell processes spawned by this stager (e.g. PID 3852 at 03:05:24, PID 3876 at 03:00:13) then opened MicrosoftEdge.exe, MicrosoftEdgeCP.exe and MicrosoftEdgeSH.exe with GrantedAccess 0x1fffff (PROCESS_ALL_ACCESS) at 03:05:17 and 03:05:17.094 — full read/write access to browser processes, the standard prerequisite for dumping session cookies/tokens from browser memory. Earlier, lower-privilege accesses (0x1000/0x2000/0x3000) to the same Edge processes came from Explorer.exe and svchost.exe, which is normal; the 0x1fffff access from PowerShell is the anomalous one. The same host later shows additional hidden/encoded PowerShell ("-nop -w hidden -e ..." at 03:21:28) launched from a registry-stored payload (Get-ItemPropertyValue 'HKLM:\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression via hostui.exe), indicating an established intrusion. No browser cookie database file (Cookies/Login Data) was created or modified in the window, so the theft appears to be memory-based rather than file-based; the actual cookie exfiltration content is not directly visible in the telemetry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:17.076Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlS | q-7a0e1cd84a | ok |
| 2 | 2020-05-02 03:05:17.076Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlS | q-7a0e1cd84a | ok |
| 3 | 2020-05-02 03:05:17.076Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlS | q-1e8ed83705 | ok |
| 4 | 2020-05-02 03:05:17.094Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\MicrosoftEdgeSH.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlZ | q-7a0e1cd84a | ok |
| 5 | 2020-05-02 03:05:17.094Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\Windows\System32\MicrosoftEdgeCP.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAla | q-7a0e1cd84a | ok |
| 6 | 2020-05-02 03:05:24.771Z | scranton.dmevals.local | windows.sysmon | win.ParentCommandLine | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63Bwm6 | q-14367e391f | ok |
| 7 | 2020-05-02 03:21:28.949Z | scranton.dmevals.local | windows.sysmon | win.ParentCommandLine | powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL17AQxS | q-42732fb4a3 | ok |

### F29 · malicious / high · T1552 · Unsecured credentials staged and exfiltrated via Invoke-Exfil on scranton

Evidence status: **verified**

On scranton.dmevals.local at 03:08:02 UTC, pbeesly executed script block b2b03a9c-43f0-4285-837d-f22d4600b2ae (Path C:\Program Files\SysinternalsSuite\psversion.ps1) defining Invoke-Exfil: it installs 7Zip4Powershell, compresses the entire Downloads directory (which held the exported .pfx) into $env:APPDATA\OfficeSupplies.7z with password 'lolol', then maps \\192.168.0.4\webdav using hardcoded credentials cozy/MyCozyPassw0rd! and copies the archive out. Sysmon confirms OfficeSupplies.7z created at 03:08:35.270Z and deleted at 03:08:51.520Z. The surrounding tooling (SysinternalsSuite download, accesschk, sdelete64 wiping of Draft.Zip/SysinternalsSuite.zip) is attacker tradecraft, not normal administration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-cbc95ea8bc | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-fb402e0c2e | ok |
| 3 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2lq7zj | q-c7d13bfb44 | ok |
| 4 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL69HSbI | q-42e2e82e37 | ok |

### F62 · malicious / high · T1552 · Plaintext credentials used in PsExec and WebDAV exfil

Evidence status: **verified**

pbeesly passed cleartext password Fl0nk3rt0n!T0by to PsExec against NASHUA and hardcoded WebDAV creds for exfil.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ioON3 | q-09135d5471 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-75ad245c21 | ok |

### F28 · malicious / high · T1552.001 · Credential-hunting file collection and plaintext password use by pbeesly

Evidence status: **verified**

On nashua.dmevals.local at 03:15:59 UTC, pbeesly ran a PowerShell script block that recursively enumerates the user profile for credential-bearing file patterns (*psw*, *pass*, *login*, *admin*, *sifr*, *sifer*, *vpn, *.txt, *.pst, *.ost, *.zip, *.rar ...) and compresses the results into $env:APPDATA\working.zip; Sysmon shows working.zip created at 03:16:00.353Z, re-archived with Rar.exe -hpfGzq5yKw to Desktop\working.zip at 03:16:19.462Z, then shredded with sdelete64. On scranton, pbeesly also ran accesschk.exe (03:04:34.951Z) which created C:\Program Files\SysinternalsSuite\passwordsDB (03:04:35.069Z), and used a plaintext credential in PsExec64.exe -u dmevals\pbeesly -p Fl0nk3rt0n!T0by against \\NASHUA four times (03:11:18-03:14:42Z), showing harvested credentials in use.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMANA6l9 | q-d5a4aa23bf | ok |
| 2 | 2020-05-02 03:16:00.353Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ae3Po | q-c7d13bfb44 | ok |
| 3 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63C9mM | q-675b0f374d | ok |
| 4 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ioON3 | q-42e2e82e37 | ok |
| 5 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAOBvlP | q-cbc95ea8bc | ok |

### F60 · malicious / high · T1552.001 · Credential-hunting archive on nashua

Evidence status: **verified**

On nashua pbeesly compressed password/login/vpn files into working.zip, Rar'd it with a password and sdelete'd the archives.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMANA6l9 | q-253d13258d | ok |
| 2 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2Ze6tB | q-09135d5471 | ok |
| 3 | 2020-05-02 03:16:52.456Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2WaNu5 | q-09135d5471 | ok |

### F27 · malicious / high · T1552.004 · Get-PrivateKeys PowerShell function exported machine certificates to .pfx on scranton

Evidence status: **verified**

On 2020-05-02 at 03:04:56 UTC, user pbeesly on scranton.dmevals.local executed a script block (ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b, Path C:\Program Files\SysinternalsSuite\readme.ps1) defining function Get-PrivateKeys. It enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint, writing to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded password 'saribas'. Sysmon confirms the export: powershell.exe created C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx at 03:04:57.460Z, and that file was deleted (Sysmon 23) at 03:08:51.489Z after being bundled into the exfil archive. This is deliberate private-key/certificate theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-cbc95ea8bc | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-9137f194a6 | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CdmD | q-c7d13bfb44 | ok |
| 4 | 2020-05-02 03:08:51.489Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kqttt | q-c7d13bfb44 | ok |

### F61 · malicious / high · T1552.004 · Get-PrivateKeys exported LocalMachine certs to .pfx on scranton

Evidence status: **verified**

pbeesly ran Get-PrivateKeys exporting every LocalMachine certificate with private key to .pfx in Downloads.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-cc1c01ca18 | ok |
| 2 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CdmD | q-a8ee5dc064 | ok |

### F59 · malicious / high · T1555.004 · wsmprovhost opened LSASS 0x1f3fff on nashua after process-owner enumeration

Evidence status: **verified**

On nashua at 03:09:29 the WinRM host opened lsass with 0x1f3fff one second after pbeesly enumerated process owners.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-b1afd86234 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-b1afd86234 | ok |
| 3 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAMA2AH | q-253d13258d | ok |

### F36 · malicious / medium · T1556 · PowerShell and WinRM-host processes opened LSASS with full-access rights on scranton and nashua

Evidence status: **verified**

On 2020-05-02, 326 Sysmon event-10 records show processes accessing lsass.exe. Stacking by GrantedAccess/SourceImage shows the bulk is benign (svchost.exe 286x at 0x1000, Azure antimalware/telemetry at 0x1400). The rare outliers are attacker-relevant: on scranton.dmevals.local PowerShell.exe (PID 2976) opened lsass.exe (PID 736) with 0x1F3FFF at 03:05:16.623Z and with 0x1FFFFF at 03:05:16.654Z, and on nashua.dmevals.local wsmprovhost.exe (PID 7720, a WinRM remote-PowerShell host) opened lsass.exe (PID 728) with 0x1F3FFF at 03:09:29.430Z. The wsmprovhost call trace runs through Microsoft.PowerShell.Commands.Management.ni.dll, i.e. a PowerShell cmdlet performed the access. These are full-access LSASS handles from scripting hosts, consistent with credential theft tooling rather than normal system behaviour. No evidence of an actual authentication-process modification (no LSASS image-load of a non-Microsoft DLL, no registry write to LSASS/SAM/msv1_0, no service/DLL registration) was found, so the T1556 family itself is not confirmed as modified authentication.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-b8879aae2d | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-b8879aae2d | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-cf893fb969 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-1a470a36d7 | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-1a470a36d7 | ok |
| 6 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | host.name | nashua.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-1a470a36d7 | ok |

### F37 · malicious / high · T1556.007 · Get-PrivateKeys PowerShell function exported all LocalMachine certificates with private keys to .pfx files on scranton

Evidence status: **verified**

At 2020-05-02T03:04:56Z on scranton.dmevals.local, user pbeesly (SID S-1-5-21-1830255721-3727074217-2423397540-1107) executed a script block (ID 9d153741-75c3-4062-afe3-aeca0aee611b) from path C:\Program Files\SysinternalsSuite\readme.ps1 defining Get-PrivateKeys: it enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint, writing password-protected .pfx files into $env:USERPROFILE\Downloads with the hardcoded password "saribas". This is certificate/private-key harvesting that enables forging authentication assertions (hybrid-identity / token-signing abuse). It is followed at 03:08:02Z by an Invoke-Exfil function (script block b2b03a9c-43f0-4285-837d-f22d4600b2ae) that installs 7Zip4Powershell and compresses the Downloads directory into $env:APPDATA\OfficeSupplies.7z with password "lolol", staging the stolen keys for exfiltration. The same PowerShell process (PID 3876) then opened lsass.exe with 0x1000 at 03:01:03Z and loaded samcli.dll/samlib.dll at 03:04:04Z. This is attacker credential access, not normal administration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-73058bfcf7 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-73058bfcf7 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-73058bfcf7 | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | host.name | scranton.dmevals.local | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-73058bfcf7 | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-2a2ff21479 | ok |
| 6 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-2a2ff21479 | ok |

### F47 · malicious / medium · T1558 · Credential-access tooling on scranton: obfuscated PowerShell shellcode loader and LSASS handle with full-access mask

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran an obfuscated PowerShell scriptblock (4104, 2020-05-01T23:21:29-04:00, ScriptBlockId bc19aae2-d1f9-49b2-b718-192531ae928f) that resolves GetProcAddress/GetModuleHandle via Microsoft.Win32.UnsafeNativeMethods, builds a 'ReflectedDelegate' dynamic assembly and decodes a base64 blob starting '/EiD5PDozAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIs' — a classic in-memory shellcode loader. Earlier the same host's PowerShell.exe (PID 2976) opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff (2020-05-02T03:05:16Z), and wsmprovhost.exe on nashua.dmevals.local opened lsass.exe with 0x1f3fff at 03:09:29Z. These are the only non-system processes in the whole LSASS-access population (326 events, dominated by svchost.exe 289) using full-access masks, i.e. credential/ticket material access. No Kerberos ticket-forging artefacts (no RC4 0x17 tickets, no krbtgt anomalies beyond normal machine-account TGT requests) were observed, so the ticket-theft family is supported by the credential-access precursor rather than by forged-ticket evidence.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWJWyf | q-727eab3277 | ok |
| 2 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockId | bc19aae2-d1f9-49b2-b718-192531ae928f | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWJWyf | q-727eab3277 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-a571fdbe5d | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-4a524dea9c | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-e27c00415f | ok |
| 6 | 2020-05-02 03:17:59.493Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\PsExec64.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2TW2Y3 | q-93bfbb1400 | ok |

### F52 · malicious / high · T1606 · Credential/certificate theft tooling staged on SCRANTON by pbeesly (Get-PrivateKeys, LSASS access, exfil staging) — no web-credential forging observed

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell intrusion toolkit from C:\Program Files\SysinternalsSuite\readme.ps1 between 03:00 and 03:11 UTC on 2020-05-02. It defined Get-PrivateKeys (enumerates cert:\LocalMachine and exports every certificate with a private key to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded password "saribas"), Invoke-Exfil (installs 7Zip4Powershell and compresses the Downloads directory into $env:APPDATA\OfficeSupplies.7z with password "lolol"), and Invoke-BeachCleanup (deletes *.pfx, *.bmp, *.png and OfficeSupplies.7z). At 03:05:16 the same PowerShell.exe (PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1F3FFF and 0x1FFFFF, i.e. full-process access consistent with credential dumping. At 03:11:18 pbeesly ran PsExec64.exe against \\NASHUA with the cleartext password "Fl0nk3rt0n!T0by" to launch C:\Windows\Temp\python.exe, and Invoke-SeaDukeStage -ComputerName NASHUA was invoked at 03:10:22. This is real credential-access activity (certificate/private-key theft and LSASS access) that could feed forged web credentials, but no artifact in the retrieved data shows a forged cookie or SAML assertion being minted or used.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-bf6d8c64c0 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-bf6d8c64c0 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-faf35b21d6 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-2286fc14a8 | ok |
| 5 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-bf6d8c64c0 | ok |

### F56 · malicious / high · T1649 · PowerShell Get-PrivateKeys exported all LocalMachine certificate private keys to .pfx files on SCRANTON, followed by anti-forensic cleanup

Evidence status: **verified**

On scranton.dmevals.local, in the context of user pbeesly (SID S-1-5-21-1830255721-3727074217-2423397540-1107), a PowerShell script block named 'Get-PrivateKeys' was logged at 2020-05-02T03:04:56Z (script block 9d153741-75c3-4062-afe3-aeca0aee611b, Path C:\Program Files\SysinternalsSuite\readme.ps1). It enumerates the entire cert:\LocalMachine store recursively and calls Export-PfxCertificate for every certificate with a thumbprint, writing each to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded password 'saribas'. One second later (03:04:57Z) Sysmon file-create event recorded C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx written by powershell.exe, confirming the export actually produced a private-key container on disk. At 03:08:51Z a second function 'Invoke-BeachCleanup' (script block 31f21f1d-9199-4d21-9ea8-c29b97841202, Path C:\Program Files\SysinternalsSuite\psversion.ps1) deleted $env:USERPROFILE\Downloads\*.pfx, *.bmp, *.png and $env:APPDATA\OfficeSupplies.7z — i.e. the stolen certificate containers plus the staging artifacts. The same session shows prior collection/staging activity (Compress-Archive of documents/password-named files, a System.Drawing bitmap-decoded IEX payload from monkey.png, and HKCU Folder\shell\open\command DelegateExecute hijack setup that was later removed), so the certificate theft is part of a broader hands-on-keyboard intrusion. This is theft of authentication certificates/private keys (T1649) enabling on-host or domain authentication with the victim's certificates. The only other certificate-related registry hit (4657 on NASHUA for SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656, process C:\Windows\Sysmon.exe, SYSTEM) is a routine root-store blob update, and the 4768 TGT requests for pbeesly/SCRANTON$ are normal Kerberos logons; neither is attacker activity.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-fffca9832c | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-5da82c978f | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-5da82c978f | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-5da82c978f | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CdmD | q-c950a8ea92 | ok |
| 6 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMANA6lp | q-6c06c69c84 | ok |
| 7 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMANA6lp | q-6c06c69c84 | ok |
| 8 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9FgwRA | q-e05112b5b8 | ok |

### F09 · suspicious / medium · T1040 · Attacker python.exe on nashua is a C2/exfil client, not a sniffer

Evidence status: **verified**

On nashua.dmevals.local the attacker (user pbeesly) dropped C:\Windows\Temp\python.exe at 2020-05-02T03:10:23Z and launched it via PsExec64 from scranton.dmevals.local with plaintext credentials (\\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe), spawning it under C:\Windows\PSEXESVC.exe. The binary unpacks a PyInstaller bundle (_MEI29522\python27.dll) and then makes hundreds of outbound TCP connections to 192.168.0.4:8443. This is interactive C2/exfiltration traffic, not passive capture: no capture driver, no promiscuous-mode or pcap artifacts were found for it, so T1040 itself is not evidenced, but the host is clearly compromised.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.626Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2jo9KZ | q-0070ad3239 | ok |
| 2 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2in-NH | q-4f83e4bbb8 | ok |
| 3 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Uyl9o | q-6f8396ca62 | ok |
| 4 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.port | 8443 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2bgjeM | q-ef4bcf112c | ok |
| 5 | 2020-05-02 03:15:04.213Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Temp\_MEI29522\python27.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2bgjf4 | q-a0de23ff05 | ok |

### F66 · suspicious / low · T1552 · hostui.exe launched by PowerShell on scranton

Evidence status: **verified**

hostui.exe was started by PowerShell on scranton, an unusual parent for this binary.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\System32\hostui.exe"  | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx6_ejg | q-09135d5471 | ok |

### F67 · suspicious / low · T1552 · sdclt.exe spawned by cmd on scranton

Evidence status: **verified**

sdclt.exe, a UAC-bypass-capable binary, was spawned three times by cmd under pbeesly on scranton.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\sdclt.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7Wi8c6 | q-09135d5471 | ok |

### F32 · suspicious / medium · T1555 · Hands-on-keyboard intrusion by pbeesly on scranton/nashua: LSASS handle with full-access mask from PowerShell, but no password-store extraction observed

Evidence status: **verified**

On 2020-05-02 between 02:56 and 03:22 UTC the account pbeesly ran an interactive PowerShell intrusion on scranton.dmevals.local (discovery, Invoke-Persistence, accesschk, Get-PrivateKeys exporting certs to .pfx, screen capture, Get-Keystrokes, Get-Clipboard, Invoke-Exfil to \\192.168.0.4\webdav) and on nashua.dmevals.local (WinRM wsmprovhost session, archive of *pass*/*login*/*vpn* files, Rar.exe with password). Two LSASS process-access events stand out from the 326 LSASS handles: PowerShell.exe (PID 2976) opened lsass with GrantedAccess 0x1f3fff and 0x1fffff at 03:05:16 on scranton, and wsmprovhost.exe (PID 7720) opened lsass with 0x1f3fff at 03:09:29 on nashua. However, no credential-store artefact was found: no sekurlsa/lsadump/mimikatz/vaultcmd/cmdkey strings in process command lines or script blocks, no reads of browser Login Data/logins.json, no Credential Manager or DPAPI vault file/registry access, and the only 'credential' PowerShell hits were benign module resource strings. The high-mask LSASS handles are therefore suspicious but not confirmed password-store theft; the surrounding activity is clearly malicious credential-adjacent collection (keystrokes, clipboard, private keys).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-a24264f47b | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-a24264f47b | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-87af68287e | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-87af68287e | ok |
| 5 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-6220a66c02 | ok |
| 6 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMANA6l9 | q-0c84a13afb | ok |
| 7 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-77d401be8f | ok |

### F34 · suspicious / medium · T1555.004 · LSASS handle stacking: rare full-access masks from PowerShell/wsmprovhost, but no Credential Manager or DPAPI vault access

Evidence status: **verified**

Stacking the 326 Sysmon event-10 handles on lsass.exe shows 293 with 0x1000 and 24 with 0x1400 (routine svchost/Azure telemetry/antimalware), plus rare outliers: 0x1fffff (3), 0x1f3fff (2), 0x101001 (2), 0x1000000 (1), 0x3000 (1). The 0x1f3fff/0x1fffff handles come from PowerShell.exe on scranton (03:05:16) and wsmprovhost.exe on nashua (03:09:29) under pbeesly; the 0x101001 handles come from svchost.exe with an lsm.dll call trace (normal LSA plumbing) and 0x1fffff also from wininit/csrss at boot. Security 4663/4656 auditing shows the same pbeesly PowerShell/wsmprovhost access to lsass.exe with AccessMask 0x1f3fff/0x1fffff. No cmdkey/vaultcmd usage, no Credential Manager vault file or registry access, and no DPAPI Protect-blob access by a non-system process was found; the only 'vault'/'credential' registry hits were services.exe MuiCache and CredentialEnrollmentManagerUserSvc service registration, and Credential Guard was reported disabled (0x0) on scranton. Suspicious LSASS access, but Credential Manager theft is not evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-ca31c1fe55 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-ca31c1fe55 | ok |
| 3 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Qtr32 | q-8a6eca4231 | ok |
| 4 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9VzibT | q-8a6eca4231 | ok |
| 5 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3yMh | q-c66dfc871a | ok |
| 6 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x101001 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2QULdY | q-ca31c1fe55 | ok |

### F02 · benign / medium · T1003.002 · SAM hive registry access on scranton by lsass only; no attacker SAM dump observed

Evidence status: **verified**

The only SAM-related registry activity in the window is lsass.exe itself touching HKLM\SAM\SAM\RXACT and HKLM\SAM\SAM\Domains\Account\F on scranton.dmevals.local at 03:19:10 UTC, and the only SAM_SERVER/SAM_DOMAIN/SAM_ALIAS handle requests are made by lsass.exe under the machine account SCRANTON$ (e.g. SAM_SERVER 'SAM' AccessMask 0xf003f). No non-lsass process requested SAM objects, no 'reg save' / hive-copy command lines were found, and the only file-create hits matching SAM/SECURITY were Prefetch .pf files. This is normal local SAM maintenance, not credential dumping.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SAM\SAM\Domains\Account\F | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtI | q-f87831d423 | ok |
| 2 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SAM\SAM\RXACT | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrs6 | q-f87831d423 | ok |
| 3 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectType | SAM_SERVER | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL81V4Qj | q-546fc3b995 | ok |
| 4 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL81V4Qj | q-546fc3b995 | ok |
| 5 | 2020-05-02 03:21:28.476Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\Prefetch\SECURITYHEALTHSYSTRAY.EXE-41AD6DE1.pf | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL17AAad | q-6ce3d48c12 | ok |

### F04 · benign / medium · T1003.003 · No NTDS / volume-shadow credential dumping observed

Evidence status: **verified**

No hits were returned for NTDS file creation, ntdsutil/vssadmin/diskshadow command lines, or shadow-copy related messages in sysmon, security, powershell or windows.other. The only vssvc.exe activity seen was as a process-access target, not a shadow-copy creation by attacker tooling. Nothing in the retrieved data supports domain-database theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtq | q-50d32ab84d | ok |

### F05 · benign / medium · T1003.004 · No LSA Secrets / lsadump activity observed

Evidence status: **verified**

Searches for 'secrets', 'lsadump', 'reg save HKLM\SECURITY' in process command lines, for SECURITY\Policy\Secrets object access, and for LSA/Secrets strings in PowerShell script blocks and windows.other messages returned no hits. The SECURITY hive touches that were found are lsass writing HKLM\SECURITY\RXACT and HKLM\SECURITY\Cache, which is normal LSA behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.928Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SECURITY\RXACT | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrt8 | q-f87831d423 | ok |

### F03 · benign / medium · T1003.005 · HKLM\SECURITY\Cache (NL$) writes by lsass on nashua/scranton — normal cached-credential updates

Evidence status: **verified**

Sysmon registry-set events on HKLM\SECURITY\Cache\NL$1 were recorded on nashua.dmevals.local at 03:11:40, 03:12:46, 03:13:49 and 03:15:03 UTC and on scranton.dmevals.local at 03:20:46 UTC, all with Image C:\windows\system32\lsass.exe and Details 'Binary Data'. These are the LSA writing cached domain credential entries itself; no other process read or exported the SECURITY\Cache key, and no PowerShell script block referenced cache/DCC2/mscache. Note the timing coincides with the attacker's PsExec/python activity on nashua, but the writes are performed by lsass, not by the attacker tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2in-Mz | q-f87831d423 | ok |
| 2 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2in-Mz | q-f87831d423 | ok |
| 3 | 2020-05-02 03:20:46.691Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx4yjcI | q-f87831d423 | ok |
| 4 | 2020-05-02 03:19:09.994Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SECURITY\Cache | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrte | q-f87831d423 | ok |

### F06 · benign / medium · T1003.006 · No DCSync / DRSUAPI replication abuse observed

Evidence status: **verified**

No process command lines or PowerShell script blocks referencing drsuapi, dcsync or lsadump were found in sysmon or powershell. The attacker's lateral movement used PsExec64.exe with explicit credentials (\\NASHUA -u dmevals\pbeesly -p ...) and a PyInstaller-packed python.exe, not directory replication. No evidence of DCSync in the retrieved data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ioON3 | q-4696e5ed2d | ok |

### F08 · benign / high · T1040 · No network sniffing observed; Azure Network Watcher agent install is benign platform activity

Evidence status: **verified**

The only capture-capable component seen is Microsoft's Azure Network Watcher agent on scranton.dmevals.local. It was started as a service by services.exe at 2020-05-02T03:19:13Z and then Test/Install/Start'd at 03:20:41-03:20:42Z by cmd.exe running the Azure guest-agent extension script C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\enable.cmd, whose parent is C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe (SYSTEM). This is the standard Azure VM extension provisioning path, signed by 'Microsoft CoreXT', and no Npcap/WinPcap driver load (sysmon event 6) or pcap service install (7045) was found. No tcpdump/windump/wireshark/rawcap execution and no pcap/sniff/promiscuous command lines or script blocks were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:13.877Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe" /service | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2MP8lJ | q-4f83e4bbb8 | ok |
| 2 | 2020-05-02 03:20:41.467Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx3viRd | q-94cb7557e3 | ok |
| 3 | 2020-05-02 03:20:41.941Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe"  Install /service /autoSt… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx3w9Hq | q-4f83e4bbb8 | ok |
| 4 | 2020-05-02 03:19:13.877Z | scranton.dmevals.local | windows.sysmon | win.Company | Microsoft CoreXT | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2MP8lJ | q-4f83e4bbb8 | ok |

### F12 · benign / medium · T1056.001 · No keylogger indicators found

Evidence status: **verified**

No process creation or PowerShell script block referencing keylogging APIs (GetAsyncKeyState, SetWindowsHookEx, keylog) was found; the dedicated checks returned zero hits. The LSASS/winlogon process-access events observed are handle opens by svchost.exe (0x1000), wininit.exe/csrss.exe (0x1fffff at boot 03:19:09Z) and the malicious PowerShell/python described above, not a keyboard-hook implant.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtr | q-ef1a83986f | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\csrss.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrt3 | q-ef1a83986f | ok |

### F13 · benign / medium · T1056.002 · No GUI credential-prompt capture observed

Evidence status: **verified**

No 4688 process creation or PowerShell script block matching Credential/prompt/Read-Host was found (checks C076/C080 returned zero hits). The only 'prompt' script blocks are the normal interactive PowerShell prompt strings in pbeesly's session on scranton and nashua.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:15.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | prompt | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWIhZ8 | q-9ced4397e2 | ok |

### F14 · benign / medium · T1056.003 · No web portal capture observed

Evidence status: **verified**

No file writes to wwwroot/inetpub/login paths, no w3wp/IIS command lines, no 4663 access to web content and no HTTP POST or login/portal URLs in the zeek window were found (checks C084/C086/C087/C089/C091 all zero hits). The only web-related activity is rundll32 davclnt.dll DavSetCookie to http://192.168.0.4/webdav on scranton, which is WebDAV client access, not a credential-capturing portal.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:50.846Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2lq7xd | q-4bede45d2c | ok |

### F15 · benign / high · T1110 · No brute-force authentication activity; credential theft occurred via LSASS access instead

Evidence status: **verified**

Across windows.security (2020-05-02T02:55:25Z..03:28:09Z) there are zero 4625 failed-logon events and zero 4740 lockouts; the only 4776 credential validation is a success (Status 0x0) for pbeesly from workstation 10.0.1.4 on newyork.dmevals.local at 23:20:40 local. 4624 logons are 297 total, dominated by machine-account network logons (NEWYORK$ 123, SCRANTON$ 37, NASHUA$ 25) and SYSTEM service logons, with only pbeesly as an interactive user. The 4648 explicit-credential events (15) are pbeesly re-using its own credentials via PSEXESVC.exe on nashua and svchost/winlogon on scranton, plus DWM/UMFD/SCRANTON$ system logons — lateral movement with already-known credentials, not guessing. No authentication-failure burst exists to support any T1110 sub-technique.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8xSa_z | q-1350aae442 | ok |
| 2 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | event.code | 4776 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8xSa_z | q-1350aae442 | ok |
| 3 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFR | q-021be09033 | ok |

### F16 · benign / high · T1110.001 · No password guessing: zero 4625 failures and no password-bearing command lines

Evidence status: **verified**

No 4625 events exist in windows.security, so there is no sequence of failed authentications against any account. Sysmon process-creation events with 'password' in the command line returned nothing, and PowerShell 4104 script blocks contained no Password/Credential strings. The only authentication-related PowerShell activity is an obfuscated reflective loader (see T1110.002 finding), which is credential theft, not guessing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8xSa_z | q-1350aae442 | ok |
| 2 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Workstation | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8xSa_z | q-1350aae442 | ok |

### F18 · benign / high · T1110.003 · No password spraying: single account, no failures, no user-list tooling

Evidence status: **verified**

Only one user account (pbeesly) appears in 4624/4648/4776 authentication events; there is no spread of one password across many accounts and no 4625 failures or 4740 lockouts that spraying would produce. The 4648 events on nashua.dmevals.local show pbeesly's own credentials being passed to PSEXESVC.exe for remote execution, and the sysmon command-line stack for '*user*' returned only C:\windows\system32\userinit.exe. No spray tooling or user lists were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | user.name | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFR | q-021be09033 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | host.name | nashua.dmevals.local | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFR | q-021be09033 | ok |

### F19 · benign / high · T1110.004 · No credential stuffing: no failed logons and no external credential source

Evidence status: **verified**

There are no 4625 failed logons in windows.security, so no stuffing attempt (which requires many rejected credential pairs) is visible. The only credential-validation record is a successful 4776 for pbeesly from 10.0.1.4, and the 4648 events are internal re-use of pbeesly's credentials. Credential-related messages in windows.other are benign system records (Credential Guard configuration 0x0 on scranton, SAM remote-call security descriptor notice). The stolen-credential activity on these hosts is LSASS memory access, not stuffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8xSa_z | q-1350aae442 | ok |
| 2 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3yMh | q-938b6ef70c | ok |

### F20 · benign / medium · T1111 · No MFA/smart-card interception observed; credential theft on scranton/nashua is plaintext password reuse via PsExec, not MFA bypass

Evidence status: **verified**

The T1111 check hits are explained by benign Windows behaviour plus a non-MFA credential-access chain. (1) The only 'Credential*' registry writes are routine: lsass.exe setting HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled to DWORD (0x00000000) on scranton at 2020-05-02T03:19:09.865Z (Credential Guard not enabled, matching the Wininit event 14 'Credential Guard configuration: 0x0, 0' on the same host at 03:19:09), and services.exe creating the standard CredentialEnrollmentManagerUserSvc_13619b service keys on scranton (03:20:48) and MuiCache entries on nashua (03:21:58). (2) LSASS handle access (Sysmon 10) is dominated by svchost.exe with GrantedAccess 0x1000 (216 on scranton, 30 newyork, 28 nashua, 12 utica) and Azure antimalware/telemetry processes with 0x1400; the rare full-access handles (0x1f3ffff/0x1fffff) come from PowerShell.exe on scranton at 03:05:16 and wsmprovhost.exe on nashua at 03:09:29, i.e. the attacker's own PowerShell/WinRM session, not an MFA token provider. (3) The 4648 explicit-credential logons are pbeesly re-authenticating to NASHUA through PSEXESVC.exe (localhost target, 4 times between 03:11:40 and 03:15:03) plus DWM/UMFD/winlogon/taskhostw system logons on scranton. The driving activity is a plaintext password ('Fl0nk3rt0n!T0by') passed on the PsExec64.exe command line from scranton to \\NASHUA, with C:\Windows\Temp\python.exe launched as a child of PSEXESVC.exe on nashua — credential reuse, not MFA interception. No smart-card, token-provider, or MFA-related script block was found (the 4104 search for Credential/MFA/token/lsass/sekurlsa/smartcard returned only the attacker's image-steganography loader, an Invoke-Exfil function, and benign AD/script resource modules).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtv | q-56970d3b6f | ok |
| 2 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3yMh | q-2014ff1b50 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-b4ba069088 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-b4ba069088 | ok |
| 5 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFR | q-05d93f5075 | ok |
| 6 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAOBvlP | q-e34eb790c4 | ok |
| 7 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2in-NH | q-060e168fd2 | ok |
| 8 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3iOg | q-7cbcc883f3 | ok |

### F22 · benign / medium · T1187 · SMB share access events (5140/5145) are domain-controller SYSVOL replication, not forced authentication

Evidence status: **verified**

The 163 events matching 5140/5145 are machine-account access to the SYSVOL share on newyork.dmevals.local: NEWYORK$ from its own link-local IPv6 address fe80::e40c:95b6:b0a7:6429 and SCRANTON$ from 10.0.1.4, all with Share Name \\*\SYSVOL and Share Path \??\F:\SYSVOL\sysvol. These are normal DFSR/Group Policy replication reads by domain controllers (matching the DFSR config XML and GptTmpl.inf file transfers seen in Zeek), not inbound authentication coerced from a victim. The corresponding Sysmon 3 SMB connections to 10.0.0.4/10.0.1.6 are System process (PID 4) kernel SMB traffic between DCs. No user-account SMB authentication to an external or unusual host was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Tx5o2 | q-21fe451d33 | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | source.ip | fe80::e40c:95b6:b0a7:6429 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Tx5o2 | q-21fe451d33 | ok |
| 3 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9KmX__ | q-21fe451d33 | ok |
| 4 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | source.ip | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9KmX__ | q-21fe451d33 | ok |
| 5 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL69HyZX | q-a66624dcc1 | ok |

### F24 · benign / high · T1212 · Routine LSASS handle opens by svchost, Azure agents and boot-time wininit/csrss are benign

Evidence status: **verified**

The bulk of Sysmon event 10 activity targeting lsass.exe is normal Windows behaviour: svchost.exe with GrantedAccess 0x1000 (216 on scranton, 30 on newyork, 28 on nashua, 12 on utica), WindowsAzureTelemetryService.exe and the Azure IaaSAntimalware AntimalwareConfig.exe with 0x1000/0x1400 on scranton, and wininit.exe/csrss.exe opening lsass with 0x1fffff/0x1000000 at 03:19:09 on scranton during a boot/init sequence (CallTraces resolve entirely into wininit.exe/csrsrv/basesrv). None of these show the UNKNOWN-module call trace or the PowerShell/wsmprovhost source seen in the malicious events. The Kerberos 4768/4769 events (14 and 28, all Status 0x0, encryption type 0x12, only on newyork.dmevals.local, service names krbtgt/NEWYORK$/NASHUA$/SCRANTON$/WEC$) are ordinary domain authentication with no roasting or anomalous ticket options. Zeek notices/weirds (14 events, 2020-04-30) are in a non-overlapping window and carry no exploit indicators.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:23.551Z | utica.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7anEhk | q-a4c328a24e | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9d934\|C:\windows\System32\KERNELBASE.dll+5f42a\|C:\windows\System32\KERNELBASE.dll+5bdc6\|C:\windows\System32\KERNEL32.DLL+1be93\… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtr | q-b426b40c32 | ok |
| 3 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | message | A Kerberos service ticket was requested.    Account Information:  	Account Name:		pbeesly@DMEVALS.LOCAL  	Account Domain:		DMEVALS.LOCAL  	Logon GUID:		{b4946ef… | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9MpvNN | q-9304c4727c | ok |
| 4 | 2020-04-30 00:15:18.392Z | simplerockbuild.simplerock.lan | zeek | message | notice | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw1X | q-24980a552c | ok |

### F26 · benign / high · T1539 · DavSetCookie rundll32 invocations on scranton.dmevals.local are WebDAV client behaviour, not cookie theft

Evidence status: **verified**

Five 4688 events on scranton.dmevals.local show rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav, spawned by svchost.exe under the pbeesly logon. This is the standard Windows WebDAV redirector (davclnt) storing a WebDAV auth cookie for the share http://192.168.0.4/webdav — it writes a cookie, it does not steal one. The matching network view (zeek, non-overlapping window) shows the same WebDAV client user agent Microsoft-WebDAV-MiniRedir/10.0.18362 from 10.0.1.4 to 192.168.0.4:80 retrieving /webdav/python.exe (401 then 200, application/x-dosexec, 5305104 bytes), i.e. a WebDAV file download rather than cookie exfiltration. The only cookie-named file creation in the whole window is svchost.exe writing C:\Windows\ServiceProfiles\LocalService\...\AC\INetCookies, a normal WinINet cache artifact.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:50.000Z | scranton.dmevals.local | windows.security | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9IkK9d | q-dc97acdf64 | ok |
| 2 | 2020-05-02 03:08:50.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\Windows\System32\svchost.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9IkK9d | q-476bd24586 | ok |
| 3 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx56e_Q | q-6c0221da32 | ok |
| 4 | 2020-04-30 00:35:25.658Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA01 | q-e163cd4fc8 | ok |
| 5 | 2020-04-30 00:35:25.658Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/python.exe | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA01 | q-e163cd4fc8 | ok |

### F30 · benign / high · T1552.002 · Registry Password/Credential value sets are OS service activity, not credential theft

Evidence status: **verified**

The 17 Sysmon 13 hits on Password/Credential registry paths are all written by legitimate Windows components: svchost.exe setting HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength/CharacterGroups on nashua and scranton, lsass.exe setting DeviceGuard\Scenarios\CredentialGuard\Enabled, and services.exe creating the CredentialEnrollmentManagerUserSvc_13619b service keys plus winlogon.exe writing PasswordExpiryNotification\NotShownTime. No attacker process read or wrote credential stores in the registry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:28.255Z | nashua.dmevals.local | windows.sysmon | win.TargetObject | HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL21_2XV | q-c832712e24 | ok |
| 2 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtv | q-c832712e24 | ok |
| 3 | 2020-05-02 03:20:48.264Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\System\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc_13619b\Type | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx4z3lf | q-c832712e24 | ok |

### F31 · benign / medium · T1552.006 · No Group Policy Preferences credential access observed

Evidence status: **verified**

Searches for sysvol/groups.xml access in Sysmon process creation, Security object access and windows.other returned no hits. The only GPP-related file activity is the legitimate GroupPolicy DataStore write of GptTmpl.inf and gpt.ini under C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local, which is normal policy refresh, not cpassword harvesting.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63C9mM | q-675b0f374d | ok |

### F33 · benign / high · T1555.003 · No browser credential-store access observed

Evidence status: **verified**

Checks C209-C214 returned zero hits: no process command line referencing Login Data, logins.json or browser profile paths, no file creation of browser credential files, no process-access events against chrome.exe/firefox.exe, no object-access auditing on browser credential files, and no PowerShell or other-channel references. The only browser-related activity retrieved was MicrosoftEdge.exe writing its own AppContainer DataStore/Recovery files on scranton at 03:21:05, which is normal Edge runtime behaviour, not credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.198Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\DataStore\_TempTestAccess.txt | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx559LG | q-b0d090e4a3 | ok |
| 2 | 2020-05-02 03:21:05.198Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx559LG | q-b0d090e4a3 | ok |

### F35 · benign / high · T1555.005 · No password-manager artefacts observed

Evidence status: **verified**

Checks C221-C226 returned zero hits: no KeePass/1Password/Bitwarden/LastPass process executions, no .kdbx or password-manager file creation, no process-access events against password-manager processes, no command lines or script blocks referencing them, and no other-channel messages. The archive command on nashua (Rar.exe with -hpfGzq5yKw) and the *pass*/*login* file globbing are generic file collection, not password-manager store access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2Ze6tB | q-e2e52e38a4 | ok |

### F38 · benign / medium · T1556.001 · Network logons (4624 type 3) and explicit-credential logons (4648) are routine machine-account and PsExec activity

Evidence status: **verified**

218 event-4624 LogonType 3 records are dominated by machine account NEWYORK$ from ::1, fe80::e40c:95b6:b0a7:6429 and 10.0.0.4 — normal local/loopback and DC machine-account authentication. The 15 event-4648 explicit-credential logons are pbeesly authenticating from 10.0.1.6 on scranton and via C:\Windows\PSEXESVC.exe on nashua, plus winlogon.exe DWM-1 logons; these are consistent with PsExec-based administration rather than a DC authentication backdoor. No 5136/4739 directory-service or policy changes were observed, so no evidence of modified domain-controller authentication.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Tx5o4 | q-b8c0437ce0 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFR | q-8e2ff8e6dd | ok |
| 3 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | user.name | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFR | q-8e2ff8e6dd | ok |

### F39 · benign / medium · T1556.002 · No password-filter DLL registration or System32 DLL drops observed

Evidence status: **verified**

Checks for registry writes to Notification Packages / PasswordFilter / lsass keys (4657), process creation referencing Notification/PasswordFilter (4688), PowerShell referencing Notification/PasswordFilter/lsass (4104) and Sysmon file-create of DLLs in System32 all returned zero hits. The only authentication-DLL image loads seen are Microsoft-signed system DLLs (cryptdll.dll, samcli.dll, samlib.dll, msv1_0.dll) loaded by svchost.exe, WmiPrvSE.exe, SearchIndexer.exe, LogonUI.exe, dsregcmd.exe and lsass.exe itself — normal behaviour. No password filter DLL was installed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:42.236Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\samlib.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL6-IgT8 | q-d6521b5847 | ok |
| 2 | 2020-05-02 03:06:14.783Z | newyork.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\dsregcmd.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2x8I9e | q-d6521b5847 | ok |

### F40 · benign / medium · T1556.005 · No reversible-encryption or account-flag modification activity

Evidence status: **verified**

Queries for AllowReversiblePasswordEncryption / ReversibleEncryption in PowerShell script blocks (4104/4103), in Sysmon process command lines (Set-ADUser/dsmod/Reversible), in windows.other messages, and for event 4739 (domain policy change) all returned zero hits. No evidence that reversible password encryption was enabled.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-cf893fb969 | ok |

### F41 · benign / medium · T1556.006 · No MFA configuration or authentication-policy changes observed

Evidence status: **verified**

Event 4739 (domain policy changed) returned zero hits, and no 5136 directory-service changes or Set-ADUser/Set-ADAuthenticationPolicy command lines were found in Sysmon or PowerShell. No evidence of MFA registration or MFA-bypass modification.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-1a470a36d7 | ok |

### F42 · benign / medium · T1556.008 · No Network Provider DLL registration activity

Evidence status: **verified**

Queries for registry writes (4657) to NetworkProvider/Credential keys and for PowerShell script blocks referencing NetworkProvider or New-ItemProperty returned zero hits. No network provider DLL was registered to capture credentials.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-1a470a36d7 | ok |

### F43 · benign / medium · T1557 · No adversary-in-the-middle activity observed; hits reflect a separate credential-access/lateral-movement intrusion

Evidence status: **verified**

The T1557 checks surfaced no AiTM positioning. Sysmon event.code 3 destination hostnames were uniformly '-' (1229/1229), DNS query names (81 events) contained only ordinary AD/DC discovery, Microsoft telemetry and update lookups, and the only 'wpad' lookups were routine wpad.dmevals.local queries answered NXDOMAIN by the domain controller 10.0.0.4 from 10.0.1.4 and 10.0.1.6. The two windows.other hits returned by the object-access/network checks were unrelated System-channel records (a Hyper-V miniport initialization and an RDP shell-start notification for DMEVALS\pbeesly from 172.18.39.2). What the data does show is a real intrusion on scranton.dmevals.local and nashua.dmevals.local by user pbeesly (SeaDuke-style PowerShell staging, PsExec64 with plaintext password to \\NASHUA, javamtsup service persistence, python.exe beaconing to 192.168.0.4:8443), but none of it is AiTM.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:04.000Z | scranton.dmevals.local | windows.other | message | The miniport 'Microsoft Hyper-V Network Adapter' was successfully initialized | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3yNV | q-71acb14b42 | ok |
| 2 | 2020-05-02 03:20:48.000Z | scranton.dmevals.local | windows.other | message | Remote Desktop Services: Shell start notification received:    User: DMEVALS\pbeesly  Session ID: 2  Source Network Address: 172.18.39.2 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3iPp | q-71acb14b42 | ok |
| 3 | 2020-05-02 03:14:42.601Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2chAnX | q-6f841552e6 | ok |

### F44 · benign / medium · T1557.001 · No name-resolution poisoning or SMB relay; SMB traffic is legitimate PsExec admin-share use

Evidence status: **verified**

No LLMNR/NBT-NS poisoning or SMB relay indicators were found. The 23 event.code 4697 service installations were almost all Windows per-user service registrations on scranton.dmevals.local at 03:20:48 (svchost.exe -k UnistackSvcGroup etc.) plus four PSEXESVC installs on nashua.dmevals.local by pbeesly and one javamtsup install on scranton.dmevals.local by pbeesly. The SMB share events (5140/5145) show only normal machine-account IPC$/SYSVOL/samr/lsarpc traffic to the DC newyork.dmevals.local and pbeesly's ADMIN$/IPC$ access from 10.0.1.4 to nashua.dmevals.local, i.e. the PsExec lateral movement, not a relayed authentication. The javamtsup service (C:\Windows\System32\javamtsup.exe, LocalSystem, auto-start) is malicious persistence but is not name-resolution poisoning or SMB relay.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.security | win.ServiceFileName | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Qtr33 | q-c753ba7ae1 | ok |
| 2 | 2020-05-02 03:18:20.000Z | nashua.dmevals.local | windows.security | win.RelativeTargetName | PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8-bXAb | q-123846f168 | ok |
| 3 | 2020-05-02 03:21:57.000Z | newyork.dmevals.local | windows.security | win.RelativeTargetName | samr | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8nPsje | q-123846f168 | ok |

### F45 · benign / medium · T1557.002 · No ARP cache poisoning; MAC/IP mappings are stable and the odd responder MAC is a placeholder

Evidence status: **verified**

Zeek conn records show only three source MACs (00:0d:3a:13:e3:69, 00:0d:3a:4d:42:f2, fc:bd:67:e1:a9:c1) and three responder MACs (12:34:56:78:9a:bc, 00:0d:3a:13:e3:69, ff:ff:ff:ff:ff:ff broadcast). The 12:34:56:78:9a:bc value is a synthetic/placeholder MAC, not a real host claiming multiple IPs, and it appears consistently as the responder for 10.0.1.4/10.0.1.6 traffic to 10.0.0.4 and 10.0.1.6. No duplicate MAC-to-IP mapping or gratuitous-ARP pattern is present, and no PowerShell script block referenced arp or netsh interface manipulation.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:45:00.056Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw3Z | q-d2b57a79fd | ok |
| 2 | 2020-04-30 00:44:45.015Z | simplerockbuild.simplerock.lan | zeek | zeek.orig_l2_addr | 00:0d:3a:4d:42:f2 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA6q | q-d2b57a79fd | ok |

### F46 · benign / medium · T1557.003 · No DHCP spoofing indicators; no DHCP events or DHCP traffic in any dataset

Evidence status: **verified**

The windows.other System channel contains no DHCP-related event codes (1341/1342/1020/1063 absent from the 216-event code stack), no PowerShell script block referenced DHCP, and Sysmon event.code 3 destination ports contain no 67/68 traffic (top ports were 8443, 389, 88, 53, 135, 445). The Zeek capture has no dhcp log type at all (only conn, files, ssl, x509, dce_rpc, http, dns, kerberos, dpd, smb_files, weird, smb_mapping, notice, pe), so DHCP spoofing is not observable and nothing suggests it occurred.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:04.000Z | scranton.dmevals.local | windows.other | event.code | 3 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3yNV | q-71acb14b42 | ok |
| 2 | 2020-04-30 00:35:04.274Z | simplerockbuild.simplerock.lan | zeek | event.action | weird | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA0q | q-f627bcf3a8 | ok |

### F48 · benign / medium · T1558.001 · No golden-ticket evidence: krbtgt service tickets are AES256 (0x12) for machine accounts only

Evidence status: **verified**

All 28 Kerberos service-ticket requests (4769) on newyork.dmevals.local used Ticket Encryption Type 0x12 (AES256) with Ticket Options 0x60810010 and Failure Code 0x0 — no RC4 (0x17) downgrade typical of forged golden tickets. The three krbtgt service tickets were requested by pbeesly@DMEVALS.LOCAL (23:04:04) and SCRANTON$@DMEVALS.LOCAL (23:19:13 and 23:19:15) from 10.0.1.4, consistent with normal machine-account TGT renewal; SCRANTON$ also logged on to newyork with Kerberos logon type 3 from 10.0.1.4. No 4672 special-privilege logon anomalies were found (the 212 events carry no TargetUserName value; sampled events show machine account NEWYORK$ with standard service privileges). No golden-ticket forging observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8-bHCF | q-451df476da | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | SCRANTON$@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8-bHCF | q-451df476da | ok |
| 3 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9TypoZ | q-9ebc90832d | ok |

### F49 · benign / medium · T1558.002 · No silver-ticket evidence: service tickets only for machine accounts, all AES256 and successful

Evidence status: **verified**

The 4769 service-name distribution is NEWYORK$ (11), NASHUA$ (10), SCRANTON$ (3), krbtgt (3), WEC$ (1) — only computer accounts, no user service accounts with SPNs that would be targets of silver-ticket forging or service-ticket abuse. All requests succeeded (Status 0x0) with AES256 encryption and were issued by the KDC on newyork.dmevals.local, i.e. validated tickets, not forged ones. No silver-ticket behaviour observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9MpvNN | q-f8d243fed4 | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9MpvNN | q-f8d243fed4 | ok |

### F50 · benign / medium · T1558.003 · No Kerberoasting: no RC4 service-ticket requests and no roasting tooling in PowerShell logs

Evidence status: **verified**

Kerberoasting requires TGS requests for SPN-bearing accounts returned with RC4 (0x17) encryption. All 28 4769 events show Ticket Encryption Type 0x12 (AES256) only, and the requested services are computer accounts (NEWYORK$, NASHUA$, SCRANTON$, WEC$) plus krbtgt. PowerShell script-block searches for Kerberoast/Invoke-Kerberoast/Rubeus returned zero hits, and the zeek Kerberos records (separate 2020-04-30 window) show only pbeesly AS/TGS requests for krbtgt, cifs/NEWYORK, ldap/NEWYORK, HTTP/NASHUA and cifs/NASHUA with aes256-cts-hmac-sha1-96. No Kerberoasting observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9MpvNN | q-f8d243fed4 | ok |
| 2 | 2020-04-30 00:24:19.122Z | simplerockbuild.simplerock.lan | zeek | zeek.service | cifs/NEWYORK | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw1d | q-b1e78f3931 | ok |
| 3 | 2020-04-30 00:24:19.122Z | simplerockbuild.simplerock.lan | zeek | zeek.cipher | aes256-cts-hmac-sha1-96 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw1d | q-b1e78f3931 | ok |

### F51 · benign / medium · T1558.004 · No AS-REP roasting: AS exchanges show normal pre-authentication

Evidence status: **verified**

In the zeek Kerberos capture (2020-04-30, non-overlapping with the Windows window) the AS exchange from 10.0.1.4 for pbeesly/DMEVALS.LOCAL first returned KDC_ERR_PREAUTH_REQUIRED and then succeeded with aes256-cts-hmac-sha1-96, i.e. pre-authentication is enforced — the opposite of an AS-REP-roastable account. PowerShell searches for AS-REP/GetNPUsers/DontRequirePreAuth returned zero hits. No AS-REP roasting observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:24:19.110Z | simplerockbuild.simplerock.lan | zeek | zeek.error_msg | KDC_ERR_PREAUTH_REQUIRED | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw1f | q-b1e78f3931 | ok |
| 2 | 2020-04-30 00:24:19.119Z | simplerockbuild.simplerock.lan | zeek | zeek.cipher | aes256-cts-hmac-sha1-96 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw1g | q-b1e78f3931 | ok |

### F53 · benign / medium · T1606.001 · No forged web cookies observed; only benign INetCookies file creation and WebDAV DavSetCookie calls

Evidence status: **verified**

The only cookie-related file creation in the window is C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies created by svchost.exe on scranton.dmevals.local at 03:21:05, which is a normal per-package cookie store for a service profile. The only cookie-related process activity is rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav (five executions on scranton at 03:08:50 and 03:10:22-23, parent svchost.exe), which is the standard WebDAV redirector setting a session cookie for a WebDAV share, not a forged authentication cookie. No PowerShell script block in the dataset references cookie, Set-Cookie or session (zero hits), and no browser cookie store was read or modified by the intrusion tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx56e_Q | q-47acbf4712 | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx56e_Q | q-47acbf4712 | ok |

### F54 · benign / medium · T1606.002 · No SAML token forgery observed; certificate export is the closest precursor

Evidence status: **verified**

No SAML assertion, NotOnOrAfter or Assertion strings appear in any PowerShell script block (zero hits), no process command line references saml/token/cert (zero hits), and no HTTP request in the Zeek window targets saml, adfs or token URLs (zero hits). The Zeek window (2020-04-30) does not overlap the Windows window (2020-05-02), so web authentication traffic cannot be correlated with the host activity. The relevant precursor is the Get-PrivateKeys certificate/private-key export on scranton.dmevals.local, which could enable token-signing certificate abuse, but no forging or token use was observed in the retrieved data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-bf6d8c64c0 | ok |

### F55 · benign / high · T1621 · No MFA/2FA request-generation activity observed; hits are benign WMI provider and authentication noise

Evidence status: **verified**

Hunted for T1621 (MFA request generation / MFA fatigue) across windows.other, windows.security, windows.powershell, windows.sysmon and zeek. No MFA/2FA/authenticator/push/OTP-related script blocks, command lines, HTTP URLs or authentication-failure bursts were found. The only windows.other hits for the C355 check (event.code 5857/5858, 85 events) are WMI provider start/DeleteInstance records from wmiprvse.exe on newyork.dmevals.local (e.g. dsccore, CIMWin32, StorageWMI, WMIProv providers, all ResultCode 0x0 / 0x80041002 RSOP cleanup) — routine WMI/RSoP housekeeping, not authentication prompting. The single windows.security authentication-failure-family event is a successful NTLM credential validation (4776, Error Code 0x0) for pbeesly from workstation 10.0.1.4 on newyork.dmevals.local; no 4625 failures exist in the dataset. 4624 logons are ordinary Kerberos/Negotiate machine and user logons (NEWYORK$, SCRANTON$, NASHUA$, pbeesly, SYSTEM). The only sysmon process-creation hit for the C356 check was svchost.exe -k netsvcs -p -s TokenBroker on scranton.dmevals.local, a standard Windows service host. The zeek window (2020-04-30) does not overlap the Windows telemetry and contained no login/auth/mfa HTTP URLs. Separately, the same hosts do show unrelated hands-on-keyboard activity by user pbeesly (PsExec64 to \\NASHUA with a plaintext password, C:\Windows\Temp\python.exe, sdelete64 wiping archives, hidden base64/gzip PowerShell on scranton.dmevals.local), which is credential-access-adjacent but is not T1621 and is out of scope for this technique family.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:28.000Z | newyork.dmevals.local | windows.other | message | dsccore provider started with result code 0x0. HostProcess = wmiprvse.exe; ProcessID = 5344; ProviderPath = %systemroot%\system32\DscCore.dll | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3iO6 | q-4f7aa4e7b4 | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3yMK | q-f6229d71d9 | ok |
| 3 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | message | The computer attempted to validate the credentials for an account.    Authentication Package:	MICROSOFT_AUTHENTICATION_PACKAGE_V1_0  Logon Account:	pbeesly  Sou… | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8xSa_z | q-0b6e7b6a39 | ok |
| 4 | 2020-05-02 03:20:48.898Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\svchost.exe -k netsvcs -p -s TokenBroker | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx40qiu | q-41eda3a354 | ok |
| 5 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.security | process.command_line | "powershell.exe" -nop -w hidden -c &amp;([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System… | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8tQ-__ | q-8b5885ae4e | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Self-restarting Skype app with WerFault crash. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | Packed python dropped via PsExec, spawns conhost/cmd/powershell and opens LSASS. |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Password-protected Rar of credential-hunting archive, then sdelete'd. |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Anti-forensic deletion of Rar.exe and working.zip. |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure guest agent log collection. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher agent. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure antimalware extension. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure custom script extension. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure domain-join extension. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google updater crash handler. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google updater crash handler. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Google updater service. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Attacker-staged Sysinternals tool run from PowerShell for permission recon. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Used with cleartext password to launch python.exe on NASHUA. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Anti-forensic wiping of payload and archives. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Defender service. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Defender network inspection service. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Masqueraded screen-saver payload launched from explorer, later sdelete'd. |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Compiles attacker C# from PowerShell temp dirs into DLLs. |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Rare binary started by PowerShell on scranton. |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | UAC-bypass-capable binary spawned by cmd under pbeesly. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent firewall tool. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent volume helper. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure guest agent service. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | 1 | C:\Windows\System32\services.exe | benign | Azure telemetry service. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\WaAppAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure agent service. |
| scranton.dmevals.local | C:\WindowsAzure\SecAgent\WaSecAgentProv.exe | 2 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure security agent provider. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\Plugins\VFPl… | 1 | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | benign | Azure network agent plugin. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | 1 | C:\Windows\System32\services.exe | benign | Azure network agent service. |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | Credential-access toolchain staged and executed. |
| T1003.001 LSASS Memory | malicious | Full-access LSASS handle from wsmprovhost on nashua. |
| T1003.002 Security Account Manager | benign | Only lsass.exe touched HKLM\SAM and SAM_SERVER/SAM_DOMAIN objects; no non-lsass SAM access, no reg save/hive copy, no SAM dump files. |
| T1003.003 NTDS | not_observed | No NTDS file creation, ntdsutil/vssadmin/diskshadow command lines or shadow-copy messages in any dataset. |
| T1003.004 LSA Secrets | not_observed | No lsadump/secrets command lines, no SECURITY\Policy\Secrets object access, no LSA/Secrets strings in PowerShell or windows.other. |
| T1003.005 Cached Domain Credentials | benign | HKLM\SECURITY\Cache\NL$1 writes were performed by lsass.exe itself (normal cached-credential updates); no other process read or exported the cache. |
| T1003.006 DCSync | not_observed | No drsuapi/dcsync/lsadump references in process command lines or PowerShell script blocks; lateral movement used PsExec with explicit credentials, not directory replication. |
| T1040 Network Sniffing | not_observed | No network sniffing artifacts in any dataset: no tcpdump/windump/wireshark/rawcap execution (sysmon 1 and security 4688 stacks), no pcap/sniff/promiscuous command lines or PowerShell script blocks, no Npcap/WinPcap drive… |
| T1056 Input Capture | malicious | Input capture via keystrokes and clipboard. |
| T1056.001 Keylogging | malicious | Get-Keystrokes job run on scranton. |
| T1056.002 GUI Input Capture | malicious | Get-Clipboard executed by pbeesly. |
| T1056.003 Web Portal Capture | not_observed | No IIS/wwwroot/login file or process activity and no HTTP POST or login/portal URLs; checks C084/C086/C087/C089/C091 returned zero hits. |
| T1056.004 Credential API Hooking | malicious | Credential API access via full-access LSASS handles. |
| T1110 Brute Force | not_observed | Zero 4625 failed logons and zero 4740 lockouts in windows.security; the only 4776 is a success (0x0). No authentication-failure burst exists. |
| T1110.001 Password Guessing | not_observed | No 4625 events, no password-bearing process command lines, no Password/Credential strings in PowerShell 4104 blocks. |
| T1110.002 Password Cracking | suspicious | No cracking tooling, wordlists or potfiles were seen, but LSASS was opened with 0x1FFFFF by PowerShell on scranton at 03:05:16Z and an obfuscated reflective shellcode loader ran at 23:21:29 local — credential extraction … |
| T1110.003 Password Spraying | not_observed | Only one user account (pbeesly) authenticates; no failures, no lockouts, no user-list spray tooling. |
| T1110.004 Credential Stuffing | not_observed | No failed logons and no external credential source; 4648 events are internal re-use of pbeesly's own credentials. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA/smart-card/token-provider interception artifacts. The Credential* registry hits are routine Credential Guard configuration (Enabled=0x00000000 by lsass.exe, Wininit event 14 'Credential Guard configuration: 0x0, 0… |
| T1187 Forced Authentication | malicious | WebDAV/UNC coercion to 192.168.0.4. |
| T1212 Exploitation for Credential Access | malicious | LSASS full-access handles from PowerShell/WinRM hosts. |
| T1539 Steal Web Session Cookie | suspicious | No browser cookie database was read or copied (only a benign svchost INetCookies cache write), but on scranton.dmevals.local a hidden, execution-policy-bypassing PowerShell stager (payload decoded from C:\Users\pbeesly\D… |
| T1552 Unsecured Credentials | malicious | Cleartext passwords used in PsExec and WebDAV exfil. |
| T1552.001 Credentials In Files | malicious | Password/login/vpn file collection archived on nashua. |
| T1552.002 Credentials in Registry | benign | All 17 Password/Credential registry value sets come from svchost.exe, lsass.exe, services.exe and winlogon.exe performing normal OS/service configuration. |
| T1552.003 Shell History | not_observed | No process-creation or object-access events referencing consolehost_history or PowerShell history files. |
| T1552.004 Private Keys | malicious | LocalMachine certs exported to .pfx. |
| T1552.006 Group Policy Preferences | not_observed | No sysvol/groups.xml or cpassword access found; only routine GroupPolicy DataStore writes of GptTmpl.inf/gpt.ini. |
| T1555 Credentials from Password Stores | suspicious | No Credential Manager or vault extraction seen. |
| T1555.003 Credentials from Web Browsers | not_observed | All browser-credential checks (C209-C214) returned zero hits; only normal MicrosoftEdge.exe writes to its own AppContainer DataStore were seen. |
| T1555.004 Windows Credential Manager | malicious | wsmprovhost opened LSASS 0x1f3fff on nashua. |
| T1555.005 Password Managers | not_observed | All password-manager checks (C221-C226) returned zero hits; Rar.exe archiving of *pass*/*login* files is generic collection, not password-manager store access. |
| T1556 Modify Authentication Process | suspicious | Full-access LSASS handles (0x1F3FFF/0x1FFFFF) from PowerShell.exe on scranton and wsmprovhost.exe on nashua indicate credential-theft tooling touching the authentication process, but no actual modification of LSASS/authe… |
| T1556.001 Domain Controller Authentication | not_observed | 4624 type-3 logons are machine-account/loopback traffic and 4648 logons are PsExec/winlogon; no 5136/4739 DC authentication changes. |
| T1556.002 Password Filter DLL | not_observed | No Notification Packages/PasswordFilter registry writes, no password-filter DLL drops, only Microsoft-signed auth DLL loads. |
| T1556.005 Reversible Encryption | not_observed | No AllowReversiblePasswordEncryption/ReversibleEncryption references and no 4739 events. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739/5136 policy changes and no MFA-related cmdlets in PowerShell logs. |
| T1556.007 Hybrid Identity | malicious | Certificate private keys exported for trust abuse. |
| T1556.008 Network Provider DLL | not_observed | No NetworkProvider/Credential registry writes or PowerShell references to network provider DLLs. |
| T1557 Adversary-in-the-Middle | not_observed | No AiTM positioning: Sysmon 3 destination hostnames all '-', DNS queries only routine AD/telemetry lookups, wpad.dmevals.local answered NXDOMAIN by the DC. The intrusion present (PsExec64 with plaintext password to NASHU… |
| T1557.001 Name Resolution Poisoning and SMB Relay | not_observed | No LLMNR/NBT-NS poisoning or SMB relay. 4697 events are Windows per-user service registrations plus PSEXESVC and javamtsup installs; 5140/5145 show only normal machine-account IPC$/SYSVOL/samr/lsarpc and pbeesly's ADMIN$… |
| T1557.002 ARP Cache Poisoning | not_observed | Only three source and three responder MACs in Zeek conn data; the unusual responder 12:34:56:78:9a:bc is a placeholder MAC used consistently, with no duplicate MAC-to-IP mapping or gratuitous ARP pattern. |
| T1557.003 DHCP Spoofing | not_observable | No DHCP event codes in windows.other, no DHCP PowerShell content, no Sysmon connections to ports 67/68, and the Zeek capture contains no dhcp log type, so DHCP spoofing cannot be seen and nothing indicates it. |
| T1558 Steal or Forge Kerberos Tickets | suspicious | Credential-access precursor confirmed on scranton (obfuscated PowerShell shellcode loader by pbeesly) and full-access LSASS handles from PowerShell.exe (0x1f3fff/0x1fffff) and wsmprovhost.exe on nashua (0x1f3fff), but no… |
| T1558.001 Golden Ticket | not_observed | All 28 4769 tickets AES256 (0x12), krbtgt tickets only for pbeesly and SCRANTON$ machine account, no RC4 downgrade or anomalous 4672 logons. |
| T1558.002 Silver Ticket | not_observed | Service tickets requested only for computer accounts (NEWYORK$, NASHUA$, SCRANTON$, WEC$) with Status 0x0 and AES256; no forged service tickets. |
| T1558.003 Kerberoasting | not_observed | No RC4 service-ticket requests, no SPN user accounts targeted, no Kerberoast/Rubeus script blocks. |
| T1558.004 AS-REP Roasting | not_observed | AS exchange required pre-authentication (KDC_ERR_PREAUTH_REQUIRED then AES256 success); no AS-REP roasting tooling in PowerShell logs. |
| T1606 Forge Web Credentials | suspicious | Real credential-access activity on scranton.dmevals.local: pbeesly's PowerShell toolkit exported all LocalMachine certificates with private keys to .pfx (Get-PrivateKeys, hardcoded password "saribas"), PowerShell.exe ope… |
| T1606.001 Web Cookies | not_observed | Only benign cookie artifacts: a service-profile INetCookies file created by svchost.exe and standard WebDAV davclnt.dll DavSetCookie calls to 192.168.0.4. No browser cookie theft or forged cookie use in any dataset. |
| T1606.002 SAML Tokens | not_observed | No SAML/Assertion/NotOnOrAfter strings in PowerShell, no saml/token/cert command lines in Sysmon, and no saml/adfs/token HTTP URLs in Zeek. Certificate export is a precursor only; no token forging or use was seen. |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | No MFA/2FA/authenticator/push/OTP artifacts in PowerShell 4104 script blocks, sysmon process command lines, security logon events or zeek HTTP URLs. The C355 windows.other hits are routine WMI provider start/DeleteInstan… |
| T1649 Steal or Forge Authentication Certificates | malicious | Certificate private keys exported to .pfx. |

## Context (outside the hypothesis)

Activity reported under techniques outside the hypothesis' scope. Not verified, not part of the verdict.

- T1113 · malicious/high · Invoke-ScreenCapture screenshot job on scranton (pivot)
- T1113 · malicious/high · Invoke-ScreenCapture screenshot job on scranton (pivot)

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

Every MCP tool call of this run (1340), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-95a520f45a | scope | list_data_sources | {} | None |  |
| q-3cf09946bd | scope | get_registry | {} | None |  |
| q-2f754756f2 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-1629bdde50 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-4e9adebc8e | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-3b3b32072a | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-585f98a49b | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-7552f7714a | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-ef8e419d42 | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-15aae0119c | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:(4656 OR 4663 OR 4670)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-be019b2ec4 | check C004 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-0d6828244a | check C005 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*mimikatz* OR powershell.script_block_text:*sekurlsa* OR powershell.script_block_text:*DumpCreds*)", "time_from": null, "time_… | 0 |  |
| q-ec7e1fa337 | check C006 | search | {"dataset": "windows.other", "query": "message:(*lsass* OR *mimikatz* OR *sekurlsa* OR *procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-2f5cd5b43d | check C007 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-9dba403750 | check C008 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-075845590c | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-73a16e0c65 | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*lsass* OR file.path:*.dmp)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 2 |  |
| q-7e71bbe15d | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 1 |  |
| q-eb0338cc8a | check C012 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND registry.path:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-3a5703d438 | check C013 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 934 |  |
| q-6a06708815 | check C014 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 13 |  |
| q-1952bdbd91 | check C015 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*MiniDump* OR powershell.script_block_text:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-0fb05c4ea4 | check C016 | search | {"dataset": "windows.other", "query": "message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-6ce3d48c12 | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*SAM* OR file.path:*SECURITY* OR file.path:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 3 | F02 |
| q-21f5e58451 | check C018 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND (registry.path:*SAM* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 7 |  |
| q-cc5492c1b8 | check C019 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (process.command_line:*SAM* OR process.command_line:*reg*save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-ae43522b08 | check C020 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg save* OR process.command_line:*save*hklm* OR process.command_line:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-237667cdea | check C021 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*save*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-fb8d38e316 | check C022 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663) AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 10 |  |
| q-1337c2edf5 | check C023 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAM* OR powershell.script_block_text:*reg save* OR powershell.script_block_text:*hive*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 2 |  |
| q-679b19b4b1 | check C024 | search | {"dataset": "windows.other", "query": "message:(*SAM* OR *SECURITY hive* OR *reg save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-939f2ed0f2 | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ntds* OR file.path:*NTDS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-7e745711a4 | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*ntdsutil* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-4de5780219 | check C027 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND file.path:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-7aba12f0f2 | check C028 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "size": 50, "sub_field": … | 0 |  |
| q-82e4bc4b17 | check C029 | search | {"dataset": "windows.other", "query": "message:(*shadow* OR *VSS* OR *ntds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-0c0bdfd30e | check C030 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*ntds* OR powershell.script_block_text:*diskshadow* OR powershell.script_block_text:*vssadmin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-bea5efd147 | check C031 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-f0ba51198c | check C032 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*secrets* OR process.command_line:*lsadump* OR process.command_line:*reg save*HKLM\\\\SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observe… | 0 |  |
| q-18efa76a83 | check C033 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-b41f4aaebe | check C034 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*SECURITY*Policy*Secrets*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-b46cc298b5 | check C035 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Secrets*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-fc37a8e493 | check C036 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Secrets* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*LSA*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name",… | 0 |  |
| q-941cc27519 | check C037 | search | {"dataset": "windows.other", "query": "message:(*Secrets* OR *LSA* OR *lsadump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-084a999842 | check C038 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-00290536d1 | check C039 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*DCC2* OR process.command_line:*mscache* OR process.command_line:*cachedump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 4 |  |
| q-5151b77b25 | check C040 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND (win.ObjectName:*Cache* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "u… | 0 |  |
| q-d828bbdaa4 | check C041 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Cache*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-d7b7629bde | check C042 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cache* OR powershell.script_block_text:*DCC2* OR powershell.script_block_text:*mscache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 0 |  |
| q-ec448b4834 | check C043 | search | {"dataset": "windows.other", "query": "message:(*cached*credential* OR *mscache* OR *DCC2*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-bdaefa4299 | check C044 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-0fd6d64515 | check C045 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-6af832954c | check C046 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-2b61e16765 | check C047 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-a69a73ef09 | check C048 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*DCSync* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-31039f8a45 | check C049 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-dbce0da853 | check C050 | search | {"dataset": "zeek", "query": "event.action:dce_rpc AND (zeek.operation:*DRSUAPI* OR zeek.endpoint:*drsuapi* OR zeek.named_pipe:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code"… | 9 |  |
| q-41f1e44c90 | check C051 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-98a7105190 | check C052 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pcap* OR process.command_line:*sniff* OR process.command_line:*promisc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-154be3b9ce | check C053 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-0ad388cd41 | check C054 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*tcpdump* OR process.executable:*windump* OR process.executable:*wireshark* OR process.executable:*rawcap* OR process.executable:*npcap*)", "time_from": null, "time_to": null, "fields… | 0 |  |
| q-e693826952 | check C055 | search | {"dataset": "windows.sysmon", "query": "event.code:6 AND (win.Image:*npcap* OR win.Image:*pcap* OR win.Image:*winpcap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-483307eea9 | check C056 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*pcap* OR powershell.script_block_text:*sniff* OR powershell.script_block_text:*promiscuous*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-e9ee92f822 | check C057 | search | {"dataset": "zeek", "query": "event.action:conn AND network.transport:icmp", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 0 |  |
| q-bf2bda40d0 | check C058 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-4496d42aca | check C059 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4656 OR event.code:4663", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10834 |  |
| q-b4d78e6fbd | check C060 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*credential* OR win.ObjectName:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 23 |  |
| q-b148186498 | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-34d177bb39 | check C062 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-6efb8ed06a | check C063 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1010 OR win.GrantedAccess:0x1410 OR win.GrantedAccess:0x1438 OR win.GrantedAccess:0x143a)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 0 |  |
| q-36e399ff0f | check C064 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Credential* OR powershell.script_block_text:*CredentialManager* OR powershell.script_block_text:*keylog*)", "time_from": null, "time_to": null, "fields": ["@time… | 0 |  |
| q-5286f5c521 | check C065 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-fbd71e6ddb | check C066 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-0df16572ad | check C067 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-ea5ce1263e | check C068 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon* OR win.TargetImage:*explorer*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 470 |  |
| q-61123d69f7 | check C069 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*Scancode*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 26 |  |
| q-8afb0c8514 | check C070 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*keylog* OR process.command_line:*GetAsyncKeyState* OR process.command_line:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer… | 0 |  |
| q-8d609875bd | check C071 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-3adf17f2f4 | check C072 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*winlogon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 13 |  |
| q-5074e851c7 | check C073 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-53ed29891a | check C074 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keylog* OR powershell.script_block_text:*GetAsyncKeyState* OR powershell.script_block_text:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@tim… | 0 |  |
| q-b8ba516b63 | check C075 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-8308c2f373 | check C076 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*Prompt* OR powershell.script_block_text:*Read-Host*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-af8104f099 | check C077 | aggregate | {"dataset": "windows.powershell", "field": "win.ScriptBlockId", "query": "event.code:4104", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 414 |  |
| q-e68ae1582b | check C078 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 3 |  |
| q-493f05b51f | check C079 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-b33db18ff1 | check C080 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*prompt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user… | 0 |  |
| q-25c3c3befa | check C081 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-a83998707a | check C082 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-a65f86ffc6 | check C083 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-07d503b373 | check C084 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*login* OR file.path:*portal* OR file.path:*wwwroot* OR file.path:*inetpub*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "eve… | 0 |  |
| q-317b0cffed | check C085 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1649 |  |
| q-eb0365290c | check C086 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*iis* OR process.command_line:*w3wp* OR process.command_line:*wwwroot*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-5f352cf015 | check C087 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*wwwroot* OR win.ObjectName:*inetpub* OR win.ObjectName:*login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 0 |  |
| q-0ebabc903e | check C088 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5337 |  |
| q-3926e9c2ea | check C089 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*wwwroot* OR powershell.script_block_text:*login* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-602f0c6d75 | check C090 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-845af15cbc | check C091 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*portal*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-9354a87de5 | check C092 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-7a1af6bff3 | check C093 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-5d21738421 | check C094 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-f3eac9b389 | check C095 | search | {"dataset": "windows.sysmon", "query": "event.code:8", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 95 |  |
| q-04855a200b | check C096 | aggregate | {"dataset": "windows.security", "field": "win.CallerProcessName", "query": "event.code:4656 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-7cfc8653d9 | check C097 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hook* OR powershell.script_block_text:*SetWindowsHookEx* OR powershell.script_block_text:*MiniDump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 0 |  |
| q-87374423bf | check C098 | search | {"dataset": "windows.other", "query": "message:*hook* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-86cb25f7f3 | check C099 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-6e9d5e841e | check C100 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-188290a86c | check C101 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-dd03ff9b09 | check C102 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 2 |  |
| q-cc8a725268 | check C103 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-4c892f7863 | check C104 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*login*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 30 |  |
| q-820c7b4db0 | check C105 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a251b6248a | check C106 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-c567677079 | check C107 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-3e34e187f6 | check C108 | search | {"dataset": "windows.other", "query": "message:*4625* OR message:*failed*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 2 |  |
| q-3759ece00a | check C109 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-623429bbee | check C110 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b64623df3b | check C111 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-d1c8b6f043 | check C112 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ed2decfd85 | check C113 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*hash* OR process.command_line:*crack*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-829beddb6b | check C114 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.pot)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20 |  |
| q-f737202b4c | check C115 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*SAM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-cef90f3af8 | check C116 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hash* OR powershell.script_block_text:*ConvertTo-SecureString*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 0 |  |
| q-0ef0f87fe4 | check C117 | search | {"dataset": "windows.other", "query": "message:*SAM* OR message:*hash*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 1 |  |
| q-3791d75d0e | check C118 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-7e6eb93ca1 | check C119 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-021be09033 | check C120 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F15, F18 |
| q-3ccc71e07e | check C121 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-1ccd2fe0ee | check C122 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*account*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 7 |  |
| q-371a4c70ee | check C123 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-bc1a7d7ebe | check C124 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*user*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-8f85604a85 | check C125 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-f5937c762c | check C126 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-84299df3bb | check C127 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-7738688156 | check C128 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 4 |  |
| q-c2e312a8b7 | check C129 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-ffd72f63f6 | check C130 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3a6d04026c | check C131 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-05d93f5075 | check C132 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F20 |
| q-4fc1aac471 | check C133 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-56970d3b6f | check C134 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 11 | F20 |
| q-eac5968c6e | check C135 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 0 |  |
| q-2014ff1b50 | check C136 | search | {"dataset": "windows.other", "query": "message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "des… | 2 | F20 |
| q-4d8c35ae11 | check C137 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-21fe451d33 | check C138 | search | {"dataset": "windows.security", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 163 | F22 |
| q-79c73e1370 | check C139 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-a66624dcc1 | check C140 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 66 | F22 |
| q-1193af3b28 | check C141 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*445* OR powershell.script_block_text:*WebDAV* OR powershell.script_block_text:*NTLM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 0 |  |
| q-b17d30572d | check C142 | search | {"dataset": "windows.other", "query": "message:*445* OR message:*WebDAV*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-12c5fc217d | check C143 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-b931867a03 | check C144 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:MOVE OR http.request.method:OPTIONS)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 |  |
| q-93b342c21a | check C145 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 42 |  |
| q-9304c4727c | check C146 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 | F24 |
| q-cd74693656 | check C147 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-a4c328a24e | check C148 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.GrantedAccess:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 39283 | F24 |
| q-9a26a61a43 | check C149 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Invoke-* OR powershell.script_block_text:*Exploit*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 0 |  |
| q-bde82c770d | check C150 | search | {"dataset": "windows.other", "query": "message:*exploit*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destin… | 0 |  |
| q-24980a552c | check C151 | search | {"dataset": "zeek", "query": "event.action:notice OR event.action:weird", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 14 | F24 |
| q-120bd0c191 | check C152 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-dc97acdf64 | check C153 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*cookie* OR process.command_line:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 5 | F26 |
| q-f517848fa5 | check C154 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-6c0221da32 | check C155 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 1 | F26 |
| q-a16f5782cd | check C156 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-cbfaf15635 | check C157 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-cee4551d72 | check C158 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "even… | 0 |  |
| q-023b0ebfc2 | check C159 | search | {"dataset": "windows.other", "query": "message:*cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destina… | 0 |  |
| q-e163cd4fc8 | check C160 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:GET", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 2 | F26 |
| q-2dc0087ed3 | check C161 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-f6539afbb0 | check C162 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*unattend*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name",… | 0 |  |
| q-c147158f46 | check C163 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-675b0f374d | check C164 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*unattend* OR win.TargetFilename:*password* OR win.TargetFilename:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 1 | F28, F31 |
| q-6ea6c1ea51 | check C165 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 OR event.code:14", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-c832712e24 | check C166 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 17 | F30 |
| q-4e4c98a279 | check C167 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*password* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-30c5f5885c | check C168 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-45682e9ebd | check C169 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-d3638783bf | check C170 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-cb9ce27f3e | check C171 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-1d3ff8b590 | check C172 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-850597b8e9 | check C173 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*config*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 8 |  |
| q-84a4db1510 | check C174 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-f4b47511ff | check C175 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.txt)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 44 |  |
| q-954e6b297e | check C176 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Content* OR powershell.script_block_text:*Select-String*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-f2ef7e6f8a | check C177 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-3ebc3f9843 | check C178 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-2d0bef427f | check C179 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*\\\\sam\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\security\\\\*\" OR TO_LOWER(registry.path) LIKE \"*password*\" OR TO_LOWER… | ERROR |  |
| q-d2dc861799 | check C179 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*sam*\" OR TO_LOWER(registry.path) LIKE \"*security*\" OR TO_LOWER(registry.path) LIKE \"*password*\" OR TO_LOWER(registry.path) … | 170 |  |
| q-9697b9a677 | check C180 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-010cd31e51 | check C181 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\sam*\" OR… | ERROR |  |
| q-73d3fa48ef | check C181 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*sam*\" OR TO_… | 5 |  |
| q-0e82b22f0b | check C182 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*\\\\security*\" OR TO_LOWER(win.ObjectName) LIK… | ERROR |  |
| q-66b844dd74 | check C182 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*security*\" OR TO_LOWER(win.ObjectName) LIKE \"*lsa… | 500 |  |
| q-b0abbfe763 | check C183 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*reg query*\" OR TO_LOWER(COALESCE(powershell.script_block_t… | ERROR |  |
| q-3ebc113c39 | check C183 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*reg query*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*reg save*\" OR TO_L… | 1 |  |
| q-eaa6a26c6b | check C184 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\security*\" OR TO_LOWER(COALESCE(message, win.Message, \"\"… | ERROR |  |
| q-ad9b24aa90 | check C184 (repaired) | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\\\\\sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\\\\\security*\" OR TO_LOWER(COALESCE(message, win.Messa… | 3 |  |
| q-ba8dfb1dee | check C185 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(powershell.script_block_tex… | ERROR |  |
| q-a38c17223c | check C185 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*consolehost_history*\… | 1 |  |
| q-119cffe2bb | check C186 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*consolehost_history*\" OR TO_LOWER(process.command_line) LIKE \"*psreadline*\" OR TO_LOWER(process.command_line) LIKE \"*h… | 0 |  |
| q-8c35dc8048 | check C187 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*\\\\history*\" OR TO_LOWER(file.p… | ERROR |  |
| q-7854fb3d05 | check C187 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*history*\" OR TO_LOWER(file.path)… | 15 |  |
| q-e32b3ff7c2 | check C188 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*consolehost_history*\" OR TO_LOWER(win.ObjectName) LIKE \"*psreadline*\" OR TO_LOWER(win.ObjectName) LI… | 0 |  |
| q-4ad7be8441 | check C189 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*psreadline*\" \| KEEP @timestamp, host.name, event.code, messag… | 5 |  |
| q-f057237100 | check C190 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*.key\" OR TO_LOWER(file.path) LIKE \"*.pgp\" OR TO_LOWER(file.path) LIKE \"*.gpg\" OR TO_LOWER(file.path) LIKE \"*.ppk\" OR TO_LOWER… | 1 |  |
| q-5f3ae423a2 | check C191 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*.pem*\" OR TO_LOWER(process.command_line) LIKE \"*.pfx*\" OR TO_LOWER(process.command_line) LIKE \"*.p12*\" OR TO_LOWER(pr… | 0 |  |
| q-7db09d5182 | check C192 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*.key\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pem\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pfx\" OR TO_… | 0 |  |
| q-63be3c40f7 | check C193 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*.key\" OR TO_LOWER(win.ObjectName) LIKE \"*.pem\" OR TO_LOWER(win.ObjectName) LIKE \"*.pfx\" OR TO_LOWE… | 0 |  |
| q-319818357c | check C194 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(powershell.script_block_text, … | ERROR |  |
| q-6a42632f7b | check C194 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*.pfx*\" OR TO_LOWER(COAL… | 2 |  |
| q-aef2767aa6 | check C195 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pfx*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*… | 0 |  |
| q-b2f1ff69df | check C196 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(powershell.script_block_… | ERROR |  |
| q-c3949130f8 | check C196 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*sysvol*\" OR TO_LO… | 32 |  |
| q-b879383c5d | check C197 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sysvol*\" OR TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR TO_LOWER(process.command_line) LIKE \"*cpassword*\" O… | 0 |  |
| q-50e17fc92d | check C198 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*groups.xml*\" OR TO_LOWER(file.path) LIKE \"*sysvol*\" OR TO_LOWER(file.path) LIKE \"*gpprefdecrypt*\" OR TO_LOWER(file.path) LIKE \… | 22 |  |
| q-91709d70c2 | check C199 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ShareName) LIKE \"*sysvol*\" OR TO_LOWER(win.ShareName) LIKE \"*netlogon*\") \| KEEP … | 56 |  |
| q-c410cfdda0 | check C200 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ObjectName) LIKE \"*sysvol*\" OR TO_LOWER(win.ObjectName) LIKE \"*gpp*\")… | 0 |  |
| q-88a066d0eb | check C201 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*sysvol*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) … | 0 |  |
| q-e3b33fd413 | check C202 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" OR TO_LOWER(win.SourceImage) LIKE \"*lsass.exe\") \| KEEP @timestamp, host.name, user.name, win.SourceImage, win.T… | 500 |  |
| q-8c048e060f | check C203 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-19b2d8f44c | check C204 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" OR … | 0 |  |
| q-268638fa39 | check C205 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\protect\\\\*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectNam… | ERROR |  |
| q-8a6eca4231 | check C205 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*protect*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE … | 19 | F34 |
| q-3e3a71b851 | check C206 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\… | 0 |  |
| q-d1d4dc8f77 | check C207 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*sekurlsa*\" OR TO_LOWER(COALESCE(powershell.script_block_te… | ERROR |  |
| q-03b5574334 | check C207 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*sekurlsa*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*lsadump*\" OR TO_LOW… | 5 |  |
| q-51b70ee10d | check C208 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*lsass*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*credential*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) L… | 2 |  |
| q-b3811bc42a | check C209 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\google\\\\chrome\\\\user data*\" OR TO_LOWER(process.command_l… | ERROR |  |
| q-491e1a461d | check C209 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*google*chrome*user data*\" OR TO_LOWER(process.command_line) LIKE … | 0 |  |
| q-4bc7d2e41b | check C210 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | ERROR |  |
| q-74103d5b18 | check C210 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | 0 |  |
| q-2753c4216b | check C211 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*chrome.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*msedge.exe\" OR TO_LOWER(… | 0 |  |
| q-41fd87cdeb | check C212 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | ERROR |  |
| q-3008681af0 | check C212 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | 0 |  |
| q-96a0c2b896 | check C213 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(powershell.script_block_… | ERROR |  |
| q-3078e9d8fb | check C213 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*logins.json*\" OR … | 0 |  |
| q-935647eb32 | check C214 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*logins.json*\" OR TO_LOWER(COALESCE(message, win.Message, \"… | 0 |  |
| q-09684496b9 | check C215 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-d1a335a630 | check C216 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-ea58b37076 | check C217 | search | {"dataset": "windows.sysmon", "query": "event.code:15 AND file.path:*Credentials*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 0 |  |
| q-e5ab20acd2 | check C218 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*Credential* OR process.command_line:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-c5374293e1 | check C219 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*vault* OR powershell.script_block_text:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 0 |  |
| q-c66dfc871a | check C220 | search | {"dataset": "windows.other", "query": "message:*Credential* OR message:*vault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 | F34 |
| q-bf396cbbd3 | check C221 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*keepass* OR process.executable:*1password* OR process.executable:*bitwarden* OR process.executable:*lastpass* OR process.executable:*dashlane*)", "time_from": null, "time_to": null, … | 0 |  |
| q-bcb8df5ca7 | check C222 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*keepass* OR file.path:*1password* OR file.path:*bitwarden* OR file.path:*lastpass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 0 |  |
| q-be85912e2a | check C223 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 0 |  |
| q-e0689d58c1 | check C224 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*kdbx*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 0 |  |
| q-db62eb770a | check C225 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keepass* OR powershell.script_block_text:*kdbx* OR powershell.script_block_text:*1password* OR powershell.script_block_text:*bitwarden*)", "time_from": null, "time_t… | 0 |  |
| q-dd4d443595 | check C226 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*1password* OR message:*bitwarden* OR message:*kdbx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-74df6665ab | check C227 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-aeaf03de04 | check C228 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-d6521b5847 | check C229 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 77 | F39 |
| q-ae3126a317 | check C230 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*cryptdll* OR win.ObjectName:*msv1_0* OR win.ObjectName:*sam*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-d52da5470b | check C231 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*cryptdll* OR process.command_line:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-916fe1943d | check C232 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*msv1_0* OR powershell.script_block_text:*SecurityPackages*)", "time_from": null, "… | 0 |  |
| q-6e84b5d75f | check C233 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll* OR message:*msv1_0*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-b8c0437ce0 | check C234 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 218 | F38 |
| q-8e2ff8e6dd | check C235 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F38 |
| q-0bfa681933 | check C236 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-98583a00bb | check C237 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-5edf1f9ef4 | check C238 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-fa220abeae | check C239 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-3fd93c4126 | check C240 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*Skeleton* OR powershell.script_block_text:*DCShadow*)", "time_from": null, "time_t… | 0 |  |
| q-6c75dad0bd | check C241 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*System32* AND (file.path:*.dll))", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-ea3089dc2f | check C242 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-d25e5f9a52 | check C243 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Notification\\ Packages* OR win.ObjectName:*Password* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-2794ba9df9 | check C244 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Notification* OR process.command_line:*PasswordFilter*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 0 |  |
| q-551ee134fc | check C245 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Notification* OR powershell.script_block_text:*PasswordFilter* OR powershell.script_block_text:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 0 |  |
| q-dea84f1587 | check C246 | search | {"dataset": "windows.other", "query": "message:*Notification* OR message:*PasswordFilter* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 10 |  |
| q-93f8f0f1a2 | check C247 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*AllowReversiblePasswordEncryption* OR powershell.script_block_text:*ReversibleEncryption* OR powershell.script_block_text:*Set-ADUser*)", "time_from": null, "time_to… | 0 |  |
| q-18cd27689a | check C248 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (message:*AllowReversiblePasswordEncryption* OR message:*ReversibleEncryption*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 0 |  |
| q-ec982b2f77 | check C249 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-0bfd76c526 | check C250 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-22d295d0ca | check C251 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-2eed75af7e | check C252 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*AllowReversiblePasswordEncryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 0 |  |
| q-a9c2cacbbf | check C253 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*set-aduser*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(powershell.script_block_text)… | ERROR |  |
| q-8332bf1dae | check C253 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthenticati… | 1 |  |
| q-03ddba84b5 | check C254 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-4e3724ddc2 | check C255 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:5136 OR event.code:4739", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-cad21ddc79 | check C256 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LI… | 0 |  |
| q-508ff75d72 | check C257 | search | {"dataset": "windows.other", "query": "event.code:4739 OR event.code:5136 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-616614e386 | check C258 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-84f946d645 | check C259 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-8cee25d9cc | check C260 | count | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null} | 0 |  |
| q-663e5ea4ed | check C261 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-9664c1ae4d | check C262 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*connect-msolservice*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*connect-azuread*\" OR TO_LOWER(powershell.script_block_text) L… | ERROR |  |
| q-dc29bc147b | check C262 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-azuread*\" OR TO… | 0 |  |
| q-e9a0b1f113 | check C263 | search | {"dataset": "windows.other", "query": "event.code:5136 OR event.code:4739 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-a0495d9fb0 | check C264 | count | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null} | 36 |  |
| q-59132253ad | check C265 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND (TO_LOWER(win.ObjectName) LIKE \"*networkprovider*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE \"*winlogon*\") \| KE… | 0 |  |
| q-566131bf6d | check C266 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*networkprovider*\" OR TO_LOWER(file.path) LIKE \"*system32*credential*\" OR TO_LOWER(file.path) LIKE \"*winlogon*\") \| KEEP @timest… | 1 |  |
| q-8833a83ccb | check C267 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-eccab7ebb4 | check C268 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-46afd85473 | check C269 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*networkprovider*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*new-itemproperty*\" OR TO_LOWER(powershell.script_block_text) LIKE… | ERROR |  |
| q-09f71f9488 | check C269 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-itemproperty*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*reg add*\" \| KEEP @tim… | 0 |  |
| q-74e58b9bfa | check C270 | search | {"dataset": "windows.other", "query": "event.code:4657 OR event.code:11 OR event.code:7", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 4 |  |
| q-582ed6623a | check C271 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-6d9395a630 | check C272 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-252e25a214 | check C273 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-ad0934cd99 | check C274 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-65fecd9e3b | check C275 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*mitm*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*arpspoof*\" OR… | ERROR |  |
| q-8706386d18 | check C275 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mitm*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*arpspoof*\" OR TO_LOWER(win.ScriptBlockTe… | 0 |  |
| q-71acb14b42 | check C276 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4670 OR event.code:4656 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 2 | F43, F46 |
| q-f402b5afe1 | check C277 | aggregate | {"dataset": "zeek", "field": "zeek.conn_state", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-7b968921f7 | check C278 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-e3fae08338 | check C279 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-a9acd015db | check C280 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND TO_LOWER(win.ObjectName) LIKE \"*dnsclient*\" \| KEEP @timestamp, host.name, user.name, win.ObjectName, win.NewValue, _id, _index"} | 0 |  |
| q-dbb9b10a80 | check C281 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-64e3afd3c7 | check C282 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-f42e6fa564 | check C283 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*llmnr*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*nbt-ns*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR … | ERROR |  |
| q-6a5c5b60ad | check C283 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*nbt-ns*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockTex… | 0 |  |
| q-05cc165317 | check C284 | search | {"dataset": "windows.other", "query": "event.code:4697 OR event.code:4657 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-b9c43f64ad | check C285 | aggregate | {"dataset": "zeek", "field": "zeek.id_resp_h", "query": "event.action:conn AND zeek.service:smb", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-1cdc723755 | check C286 | aggregate | {"dataset": "zeek", "field": "zeek.query", "query": "event.action:dns", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 53 |  |
| q-4d0815cd30 | check C287 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-124a444616 | check C288 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-f6225ace70 | check C289 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-1357a2c1e4 | check C290 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*arp*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*netsh interface*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*get-netne… | ERROR |  |
| q-0a43b6f628 | check C290 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*netsh interface*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-netneighbor*\" OR TO_LOWER(win.S… | 0 |  |
| q-312468b883 | check C291 | search | {"dataset": "windows.other", "query": "event.code:3 OR event.code:22 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-1e784fb9f3 | check C292 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-09597fe0c3 | check C293 | aggregate | {"dataset": "zeek", "field": "zeek.resp_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-459ebe1d37 | check C294 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-0c139bcefe | check C295 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-9f745c4f1e | check C296 | search | {"dataset": "windows.security", "query": "event.code:5156 AND win.Direction:Inbound", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-eb06cb1e05 | check C297 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-c1c727bea4 | check C298 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Dhcp* OR *dhcp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-25b9f8abeb | check C299 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-b4d280263b | check C300 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-50921c1966 | check C301 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-56c0089953 | check C302 | search | {"dataset": "windows.security", "query": "event.code:4634", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 236 |  |
| q-41d66ee1ee | check C303 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-a21434d021 | check C304 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-9eb0f766af | check C305 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*kerberos* OR *Kerberos* OR *ticket* OR *Ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-7086a88e7b | check C306 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-2fd10549bc | check C307 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-b178986e80 | check C308 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-63eff86930 | check C309 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-fa53cb2e58 | check C310 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-a9dd2e2883 | check C311 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-35825066a4 | check C312 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*golden* OR *Golden* OR *krbtgt* OR *KRBTGT*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-897c07f8c0 | check C313 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-b0db1ecceb | check C314 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-1d3bd44ca4 | check C315 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-7a819fbe41 | check C316 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-d0ade8f361 | check C317 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-45edd88550 | check C318 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-7b642f3c37 | check C319 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*silver* OR *Silver* OR *service ticket* OR *SPN*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 0 |  |
| q-bccb9cb9a0 | check C320 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-3ad0687acb | check C321 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-e926d93e00 | check C322 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-8abd4fec73 | check C323 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-73016c0d48 | check C324 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-d42f79ea9c | check C325 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-23218b1873 | check C326 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-8466029792 | check C327 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Kerberoast* OR *kerberoast* OR *Invoke-Kerberoast* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 0 |  |
| q-afac53528d | check C328 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-872301d058 | check C329 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-34ac970560 | check C330 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-7b307d83c8 | check C331 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 14 |  |
| q-67176f71ac | check C332 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-85f849aecf | check C333 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-fa939e9a83 | check C334 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*AS-REP* OR *asrep* OR *GetNPUsers* OR *DontRequirePreAuth*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 0 |  |
| q-57c5c6c151 | check C335 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-810305384e | check C336 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-63f3b3263d | check C337 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-1064988ada | check C338 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e7c3ed8af0 | check C339 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*token* OR powershell.script_block_text:*SAML*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 0 |  |
| q-24e3a7cba5 | check C340 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-b13af3c499 | check C341 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "event.action:http OR event.action:ssl OR event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 475 |  |
| q-7e746991f6 | check C342 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-89e2d7f7d5 | check C343 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-a38daa16b0 | check C344 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Set-Cookie* OR powershell.script_block_text:*session*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 0 |  |
| q-b015edce97 | check C345 | search | {"dataset": "windows.other", "query": "event.code:11 OR event.code:16", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source… | 9 |  |
| q-6f411f3a0b | check C346 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 62 |  |
| q-46dd691018 | check C347 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-e407dc4794 | check C348 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAML* OR powershell.script_block_text:*NotOnOrAfter* OR powershell.script_block_text:*Assertion*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-742eeb15de | check C349 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-df750c6e2e | check C350 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*saml* OR process.command_line:*token* OR process.command_line:*cert*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-fcf0cf9aa2 | check C351 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*saml* OR url.original:*adfs* OR url.original:*token*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-f270c80582 | check C352 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f28e063d05 | check C353 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b58636fb46 | check C354 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*MFA* OR powershell.script_block_text:*2FA* OR powershell.script_block_text:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 0 |  |
| q-f6229d71d9 | check C355 | search | {"dataset": "windows.other", "query": "event.code:4625 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 85 | F55 |
| q-0ced1a989b | check C356 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*login* OR process.command_line:*auth* OR process.command_line:*mfa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-02b94aefed | check C357 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*auth* OR url.original:*mfa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-891c6debc8 | check C358 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-e81ac3d814 | check C359 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-b63a92b3ec | check C360 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Certificate* OR registry.path:*Crypto* OR registry.path:*Keys*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1133 |  |
| q-b6b2e899b9 | check C361 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Certificate* OR powershell.script_block_text:*Export-PfxCertificate* OR powershell.script_block_text:*New-SelfSignedCertificate*)", "time_from": null, "time_to": nul… | 0 |  |
| q-d59df4b9eb | check C362 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-da7e00fa3f | check C363 | aggregate | {"dataset": "zeek", "field": "zeek.certificate_subject", "query": "event.action:x509", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 378 |  |
| q-a788e744ce | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND NOT win.GrantedAccess:(0x1000 OR 0x1400)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.SourceImage", "win.GrantedAcce… | 9 | F01 |
| q-546fc3b995 | triage T1003 step 1 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectType:(SAM_DOMAIN OR SAM_SERVER OR SAM_ALIAS OR Process)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "process.ex… | 40 | F01, F02 |
| q-642ae2b65e | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-e8d159638d | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9VzibT"} | None |  |
| q-cafbd79d15 | triage T1003 step 2 | search | {"dataset": "windows.powershell", "query": "user.name:pbeesly AND event.code:(4104 OR 4103 OR 800)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "process.command_line", "win.ScriptBlockText", "win.Path"]… | 4283 |  |
| q-7ae7b910b4 | triage T1003 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND user.name:pbeesly AND @timestamp:[2020-05-02T03:00:00.000Z TO 2020-05-02T03:15:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "proc… | 110 |  |
| q-50d32ab84d | triage T1003 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*OpenProcess* OR process.command_line:*Get-Process* OR process.command_line:*MiniDump* OR process.command_line:*Dump* OR process.command_line:*lsass* OR process.command_line:*Invoke… | 2 | F04 |
| q-9fe19b7e28 | triage T1003 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND user.name:pbeesly AND @timestamp:[2020-05-02T03:02:10.000Z TO 2020-05-02T03:12:00.000Z] AND NOT win.ScriptBlockText:prompt", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 64 | F01, F07 |
| q-4696e5ed2d | triage T1003 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*SysinternalsSuite* OR process.executable:*sdelete* OR process.executable:*procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.n… | 11 | F06, F07 |
| q-faf858b0bc | triage T1003 step 5 | search | {"dataset": "windows.sysmon", "query": "host.name:nashua.dmevals.local AND (process.executable:*python* OR process.executable:*Rar* OR process.executable:*rar* OR win.TargetFilename:*working.zip* OR win.TargetFilename:*Rar* OR win.TargetImage:*lsass*)", "time_… | 587 | F07 |
| q-a3a71d4716 | triage T1003 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:(12 OR 13 OR 14) AND (win.TargetObject:*SAM* OR win.TargetObject:*SECURITY* OR win.TargetObject:*lsa* OR win.TargetObject:*Cache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "e… | 15298 |  |
| q-f87831d423 | triage T1003 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:(12 OR 13 OR 14) AND (win.TargetObject:*\\\\SAM* OR win.TargetObject:*\\\\SECURITY* OR win.TargetObject:*lsa* OR win.TargetObject:*NL$*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 9 | F02, F03, F05 |
| q-3db179eaf5 | triage T1003 step 6 | search | {"dataset": "windows.sysmon", "query": "host.name:nashua.dmevals.local AND (event.code:11 OR event.code:3 OR event.code:22) AND (process.executable:*python* OR process.executable:*Rar* OR process.executable:*rar* OR process.executable:*cmd.exe*)", "time_from":… | 373 |  |
| q-af514f9107 | triage T1003 step 7 | search | {"dataset": "windows.sysmon", "query": "host.name:nashua.dmevals.local AND process.executable:*python.exe AND event.code:(3 OR 22 OR 11)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "process.executable"… | 367 |  |
| q-5ff33f8816 | triage T1003 step 7 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectType:(SAM_DOMAIN OR SAM_SERVER OR SAM_ALIAS) AND NOT win.ProcessName:*lsass.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", … | 0 |  |
| q-66b878f09f | triage T1003 step 8 | search | {"dataset": "windows.sysmon", "query": "host.name:nashua.dmevals.local AND (event.code:3 OR event.code:22) AND (process.executable:*python.exe OR process.executable:*Rar.exe OR process.executable:*rar.exe)", "time_from": null, "time_to": null, "fields": ["@tim… | 348 | F07 |
| q-bcfec6c8a7 | triage T1003 step 8 | search | {"dataset": "windows.sysmon", "query": "host.name:nashua.dmevals.local AND event.code:1 AND (process.executable:*cmd.exe OR process.executable:*Rar.exe OR process.executable:*rar.exe OR process.executable:*PSEXESVC.exe)", "time_from": null, "time_to": null, "f… | 8 | F07 |
| q-1c310abaa7 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-8b88f1b67e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-82fd6191c4 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-e56630127e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9VzibT"} | None |  |
| q-80042da8bf | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9VzibT"} | None |  |
| q-bc04b55b7e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-01eba3ee36 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-1f42b7d64b | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-366c59af99 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-1b9a13025b | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtI"} | None |  |
| q-6bfe018dd1 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrs6"} | None |  |
| q-f026a99158 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-be4dbe24b7 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-3b77352600 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17AAad"} | None |  |
| q-8db90a22e3 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-Mz"} | None |  |
| q-6782394db9 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-Mz"} | None |  |
| q-6f5291cfc8 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx4yjcI"} | None |  |
| q-864f58f16a | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrte"} | None |  |
| q-d12b7a4353 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtq"} | None |  |
| q-3ca33309a0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrt8"} | None |  |
| q-08dfb46fbd | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-91d2d7f9bc | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-abc81d2a9c | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVp3"} | None |  |
| q-a5de8beed7 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-d839d01ee1 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-bcb61ab935 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjeM"} | None |  |
| q-790c535801 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-782cbf076c | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HSbI"} | None |  |
| q-6f8396ca62 | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.executable:*NetworkWatcher* OR process.executable:*PsExec* OR process.executable:*sdelete* OR process.executable:*python*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 19 | F09 |
| q-084b4733b8 | triage T1040 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-4f83e4bbb8 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*NetworkWatcher* OR process.executable:*python* OR process.executable:*PSEXESVC*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.exe… | 13 | F08, F09 |
| q-b4a4890d58 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.Image:*npcap* OR win.Image:*pcap* OR win.Image:*winpcap* OR win.Image:*NetworkWatcher*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable",… | 0 |  |
| q-94cb7557e3 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND (process.executable:*cmd.exe OR process.executable:*NetworkWatcher*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process… | 15 | F08 |
| q-ef4bcf112c | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (process.executable:*python* OR process.executable:*NetworkWatcher*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "destination.ip", "dest… | 348 | F09 |
| q-63ffef465d | triage T1040 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*python* OR win.ScriptBlockText:*8443* OR win.ScriptBlockText:*192.168.0.4*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.co… | 5 |  |
| q-63555d810a | triage T1040 step 4 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 613 |  |
| q-7e04a7b3b9 | triage T1040 step 5 | search | {"dataset": "zeek", "query": "event.action:notice OR event.action:weird OR destination.port:1234 OR network.transport:icmp", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "source.ip", "destination.ip", "destination.port", "networ… | 15 |  |
| q-a0de23ff05 | triage T1040 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*python* OR file.path:*pcap* OR file.path:*npcap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "file.path", "win.TargetFilename", "w… | 3 | F09 |
| q-0070ad3239 | triage T1040 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2jo9KZ"} | None | F09 |
| q-54f31ff15c | triage T1040 step 6 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*NetworkWatcher* OR win.ServiceName:*NetworkWatcher* OR win.ImagePath:*pcap* OR win.ServiceName:*pcap* OR win.ServiceName:*npcap*)", "time_from": null, "time_to": null, "fields": ["@time… | 0 |  |
| q-1362c31172 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2MP8lJ"} | None |  |
| q-219347b8ae | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx3viRd"} | None |  |
| q-368e314efb | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx3w9Hq"} | None |  |
| q-cd433e8123 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2MP8lJ"} | None |  |
| q-1f0d5fa896 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2jo9KZ"} | None |  |
| q-81997e5cc4 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-b2411e1611 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Uyl9o"} | None |  |
| q-c77c07418d | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjeM"} | None |  |
| q-612fb14d64 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjf4"} | None |  |
| q-4a315002b5 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" \| STATS cnt = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT cnt DESC"} | ERROR |  |
| q-a716851a18 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.name,… | ERROR |  |
| q-db2523bbb8 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| STATS cnt = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT cnt DESC"} | 18 |  |
| q-ef1a83986f | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.n… | 33 | F10, F12 |
| q-8124962722 | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None | F10 |
| q-320d9ff97f | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None | F11 |
| q-9ced4397e2 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC \| LIMIT 60"} | 60 | F13 |
| q-d8354f87f2 | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None | F10 |
| q-4bede45d2c | triage T1056 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*procdump*\" OR process.command_line LIKE \"*MiniDump*\" OR process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*com… | 8 | F14 |
| q-40814c6b5b | triage T1056 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4656\" AND win.ObjectName LIKE \"*lsass*\" \| KEEP @timestamp, host.name, user.name, process.executable, win.AccessMask, win.ObjectType, win.ObjectName, _id, _index \| … | 13 | F10, F11 |
| q-7ef43ad033 | triage T1056 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:00:00Z\" AND @timestamp <= \"2020-05-02T03:12:00Z\" \| KEEP @timestamp, user.name, proce… | 47 |  |
| q-3aafd6b0c2 | triage T1056 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4656\" AND win.ObjectType IN (\"SAM_SERVER\",\"SAM_DOMAIN\",\"SAM_ALIAS\") \| KEEP @timestamp, host.name, user.name, process.executable, win.AccessMask, win.ObjectType,… | 21 |  |
| q-54c95b271a | triage T1056 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (process.command_line LIKE \"*procdump*\" OR process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*MiniDump*\" OR process.command_line LIKE \… | 0 |  |
| q-2154f1d466 | triage T1056 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND @timestamp >= \"2020-05-02T03:08:00Z\" AND @timestamp <= \"2020-05-02T03:12:00Z\" \| KEEP @timestamp, user.name, process… | 7 | F11 |
| q-750971d571 | triage T1056 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND process.executable LIKE \"*python.exe\" \| STATS cnt = COUNT(*) BY host.name, win.TargetImage, win.GrantedAccess \| SORT cnt DESC"} | 3 |  |
| q-f6339477d0 | triage T1056 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC \| LIMIT 40"} | 11 | F11 |
| q-d1fa16b8d4 | triage T1056 step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND process.executable LIKE \"*python.exe\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, win.CallTrace, _id, _index"} | 3 | F11 |
| q-6e05d3d2f3 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-e724cdd4bb | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-40af1e7878 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-633956107b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-f6f54ca2c7 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qtr32"} | None |  |
| q-cb41af3737 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-c9135b77a2 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-3ecc65ef97 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-a82d2fd824 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9VzibT"} | None |  |
| q-d5154189a3 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-ce5b454d22 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgTcg"} | None |  |
| q-0f1ef53d3c | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-961aab13cd | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtr"} | None |  |
| q-1f1d9c1212 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrt3"} | None |  |
| q-2737f82f5d | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIhZ8"} | None |  |
| q-00caf56842 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7xd"} | None |  |
| q-40244d5104 | triage T1110 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-ee5425f875 | triage T1110 step 1 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 AND win.ObjectName:SAM", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-1ff16ac647 | triage T1110 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_… | 5 |  |
| q-5b7479ec87 | triage T1110 step 2 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:SAM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ProcessName", "win.ObjectName", "win.AccessMask", "win.SubjectUserName", "win.ObjectType"], "size"… | 0 |  |
| q-872025836f | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None | F17 |
| q-13b05cc97f | triage T1110 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Dump* OR win.ScriptBlockText:*Amsi* OR win.ScriptBlockText:*Reflection*)", "time_from": null, "time_to": null… | 2 |  |
| q-92cb41666f | triage T1110 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJWyf"} | None | F17 |
| q-2e105995f7 | triage T1110 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*PowerShell.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executable", "user.name"], "si… | 0 |  |
| q-ecd8fb8ea5 | triage T1110 step 5 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.TargetUserName"} | 297 |  |
| q-1c780c56d3 | triage T1110 step 5 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 30, "sub_field": "host.name"} | 15 |  |
| q-be13d7229f | triage T1110 step 6 | count | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4740 OR event.code:4771 OR event.code:4776", "time_from": null, "time_to": null} | 1 |  |
| q-1730068d6f | triage T1110 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.dmp OR win.TargetFilename:*lsass* OR win.TargetFilename:*.zip OR win.TargetFilename:*.7z)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.execu… | 8 | F17 |
| q-1350aae442 | triage T1110 step 7 | search | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4740 OR event.code:4771 OR event.code:4776", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "win.LogonType", "win.Status", "w… | 1 | F15, F16, F19 |
| q-8d3378c8a1 | triage T1110 step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*OfficeSupplies* OR process.command_line:*working.zip OR process.command_line:*Rar.exe* OR process.command_line:*Compress-Archive*)", "time_from": null, "time_to": null, "fields": [… | 2 | F17 |
| q-da0835eff3 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-78af6b0b9a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-f4182fb9ad | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-08421adedf | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-98cb3bb6c2 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-206d253362 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-c9f2c6e67c | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-3abe941b30 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-7c7cc290ae | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJWyf"} | None |  |
| q-6993f0bba3 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7zj"} | None |  |
| q-b180397f74 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-5f6f241656 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2WaNu5"} | None |  |
| q-5e10d2d8ca | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-f8df93ed1e | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-53f4b62602 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-432dc3c4d2 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3Mh"} | ERROR |  |
| q-938b6ef70c | triage T1110 step 9 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None | F19 |
| q-0beb50ad0d | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-be00e6a98b | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtv"} | None |  |
| q-50baf9396b | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-f840fd3ea4 | triage T1111 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" \| STATS c = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT c DESC \| LIMIT 50"} | ERROR |  |
| q-5ffb58629a | triage T1111 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4624 AND win.LogonType IN (\"2\",\"10\",\"0\") \| KEEP @timestamp, host.name, user.name, win.LogonType, win.LogonProcessName, win.IpAddress, win.Workstation, win.Authenti… | ERROR |  |
| q-2b0bdd5f41 | triage T1111 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" \| STATS c = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT c DESC \| LIMIT 50"} | 18 |  |
| q-92b66cdd06 | triage T1111 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType IN (\"2\",\"10\",\"0\") \| KEEP @timestamp, host.name, user.name, win.LogonType, win.LogonProcessName, win.IpAddress, win.Workstation, win.Auth… | 18 |  |
| q-b4ba069088 | triage T1111 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" AND win.GrantedAccess IN (\"0x1f3fff\",\"0x1fffff\",\"0x101001\",\"0x3000\") \| KEEP @timestamp, host.name, process… | 8 | F20 |
| q-31202afdad | triage T1111 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*pbeesly*\" OR TO_LOWER(user.name) LIKE \"*pbeesly*\") \| KEEP @timestamp, host.name, user.name, process.executable, proces… | 30 |  |
| q-e34eb790c4 | triage T1111 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*credential*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mfa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*token*\" OR T… | 11 | F20 |
| q-dc981ef60c | triage T1111 step 5 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" OR event.code == \"4697\" \| KEEP @timestamp, host.name, win.ServiceName, win.ImagePath, win.ServiceFileName, win.ServiceAccount, user.name, _id, _index \| SORT @ti… | ERROR |  |
| q-7cbcc883f3 | triage T1111 step 6 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" \| KEEP @timestamp, host.name, win.ServiceName, win.ImagePath, win.ServiceType, win.StartType, user.name, _id, _index \| SORT @timestamp ASC \| LIMIT 20"} | 5 | F20 |
| q-060e168fd2 | triage T1111 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*psexec*\" OR TO_LOWER(process.executable) LIKE \"*python.exe\" OR TO_LOWER(process.command_line) LIKE \"*psexec*\") \| KEEP … | 9 | F20 |
| q-f375c7dcd0 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtv"} | None |  |
| q-aca4b26db9 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-c8cf0174d1 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-fbd8e2697d | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-3e47638df7 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-8598ee263e | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBvlP"} | None |  |
| q-5680a29bd5 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-e4cdc113bf | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-a7d6f5c891 | triage T1187 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" AND (http.request.method == \"PROPFIND\" OR http.request.method == \"MOVE\" OR http.request.method == \"OPTIONS\") \| KEEP @timestamp, source.ip, destination.ip, destinati… | 36 | F21 |
| q-8f27baa697 | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 30, "sub_field": "source.ip"} | 50 |  |
| q-5a264789a7 | triage T1187 step 2 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None | F21 |
| q-a687cf7d59 | triage T1187 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND destination.ip == \"192.168.0.4\" \| KEEP @timestamp, source.ip, source.port, destination.ip, destination.port, network.transport, zeek.conn_state, zeek.duration, zeek… | 30 | F21 |
| q-fe1cf2498d | triage T1187 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"files\" AND (source.ip == \"10.0.1.4\" OR destination.ip == \"10.0.1.4\") \| KEEP @timestamp, source.ip, destination.ip, file.mime_type, file.path, zeek.filename, zeek.fuid, zeek… | 0 |  |
| q-a47207b59e | triage T1187 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 3 AND (destination.ip == \"192.168.0.4\" OR source.ip == \"192.168.0.4\" OR destination.port == 80) \| KEEP @timestamp, host.name, process.executable, user.name, source.ip,… | ERROR |  |
| q-3b2bc28725 | triage T1187 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.ip == \"192.168.0.4\" OR source.ip == \"192.168.0.4\" OR destination.port == \"80\") \| KEEP @timestamp, host.name, process.executable, user.name, so… | ERROR |  |
| q-52ba28c733 | triage T1187 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"files\" \| KEEP @timestamp, source.ip, destination.ip, file.mime_type, file.path, zeek.filename, zeek.fuid, zeek.md5, zeek.total_bytes, _id, _index \| SORT @timestamp ASC \| LIMI… | 30 |  |
| q-5946689b75 | triage T1187 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.ip == \"192.168.0.4\" OR source.ip == \"192.168.0.4\") \| KEEP @timestamp, host.name, process.executable, user.name, source.ip, destination.ip, desti… | 40 |  |
| q-ab7eb64a69 | triage T1187 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*webdav*\" OR TO_LOWER(process.command_line) LIKE \"*192.168.0.4*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\\\\\*\") … | 40 |  |
| q-a79240a76a | triage T1187 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7yE"} | None | F21 |
| q-3077e5d41c | triage T1187 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttk"} | None | F21 |
| q-7dffbb7fcb | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-a88609a3fd | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-d13499cd5f | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-f3b160971b | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0a"} | None |  |
| q-2b132a40b0 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0a"} | None |  |
| q-120a9a5049 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA7g"} | None |  |
| q-b28ceaef3b | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0j"} | None |  |
| q-c2b8b42f7d | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7yE"} | None |  |
| q-b8364b3589 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7yE"} | None |  |
| q-2062a90c03 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttk"} | None |  |
| q-997b10b53d | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttk"} | None |  |
| q-a7be7f413f | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o2"} | None |  |
| q-76b69378f2 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o2"} | None |  |
| q-eeddaefa64 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9KmX__"} | None |  |
| q-6c369028f2 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9KmX__"} | None |  |
| q-86f1714336 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HyZX"} | None |  |
| q-47ef58d230 | triage T1212 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| STATS c = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT c ASC \| KEEP c, process.executable, win… | ERROR |  |
| q-15ac248935 | triage T1212 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4769 OR event.code == 4768 \| STATS c = COUNT(*) BY event.code, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.Status, host.name \| SORT c ASC \| KEEP … | ERROR |  |
| q-31f9b49fb3 | triage T1212 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| STATS c = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT c ASC \| KEEP c, process.executable,… | 18 |  |
| q-0288a42541 | triage T1212 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" OR event.code == \"4768\" \| STATS c = COUNT(*) BY event.code, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.Status, host.name \| SORT c ASC … | 7 |  |
| q-b426b40c32 | triage T1212 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" AND (process.executable LIKE \"*PowerShell.exe\" OR process.executable LIKE \"*wsmprovhost.exe\" OR process.executable… | 6 | F23, F24 |
| q-3e88524b13 | triage T1212 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None | F23 |
| q-c41d49d1ea | triage T1212 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None | F23 |
| q-bf32b1a1aa | triage T1212 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credential*\"… | 20 | F23 |
| q-3438a67bd7 | triage T1212 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*powershell*\" OR TO_LOWER(process.executable) LIKE \"*wsmprovhost*\" OR TO_LOWER(process.executable) LIKE \"*rundll32*\" OR … | 20 | F23 |
| q-8a7ccc17df | triage T1212 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*seaduke*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR… | 7 |  |
| q-abc02b5afc | triage T1212 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND (win.LogonType == \"3\" OR win.LogonType == \"9\" OR win.LogonType == \"10\") \| STATS c = COUNT(*) BY win.LogonType, win.TargetUserName, win.LogonProcessNam… | 11 |  |
| q-60c98a6127 | triage T1212 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBExi"} | None | F23 |
| q-7c4e422ee9 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-76b068f83f | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-90898a04e7 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-f49d4de126 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-88edb0ead6 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-6fbd82b9e2 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-d4e3ca8fd7 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqds5"} | None |  |
| q-8fa44218ce | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOAxHj"} | None |  |
| q-2fa6f3f7ee | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBExi"} | None |  |
| q-0f93dba031 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFmw"} | None |  |
| q-e7cc36d43b | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-6dbc7356fd | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-3fa83f4bf7 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7anEhk"} | None |  |
| q-edbdb25a0a | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtr"} | None |  |
| q-4dba82156b | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-a0e1d39913 | triage T1212 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1X"} | None |  |
| q-476bd24586 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9IkK9d"} | None | F26 |
| q-ae03504741 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-7cae2eb141 | triage T1539 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1r"} | None |  |
| q-75f24b2441 | triage T1539 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA01"} | None |  |
| q-9f1aa316e8 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*\\\\ac\\\\*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LO… | ERROR |  |
| q-e97fab8eec | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND (TO_LOWER(win.TargetImage) LIKE \"*edge*\" OR TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\" OR TO_LOWER(win.TargetImage… | ERROR |  |
| q-b8eefabd99 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" OR TO_… | 1 |  |
| q-7a0e1cd84a | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*edge*\" OR TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\" OR TO_LOWER(win.TargetI… | 374 | F25 |
| q-1e8ed83705 | triage T1539 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlS"} | None | F25 |
| q-de56fb68a6 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.GrantedAccess == \"0x1fffff\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, _id, _index \| SORT @timestamp ASC"} | 500 |  |
| q-d60071aa93 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*edge*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*readprocessmemory*\" OR … | ERROR |  |
| q-4e181ed18d | triage T1539 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*edge*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*readprocessmemor… | 0 |  |
| q-fc93f39bbe | triage T1539 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND TO_LOWER(process.executable) LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, … | 12 |  |
| q-14367e391f | triage T1539 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63Bwm6"} | None | F25 |
| q-549f0a4077 | triage T1539 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7DPnAM"} | None |  |
| q-42732fb4a3 | triage T1539 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17AQxS"} | None | F25 |
| q-4192f5f410 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlS"} | None |  |
| q-7a26708111 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlS"} | None |  |
| q-4a63b45a0c | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlS"} | None |  |
| q-45b9d853fe | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlZ"} | None |  |
| q-f45ea3bc31 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAla"} | None |  |
| q-73001ea96f | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63Bwm6"} | None |  |
| q-4add66db6f | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17AQxS"} | None |  |
| q-1c09195347 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9IkK9d"} | None |  |
| q-3bbac4f5f7 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9IkK9d"} | None |  |
| q-89d653e9d2 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-453e8e27db | triage T1539 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA01"} | None |  |
| q-a1a937e7ee | triage T1539 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA01"} | None |  |
| q-d5d60536cc | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-102ca12d04 | triage T1552 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(process.executable) LIKE \"*accesschk*\" OR TO_LOWER(process.command_line) LIKE \"*accesschk*\" OR TO_LOWER(win.TargetFilename) LIKE \"*passwordsdb*\" \| KEEP @timestamp, host.n… | 22 |  |
| q-4d184c3c5f | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*sysinternals*\" OR TO_LOWER(process.parent.executable) LIKE \"*sysinternals*\" OR TO_LOWER(process.executable) LIKE \"*\\\\t… | ERROR |  |
| q-1e7bd8be68 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*passwords*\" OR TO_LOWER(win.TargetFilename) LIKE \"*\\\\temp\\\\*\" OR TO_LOWER(win.TargetFilename) LIKE \"*sysinternals*\… | ERROR |  |
| q-42e2e82e37 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) RLIKE \".*sysinternals.*\" OR TO_LOWER(process.parent.executable) RLIKE \".*sysinternals.*\" OR TO_LOWER(process.executable) RLIKE \… | 17 | F28, F29 |
| q-cec9ae1548 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) RLIKE \".*passwords.*\" OR TO_LOWER(win.TargetFilename) RLIKE \".*temp.*\" OR TO_LOWER(win.TargetFilename) RLIKE \".*sysinternals.*… | 500 |  |
| q-cbc95ea8bc | triage T1552 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) RLIKE \".*passw.*\" OR TO_LOWER(win.ScriptBlockText) RLIKE \".*cred.*\" OR TO_LOWER(win.ScriptBlockText) RLIKE \".*accesschk… | 18 | F27, F28, F29 |
| q-24109e7bef | triage T1552 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\",\"5145\") AND (TO_LOWER(win.ObjectName) RLIKE \".*passwords.*\" OR TO_LOWER(win.ObjectName) RLIKE \".*sysinternals.*\" OR TO_LOWER(win.Relativ… | 0 |  |
| q-9137f194a6 | triage T1552 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None | F27 |
| q-fb402e0c2e | triage T1552 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F29 |
| q-d5a4aa23bf | triage T1552 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None | F28 |
| q-c7d13bfb44 | triage T1552 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(win.TargetFilename) RLIKE \".*\\\\.pfx\" OR TO_LOWER(win.TargetFilename) RLIKE \".*\\\\.7z\" OR TO_LOWER(win.TargetFilename) RLIKE \".*officesupplies.*\" OR TO_LOWER(win.TargetF… | 9 | F27, F28, F29 |
| q-65d35a8cdb | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-bbbd031f55 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-07559e11d9 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-13e825d9fb | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None |  |
| q-cef5f045d4 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-f8590895f5 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ae3Po"} | None |  |
| q-34fefb9b41 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-230e36ae2f | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-f758920652 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBvlP"} | None |  |
| q-970f8853ce | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-77f180a363 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-4caffa9f01 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7zj"} | None |  |
| q-23d7c080db | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HSbI"} | None |  |
| q-cfe554b482 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL21_2XV"} | None |  |
| q-68545a89aa | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtv"} | None |  |
| q-adb05731ae | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx4z3lf"} | None |  |
| q-708f3fb57b | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-ca31c1fe55 | triage T1555 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.n… | 33 | F34 |
| q-77d401be8f | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F32 |
| q-2a6ca4295f | triage T1555 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*minidump*\" OR TO_LOWER(process.command_line) LIKE \"*comsvcs*\" OR TO_… | 2 |  |
| q-aa5333f32e | triage T1555 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*powershell*\" OR TO_LOWER(process.executable) LIKE \"*wsmprovhost*\") \| KEEP @timestamp, host.name, user.name, process.exec… | 13 |  |
| q-ab78bc5578 | triage T1555 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17AQxS"} | None |  |
| q-d836d7ccaf | triage T1555 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*\\\\appdata\\\\roaming\\\\microsoft\\\\credentials*\" OR TO_LOWER(file.path) LIKE \"*\\\\appdata\\\\local\\\\microsoft\\\\credentia… | ERROR |  |
| q-b0d090e4a3 | triage T1555 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*microsoft*credentials*\" OR TO_LOWER(file.path) LIKE \"*microsoft*protect*\" OR TO_LOWER(file.path) LIKE \"*microsoft*vault*\" OR T… | 44 | F33 |
| q-a24264f47b | triage T1555 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None | F32 |
| q-6220a66c02 | triage T1555 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:11:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _i… | 79 | F32 |
| q-0c84a13afb | triage T1555 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 11 | F32 |
| q-e2e52e38a4 | triage T1555 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"1\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \… | 61 | F35 |
| q-87af68287e | triage T1555 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None | F32 |
| q-4b8250d2c4 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-55fa775c63 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-8b9c5456d2 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-12b25f4a84 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-b149be8078 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-e357ac614e | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-4c4eb914f2 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-db7c410fa5 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx559LG"} | None |  |
| q-abf7207844 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx559LG"} | None |  |
| q-e97120901e | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-51fff84ec4 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-3e56529e3f | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qtr32"} | None |  |
| q-b26cef85ed | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9VzibT"} | None |  |
| q-867814f953 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-324bd3a818 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2QULdY"} | None |  |
| q-1721b6f749 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-3586da0402 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.SourceImage"} | 326 |  |
| q-56fe9c72dc | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*msv1_0*)", "time_from": null, "time_to": null, "size": 40, "sub_field": "pr… | 77 |  |
| q-c5789ef7eb | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff OR win.SourceImage:*wsmprovhost* OR win.SourceImage:*PowerShell.exe)", "time_from": null, "time_to": null, "fields":… | 5 |  |
| q-b86f7bf874 | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-b8879aae2d | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None | F36 |
| q-1a470a36d7 | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None | F36, F41, F42 |
| q-3cda6ec363 | triage T1556 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*procdump*\" O… | 6 |  |
| q-7e7e7bd6a6 | triage T1556 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*minidump*\" OR TO_LOWER(process.command_line) LIKE \"*procdump*\" OR TO… | 1 |  |
| q-cf893fb969 | triage T1556 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None | F36, F40 |
| q-2a2ff21479 | triage T1556 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockId == \"9d153741-75c3-4062-afe3-aeca0aee611b\" OR win.ScriptBlockId == \"b2b03a9c-43f0-4285-837d-f22d4600b2ae\") \| KEEP @timestamp, host.n… | 2 | F37 |
| q-73058bfcf7 | triage T1556 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None | F37 |
| q-edd1acfd19 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-4c93b44055 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-75373f9b62 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-89db12b3db | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-1499983191 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-1990754c37 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-12966b19fc | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-fc1e51e297 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-f52492e9d7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-067153be04 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-d168d745b8 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-5e58bd7a36 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-81a60bbe6c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o4"} | None |  |
| q-2c18a56c8e | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-0aaa0908ca | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-ba586a9204 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL6-IgT8"} | None |  |
| q-9d58d36157 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2x8I9e"} | None |  |
| q-920af39198 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-24a6931ee2 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-0a2b1ac799 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-d2b57a79fd | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND zeek.resp_l2_addr == \"12:34:56:78:9a:bc\" \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.service, zeek.orig_l2_addr, zeek.resp_l2_addr, zeek.co… | 20 | F45 |
| q-dad2d7ea20 | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"dns\" AND (zeek.query LIKE \"*wpad*\" OR zeek.query LIKE \"*NASHUA*\" OR zeek.query LIKE \"*SCRANTON*\") \| KEEP @timestamp, source.ip, destination.ip, zeek.query, zeek.answers, … | 14 |  |
| q-f627bcf3a8 | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"notice\" OR event.action == \"weird\" \| KEEP @timestamp, event.action, zeek.note, zeek.msg, source.ip, destination.ip, zeek.id_orig_h, zeek.id_resp_h, _id, _index \| LIMIT 30"} | 14 | F46 |
| q-ba858fb441 | triage T1557 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4697\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.ServiceFileName, win.ServiceAccount, _id, _index \| LIMIT 30"} | 23 |  |
| q-788bda12d3 | triage T1557 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4697\" AND win.ServiceName == \"javamtsup\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.ServiceFileName, win.ServiceAccount, win.ServiceStartType, wi… | 1 |  |
| q-70c7d6827d | triage T1557 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*javamtsup*\" OR TO_LOWER(process.command_line) LIKE \"*javamtsup*\" OR TO_LOWER(process.executable) LIKE \"*psexe*\") \| KEE… | 9 |  |
| q-c906ff3104 | triage T1557 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (process.executable LIKE \"*javamtsup*\" OR process.executable LIKE \"*python*\") \| KEEP @timestamp, host.name, user.name, process.executable, destination.ip, de… | 40 |  |
| q-f8e053a55d | triage T1557 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType IN (\"3\",\"9\") \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.LogonType, win.IpAddress, win.Workstation, win.Authenticatio… | 40 |  |
| q-15a58794ed | triage T1557 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND process.executable LIKE \"*javamtsup*\" \| KEEP @timestamp, host.name, user.name, process.executable, destination.ip, destination.port, _id, _index \| LIMIT 30"} | 0 |  |
| q-123846f168 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5140\" OR event.code == \"5145\" \| KEEP @timestamp, host.name, user.name, win.ShareName, win.ShareLocalPath, win.SubjectUserName, win.IpAddress, win.RelativeTargetName… | 40 | F44 |
| q-bce05f6251 | triage T1557 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"11\" OR event.code == \"1\") AND (TO_LOWER(file.path) LIKE \"*javamtsup*\" OR TO_LOWER(process.command_line) LIKE \"*javamtsup*\" OR TO_LOWER(process.command_line) LIKE … | 12 |  |
| q-520d81395a | triage T1557 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*net user*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*service*\" … | 20 |  |
| q-4957eb6004 | triage T1557 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND destination.port == 8443 \| STATS cnt = COUNT(*) BY host.name, process.executable, destination.ip \| SORT cnt DESC \| LIMIT 20"} | 1 |  |
| q-890df4ad17 | triage T1557 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*javasoft*\" OR TO_LOWER(registry.path) LIKE \"*javamtsup*\") \| KEEP @timestamp, host.name, user.name, registry.path, registry.d… | 7 |  |
| q-6f841552e6 | triage T1557 step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2chAnX"} | None | F43 |
| q-c753ba7ae1 | triage T1557 step 8 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qtr33"} | None | F44 |
| q-82b1305bc1 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yNV"} | None |  |
| q-b0667f1f3a | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iPp"} | None |  |
| q-3775c6db68 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2chAnX"} | None |  |
| q-94b10fc8f7 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qtr33"} | None |  |
| q-092f823fde | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bXAb"} | None |  |
| q-87f6ed7dfd | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8nPsje"} | None |  |
| q-b8183b54c2 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw3Z"} | None |  |
| q-18b1b3b7c7 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6q"} | None |  |
| q-a54ee9d283 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yNV"} | None |  |
| q-2f2044a6db | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0q"} | None |  |
| q-4a524dea9c | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F47 |
| q-c5f5b020ef | triage T1558 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 40, "sub_field": null} | 326 |  |
| q-a571fdbe5d | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None | F47 |
| q-e27c00415f | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None | F47 |
| q-f21cafa4f2 | triage T1558 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:(4104 OR 4103 OR 800) AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*LSASS* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*minidump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBloc… | 2 |  |
| q-727eab3277 | triage T1558 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJWyf"} | None | F47 |
| q-861c4676ea | triage T1558 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:scranton.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "process.command_line", "win.ScriptBlockText", "win.Path"], … | 146 |  |
| q-93bfbb1400 | triage T1558 step 4 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND (event.code:1 OR event.code:11 OR event.code:3 OR event.code:22) AND @timestamp:[2020-05-02T03:15:00.000Z TO 2020-05-02T03:28:00.000Z]", "time_from": null, "time_to": null, "fields": … | 622 | F47 |
| q-f8d243fed4 | triage T1558 step 4 | search | {"dataset": "windows.security", "query": "event.code:4769 AND (win.ServiceName:krbtgt OR win.ServiceName:KRBTGT)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "win.ServiceName", "win.TicketEncryptionType… | 3 | F49, F50 |
| q-9e277496df | triage T1558 step 5 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 28 |  |
| q-7e07834307 | triage T1558 step 5 | search | {"dataset": "windows.security", "query": "event.code:4624 AND (win.TargetUserName:SCRANTON$ OR win.TargetUserName:pbeesly)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "win.TargetUserName", "win.LogonTy… | 67 |  |
| q-b1e78f3931 | triage T1558 step 6 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "source.ip", "destination.ip", "zeek.request_type", "zeek.client", "zeek.service", "zeek.success", "zeek.error_msg", "zeek.cipher… | 35 | F50, F51 |
| q-eb284043c5 | triage T1558 step 6 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 212 |  |
| q-451df476da | triage T1558 step 7 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHCF"} | None | F48 |
| q-9ebc90832d | triage T1558 step 7 | search | {"dataset": "windows.security", "query": "event.code:4672", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "win.SubjectUserName", "win.PrivilegeList", "win.TargetUserName"], "size": 5, "sort": "asc"} | 212 | F48 |
| q-770953048a | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJWyf"} | None |  |
| q-c0053b08f8 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJWyf"} | None |  |
| q-afef0d2e81 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-dbef42009b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-fbc6ecb80c | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-ff9b30f7b1 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2TW2Y3"} | None |  |
| q-e46ace5c42 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHCF"} | None |  |
| q-f9d254b3ab | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHCF"} | None |  |
| q-cfe8e062ae | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TypoZ"} | None |  |
| q-e85f6fe51f | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-f6100e421f | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-7de759cd49 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-f78f7fdfc0 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1d"} | None |  |
| q-53475f1886 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1d"} | None |  |
| q-da92830091 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1f"} | None |  |
| q-383bd1ae66 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1g"} | None |  |
| q-1519ceba31 | triage T1606 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 |  |
| q-47acbf4712 | triage T1606 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "file.path", "user.name"], "size": 1… | 1 | F53 |
| q-faf35b21d6 | triage T1606 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None | F52 |
| q-2286fc14a8 | triage T1606 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None | F52 |
| q-73873ed39c | triage T1606 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.… | 30 |  |
| q-ce28fa32bf | triage T1606 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*pfx*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cert*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOW… | 11 |  |
| q-1825d30faa | triage T1606 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*pfx*\" OR TO_LOWER(process.command_line) LIKE \"*certutil*\" OR TO_LOWER(process.command_line) LIKE \"*export*\" OR TO_LOW… | 6 |  |
| q-a0c09ea776 | triage T1606 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE win.ScriptBlockId IN (\"9d153741-75c3-4062-afe3-aeca0aee611b\", \"b2b03a9c-43f0-4285-837d-f22d4600b2ae\") \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.ScriptBlock… | 2 |  |
| q-1bb65de6e8 | triage T1606 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2D"} | ERROR |  |
| q-b2aa1a655b | triage T1606 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE win.ScriptBlockId == \"9d153741-75c3-4062-afe3-aeca0aee611b\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.ScriptBlockText"} | 1 |  |
| q-100d4589f5 | triage T1606 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE win.ScriptBlockId == \"9d153741-75c3-4062-afe3-aeca0aee611b\" \| KEEP _id, _index, @timestamp, host.name, user.name, win.ScriptBlockText"} | 1 |  |
| q-bf6d8c64c0 | triage T1606 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None | F52, F54 |
| q-5e8ee61362 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-ef0d44ddb9 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-b6a4a174c6 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-885f1ce9c2 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-ee6ffc61c8 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-850d9a388d | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-b81e72bfb9 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-3de0b9e457 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-92030ea982 | triage T1621 step 1 | count | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776", "time_from": null, "time_to": null} | 1 |  |
| q-9a5f77f596 | triage T1621 step 1 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 216 |  |
| q-792ea9923e | triage T1621 step 1 | aggregate | {"dataset": "windows.other", "field": "host.name", "query": "event.code:5857 OR event.code:5858 OR event.code:5860", "time_from": null, "time_to": null, "size": 10, "sub_field": null} | 88 |  |
| q-0b6e7b6a39 | triage T1621 step 2 | search | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proc… | 1 | F55 |
| q-4f7aa4e7b4 | triage T1621 step 2 | search | {"dataset": "windows.other", "query": "event.code:5857 OR event.code:5860", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "message", "process.executable"], "size": 10, "sort": "asc"} | 39 | F55 |
| q-acb28e5c14 | triage T1621 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4624 \| STATS c = COUNT(*) BY win.LogonType, win.AuthenticationPackageName, win.TargetUserName \| SORT c DESC \| LIMIT 30"} | ERROR |  |
| q-c9641db9fe | triage T1621 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*mfa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*authenticator*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*2fa*\" OR … | ERROR |  |
| q-61f1340194 | triage T1621 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" \| STATS c = COUNT(*) BY win.LogonType, win.AuthenticationPackageName, win.TargetUserName \| SORT c DESC \| LIMIT 30"} | 18 |  |
| q-298e8e20c3 | triage T1621 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*mfa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*authenticator*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*2fa*\"… | 0 |  |
| q-41eda3a354 | triage T1621 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| WHERE TO_LOWER(process.command_line) LIKE \"*login*\" OR TO_LOWER(process.command_line) LIKE \"*auth*\" OR TO_LOWER(process.command_line) LIKE \"*mfa*\" OR TO_LOWE… | 1 | F55 |
| q-11efcf932b | triage T1621 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| STATS c = COUNT(*) BY process.executable, host.name \| SORT c DESC \| LIMIT 40"} | 40 |  |
| q-34b7bffbcf | triage T1621 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*python.exe\" OR process.executable LIKE \"*PsExec64.exe\" OR process.executable LIKE \"*PSEXESVC.exe\" OR process.executable LIKE \"*s… | 26 |  |
| q-264405965c | triage T1621 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" \| STATS c = COUNT(*) BY process.executable, host.name \| SORT c DESC \| LIMIT 30"} | 30 |  |
| q-1794369086 | triage T1621 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| LIMIT 15"} | 15 |  |
| q-9c76fe655b | triage T1621 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND process.executable LIKE \"*powershell.exe\" \| KEEP @timestamp, host.name, user.name, process.command_line, process.parent.executable, _id, _index \| LIMIT 1… | 13 |  |
| q-8b5885ae4e | triage T1621 step 8 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8tQ-__"} | None | F55 |
| q-b53b421ebb | triage T1621 step 8 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8tRO9P"} | None |  |
| q-ca6456df76 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iO6"} | None |  |
| q-78fa24b6bb | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMK"} | None |  |
| q-a6ec615764 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-3102310b58 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx40qiu"} | None |  |
| q-e76750828c | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8tQ-__"} | None |  |
| q-e05112b5b8 | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 1 | F56 |
| q-e196a4d78e | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-1146c48050 | triage T1649 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None |  |
| q-90de3cd8c6 | triage T1649 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*certutil*\" OR TO_LOWER(process.command_line) LIKE \"*certificate*\" OR TO_LOWER(process.command_line) LIKE \"*pfx*\" OR T… | 0 |  |
| q-aff4b50a98 | triage T1649 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (registry.path LIKE \"*SystemCertificates*\" OR registry.path LIKE \"*Crypto*\" OR registry.path LIKE \"*Keys*\") \| STATS c = COUNT(*) BY registry.path, host.na… | 30 |  |
| q-fffca9832c | triage T1649 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*cert*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*pfx*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*crypto*\" OR TO_LOW… | 4 | F56 |
| q-5da82c978f | triage T1649 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None | F56 |
| q-6c06c69c84 | triage T1649 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6lp"} | None | F56 |
| q-c950a8ea92 | triage T1649 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*.pfx*\" OR TO_LOWER(file.path) LIKE \"*officeSupplies*\" OR TO_LOWER(file.path) LIKE \"*downloads*\")) OR (event.code == \"1\" AND … | 30 | F56 |
| q-0bf9341891 | triage T1649 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*get-privatekeys*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*beachcleanup*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"… | 5 |  |
| q-1dbc188060 | triage T1649 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND user.name == \"pbeesly\" \| KEEP @timestamp, win.Path, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC … | 25 |  |
| q-636af07ad5 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-c4d111d594 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-3b8aef7a26 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-9c123904c1 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-3f7d838847 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-885f5654b2 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6lp"} | None |  |
| q-cf7d8260a0 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6lp"} | None |  |
| q-259ff1db90 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None |  |
| q-ed38569ecd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-4ac20a581b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-15e848f730 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-d99b7e7c7a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9VzibT"} | None |  |
| q-573b91f65c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9VzibT"} | None |  |
| q-e15088adee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-863f171bf4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-45914b20fd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-0f87b8c3f2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-38ddbbf62d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtI"} | None |  |
| q-59c2e5de7a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrs6"} | None |  |
| q-3428f4942c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-322d592529 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-706ca2130f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17AAad"} | None |  |
| q-b0546853c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-Mz"} | None |  |
| q-5bdee6928d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-Mz"} | None |  |
| q-88e5d4a2de | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx4yjcI"} | None |  |
| q-706926abdd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrte"} | None |  |
| q-d85350c3ff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtq"} | None |  |
| q-789b351b4a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrt8"} | None |  |
| q-d504fb441c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-03b3c1519a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-1ca3965284 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVp3"} | None |  |
| q-f22fd15971 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-1acf66f1a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-903eeeca51 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjeM"} | None |  |
| q-7f28c6c71c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-18adf4ba86 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HSbI"} | None |  |
| q-fcc4262d7d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2MP8lJ"} | None |  |
| q-91d58e9744 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx3viRd"} | None |  |
| q-81aee8065c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx3w9Hq"} | None |  |
| q-a99a99f026 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2MP8lJ"} | None |  |
| q-97a62f8d95 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2jo9KZ"} | None |  |
| q-659ec167a6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-cc377cdc0b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Uyl9o"} | None |  |
| q-ac6f002c77 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjeM"} | None |  |
| q-b4adcbd29b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjf4"} | None |  |
| q-36cd92efdd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-b8c74afc28 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-d972aaaa62 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-d8b500f21e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-306dcdce6f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qtr32"} | None |  |
| q-896ee7ab5f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-1d33584771 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-70af9c1f42 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-18989e1bb0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9VzibT"} | None |  |
| q-d6c9b30158 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-ab02200bce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgTcg"} | None |  |
| q-d899bf5476 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-0cc88121f0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtr"} | None |  |
| q-922f820005 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrt3"} | None |  |
| q-123d02807f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIhZ8"} | None |  |
| q-8a4e7eddd7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7xd"} | None |  |
| q-f9167d9615 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-e2830d623d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-aed2bc166b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-d9332e8ab9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-35e63d228e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-9b3005d6eb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-1ca53e88aa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-b476f94d6f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-871decfd4c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJWyf"} | None |  |
| q-66d3eeff2f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7zj"} | None |  |
| q-8d76b6e742 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-553a02a952 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2WaNu5"} | None |  |
| q-c4447e8c9d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-e83d4330e9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-ddb683b15d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-536246bad5 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-2bef63bad2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtv"} | None |  |
| q-9da87888c5 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-3f277d8058 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-031c8271c3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-3bf5babe6f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-f777df7abe | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBvlP"} | None |  |
| q-d89c4bc8ca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-1491f63bfc | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-99ddc81467 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-cd1b00e599 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-47b127a7d2 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-d09aed7b63 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0a"} | None |  |
| q-bf5ccfea77 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0a"} | None |  |
| q-8956ccb066 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA7g"} | None |  |
| q-f094f76c1f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0j"} | None |  |
| q-47170de4e2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7yE"} | None |  |
| q-15fdf1ea36 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7yE"} | None |  |
| q-70e6c20011 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttk"} | None |  |
| q-952067443d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttk"} | None |  |
| q-d2c1e6f85d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o2"} | None |  |
| q-ebd4533e5e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o2"} | None |  |
| q-d7025fb5cc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9KmX__"} | None |  |
| q-3cad219b11 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9KmX__"} | None |  |
| q-4bc8e3921b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HyZX"} | None |  |
| q-ef68c977cb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-b68aa94bcf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-e3fd0e3c4c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-c5ead9987b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-bd90f89e98 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-8a4c66943b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-55762d3dcf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqds5"} | None |  |
| q-89d559479f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOAxHj"} | None |  |
| q-eaff62237c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBExi"} | None |  |
| q-34db1300bb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFmw"} | None |  |
| q-fe685757d5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-b82a0c86de | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-ef74e1c0b0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7anEhk"} | None |  |
| q-f04fd6dcbf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtr"} | None |  |
| q-3264d33a29 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-2ff920e647 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1X"} | None |  |
| q-d8b222a651 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlS"} | None |  |
| q-a27fa38069 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlS"} | None |  |
| q-cfc0a39aff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlS"} | None |  |
| q-3d24f5b98b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlZ"} | None |  |
| q-5168e62abb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAla"} | None |  |
| q-afb77d030b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63Bwm6"} | None |  |
| q-20f7262c03 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17AQxS"} | None |  |
| q-111e516be2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9IkK9d"} | None |  |
| q-177795f57e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9IkK9d"} | None |  |
| q-920bb6caff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-d6ecce8830 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA01"} | None |  |
| q-41fc798290 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA01"} | None |  |
| q-be1f5c0c55 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-a1042a50a2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-6c368c8eac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-c8e2a68a6e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None |  |
| q-c8ee9c760e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-7cf81d946a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ae3Po"} | None |  |
| q-325214ebe0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-06a4d51293 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-7fca53ffc9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBvlP"} | None |  |
| q-c43700d701 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-ef120fbe1f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-5e295c06ec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7zj"} | None |  |
| q-272b91e097 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HSbI"} | None |  |
| q-1d94c9d4c1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL21_2XV"} | None |  |
| q-56a9bfa173 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtv"} | None |  |
| q-516e67d6b8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx4z3lf"} | None |  |
| q-a487c7153e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-85b7a1c302 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-2de50fbae8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-37dc232bbe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-5f79286dde | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-716ad24ad7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-acdf9dcc4a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-9a9a053b69 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-58e5de39b8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx559LG"} | None |  |
| q-5722570cf0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx559LG"} | None |  |
| q-6b7b729049 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-3afd580dd8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-6de5830f92 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qtr32"} | None |  |
| q-e8b9aa9dcb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9VzibT"} | None |  |
| q-fb94a41592 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-7ddfb3a478 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2QULdY"} | None |  |
| q-b5e9e3ef99 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-de87873cc7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-3cbb32aade | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-6f298c6cf6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-91622afa59 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-f41e9485a0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-1b73de2b7b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-21f52385b1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-a91a84c42f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-089e4d4678 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-699ab5f947 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-e4bfc817ce | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-2305a67191 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-031687c2bb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o4"} | None |  |
| q-b7d7dab180 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-9c8aff7b11 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-4e1fa11e69 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL6-IgT8"} | None |  |
| q-6d3db2c6f2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2x8I9e"} | None |  |
| q-f146c3d782 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-c344c3b8cd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-26f6680d46 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-9ae42ad204 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yNV"} | None |  |
| q-5c07994a25 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iPp"} | None |  |
| q-e233596c39 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2chAnX"} | None |  |
| q-49d93e84a3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qtr33"} | None |  |
| q-fd692fc3c5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bXAb"} | None |  |
| q-d70c81b8ee | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8nPsje"} | None |  |
| q-4914da285c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw3Z"} | None |  |
| q-501f82ab1e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6q"} | None |  |
| q-321d3d0746 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yNV"} | None |  |
| q-1cac888018 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0q"} | None |  |
| q-56043ec113 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJWyf"} | None |  |
| q-00ce407c4d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJWyf"} | None |  |
| q-8ae8c45230 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-55092c8d65 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-4f3d7ca28d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-385d6ec7e7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2TW2Y3"} | None |  |
| q-05bba4880b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHCF"} | None |  |
| q-3f6ec54c0d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHCF"} | None |  |
| q-052779ed7d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TypoZ"} | None |  |
| q-da5fc66649 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-6818ac686c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-b4aa47a518 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-8fc0d55fbd | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1d"} | None |  |
| q-3c9ac98264 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1d"} | None |  |
| q-8d40d1ccca | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1f"} | None |  |
| q-68ba4963b1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1g"} | None |  |
| q-60bfcad7e0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-6739fd3107 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-a7d947a465 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-7e2f8af097 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-2840f31eff | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-667caaf719 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-e2de8bc4dd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-df4c3a9f86 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-1c03d09393 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iO6"} | None |  |
| q-c68dda3447 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMK"} | None |  |
| q-d103b979d9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-ca2b750c7f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx40qiu"} | None |  |
| q-0f62ee4eaa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8tQ-__"} | None |  |
| q-e0045de373 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-ebbf436350 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-9c3aa0c15a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-8b8cc5e108 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-1daf09bdfa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-3ea88b1914 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6lp"} | None |  |
| q-d77ce54d5e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6lp"} | None |  |
| q-53aaf66335 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None |  |
| q-35a787b28f | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:31:52.456000+00:00", "size": 100, "sub_field": "process.pare… | 61 |  |
| q-f8ec529576 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:31:52.456000+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-d5cb812205 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:31:52.456000+00:00", "size": 100, "sub_field": "process… | 63 |  |
| q-8fe416718a | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:31:52.456000+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-ab490b3208 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.parent.ex… | 359 |  |
| q-2016ed2093 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.executable"} | 1276 |  |
| q-5f20ab8e3c | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.pare… | 370 |  |
| q-7a47324bf2 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-41cacb520c | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (process.executable LIKE \"*SysinternalsSuite*\" OR process.executable LIKE \"*\\\\\\\\Temp\\\\\\\\*\" OR process.executable LIKE \"*victim*\" OR process.executable L… | ERROR |  |
| q-ed17dbce99 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (file.path LIKE \"*\\\\\\\\Temp\\\\\\\\*\" OR file.path LIKE \"*victim*\" OR file.path LIKE \"*.pfx\" OR file.path LIKE \"*.rar\" OR file.path LIKE \"*.dll\" OR file… | ERROR |  |
| q-09135d5471 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*SysinternalsSuite*\" OR process.executable LIKE \"*\\\\\\\\Temp\\\\\\\\*\" OR process.executable LIKE \"*victim*\" OR process.executab… | 24 | F60, F62, F64, F65, F66, F67 |
| q-76eb1ac43b | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*\\\\\\\\Temp\\\\\\\\*\" OR file.path LIKE \"*victim*\" OR file.path LIKE \"*.pfx\" OR file.path LIKE \"*.rar\" OR file.path LIKE \"*.dll\" OR … | 213 | F65 |
| q-6a08a1568d | pivot step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _id, _index \| SORT @timestamp ASC"} | ERROR |  |
| q-2f5e65cb33 | pivot step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, win.CallTrace, _id, _index \| SORT @… | 500 |  |
| q-d207a65647 | pivot step 4 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND host.name:\"nashua.dmevals.local\"", "time_from": null, "time_to": null, "size": 30, "sub_field": "process.executable"} | 9543 |  |
| q-927998586d | pivot step 4 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-253d13258d | pivot step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 11 | F59, F60 |
| q-b1afd86234 | pivot step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND host.name == \"nashua.dmevals.local\" AND win.TargetImage LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess,… | 29 | F59, F63 |
| q-605505ee2b | pivot step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-ad814e2795 | pivot step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-a8ee5dc064 | pivot step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"11\" OR event.code == \"23\") AND (file.path LIKE \"*Credentials*\" OR file.path LIKE \"*Protect*\" OR file.path LIKE \"*Login Data*\" OR file.path LIKE \"*Cookies*\" OR… | 13 | F61 |
| q-22471cd3fd | pivot step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 146 |  |
| q-9398fd5190 | pivot step 8 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp > \"2020-05-02T03:01:51.000Z\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| SO… | 106 | F57, F58 |
| q-8608346920 | pivot step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17C4EF"} | None |  |
| q-6b17567544 | pivot step 9 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp > \"2020-05-02T03:06:47.000Z\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| SO… | 63 | F57 |
| q-19c9f5bb44 | pivot step 9 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2LO-px"} | None |  |
| q-1defa8bf93 | pivot step 10 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1lL"} | None |  |
| q-75ad245c21 | pivot step 10 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F62 |
| q-abf4d4ba6e | pivot step 11 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND (win.ScriptBlockText LIKE \"*Get-Keystrokes*\" OR win.ScriptBlockText LIKE \"*GetAsyncKeyState*\" OR win.Script… | 4 |  |
| q-cc1c01ca18 | pivot step 12 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None | F61 |
| q-c7fdaf5b2d | pivot step 12 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND win.ScriptBlockText LIKE \"*Keystrokes*\" \| KEEP @timestamp, win.ScriptBlockText, _id, _index \| SORT @timesta… | 3 |  |
| q-09b8e0d237 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFlH"} | None |  |
| q-c91445b91e | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1lL"} | None |  |
| q-a9b0f0b99b | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8E_lDK"} | ERROR |  |
| q-047b734255 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFlE"} | None |  |
| q-3cf7dcbf54 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-215895f9c0 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-fa384386c3 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-0f6abc5218 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-e4d1e59fd7 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-c763aa7a1a | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2WaNu5"} | None |  |
| q-9a6b30bf46 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-3568310b04 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-6d134c7bb1 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-0f990d7ca3 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-f236fb40ae | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-1997937134 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-a3227f49e1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-0fa492aa93 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-f21c873110 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9VzibT"} | None |  |
| q-94a95bbbac | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9VzibT"} | None |  |
| q-1822a89969 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-27d83944c1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-91ce47f485 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-7d8dc4ebfd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-6898d11501 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtI"} | None |  |
| q-6825221454 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrs6"} | None |  |
| q-d499b2e09c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-2d3c7a42b2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-2290df123e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17AAad"} | None |  |
| q-60e3359ed1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-Mz"} | None |  |
| q-09e52d544a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-Mz"} | None |  |
| q-4b5615dd8e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx4yjcI"} | None |  |
| q-20d6431e8a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrte"} | None |  |
| q-b1f778146a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtq"} | None |  |
| q-60a09a4332 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrt8"} | None |  |
| q-96a4b747fc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-fc5dfb4833 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-bd0dd3a5d0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVp3"} | None |  |
| q-6d452b03e3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-63e14a76c4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-402b495ad4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjeM"} | None |  |
| q-efab53090e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-0b0b42558c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HSbI"} | None |  |
| q-8c02fdcb69 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2MP8lJ"} | None |  |
| q-bb8a8d0686 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx3viRd"} | None |  |
| q-ab9fe02933 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx3w9Hq"} | None |  |
| q-a0cb89d0cf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2MP8lJ"} | None |  |
| q-90b0a43224 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2jo9KZ"} | None |  |
| q-9302c08dbd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-3c6741158c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Uyl9o"} | None |  |
| q-45f5b7dd7d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjeM"} | None |  |
| q-f0bc07ec2d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjf4"} | None |  |
| q-ecf83d3def | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-185c7d139b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-9631bd4ae8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-a75a62bcd7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-d86b34e07b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qtr32"} | None |  |
| q-a9884fb8b7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-544887ad33 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-a74cb69ae8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-0b8f3861e8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9VzibT"} | None |  |
| q-832db0d2f3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-b5302e7270 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgTcg"} | None |  |
| q-60b0098f30 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-9d45baee22 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtr"} | None |  |
| q-f13ca1bdab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrt3"} | None |  |
| q-52c00deca0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIhZ8"} | None |  |
| q-0b54eab3c3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7xd"} | None |  |
| q-39c3f46648 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-e199418bf3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-2274d80801 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-2ce6cec799 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-1921bdfd37 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-b1d152d6fd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-dc35b1f8a0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-69b673ac66 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-feef715763 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJWyf"} | None |  |
| q-6a349d0b00 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7zj"} | None |  |
| q-e104817dde | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-0fece4148b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2WaNu5"} | None |  |
| q-5fabd04bd8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-449e2b2614 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-0805b22f4f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-cd07e0e7c9 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-1f8de30ce8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtv"} | None |  |
| q-908aaabb33 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-3804e3be6c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-69aeb73edf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-9eb4c912f4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-b0db01a6d1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBvlP"} | None |  |
| q-deb32955e5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-15cceb776b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-0b9b3571eb | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-b364976ea8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-7a85b8a9ac | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-76d7ee1466 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0a"} | None |  |
| q-61b2e1adae | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0a"} | None |  |
| q-1b9b4ca320 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA7g"} | None |  |
| q-824bfcc527 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0j"} | None |  |
| q-0a2de58abe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7yE"} | None |  |
| q-a466cba2fe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7yE"} | None |  |
| q-e19dab5a6d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttk"} | None |  |
| q-fc49d6c687 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttk"} | None |  |
| q-9f2ab097d5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o2"} | None |  |
| q-a35ab5cc50 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o2"} | None |  |
| q-def4656d8d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9KmX__"} | None |  |
| q-ec9976e2db | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9KmX__"} | None |  |
| q-341b0e3096 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HyZX"} | None |  |
| q-8e7c22a82e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-8e8ff02af5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-8b8e9f92eb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-8d625e9da0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-52635cdfa3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-1ed494959f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-89261cba79 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqds5"} | None |  |
| q-0fe7bbc351 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOAxHj"} | None |  |
| q-0fd9292dc9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBExi"} | None |  |
| q-1884bb24f6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFmw"} | None |  |
| q-1ab2ef1feb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-3bde535f5a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-42e9a24b1a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7anEhk"} | None |  |
| q-a576943b40 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtr"} | None |  |
| q-16f669f037 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-78391f5758 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1X"} | None |  |
| q-de28049017 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlS"} | None |  |
| q-1b2956cd92 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlS"} | None |  |
| q-e0ad2ae8c8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlS"} | None |  |
| q-7a931c4c70 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlZ"} | None |  |
| q-2150c59230 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAla"} | None |  |
| q-07ba6281dc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63Bwm6"} | None |  |
| q-e65acdfe7f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17AQxS"} | None |  |
| q-bc14e85720 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9IkK9d"} | None |  |
| q-d5838b7550 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9IkK9d"} | None |  |
| q-da2bfbf59b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-686d059552 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA01"} | None |  |
| q-71dab01a29 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA01"} | None |  |
| q-37525f4125 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-16a8badec5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-4480cb0e46 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-4f3bd6529e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None |  |
| q-b462521352 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-00f198bb6e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ae3Po"} | None |  |
| q-5a94eae2b4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-504f25897f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-88f4dad3db | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBvlP"} | None |  |
| q-d3c4a3854c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-ea8d837b26 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-e858051eba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7zj"} | None |  |
| q-20e5d51aa2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HSbI"} | None |  |
| q-40c2cd3a45 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL21_2XV"} | None |  |
| q-2876d671f5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtv"} | None |  |
| q-fc4e340a82 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx4z3lf"} | None |  |
| q-bff238fcf7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-691585334e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-9a74f382d1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-433135b093 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-2f086da2d5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-5f58874955 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-97d9965d07 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-b8bd703c9c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-eca1cb768d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx559LG"} | None |  |
| q-68c7291849 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx559LG"} | None |  |
| q-23d07a8b9f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-8c60698f23 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-2540c70f4d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qtr32"} | None |  |
| q-1c00e425f6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9VzibT"} | None |  |
| q-f120b79d83 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-b8f269551b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2QULdY"} | None |  |
| q-7c41d2fceb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-071428c3a6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-d224c20697 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-458366c418 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-698ac62b68 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-2140b16a6a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-2200e5448a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-b0ae8068ae | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-4bc86ee1f3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-45c326d38d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-1d5559c6b0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-d19d36346c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-32fa64223d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-0898f9584c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o4"} | None |  |
| q-dbe700ee79 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-4e4c8e8625 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-fadf53076e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL6-IgT8"} | None |  |
| q-af7e0faae5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2x8I9e"} | None |  |
| q-2a7f3e02b3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-32a5aae61e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-e99cfa395f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-98446807b1 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yNV"} | None |  |
| q-3bddaa599c | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iPp"} | None |  |
| q-457b2b9ad1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2chAnX"} | None |  |
| q-2ac1fa0966 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qtr33"} | None |  |
| q-9c5f7a2e67 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bXAb"} | None |  |
| q-eb176d5504 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8nPsje"} | None |  |
| q-34ae817cf3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw3Z"} | None |  |
| q-3d73708d52 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6q"} | None |  |
| q-1b8555d36c | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yNV"} | None |  |
| q-e0c2432eed | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0q"} | None |  |
| q-8658e3d263 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJWyf"} | None |  |
| q-5673278bf3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJWyf"} | None |  |
| q-df35b92b1b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-3d06170892 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-ccebfce3bc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-64d03e31f7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2TW2Y3"} | None |  |
| q-0e062e2d65 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHCF"} | None |  |
| q-8ad5761d86 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHCF"} | None |  |
| q-395e83c8bd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TypoZ"} | None |  |
| q-417961a154 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-f31441316b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-06032003e1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-4c0f0b53dc | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1d"} | None |  |
| q-e0ae6f4750 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1d"} | None |  |
| q-6c238d6505 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1f"} | None |  |
| q-a5c9d3eb91 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1g"} | None |  |
| q-7bb67f8e9f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-aa2b6bcfcc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-1dc291d06c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-4d27fdfc3f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-72ac7d28a0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-d4db579c45 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-40447ed7a4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-9b352ffb3a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-d4705cdcfd | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iO6"} | None |  |
| q-568c41028f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMK"} | None |  |
| q-e425541913 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-b9de6e84fd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx40qiu"} | None |  |
| q-f1f037734b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8tQ-__"} | None |  |
| q-d5c68026b9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-808f382d4d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-e7dc52f576 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-a5945d5b0f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-6bf151c527 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-74b83ce552 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6lp"} | None |  |
| q-0d917b9b30 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6lp"} | None |  |
| q-8421e3422d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None |  |
| q-28b2d45b5d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFlH"} | None |  |
| q-88233bc0a0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1lL"} | None |  |
| q-db7f887087 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFlE"} | None |  |
| q-56096364c6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-8f78e291e1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-72ad9182c1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-727e6e4d31 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-2c4bbee011 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-0e8d4cde0c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2WaNu5"} | None |  |
| q-cdc884585a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-48b0332b3e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-4a2bf87055 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-ff93e960c1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-b23dbde0fc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-031c51f62c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-0136f95f5d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HSbI"} | None |  |
| q-754a3b5d4a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2VhsbT"} | ERROR |  |
| q-81b3fd4b8b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7VhsbV"} | None |  |
| q-ff64fcdfd6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6_ejg"} | None |  |
| q-b1c34ded96 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7Wi8c6"} | None |  |

## Verification

Evidence items cited: 241; confirmed against the stored events: 240; rejected: 1. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 4 item(s) in 3 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
