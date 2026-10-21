# Threat hunt report — 20261020-203014-converged-fixab-std1

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 11 in-scope incident(s) of verified malicious findings (confidence >= medium): I02 T1003.001 (F01, F10, F14, F17, F20, F24, F34, F46), I04 T1056 (F11), I05 T1056 (F59), I06 T1056 (F61), I07 T1056 (F62), I08 T1552.001 (F27, F58), I09 T1552.001 (F54), I12 T1552.004 (F26, F30, F53, F55), I13 T1555.003 (F57), I15 T1557 (F43), I17 T1557.002 (F41)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-20T12:30:14+00:00 / 2026-10-20T12:41:26+00:00 (671.5 s) |
| LLM calls / tokens | 182 / {'prompt': 4296252, 'completion': 147268} |
| MCP tool calls | 1212 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003 | yes | suspicious/medium | F02 | SysinternalsSuite staged on scranton ahead of LSASS access |
| I02 | T1003.001 | yes | malicious/high | F01, F10, F14, F17, F20, F24, F34, F46 | Steganographic PowerShell stager opens LSASS with full access on scranton |
| I03 | T1003.002 | yes | suspicious/medium | F56 | SAM hive opened with 0xf003f by lsass.exe after attacker tooling |
| I04 | T1056 | yes | malicious/medium | F11 | Clipboard harvesting via Get-Clipboard in pbeesly session |
| I05 | T1056 | yes | malicious/high | F59 | Masqueraded .scr dropper and hidden steganographic PowerShell stager |
| I06 | T1056 | yes | malicious/high | F61 | PowerShell-driven csc.exe compiled attacker DLLs in Temp |
| I07 | T1056 | yes | malicious/high | F62 | cmd.exe from .scr dropper launched attacker PowerShell chain |
| I08 | T1552.001 | yes | malicious/high | F27, F58 | Credential-harvesting toolkit: accesschk passwordsDB, discovery, archive staging |
| I09 | T1552.001 | yes | malicious/high | F54 | Nashua: PsExec-launched python.exe ran credential-file harvesting and RAR staging |
| I10 | T1552.002 | yes | suspicious/medium | F28 | Registry reads of LSA and Winlogon keys by powershell.exe |
| I11 | T1552.002 | yes | suspicious/low | F63 | sdclt.exe spawned by cmd.exe in attacker session |
| I12 | T1552.004 | yes | malicious/high | F26, F30, F53, F55 | Private-key/certificate export and credential-store theft on scranton |
| I13 | T1555.003 | yes | malicious/medium | F57 | User credential-bearing files archived and staged for exfiltration |
| I14 | T1555.004 | yes | suspicious/medium | F31 | No Credential Manager/Vault access; LSASS handle is the only store-relevant hit |
| I15 | T1557 | yes | malicious/medium | F43 | Adversary-in-the-middle positioning confirmed by L2 redirection |
| I16 | T1557.001 | yes | suspicious/medium | F42 | SMB session to NASHUA relayed through rogue MAC with SAMR/LSAR enumeration |
| I17 | T1557.002 | yes | malicious/high | F41 | ARP cache poisoning: single MAC fronts all off-subnet destinations |
| I18 | T1606.001 | yes | suspicious/medium | F51 | WebDAV cookie set during exfiltration staging; no browser cookie theft |

## Findings

### F01 · malicious / high · T1003.001 · Hidden PowerShell stager (control.exe parent) opened lsass.exe with full access and read its memory on scranton.dmevals.local

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T02:58:44Z, user DMEVALS\pbeesly spawned a hidden, execution-policy-bypassing PowerShell (PID 2976) from the parent 'C:\Windows\System32\control.exe"  /name Microsoft.BackupAndRestoreCenter' — a classic APT29 stager pattern. The command line decodes a bitmap (C:\Users\pbeesly\Downloads\monkey.png) into shellcode and IEXes it. At 03:05:16Z that same PID 2976 opened lsass.exe (PID 736) with GrantedAccess 0x1f3fff and 0x1fffff (PROCESS_ALL_ACCESS) with an UNKNOWN call trace, and Security 4656/4663 confirm the handle request and a 0x10 (VM_READ) read of \Device\HarddiskVolume2\Windows\System32\lsass.exe by powershell.exe as pbeesly. This is LSASS memory credential dumping. The same actor then used WinRM to nashua.dmevals.local (wsmprovhost.exe PID 7720, also as pbeesly) which opened lsass with 0x1f3fff at 03:09:29Z. Benign lsass accessors in the same window (svchost.exe 0x1000/0x1400, AntimalwareConfig.exe, WindowsAzureTelemetryService.exe, MsMpEng.exe, CollectGuestLogs.exe) are baseline AV/telemetry behaviour and are not part of this finding.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-82c5a0ea42 | ok |
| 2 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | "C:\Windows\System32\control.exe"  /name Microsoft.BackupAndRestoreCenter | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-82c5a0ea42 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-dab0e987dc | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-231c467015 | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x10 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72Yf | q-ab0c774346 | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72YQ | q-ab0c774346 | ok |
| 7 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-536fb167dc | ok |

### F10 · malicious / high · T1056 · Hidden PowerShell stager on scranton decodes a PNG-embedded payload and opens a full-access handle to lsass.exe

Evidence status: **verified**

On scranton.dmevals.local, user DMEVALS\pbeesly launched a screen-saver binary C:\ProgramData\victim\â€®cod.3aka3.scr (parent explorer.exe, /S) at 02:55:56Z. At 02:58:44Z a hidden, execution-policy-bypassing PowerShell (PID 2976, parent control.exe /name Microsoft.BackupAndRestoreCenter, IntegrityLevel High) read C:\Users\pbeesly\Downloads\monkey.png, extracted a byte array from pixel data and IEX'd the decoded ASCII — a fileless stager. At 03:05:16Z that same PowerShell process (PID 2976) opened lsass.exe with GrantedAccess 0x1F3FFF (and 0x1FFFFF), i.e. full read/write/VM access to the credential store, with a call trace ending in an UNKNOWN module. This is attacker input/credential capture tooling, not normal system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy0krT | q-3f23915660 | ok |
| 2 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-06cd3bf394 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-03b4deddd6 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D252982) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-03b4deddd6 | ok |
| 5 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\monkey.png | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hwyqdH | q-26deffb55c | ok |

### F59 · malicious / high · T1056 · Scranton: masqueraded .scr dropper and hidden steganographic PowerShell stager

Evidence status: **verified**

On scranton, the ProgramData screen-saver dropper wrote monkey.png and control.exe launched a hidden PowerShell that decoded it and drove the credential-theft chain.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-c60ca45392 | ok |
| 2 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\monkey.png | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hwyqdH | q-f80bbbd2c9 | ok |

### F61 · malicious / high · T1056 · Scranton: PowerShell-driven csc.exe compiled attacker DLLs in Temp

Evidence status: **verified**

On scranton, csc.exe was invoked twice by the attacker PowerShell to compile DLLs (qkbkqqbs.dll, 0piklvia.dll) in the user Temp directory.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.cmdline" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htvuyY | q-1724c4a0bf | ok |
| 2 | 2020-05-02 02:58:45.292Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.dll | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htvuyT | q-c42d198316 | ok |

### F62 · malicious / high · T1056 · Scranton: cmd.exe from the .scr dropper launched the attacker PowerShell chain

Evidence status: **verified**

On scranton, cmd.exe spawned by the ProgramData .scr dropper launched the PowerShell chain that performed the credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:14.894Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hx0W8y | q-c60ca45392 | ok |
| 2 | 2020-05-02 02:56:14.894Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\cmd.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hx0W8y | q-c60ca45392 | ok |

### F11 · malicious / medium · T1056.001 · Clipboard/keystroke capture: Get-Clipboard executed in the pbeesly session on scranton after the stager ran

Evidence status: **verified**

At 03:06:42Z on scranton.dmevals.local, PowerShell (PID 3852, user pbeesly, SID S-1-5-21-1830255721-3727074217-2423397540-1107) executed the script block 'Get-Clipboard' — harvesting whatever the user had copied (passwords, tokens). This follows the .scr execution (02:55:56Z) and the hidden IEX stager (02:58:44Z) on the same host/session. No SetWindowsHookEx/GetAsyncKeyState keylogger code was found in script-block logging (C065 zero hits), so the observed input capture is clipboard-based rather than a kernel/user hook keylogger.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:42.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Clipboard | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvTCuG | q-22dec9122a | ok |
| 2 | 2020-05-02 03:06:42.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvTCuG | q-22dec9122a | ok |
| 3 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7q0Y_4v | q-c5748841dc | ok |

### F14 · malicious / medium · T1056.004 · Credential API access to lsass.exe from PowerShell and wsmprovhost with full-access masks

Evidence status: **verified**

Two non-standard processes obtained full-access handles to lsass.exe: PowerShell.exe PID 2976 on scranton.dmevals.local at 03:05:16Z (0x1F3FFF and 0x1FFFFF, call trace ending in UNKNOWN module) — the same process that ran the hidden PNG-decoding IEX stager — and wsmprovhost.exe PID 7720 on nashua.dmevals.local at 03:09:29Z (0x1F3FFF, call trace through System.ni.dll / Microsoft.PowerShell.Commands.Management.ni.dll, i.e. PowerShell remoting). The remaining high masks (csrss/wininit 0x1FFFFF, svchost 0x101001/0x3000) are normal system accessors. No MiniDump/comsvcs script blocks or lsass strings were found in PowerShell or other logs (C081/C082 zero hits), so the hooking is via direct process-handle access rather than a dump utility.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-04b2c67fea | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-03b4deddd6 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-6464b07b38 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-6464b07b38 | ok |
| 5 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\csrss.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpgKyU | q-04b2c67fea | ok |

### F17 · malicious / high · T1110.002 · Credential material accessed in memory: steganography-launched PowerShell opened lsass with 0x1f3fff/0x1fffff on scranton

Evidence status: **verified**

On scranton.dmevals.local, powershell.exe PID 2976 (started 2020-05-02T02:58:44Z by control.exe with '-noni -noexit -ep bypass -window hidden' decoding a payload from C:\Users\pbeesly\Downloads\monkey.png and IEX-ing it) opened lsass.exe (PID 736) twice at 03:05:16Z with GrantedAccess 0x1f3fff and 0x1fffff — full-process access masks consistent with reading LSASS memory to extract credential hashes/secrets for offline cracking. The call trace ends in an UNKNOWN module, unlike the benign 0x1000 query-only accesses from powershell.exe PID 3876 at 03:01:03Z. No SAM/NTDS file copies or hive dumps were found (the 'SAM' ObjectName hits are lsass.exe itself opening the SAM object as SCRANTON$, and the only *_hash* file created was _hashlib.pyd in a PyInstaller temp dir), so the cracking-relevant artifact is the in-memory LSASS access rather than an on-disk hive.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-6a18606b56 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-6a18606b56 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-91d1c0c876 | ok |
| 4 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-7fc09043c7 | ok |
| 5 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-7fc09043c7 | ok |
| 6 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectName | SAM | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ryFh2_ | q-9b48deae40 | ok |

### F20 · malicious / medium · T1111 · PowerShell and WinRM host processes opened LSASS with full-access masks on scranton and nashua during a hands-on-keyboard intrusion

Evidence status: **verified**

On 2020-05-02 between 03:05 and 03:09 UTC, two non-standard processes obtained high-privilege handles to lsass.exe: PowerShell.exe (PID 2976) on scranton.dmevals.local requested 0x1f3fff and 0x1fffff (PROCESS_ALL_ACCESS) at 03:05:16, and wsmprovhost.exe (PID 7720) on nashua.dmevals.local requested 0x1f3fff at 03:09:29 with a call trace through System.ni.dll / Microsoft.PowerShell.Commands.Management.ni.dll, i.e. a PowerShell cmdlet reading LSASS. These are the only two PowerShell-family sources among 326 LSASS-access events (the rest are svchost.exe, Azure antimalware/telemetry, wininit, csrss, services). The same user pbeesly on scranton was concurrently running a credential/token-focused PowerShell toolkit from C:\Program Files\SysinternalsSuite (readme.ps1 enumerating SE_GROUP_LOGON_ID token attributes, psversion.ps1 containing an Invoke-Exfil function with hardcoded credentials), accesschk.exe, sdelete64.exe anti-forensics, and PsExec64.exe to \\NASHUA with a cleartext password. This is credential/token material harvesting from LSASS in the course of a broader intrusion. No smartcard, SCardSvr, certificate-provider or MFA-interception artefacts were observed, so the activity is credential access rather than MFA interception specifically.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-1d01584b0c | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-1d01584b0c | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-1d01584b0c | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-1d01584b0c | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-1d01584b0c | ok |
| 6 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvTCvl | q-9ec8f6c5ad | ok |
| 7 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-3993fd8f02 | ok |
| 8 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-2b631686d8 | ok |

### F24 · malicious / high · T1212 · PowerShell (pbeesly) opened lsass.exe with full access on scranton and nashua after a steganographic PowerShell loader — credential theft via post-exploitation tooling

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a hidden, execution-policy-bypassing PowerShell one-liner (parent control.exe /name Microsoft.BackupAndRestoreCenter) that decoded a payload from C:\Users\pbeesly\Downloads\monkey.png via System.Drawing pixel extraction and IEX'd it (2020-05-02T02:58:44Z). At 03:05:16Z that PowerShell (PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1f3fff and 0x1fffff — full read/write/VM access, the classic LSASS credential-dump access mask — with an UNKNOWN call trace outside any signed module. Windows Security corroborates: 4656/4663 on \Device\HarddiskVolume2\Windows\System32\lsass.exe by C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe under SubjectUserName pbeesly with AccessMask 0x1f3fff/0x1fffff/0x10 at 23:05:16 local. The same actor then moved laterally: wsmprovhost.exe on nashua.dmevals.local opened lsass.exe with 0x1f3fff at 03:09:29Z (4656, SubjectUserName pbeesly), and pbeesly installed PSEXESVC services on nashua (7045/4697 at 23:11:39, 23:12:46, 23:13:49, 23:15:03) with type-3/type-2 logons from 10.0.1.4. A 4104 script block on scranton (pbeesly, path C:\Program Files\SysinternalsSuite\psversion.ps1) defines Invoke-Exfil, which 7-Zips the user's Downloads with password 'lolol' and copies it to a WebDAV share at \\192.168.0.4\webdav using hardcoded credentials. A service 'Java(TM) Virtual Machine Support Service' pointing at C:\Windows\System32\javamtsup.exe was installed on scranton by pbeesly at 23:04:15 and executed at 03:19:14Z. The remaining LSASS accesses (svchost.exe 289, AntimalwareConfig.exe 15, WindowsAzureTelemetryService.exe 13, csrss/wininit/services at boot) are normal system/AV behaviour; the PowerShell and wsmprovhost accesses with 0x1f3fff/0x1fffff are not.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-f0b29e4b95 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-f0b29e4b95 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D252982) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-7af755684d | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-f0b29e4b95 | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-f0b29e4b95 | ok |
| 6 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-40015b3135 | ok |
| 7 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-233a37f7d0 | ok |
| 8 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq7mb8 | q-254a826325 | ok |
| 9 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq7mb8 | q-254a826325 | ok |
| 10 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq7mb8 | q-254a826325 | ok |
| 11 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7njy6Co | q-254a826325 | ok |
| 12 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-5f50addad2 | ok |
| 13 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-661d543a05 | ok |
| 14 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | win.ImagePath | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuDg | q-8f4fb35a43 | ok |
| 15 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCk | q-8f4fb35a43 | ok |
| 16 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNuT | q-ef9cd2645d | ok |

### F27 · malicious / high · T1552.001 · Credential-harvesting toolkit on scranton: accesschk passwordsDB, discovery, and exfil of collected files

Evidence status: **verified**

On scranton.dmevals.local, pbeesly ran a staged credential-access toolkit from C:\Program Files\SysinternalsSuite. At 03:04:03 Invoke-Discovery enumerated AV/firewall products, OS info and local groups; at 03:04:34-35 accesschk.exe (child of powershell.exe) ran and created the file C:\Program Files\SysinternalsSuite\passwordsDB, a credential-dump artifact; at 03:08:02 Invoke-Exfil compressed the user's Downloads directory (which by then held the exported .pfx) into %APPDATA%\OfficeSupplies.7z with password 'lolol' and copied it to a WebDAV share at \\192.168.0.4\webdav using hardcoded credentials cozy/MyCozyPassw0rd!. Sysmon confirms C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z created by powershell.exe at 03:08:35. The same actor then used harvested credentials explicitly: PsExec64.exe was launched four times (03:11:18, 03:12:25, 03:13:28, 03:14:42) with '-u dmevals\pbeesly -p Fl0nk3rt0n!T0by' against \\NASHUA, and security 4648 explicit-credential logons for pbeesly appear on scranton (source 10.0.1.6) and on nashua via C:\Windows\PSEXESVC.exe.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hRQwNS | q-80a3ffd500 | ok |
| 2 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\accesschk.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hRQwNS | q-80a3ffd500 | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-8bf5bf3fb5 | ok |
| 4 | 2020-05-02 03:04:03.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Discovery {     $DiscoveryInfo =@()     $CurrentDir = Get-Location      $DiscoveryInfo += [PSCustomObject]@{                 CurrentDirectory = … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSytV | q-ebb1c88d89 | ok |
| 5 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c_44mH | q-5434085036 | ok |
| 6 | 2020-05-02 03:12:25.384Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7h03AIc | q-18516266eb | ok |
| 7 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-93e52cf67f | ok |

### F54 · malicious / high · T1552.001 · Nashua: PsExec-launched python.exe ran PowerShell credential-file harvesting and RAR staging

Evidence status: **verified**

On nashua, PsExec-started python.exe spawned PowerShell as pbeesly that collected *pass*/*login*/*admin* files into working.zip, then Rar.exe password-protected it.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRC92 | q-01993b0b23 | ok |
| 2 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c4xY6Y | q-1724c4a0bf | ok |
| 3 | 2020-05-02 03:15:48.652Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7culihF | q-dda74cf532 | ok |

### F58 · malicious / high · T1552.001 · Scranton: accessChk passwordsDB collection and cleartext credential reuse via PsExec64

Evidence status: **verified**

On scranton, PowerShell ran accessChk.exe which wrote passwordsDB, and PsExec64 reused the cleartext pbeesly password to push python.exe to NASHUA.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-1724c4a0bf | ok |
| 2 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hRQwNS | q-f80bbbd2c9 | ok |

### F60 · malicious / medium · T1552.002 · Scranton: elevated hostui.exe executed registry-stored payload

Evidence status: **NOT verified (1/2 evidence items)** — excluded from the verdict

On scranton, hostui.exe was started elevated via runas and then executed a registry-stored Invoke-Expression payload, followed by a hidden encoded PowerShell.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:27.859Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YJ9aYA | q-c60ca45392 | ok |
| 2 |  | None | None | process.command_line | Start-Process C:\Windows\System32\hostui.exe -verb runas | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7b8wDMC | q-c60ca45392 | FAILED: cited query did not return this event; event not found |

### F26 · malicious / high · T1552.004 · PowerShell Get-PrivateKeys exports every LocalMachine certificate to password-protected .pfx files on scranton

Evidence status: **verified**

On 2020-05-02 at 03:04:56 UTC (23:04:56 local) on scranton.dmevals.local, user pbeesly (SID S-1-5-21-1830255721-3727074217-2423397540-1107) executed a script block named 'Get-PrivateKeys' (ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b, Path C:\Program Files\SysinternalsSuite\readme.ps1). It hardcodes the export password 'saribas' via ConvertTo-SecureString -AsPlainText, enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint into $env:USERPROFILE\Downloads\<random>.pfx. One second later (03:04:57.460Z) Sysmon recorded the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by powershell.exe, confirming the private keys were actually written to disk. This is part of a larger credential-harvesting toolkit on the same host (Invoke-Discovery at 03:04:03, accesschk.exe creating C:\Program Files\SysinternalsSuite\passwordsDB at 03:04:35, Invoke-Exfil at 03:08:02 which 7-Zips the Downloads folder to %APPDATA%\OfficeSupplies.7z and copies it to \\192.168.0.4\webdav).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-be0a603b7d | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-be0a603b7d | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-be0a603b7d | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-5434085036 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-5434085036 | ok |

### F55 · malicious / high · T1552.004 · Scranton: Get-PrivateKeys exported LocalMachine cert private keys to .pfx and exfiltrated via WebDAV

Evidence status: **verified**

On scranton as pbeesly, Get-PrivateKeys exported LocalMachine cert keys to .pfx in Downloads, Invoke-Exfil 7z-compressed Downloads to \\192.168.0.4\webdav, then cleanup deleted the artifacts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-86f0624877 | ok |
| 2 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-f80bbbd2c9 | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-9486995ba4 | ok |

### F30 · malicious / high · T1555 · Credential-store theft on scranton: private-key/certificate export and lsass memory access by attacker PowerShell

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran an attacker toolkit from C:\Program Files\SysinternalsSuite\readme.ps1 (dot-sourced at 03:03:57Z). At 03:04:56Z the Get-PrivateKeys function was defined and invoked, exporting every LocalMachine certificate with a private key to a random .pfx in the user's Downloads folder protected by the hardcoded password "saribas"; the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx was created at 03:04:57Z by powershell.exe. At 03:05:16Z the same PowerShell process (PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1F3FFF and then 0x1FFFFF (PROCESS_ALL_ACCESS) — read-memory access consistent with credential harvesting from LSASS. This is part of a broader hands-on-keyboard intrusion on scranton (Sysinternals download, sdelete64 anti-forensics, Invoke-Discovery, Invoke-Persistence, Invoke-Exfil).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-216a114038 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-92428f6296 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvTSsN | q-c3a02648c3 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-e81312634e | ok |
| 5 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-617edb4894 | ok |
| 6 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-f3c64892ee | ok |

### F57 · malicious / medium · T1555.003 · Scranton: user credential-bearing files archived and staged for exfiltration

Evidence status: **verified**

On scranton, powershell.exe as pbeesly wrote Draft.Zip and compressed Downloads into OfficeSupplies.7z for WebDAV exfil, then deleted the archives with sdelete64.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:18.032Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\Draft.Zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hwzKeY | q-f80bbbd2c9 | ok |
| 2 | 2020-05-02 03:03:14.693Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\Users\pbeesly\AppData\Roaming\Draft.Zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hUTVpm | q-1724c4a0bf | ok |

### F34 · malicious / medium · T1556 · Attacker PowerShell opened LSASS with full access (0x1FFFFF) on scranton during hands-on-keyboard intrusion

Evidence status: **verified**

On scranton.dmevals.local, in the middle of a hands-on-keyboard intrusion by user pbeesly (steganographic IEX from monkey.png, SysinternalsSuite staging, sdelete64 wiping, Invoke-Discovery/Invoke-Persistence, Get-PrivateKeys certificate export), a PowerShell.exe process (PID 2976) opened lsass.exe with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) at 2020-05-02T03:05:16.654Z, preceded 31 ms earlier by a 0x1f3fff open. The call trace ends in an UNKNOWN module, i.e. code not in a loaded image. This is consistent with in-memory credential access against the authentication process rather than a legitimate auth-process modification; no LSA Notification Packages / SecurityProviders registry write was observed, so the tampering itself is not confirmed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-ea9bc7dcf6 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-ed8efb3a32 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-ea9bc7dcf6 | ok |
| 4 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-8d3e1ba51f | ok |
| 5 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-e6e029ff69 | ok |

### F43 · malicious / medium · T1557 · AiTM positioning confirmed by L2 redirection; ARP.EXE/ROUTE.EXE/ipconfig hits are Azure guest-agent telemetry (benign)

Evidence status: **verified**

The adversary-in-the-middle position is established by the L2 evidence: one MAC (12:34:56:78:9a:bc) is the responder for every off-subnet destination and for the intra-subnet SMB session, and two self-signed-certificate notices fired on the intercepted flows. The high-volume hits that looked like network reconnaissance on the Windows side are benign: all 11 ARP.EXE /a, ROUTE.EXE print, ipconfig /all and netsh trace invocations on scranton.dmevals.local at 03:19-03:20Z were spawned by Azure guest/telemetry agents (WaAppAgent.exe, WindowsAzureGuestAgent.exe, WindowsAzureTelemetryService.exe, NetworkWatcherAgent.exe) running as SYSTEM, which is normal Azure VM health telemetry. The 4663/4656/4670 object-access hits are dominated by routine registry auditing (Session Manager\Environment, Lsa, Winlogon) and the 4657 hits are WMI Autologger key writes, not DNSClient/EnableMulticast tampering.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:40:22.431Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1aD | q-94a2b6e8ed | ok |
| 2 | 2020-04-30 00:15:18.392Z | simplerockbuild.simplerock.lan | zeek | zeek.note | SSL::Invalid_Server_Cert | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Zlbm | q-bdc766645b | ok |
| 3 | 2020-05-02 03:20:04.471Z | scranton.dmevals.local | windows.sysmon | process.command_line | "arp.exe" /a | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cREvLs | q-46ba6852b8 | ok |
| 4 | 2020-05-02 03:20:04.471Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\WaAppAgent.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cREvLs | q-46ba6852b8 | ok |
| 5 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cla5Dm | q-46ba6852b8 | ok |

### F41 · malicious / high · T1557.002 · Single MAC 12:34:56:78:9a:bc answers as L2 peer for every off-subnet destination (ARP cache poisoning)

Evidence status: **verified**

In the Zeek window (2020-04-30 00:06-00:45Z) all traffic from the 10.0.1.0/24 hosts to off-subnet addresses is delivered to one responder MAC, 12:34:56:78:9a:bc. That MAC is the resp_l2_addr for 10.0.0.4 (66 flows from 10.0.1.4, 54 from 10.0.1.6), for 192.168.0.4 (376 flows from 10.0.1.6 on 8443, 16 from 10.0.1.4 on 80/445/139) and for 192.168.0.5 (3 flows from 10.0.1.4 on 443/1234). A single L2 address cannot legitimately be the gateway for three different IP subnets, which is the signature of an attacker answering ARP for the gateway/router addresses. The same MAC also appears as the responder on the SMB (445) sessions from 10.0.1.4 to 10.0.1.6, i.e. intra-subnet SMB was also redirected through it. The genuine host MACs are 00:0d:3a:4d:42:f2 (10.0.1.4), 00:0d:3a:13:e3:69 (10.0.1.6) and fc:bd:67:e1:a9:c1. Two SSL::Invalid_Server_Cert notices ('self signed certificate') were raised on the flows to 192.168.0.5:443 and 192.168.0.4:8443, consistent with traffic being intercepted by a non-legitimate endpoint. Note the Zeek window does not overlap the Windows telemetry window, so this is a separate observation of the same campaign.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:40:22.431Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1aD | q-94a2b6e8ed | ok |
| 2 | 2020-04-30 00:40:22.431Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 10.0.1.6 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1aD | q-94a2b6e8ed | ok |
| 3 | 2020-04-30 00:40:22.431Z | simplerockbuild.simplerock.lan | zeek | zeek.orig_l2_addr | 00:0d:3a:4d:42:f2 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1aD | q-94a2b6e8ed | ok |
| 4 | 2020-04-30 00:15:18.392Z | simplerockbuild.simplerock.lan | zeek | zeek.msg | SSL certificate validation failed with (self signed certificate) | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Zlbm | q-bdc766645b | ok |
| 5 | 2020-04-30 00:40:44.740Z | bobs.bigwheel.local | zeek | zeek.msg | SSL certificate validation failed with (self signed certificate) | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7qUct2z | q-bdc766645b | ok |

### F53 · malicious / high · T1649 · PowerShell Get-PrivateKeys exports LocalMachine cert private keys to .pfx on scranton

Evidence status: **verified**

After the malicious C:\ProgramData\victim\â€®cod.3aka3.scr ran as pbeesly, a PowerShell scriptblock (Get-PrivateKeys, readme.ps1) exported every cert:\LocalMachine private key via Export-PfxCertificate to C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx, then a cleanup function deleted Downloads\*.pfx.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-6c94e44b6d | ok |
| 2 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-4616cf320d | ok |
| 3 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRC9i | q-fec88a2ccd | ok |

### F02 · suspicious / medium · T1003 · Credential-access tooling staged: SysinternalsSuite downloaded and extracted by the same hidden PowerShell on scranton

Evidence status: **verified**

The hidden PowerShell PID 2976 on scranton.dmevals.local wrote C:\Users\pbeesly\Downloads\SysinternalsSuite.zip at 2020-05-02T02:59:42Z, and a second PowerShell (PID 3876) extracted the suite (hostui.txt, psversion.txt, readme.txt, Eula.txt) at 03:00:27–03:00:32Z. SysinternalsSuite contains procdump, a common LSASS dumping utility, and the extraction immediately precedes the lsass access at 03:05:16Z. No procdump command line was observed in 4688/Sysmon event 1, so the actual dump utility invocation is not directly captured; the staging is nonetheless part of the same intrusion chain.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:59:42.544Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\SysinternalsSuite.zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hjk9tr | q-605a3190fa | ok |
| 2 | 2020-05-02 03:00:27.205Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\SysinternalsSuite\hostui.txt | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hbcHpK | q-605a3190fa | ok |

### F56 · suspicious / medium · T1003.002 · Scranton: SAM hive opened with 0xf003f by lsass.exe after attacker tooling ran

Evidence status: **verified**

On scranton at 03:19-03:20, five 4656 events show SAM opened with 0xf003f by lsass.exe under SCRANTON$, right after the attacker's lsass access and cleanup.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectName | SAM | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ryFh2_ | q-05388df760 | ok |
| 2 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0xf003f | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ryFh2_ | q-05388df760 | ok |

### F28 · suspicious / medium · T1552.002 · Registry reads of LSA and Winlogon keys by powershell.exe on scranton

Evidence status: **verified**

Security 4663 key-access events show C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe reading \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa and \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon on scranton.dmevals.local as pbeesly (71 Winlogon and 25 Lsa accesses), starting at 02:56:14 UTC, i.e. in the same session that later ran Get-PrivateKeys/Invoke-Exfil. The bulk of Lsa/Winlogon access on all four hosts is by svchost.exe, lsass.exe, winlogon.exe and WmiPrvSE.exe, which is normal system behaviour; the powershell.exe reads are the outlier. No registry values containing credentials were observed being written or read out, so this is assessed as suspicious rather than confirmed credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:14.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rxFDK4 | q-072a42657e | ok |
| 2 | 2020-05-02 02:56:14.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rxFDKr | q-072a42657e | ok |
| 3 | 2020-05-02 02:56:14.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rxFDKr | q-072a42657e | ok |

### F63 · suspicious / low · T1552.002 · Scranton: sdclt.exe spawned by cmd.exe in attacker session

Evidence status: **verified**

On scranton, sdclt.exe was started three times by cmd.exe in the attacker session at 02:58:42-43, immediately before the csc.exe compile; no credential access by sdclt itself was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\sdclt.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7huwtP3 | q-1724c4a0bf | ok |
| 2 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\cmd.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7huwtP3 | q-1724c4a0bf | ok |

### F31 · suspicious / medium · T1555.004 · No Windows Credential Manager / Vault access observed; lsass access by PowerShell is the only credential-store-relevant hit

Evidence status: **verified**

No cmdkey, vaultcmd, Credential Manager file writes (\Microsoft\Credentials, \Vault) or 4663 reads of Credential/Vault objects were found (checks C182, C185, C186, C175 returned nothing relevant). The only credential-store-relevant activity is the PowerShell process on scranton.dmevals.local opening lsass.exe with 0x1F3FFF/0x1FFFFF at 03:05:16Z, which is LSASS memory access rather than Credential Manager API use. Other lsass handles (svchost 0x1000, WindowsAzureTelemetryService 0x1400, csrss/wininit 0x1FFFFF at boot) are normal system behaviour. The nashua wsmprovhost.exe 0x1F3FFF handle at 03:09:29Z carries a PowerShell/System.ni.dll call trace and is consistent with the remote Invoke-Command session pbeesly ran against NASHUA, not a dump.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-617edb4894 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-a097ef2f19 | ok |
| 3 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRbzS | q-d9a09ebdb0 | ok |

### F42 · suspicious / medium · T1557.001 · SMB sessions to 10.0.1.6:445 relayed through the same rogue MAC; SMB/RPC used for credential access and lateral movement

Evidence status: **verified**

All 45 SMB (445) connections in the Zeek window from 10.0.1.4 to 10.0.1.6 carry resp_l2_addr 12:34:56:78:9a:bc, the same MAC that fronts the off-subnet gateways, so the SMB session to NASHUA was not delivered by NASHUA's own NIC (00:0d:3a:13:e3:69). Over those sessions the client performed SMB mapping to \\NEWYORK\IPC$ and \\NEWYORK.dmevals.local\sysvol and DCE-RPC SAMR/LSAR enumeration (SamrConnect5, SamrEnumerateDomainsInSamServer, SamrLookupNamesInDomain, SamrOpenUser, SamrQueryInformationUser, LsarOpenPolicy2, LsarLookupNames3, LsarEnumerateTrustedDomains) against 10.0.0.4, plus ept_map calls to 10.0.1.6. Zeek also logged 'unknown_dce_rpc_auth_type' weirds on both 10.0.1.4 and 10.0.1.6 to 10.0.0.4. On the Windows side (non-overlapping window) the same account pbeesly used PsExec64 with a cleartext password to reach \\NASHUA ADMIN$ and drop C:\Windows\Temp\python.exe, and SYSVOL GPO files (gpt.ini, GptTmpl.inf) were read from NEWYORK. The relay/poisoning is confirmed by the L2 evidence; the SMB relay itself is inferred, not directly observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:40:22.431Z | simplerockbuild.simplerock.lan | zeek | destination.port | 445 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1aD | q-94a2b6e8ed | ok |
| 2 | 2020-04-30 00:40:22.431Z | simplerockbuild.simplerock.lan | zeek | zeek.service | gssapi | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1aD | q-94a2b6e8ed | ok |
| 3 | 2020-04-30 00:35:04.288Z | simplerockbuild.simplerock.lan | zeek | zeek.path | \\NEWYORK\IPC$ | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1bM | q-bdc766645b | ok |
| 4 | 2020-04-30 00:35:04.376Z | simplerockbuild.simplerock.lan | zeek | zeek.operation | SamrOpenUser | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1Zv | q-f5b49a07cf | ok |
| 5 | 2020-04-30 00:35:04.274Z | simplerockbuild.simplerock.lan | zeek | zeek.name | unknown_dce_rpc_auth_type | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Zlbb | q-bdc766645b | ok |
| 6 | 2020-05-02 03:12:25.384Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7h03AIc | q-2c9073608a | ok |

### F46 · suspicious / medium · T1558.001 · PowerShell on scranton.dmevals.local opened lsass.exe with full access (0x1FFFFF) during a hands-on-keyboard intrusion

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976, running as SYSTEM per the event's AccountName) opened lsass.exe (PID 736) twice within 31 ms at 03:05:16 with GrantedAccess 0x1f3fff and 0x1fffff — full-process access consistent with credential/ticket extraction from LSASS. This is the only PowerShell-to-lsass access in the dataset and it occurs inside a confirmed intrusion chain on the same host: a malicious screen saver C:\ProgramData\victim\cod.3aka3.scr launched from explorer.exe by user pbeesly at 02:55:56, which spawned cmd.exe and powershell.exe, followed by archive/collection script blocks, a HKCU Folder\shell\open\command DelegateExecute hijack, an IEX loader decoding a payload from monkey.png, csc.exe compilation, and sdelete64.exe wiping the .scr at 03:02:04. No krbtgt hash dump, golden-ticket creation or forged-TGT use is directly evidenced: the 4769 krbtgt requests on newyork are successful normal TGS requests and no 4768/4769 anomaly (e.g. RC4 0x17, missing pre-auth, unknown accounts) appears. The LSASS access is therefore treated as suspicious credential/ticket harvesting rather than confirmed golden-ticket forgery.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-03892e53f6 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-03892e53f6 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-1cd83643fb | ok |
| 4 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy0krT | q-580e1c2bb9 | ok |
| 5 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hWVSlm | q-580e1c2bb9 | ok |
| 6 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7q0Y_4v | q-f6f264ce90 | ok |

### F51 · suspicious / medium · T1606.001 · Only WebDAV cookie set by davclnt.dll during exfiltration staging; no browser cookie theft/forgery

Evidence status: **verified**

The single cookie-related file event is C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_...\AC\INetCookies created by svchost.exe on scranton at 03:21:05 (a Windows service-profile INetCookies store, not a browser credential store). The only cookie-manipulating process activity is rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav run as pbeesly on scranton at 03:08:50 and 03:10:22-23, which matches the Invoke-Exfil PowerShell function (script block b2b03a9c-43f0-4285-837d-f22d4600b2ae, path C:\Program Files\SysinternalsSuite\psversion.ps1) that maps \\192.168.0.4\webdav with hardcoded credentials and copies OfficeSupplies.7z there. This is WebDAV authentication for exfiltration, not forging of web cookies; no cookie text appears in any PowerShell script block or windows.other message.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c93Nx4 | q-1d44ee9411 | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cPCBow | q-7c97cbbc6b | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockId | b2b03a9c-43f0-4285-837d-f22d4600b2ae | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-5be83ce4b5 | ok |

### F03 · benign / medium · T1003.002 · SAM hive value write by lsass.exe on scranton is normal OS behaviour, not hive theft

Evidence status: **verified**

The only SAM-related registry write in the window is HKLM\SAM\SAM\Domains\Account\F at 2020-05-02T03:19:10Z on scranton.dmevals.local, written by C:\windows\system32\lsass.exe itself (the legitimate owner of the SAM hive). No reg save/reg export, esentutl, vssadmin or hive-file copy was observed (C017/C018/C020/C021/C022 all zero hits), and the three 'SAM/SECURITY' file-create hits were only Prefetch .pf files. The 16962 event about remote SAM access restriction is a default security-descriptor notice. No evidence of SAM dumping.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SAM\SAM\Domains\Account\F | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpgKxF | q-121adc756f | ok |
| 2 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpgKxF | q-121adc756f | ok |

### F04 · benign / high · T1003.003 · No NTDS.dit access, shadow copy or ntdsutil activity observed

Evidence status: **verified**

All NTDS checks (C024–C030) returned zero hits: no ntdsutil/vssadmin/diskshadow command lines, no .dit file creation or access, no 4663 object access on ntds. The hosts in scope are member workstations/servers, not domain controllers, so NTDS extraction was not attempted in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SAM\SAM\Domains\Account\F | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpgKxF | q-121adc756f | ok |

### F05 · benign / medium · T1003.004 · No LSA Secrets extraction; lsass accessors are baseline AV/telemetry

Evidence status: **verified**

The 326 lsass process-access events are dominated by svchost.exe (289, masks 0x1000/0x1400/0x101001/0x3000 with lsm.dll/sysmain.dll call traces), AntimalwareConfig.exe (15) and WindowsAzureTelemetryService.exe (13) — normal security/telemetry behaviour. No lsadump, reg save of SECURITY\Policy\Secrets, or SECURITY hive file copy was found (C032/C035/C037/C038 zero hits). The only SECURITY-related registry writes are HKLM\SECURITY\Cache\NL$1 by lsass.exe (see T1003.005). The malicious lsass access is reported under T1003.001.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9def4\|c:\windows\system32\lsm.dll+1aa6e\|c:\windows\system32\lsm.dll+1a9c3\|c:\windows\system32\lsm.dll+65e1\|c:\windows\system32… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cyrL9g | q-231c467015 | ok |

### F06 · benign / medium · T1003.005 · HKLM\SECURITY\Cache\NL$1 writes are lsass.exe updating the cached-credential store, not extraction

Evidence status: **verified**

Five writes to HKLM\SECURITY\Cache\NL$1 (four on nashua.dmevals.local 03:11:40–03:15:03Z, one on scranton.dmevals.local 03:20:46Z) were all performed by C:\windows\system32\lsass.exe, the legitimate owner of the cached domain credential store, consistent with normal logon/cache refresh. No mscache/dcc2/cache-dumping command line or script was found (C040/C042/C044/C045 produced no malicious hits). Note: the actor's lsass memory read on the same hosts could have captured cached credentials in memory, but that is covered by T1003.001.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | registry.path | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82OiA | q-121adc756f | ok |
| 2 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82OiA | q-121adc756f | ok |

### F07 · benign / medium · T1003.006 · Single 4662 replication-GUID read by machine account NEWYORK$ is not DCSync

Evidence status: **verified**

One 4662 event on newyork.dmevals.local at 2020-05-01T23:16:15-04:00 shows SubjectUserName NEWYORK$ (the computer account itself) with AccessMask 0x100 on object %{11487126-e2dc-4f51-acb1-1b0df0573bb5} and property {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}. A DCSync would show a user account (not the machine account) requesting DS-Replication-Get-Changes/Get-Changes-All against the domain NC, typically repeatedly. No DCSync/Invoke-Mimikatz/lsadump script blocks were found (C049 zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nhwFD7 | q-a6b53512c3 | ok |
| 2 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.AccessMask | 0x100 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nhwFD7 | q-a6b53512c3 | ok |

### F08 · benign / high · T1040 · Azure Network Watcher agent ran netsh packet capture on scranton (legitimate platform telemetry)

Evidence status: **verified**

On 2020-05-02 at 03:19:17Z on scranton.dmevals.local, netsh.exe was launched as NT AUTHORITY\SYSTEM with 'trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl"' and stopped 7 seconds later with 'netsh trace stop'. The parent process is the Microsoft Azure NetworkWatcherAgent.exe (/service) from C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\, and the netsh binary carries a Microsoft signature hash (SHA256=90F0822D26680C8FFD703A080C876F87695580747A3704C169E39E1A8802EA38). The same agent was also seen installing/starting itself via cmd.exe. This is the Azure Network Watcher packet-capture feature, not adversary sniffing: no pktmon/windump/tcpdump/rawcap command lines, no pcap/npcap/wpcap driver loads, no capture-related PowerShell script blocks, and no .pcap/.cap files were written anywhere in the window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cla5Dm | q-8a0974c63c | ok |
| 2 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cla5Dm | q-7857d0958c | ok |
| 3 | 2020-05-02 03:19:24.835Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cjZNnV | q-8a0974c63c | ok |
| 4 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe"  Install /service /autoSt… | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nKhItI | q-0b64f8aa27 | ok |

### F09 · benign / medium · T1040 · No adversary network-sniffing tooling observed; python.exe on nashua is C2 traffic, not sniffing

Evidence status: **verified**

Hunting for T1040 across all four datasets found no attacker sniffing. The suspicious activity in the window is instead lateral movement: from scranton.dmevals.local, powershell.exe launched PsExec64.exe with the plaintext credential '-u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe' against \\NASHUA, which installed PSEXESVC and started C:\Windows\Temp\python.exe as pbeesly on nashua.dmevals.local. That python.exe then made 348 outbound TCP connections to 192.168.0.4:8443 (e.g. source 10.0.1.6:60048), i.e. command-and-control/exfiltration rather than passive capture. No pcap/npcap/wpcap image loads, no pktmon/windump/tcpdump/rawcap command lines, no capture-related PowerShell script blocks, and no .pcap/.cap files were found. The logman.exe executions on scranton are the Azure WaAppAgent stopping its own GAEvents/RTEvents collectors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNv3 | q-3cba393491 | ok |
| 2 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.port | 8443 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c5ylrT | q-093a7a9f21 | ok |
| 3 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c5ylrT | q-093a7a9f21 | ok |
| 4 | 2020-05-02 03:18:38.000Z | scranton.dmevals.local | windows.security | process.command_line | "logman.exe" stop GAEvents | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ncsZp3 | q-3cba393491 | ok |

### F12 · benign / medium · T1056.002 · No fake credential-prompt / GUI input capture observed; LogonUI and consent.exe are legitimate

Evidence status: **verified**

Process-creation stacking (C066) and targeted review of LogonUI.exe, consent.exe and rundll32.exe showed only expected Windows behaviour: LogonUI.exe spawned by winlogon.exe with /flags:0x4 and /flags:0x2 on scranton (03:18:30Z, 03:19:10Z), consent.exe spawned by svchost.exe for UAC on scranton and nashua, and rundll32.exe davclnt.dll,DavSetCookie for WebDAV to 192.168.0.4. No credential-prompt lookalike binaries or Get-Credential/CredentialPrompt script blocks were found (C067 zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:30.950Z | scranton.dmevals.local | windows.sysmon | process.command_line | "LogonUI.exe" /flags:0x4 /state0:0xa3cb8855 /state1:0x41c64e6d | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c0sdf6 | q-845840d218 | ok |
| 2 | 2020-05-02 02:58:42.868Z | scranton.dmevals.local | windows.sysmon | process.command_line | consent.exe 3060 300 0000018832821060 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7huwtOr | q-845840d218 | ok |
| 3 | 2020-05-02 03:08:50.846Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c-48YI | q-845840d218 | ok |

### F13 · benign / low · T1056.003 · No web portal capture observed in the Windows telemetry

Evidence status: **verified**

No evidence of web-portal credential capture (no injected browser modules, no fake login pages, no proxy/portal-hooking artefacts) was found in the Windows datasets reviewed. The only web-related activity seen was rundll32 davclnt.dll,DavSetCookie against http://192.168.0.4/webdav on scranton, which is normal WebDAV cookie handling. Zeek data does not overlap this window, so network-side portal capture cannot be assessed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:22.994Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c93dwd | q-845840d218 | ok |

### F15 · benign / high · T1110 · No brute-force activity observed; only a single successful credential validation (4776) and no 4625 failures

Evidence status: **verified**

Across windows.security (2020-05-02T02:55:25Z..03:28:09Z) there are zero 4625 failed-logon events and zero 4771 Kerberos pre-auth failures. The only authentication-failure-family event retrieved was a single 4776 credential validation on newyork.dmevals.local for user pbeesly with Status 0x0 (success), i.e. a normal successful NTLM credential check, not a guessing attempt. The 4648 explicit-credential logons on scranton/nashua are pbeesly re-using its own credentials (including via C:\Windows\PSEXESVC.exe on nashua) plus machine-account DWM/UMFD logons, consistent with PsExec administration rather than password guessing. The 'net' command-line hits were all svchost.exe -k netsvcs service hosts and netsh.exe trace commands, i.e. benign system processes. No evidence of brute force, guessing, spraying or stuffing in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nKhItZ | q-5b86a8aeef | ok |
| 2 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | event.code | 4776 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nKhItZ | q-5b86a8aeef | ok |
| 3 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-1fb083b13f | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-ecb97cc043 | ok |

### F16 · benign / high · T1110.001 · No password-guessing pattern: zero 4625 events, no net.exe/user-enumeration guessing command lines

Evidence status: **verified**

Queries for 4625 in windows.security returned zero hits, and the windows.other 'failed' message hits were unrelated (a crash-dump initialization message and a DNS PTR registration failure on scranton). Stacking sysmon process-creation command lines containing 'net' produced only svchost.exe -k netsvcs service instances and two netsh.exe trace commands — no net use / net user / password-bearing command lines. The only PowerShell script block containing a hard-coded password was the Invoke-Exfil function on scranton (user pbeesly), which uses a single static credential ('cozy' / 'MyCozyPassw0rd!') to map a WebDAV drive for exfiltration, not repeated guessing against accounts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:54.000Z | scranton.dmevals.local | windows.other | message | Crash dump initialization failed! | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuAn | q-889cd68375 | ok |
| 2 | 2020-05-02 03:19:20.000Z | scranton.dmevals.local | windows.other | message | The system failed to register pointer (PTR) resource records (RRs) for network adapter  with settings:               Adapter Name : {3F54D943-1568-43BC-9FDA-67D… | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCH | q-889cd68375 | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-17ad45dca5 | ok |

### F18 · benign / high · T1110.003 · No password spraying: no 4625/4771 across multiple accounts, no spray tooling in PowerShell

Evidence status: **verified**

Stacking win.TargetUserName over 4625/4771/4648 in windows.security yielded only pbeesly (9), the machine account SCRANTON$ (1) and DWM-1/DWM-2/UMFD-0/UMFD-1/UMFD-2 (1 each) — all from 4648 explicit-credential events, with zero 4625 and zero 4771. A spray would show one password tried against many distinct accounts; here a single account (pbeesly) is used repeatedly from 10.0.1.6 and via PSEXESVC on nashua, which is consistent with the same operator re-using already-obtained credentials. PowerShell script-block searches for 'spray'/'password' returned only Microsoft module manifests and localized resource strings on newyork, and windows.other contained no 4625/4771 messages.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niydsP | q-1fb083b13f | ok |
| 2 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | source.ip | 10.0.1.6 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niydsP | q-1fb083b13f | ok |
| 3 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | win.ScriptBlockText | # Localized	09/15/2018 04:54 AM (GMT)	303:6.40.10614 	MSFT_ScriptResourceStrings.psd1  # Localized MSFT_ScriptResourceStrings.psd1    ConvertFrom-StringData @' … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qwUVtv | q-a8696bb8a7 | ok |

### F19 · benign / high · T1110.004 · No credential stuffing: no failed logons and no bulk credential-replay tooling

Evidence status: **verified**

Credential stuffing would require many failed authentications from lists of stolen credentials; windows.security contains zero 4625 and zero 4771 events in the window, and the only 4776 was a successful validation (Status 0x0) for pbeesly on newyork. The 218 type-3 network logons are dominated by machine accounts (NEWYORK$ 123, SCRANTON$ 37, NASHUA$ 25, WEC$ 8, UTICA$ 5) plus 20 for pbeesly, i.e. normal service/administrative authentication. The only password-bearing PowerShell was the single static credential in Invoke-Exfil on scranton, used once to mount \\192.168.0.4\webdav for exfiltration, not replayed against multiple accounts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nKhItZ | q-5b86a8aeef | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-17ad45dca5 | ok |

### F21 · benign / medium · T1111 · No smartcard, certificate-provider or MFA-interception artefacts; explicit-credential logons are PsExec administration

Evidence status: **verified**

The MFA-interception-specific indicators were benign or absent. The only registry writes touching Crypto/SCard paths were six default Windows values (Cryptography\Calais SymbolicLinkValue, CertificateTemplateCache timestamps, an SCardSvr.dll MuiCache entry) with no smartcard/MFA configuration change, and windows.other contained no SmartCard/SCardSvr/Certificate messages at all. The single PowerShell script block matching *token* was a token-attribute enumeration helper (Get-AttributesMask), not an MFA/token-theft tool. The 15 event-4648 explicit-credential logons are dominated by pbeesly (9) and are explained by PsExec64.exe -u dmevals\pbeesly against \\NASHUA (PSEXESVC.exe on nashua, TargetServerName NASHUA/localhost), plus routine DWM-1/DWM-2/UMFD-0/UMFD-1/UMFD-2 and SCRANTON$ machine-account logons from winlogon/wininit/taskhostw. Logon types were 3 (218), 5 (61), 2 (15), 10 (2), 0 (1) with no smartcard (type 8) or explicit MFA-related pattern. Zeek kerberos showed 18 success / 7 failure, and the zeek window (2020-04-30) does not overlap the Windows window, so no MFA interception can be tied to it.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-e1d4f4337e | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-85feba3c27 | ok |
| 3 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetServerName | localhost | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-85feba3c27 | ok |
| 4 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | DWM-1 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ncsJoZ | q-85feba3c27 | ok |

### F22 · benign / medium · T1187 · WebDAV traffic from scranton is client-side exfiltration upload, not forced authentication

Evidence status: **verified**

On 2020-04-30 between 00:32:18 and 00:32:21 UTC, host 10.0.1.4 (scranton) used the Windows WebDAV client (user agents 'DavClnt' and 'Microsoft-WebDAV-MiniRedir/10.0.18362') against the WebDAV server at 192.168.0.4:80, issuing OPTIONS, PROPFIND, PUT, LOCK, HEAD, PROPPATCH and UNLOCK on /webdav/OfficeSupplies.7z. The 401 responses are the client being challenged by the server and then authenticating to it; the direction of authentication is client->server, the opposite of T1187 forced authentication (where an attacker lures a victim into authenticating to an attacker-controlled listener). The archive name OfficeSupplies.7z matches the Invoke-Exfil PowerShell function seen on scranton.dmevals.local (Compress-7Zip -ArchiveFileName "$env:APPDATA\OfficeSupplies.7z"), so this traffic is best explained as exfiltration over WebDAV rather than credential coercion. No T1187 lure artifacts were found: the only shortcut file created was C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk by powershell.exe on scranton (persistence-style, not a UNC/WebDAV lure), and no WebClient/NetworkProvider registry modifications were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | DavClnt | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1YZ | q-06fb11dcca | ok |
| 2 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1br | q-06fb11dcca | ok |
| 3 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | http.request.method | PUT | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1YN | q-06fb11dcca | ok |
| 4 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1YN | q-06fb11dcca | ok |
| 5 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | source.ip | 10.0.1.4 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1YN | q-06fb11dcca | ok |
| 6 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hSRzrG | q-c38837d76d | ok |

### F23 · benign / high · T1187 · SMB share access and outbound 445/139 connections are normal domain machine-account traffic

Evidence status: **NOT verified (4/5 evidence items)** — excluded from the verdict

All 42 network share connections (event 5140) are machine-account SYSVOL/IPC$ access by NEWYORK$, NASHUA$, UTICA$, SCRANTON$ and WEC$ to the domain controller, plus pbeesly's ADMIN$/IPC$ access to nashua.dmevals.local from 10.0.1.4 during the PsExec activity. The 66 outbound SMB connections (Sysmon event 3, ports 445/139) are all made by the System process to internal addresses 10.0.0.4 (domain controller), 10.0.1.6 and the link-local fe80::e40c:95b6:b0a7:6429 — no connections to external or attacker-controlled hosts that would indicate SMB-based coercion. No UNC paths pointing to attacker hosts were found in the 5145 share-access targets.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:20.000Z | nashua.dmevals.local | windows.security | win.ShareName | \\*\ADMIN$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nftACH | q-29e8606eae | ok |
| 2 | 2020-05-02 03:18:20.000Z | nashua.dmevals.local | windows.security | win.IpAddress | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nftACH | q-29e8606eae | ok |
| 3 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.0.4 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hWVykL | q-28e4b67843 | ok |
| 4 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hWVykL | q-28e4b67843 | ok |
| 5 | 2020-05-02 02:56:48.006Z | newyork.dmevals.local | windows.sysmon | destination.ip | fe80:0:0:0:e40c:95b6:b0a7:6429 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hwyqfh | q-28e4b67843 | FAILED: claimed value differs from the stored value |

### F25 · benign / high · T1539 · No web session cookie theft observed; browser-store hits are benign Edge/GroupPolicy noise

Evidence status: **verified**

Hunted all four Windows datasets (2020-05-02 02:55–03:28Z) and the separate zeek window (2020-04-30 00:06–00:45Z) for T1539. The 162 sysmon file-creation hits for *Cookies*/*Login Data*/*Web Data* are almost entirely Windows service-state files (C:\Windows\ServiceState\EventLog\Data\lastalive0.dat / lastalive1.dat written by svchost.exe, 133 events) and GroupPolicy DataStore files under C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local. The only non-GroupPolicy/non-lastalive hit is MicrosoftEdge.exe (PID 6208, SYSTEM) creating its own DataStore\_TempTestAccess.txt in pbeesly's Edge package on scranton.dmevals.local at 03:21:05Z, immediately after a normal user-launched Edge session (MicrosoftEdge.exe -ServerName:MicrosoftEdge.AppXdnhjhccw3zf0j06tkg3jtqr00qdm0khc.mca, parent svchost.exe, user pbeesly, 03:21:01Z) with MicrosoftEdgeSH.exe and MicrosoftEdgeCP.exe children. No event anywhere references an actual cookie store (INetCookies, Cookies\, cookies.sqlite, Login Data For Account): targeted sysmon file-create queries returned 0, security 4663 object-access on Cookies/Login Data/Web Data returned 0, and 4663 on Edge/Mozilla/Chrome paths returned 0. The 4 security 4688 hits were SearchProtocolHost.exe (Windows Search indexer, parent SearchIndexer.exe) whose command line merely contains the MS Search robot user-agent string — not browser profile access. No process command line referenced browser profile directories or cookie paths (0 hits), and no PowerShell script block mentioned Cookies/Login Data/sqlite/chrome (0 hits). In the non-overlapping zeek window, all 62 HTTP requests used only Microsoft-WebDAV-MiniRedir/10.0.18362 (61) and DavClnt (1) user agents against 192.168.0.4 (WebDAV PROPFIND/OPTIONS, including /webdav/OfficeSupplies.7z) — no cookie-bearing or scripted HTTP client. Conclusion: no evidence of web session cookie theft on any host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:28.893Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceState\EventLog\Data\lastalive1.dat | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy1EsG | q-6099f24c72 | ok |
| 2 | 2020-05-02 03:21:05.198Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\DataStore\_TempTestAccess.txt | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YE4VZs | q-305300a2a9 | ok |
| 3 | 2020-05-02 03:21:05.198Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YE4VZs | q-305300a2a9 | ok |
| 4 | 2020-05-02 03:21:01.765Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe" -ServerName:MicrosoftEdge.AppXdnhjhccw3zf0j06tkg3jtqr00qdm0khc.mca | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRfJfH5wFd7b-xybj | q-b7b8b74f14 | ok |
| 5 | 2020-05-02 03:21:01.765Z | scranton.dmevals.local | windows.sysmon | user.name | pbeesly | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRfJfH5wFd7b-xybj | q-b7b8b74f14 | ok |
| 6 | 2020-05-02 02:57:01.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe6_ Global\UsGthrCtrlFltPipeMssGthrPipe6 1 -2147483646 "Software\Microsoft\Windows Se… | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rxETLY | q-7d4b68d7ee | ok |
| 7 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1br | q-f384d77ea3 | ok |

### F29 · benign / high · T1552.006 · Group Policy gpt.ini writes are routine Group Policy client activity

Evidence status: **verified**

The three gpt.ini creations (scranton 03:01:43 and 03:19:18, nashua 03:10:40) are all written by C:\windows\system32\svchost.exe into the local GroupPolicy DataStore cache for policy {31B2F340-016D-11D2-945F-00C04FB984F9}. This is the standard Group Policy client refreshing its cached policy file, not an adversary reading or writing cpassword-bearing GPP XML. No Groups.xml, Services.xml or other Preferences files with cpassword content were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:18.009Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\gpt.ini | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cZN9Bo | q-a25cb9f1de | ok |
| 2 | 2020-05-02 03:19:18.009Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cZN9Bo | q-a25cb9f1de | ok |

### F32 · benign / medium · T1555.003 · No browser credential-store access observed

Evidence status: **verified**

No file creation or 4663 access to browser credential stores (Login Data, logins.json, key3.db/key4.db, Cookies, Web Data, Local State) was found on any host in the window; the only Downloads-folder writes on scranton were the attacker's Sysinternals archive, .pfx export and screenshot files. No evidence of web-browser credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:59:42.544Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\SysinternalsSuite.zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hjk9tr | q-9fa8b50713 | ok |

### F33 · benign / medium · T1555.005 · No password-manager activity observed

Evidence status: **verified**

Checks for KeePass/1Password/LastPass/Bitwarden process execution, .kdbx/.opvault/.agilekeychain file writes, process access to password-manager processes and password-manager strings in PowerShell all returned zero hits; the windows.other 'password manager' matches were unrelated shutdown/filter-driver messages. No password-manager credential theft observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:33.000Z | scranton.dmevals.local | windows.other | message | Local multi-user session manager received system shutdown message | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuD8 | q-58a99f44e4 | ok |

### F35 · benign / medium · T1556.001 · LSASS handle opens on domain controllers are dominated by svchost/AV/telemetry with benign access masks; no DC authentication tampering

Evidence status: **verified**

Stacking all 326 sysmon event-10 hits against lsass.exe shows 289 from svchost.exe (286 with GrantedAccess 0x1000, i.e. query-limited-information), 15 from the Azure IaaSAntimalware AntimalwareConfig.exe and 13 from WindowsAzureTelemetryService.exe (0x1400), plus single csrss/wininit/services opens. The only lsass.exe image load is lsass.exe itself, signed by 'Microsoft Windows Publisher' with a Valid signature. No 4624 LogonType 9, no 4657 LSA/SecurityProviders registry changes, and no lsass/ntds/dcsync/golden-ticket PowerShell script blocks were found. The one wsmprovhost.exe 0x1f3fff open on nashua is a .NET/System.ni.dll call trace consistent with WinRM remoting, not DC auth patching.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.Signature | Microsoft Windows Publisher | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cjZNk- | q-040a52641b | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-ea9bc7dcf6 | ok |
| 3 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hx0W8_ | q-dc09226aff | ok |

### F36 · benign / high · T1556.002 · No password filter DLL: only file creation is accesschk.exe writing 'passwordsDB'; no Notification Packages registry change

Evidence status: **verified**

The single System32/password-related file creation is C:\Program Files\SysinternalsSuite\accesschk.exe creating C:\Program Files\SysinternalsSuite\passwordsDB at 2020-05-02T03:04:35Z on scranton — an output file of the attacker's accesschk run, not a DLL dropped into System32. No registry write to 'Notification Packages' (sysmon 13 and security 4657 both zero), no 4657 Notification Packages audit, and no password-filter/lsass script blocks in PowerShell. The only lsass image load is lsass.exe itself.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hRQwNS | q-d16d9252ca | ok |
| 2 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\accesschk.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hRQwNS | q-d16d9252ca | ok |

### F37 · benign / medium · T1556.005 · No reversible-encryption / account-control changes observed

Evidence status: **verified**

No 4739 (domain policy change) events, no Set-ADAccountControl/AllowReversiblePasswordEncryption/ReversibleEncryption script blocks, no command lines containing Reversible/dsmod, and no 'Reversible'/'password encryption' messages in windows.other. The 4103/4104 PowerShell volume on scranton is dominated by the attacker's discovery/persistence/certificate-theft script blocks, none of which touch reversible encryption.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:03.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Discovery | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysW | q-e6e029ff69 | ok |

### F38 · benign / low · T1556.006 · No MFA modification activity observed

Evidence status: **verified**

No 4739/4730/4662 events in windows.other and no MFA-related configuration changes in any dataset. The only authentication-adjacent activity is the attacker's LSASS access and certificate export on scranton, which is credential theft rather than MFA tampering.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvTSsN | q-e6e029ff69 | ok |

### F39 · benign / medium · T1556.007 · No hybrid-identity / directory-service modification events

Evidence status: **verified**

No 5136/5137/5138/5139/5141 directory-service change events in windows.security or windows.other. dsregcmd.exe appears only loading cryptdll.dll (5 events), which is normal device-registration behaviour, with no accompanying configuration change.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hx0W8_ | q-dc09226aff | ok |

### F40 · benign / medium · T1556.008 · No network provider DLL registration or service installs in windows.other

Evidence status: **verified**

No 4657 or 4697 events in windows.other, and no registry writes to SecurityProviders or NetworkProvider ordering in sysmon. The only LSA registry writes retrieved are by lsass.exe itself (LsaPid, LsaCfgFlagsDefault, ProductType) and HKLM\SECURITY\Cache\NL$1 by lsass.exe on nashua — normal authentication-process behaviour, not network-provider DLL registration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.834Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\Lsa\LsaPid | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpgKyX | q-382c5bd8a0 | ok |

### F44 · benign / medium · T1557.003 · No DHCP spoofing observed - no DHCP traffic, no DHCP server events, no DHCP tooling

Evidence status: **verified**

No evidence of rogue DHCP activity. The UDP destination-port stack in the Zeek window contains only 53, 389, 138, 123 and 137 - no ports 67/68, so no DHCP client or server flows were captured. windows.other contains no DHCP-server event codes (1341/1342/1020/1063 returned zero hits) and no DHCP-related service installs; the only 7045 service installs are PSEXESVC on nashua (attacker lateral movement, not DHCP) and 'Java(TM) Virtual Machine Support Service' on scranton. No PowerShell script block referenced DhcpServer cmdlets or 'rogue'. The 4624 logon-process stack is Kerberos/Advapi/User32/NtLmSsp with no anomalous authentication source attributable to DHCP-based redirection.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:12:46.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuDx | q-ce4a08a367 | ok |
| 2 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | win.ServiceName | Java(TM) Virtual Machine Support Service | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuDg | q-ce4a08a367 | ok |

### F45 · benign / medium · T1558 · Kerberos ticket activity on newyork DC is normal domain logon traffic; no ticket theft/forgery tooling observed

Evidence status: **verified**

All 28 4769 events in the window are on newyork.dmevals.local and are ordinary Kerberos service-ticket requests: pbeesly@DMEVALS.LOCAL requesting tickets for krbtgt, NEWYORK$, NASHUA$, SCRANTON$ and WEC$ from 10.0.1.4/10.0.1.6, and SCRANTON$ requesting tickets for NEWYORK$/krbtgt/WEC$/SCRANTON$ at 03:19:13-03:19:58. All have Failure Code 0x0 and encryption type 0x12 (AES256). No 4769 targeted a user service account (query for ServiceName not ending in '$' and not krbtgt returned 0 rows), so there is no Kerberoastable service-ticket burst. The only Kerberos/ticket-related message in windows.other is a single event 6038 NTLM-in-use notice on scranton. No PowerShell script block referenced kerberos/kirbi/ticket/Rubeus/Mimikatz. The lsass access-mask stack is dominated by svchost.exe (289 of 326) with the remainder being Azure agent/telemetry binaries and OS processes; the only unusual accessors are PowerShell.exe on scranton and wsmprovhost.exe on nashua, which are covered in the T1558.001 finding.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72Yx | q-b636104030 | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72Yx | q-b636104030 | ok |
| 3 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | SCRANTON$@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rzGpUD | q-fc0e5db396 | ok |
| 4 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.other | event.code | 6038 | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuAv | q-b8cff2d2d1 | ok |

### F47 · benign / medium · T1558.002 · No silver-ticket indicators: no service-account TGS requests and no service-ticket forgery evidence

Evidence status: **verified**

No 4769 event in the window requested a ticket for a user service account (filter excluding machine accounts ending in '$' and krbtgt returned 0 rows); all service names are krbtgt, NEWYORK$, NASHUA$, SCRANTON$ and WEC$ with AES256 (0x12) and Failure Code 0x0. No PowerShell script block contained silver/Rubeus/kirbi/kerberos strings. The only lsass access by a non-OS binary is PowerShell.exe on scranton (0x1fffff, 03:05:16) and wsmprovhost.exe on nashua (0x1f3fff, 03:09:29); the wsmprovhost call trace is entirely managed PowerShell/System assemblies (Microsoft.PowerShell.Commands.Management.ni.dll), i.e. a WinRM PowerShell session, and no forged service ticket or service-account hash use follows it. Nothing in the data shows a service ticket being forged or replayed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72bs | q-fc0e5db396 | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72bs | q-fc0e5db396 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-e87626351c | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-e87626351c | ok |

### F48 · benign / medium · T1558.003 · No Kerberoasting: no RC4 service-ticket requests and no roasting tooling

Evidence status: **verified**

All 28 4769 events carry Ticket Encryption Type 0x12 (AES256) and Failure Code 0x0, and none targets a user service account, so there is no RC4 (0x17) service-ticket request burst characteristic of Kerberoasting. No PowerShell script block matched kerberoast/Invoke-Kerberoast/Rubeus/GetUserSPNs. The 4769 volume is low (28 events over ~17 minutes) and confined to newyork.dmevals.local, consistent with normal domain logon traffic from pbeesly and the SCRANTON$ machine account.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niytvM | q-fc0e5db396 | ok |
| 2 | 2020-05-02 03:10:23.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NASHUA$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niytvM | q-fc0e5db396 | ok |
| 3 | 2020-05-02 03:20:45.000Z | newyork.dmevals.local | windows.security | win.ServiceName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nSlAli | q-fc0e5db396 | ok |

### F49 · benign / medium · T1558.004 · No AS-REP roasting: all 14 AS-REQs used pre-authentication

Evidence status: **verified**

All 14 4768 events on newyork.dmevals.local have PreAuthType 2 (pre-authentication enabled), Status 0x0 and AES256 (0x12) — 8 for pbeesly from 10.0.1.4/10.0.1.6 between 03:11:18 and 03:20:45, and 6 for the SCRANTON$ machine account at 03:19:13-03:19:34. No account requested a TGT without pre-authentication, which is the prerequisite for AS-REP roasting, and no PowerShell script block matched asreproast/GetNPUsers/Rubeus/asrep.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNvO | q-e28a668eae | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ncs5pb | q-e28a668eae | ok |
| 3 | 2020-05-02 03:20:45.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nKhIsr | q-e28a668eae | ok |

### F50 · benign / medium · T1606 · No forged web credential activity; lsass handle opens are OS/management components

Evidence status: **verified**

Across windows.security, windows.sysmon, windows.powershell and windows.other (2020-05-02 02:55-03:28Z) there is no evidence of forged web credentials. All 297 4624 logons use only Kerberos (217), Negotiate (78), NTLM (1) and one '-' package; the rare logon-process values are a User32/Negotiate type-10 logon and an NtLmSsp/NTLM type-3 logon for pbeesly from 172.18.39.2 on scranton, plus a type-0 SYSTEM logon at 03:19:09 during a boot sequence. The rare lsass handle-access masks (0x1fffff, 0x1f3fff, 0x101001, 0x1000000, 0x3000) come from Windows components: csrss.exe and wininit.exe at 03:19:09 on scranton (boot), svchost.exe running sysmain.dll and lsm.dll, and SYSTEM-context PowerShell.exe/wsmprovhost.exe whose call traces resolve into System.ni.dll / Microsoft.PowerShell.Commands.Management.ni.dll (PowerShell management cmdlets), not credential-dumping code. No ADFS/SAML/cookie objects appear in security object-access or service events.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-c31fa155d7 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|C:\windows\assembly\NativeImages_v4.0.30319_64\System\9803982d7bc887e2745bff18a43… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-c31fa155d7 | ok |
| 3 | 2020-05-02 03:19:59.323Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|c:\windows\system32\sysmain.dll+1e689\|c:\windows\system32\sysmain.dll+1e509\|c:\… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cTFCiC | q-c31fa155d7 | ok |
| 4 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | NtLmSsp  | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nQi3T7 | q-c9c1bfb25c | ok |
| 5 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | - | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ncsZpc | q-c9c1bfb25c | ok |

### F52 · benign / medium · T1606.002 · No SAML token forgery or ADFS token-signing access observed

Evidence status: **verified**

No SAML/ADFS artifacts exist in the collected windows data: zero hits for SAML/ADFS/NotOnOrAfter/token-signing in PowerShell script blocks and windows.other messages, and zero security events referencing ADFS objects, services or processes. The only 'token' PowerShell hit is a benign Get-AttributesMask helper (SE_GROUP_* token attribute constants) in C:\Program Files\SysinternalsSuite\readme.ps1 run by pbeesly on scranton at 03:04:04, and the only 'Token' process is svchost.exe -k netsvcs -p -s TokenBroker (Windows Token Broker service). The high-access lsass opens are SYSTEM PowerShell/wsmprovhost with PowerShell management-module call traces, not token-signing key theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvTCvl | q-a27f7b8dc9 | ok |
| 2 | 2020-05-02 03:20:48.898Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\svchost.exe -k netsvcs -p -s TokenBroker | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRfJfH5wFd7b_zRVX | q-1d44ee9411 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-c31fa155d7 | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Self-parented Skype app start, no credential access. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | PsExec-delivered payload that spawned the harvesting PowerShell, Rar and sdelete. |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Password-protected archive of harvested user files, then deleted with sdelete. |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Anti-forensics deletion of Rar.exe and staged working.zip archives. |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure guest-agent log collection, 0x1410 lsass read mask. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher agent. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure antimalware config. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure VM extension handler. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure domain-join extension. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google updater crash handler. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google updater crash handler. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Google updater service. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Attacker-staged tool run by PowerShell, wrote passwordsDB. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Lateral movement to NASHUA with cleartext pbeesly password. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Anti-forensics deletion of payload and staged archives. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Defender engine scanning lsass. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Defender network inspection service. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Masqueraded screen-saver dropper from explorer that wrote monkey.png. |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | PowerShell-driven compile of attacker DLLs in Temp. |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Elevated via runas, then ran registry-stored Invoke-Expression payload. |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | UAC-bypass-capable binary spawned by cmd in attacker session. |
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
| T1003 OS Credential Dumping | suspicious | SysinternalsSuite (contains procdump) downloaded and extracted by the hidden PowerShell stager on scranton immediately before lsass access; no direct dump-tool command line captured. |
| T1003.001 LSASS Memory | malicious | PowerShell 0x1fffff/0x1f3fff lsass handles on scranton and nashua. |
| T1003.002 Security Account Manager | suspicious | SAM opened with 0xf003f by lsass on scranton after attacker tooling. |
| T1003.003 NTDS | not_observed | No ntdsutil/vssadmin/diskshadow, no .dit file activity, no NTDS object access on any host. |
| T1003.004 LSA Secrets | benign | lsass accessors are baseline svchost/AntimalwareConfig/WindowsAzureTelemetryService; no lsadump or SECURITY hive copy. |
| T1003.005 Cached Domain Credentials | benign | NL$1 writes performed by lsass.exe itself (normal cache refresh); no mscache/dcc2 dumping tooling. |
| T1003.006 DCSync | benign | Single 4662 replication-GUID read by machine account NEWYORK$ on its own object; no user-account DCSync pattern. |
| T1040 Network Sniffing | benign | The only packet-capture activity is the Microsoft Azure Network Watcher agent (NetworkWatcherAgent.exe /service) invoking Microsoft-signed netsh.exe 'trace start capture=yes' as SYSTEM on scranton.dmevals.local for ~7 se… |
| T1056 Input Capture | malicious | Get-Clipboard executed in pbeesly session on scranton. |
| T1056.001 Keylogging | suspicious | Get-Clipboard executed as pbeesly on scranton at 03:06:42Z right after the stager; no SetWindowsHookEx/GetAsyncKeyState keylogger code found, so input capture is clipboard-based. |
| T1056.002 GUI Input Capture | not_observed | Only legitimate LogonUI.exe (winlogon parent) and consent.exe (svchost parent) GUI processes; no fake credential-prompt binaries or Get-Credential script blocks. |
| T1056.003 Web Portal Capture | not_observed | No web-portal capture artefacts in Windows telemetry; only normal davclnt.dll DavSetCookie WebDAV activity. Zeek window does not overlap. |
| T1056.004 Credential API Hooking | malicious | PowerShell.exe (scranton, 0x1F3FFF/0x1FFFFF, UNKNOWN call trace) and wsmprovhost.exe (nashua, 0x1F3FFF) obtained full-access handles to lsass.exe; other high-mask accessors are system processes. |
| T1110 Brute Force | not_observed | Zero 4625/4771 events in windows.security; the only authentication-failure-family event was a successful 4776 (Status 0x0) for pbeesly. 'net' command-line hits were svchost.exe -k netsvcs and netsh.exe trace, i.e. benign… |
| T1110.001 Password Guessing | not_observed | No failed logons and no net use/net user/password-bearing guessing command lines; the only hard-coded password was a single static credential in the Invoke-Exfil script on scranton, not repeated guessing. |
| T1110.002 Password Cracking | malicious | powershell.exe PID 2976 on scranton.dmevals.local (hidden, -ep bypass, steganographic monkey.png loader spawned by control.exe) opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff at 2020-05-02T03:05:16Z with an UN… |
| T1110.003 Password Spraying | not_observed | TargetUserName stacking over 4625/4771/4648 shows only pbeesly plus machine/DWM/UMFD accounts from 4648 explicit-credential events; no single password tried across many accounts, and no spray tooling in PowerShell script… |
| T1110.004 Credential Stuffing | not_observed | No failed authentications at all (zero 4625/4771); type-3 logons are dominated by machine accounts and 20 pbeesly logons, consistent with normal service/administrative authentication rather than replay of stolen credenti… |
| T1111 Multi-Factor Authentication Interception | malicious | PowerShell and wsmprovhost full-access lsass handles. |
| T1187 Forced Authentication | not_observed | No forced-authentication activity found. The only WebDAV traffic (10.0.1.4 -> 192.168.0.4, Microsoft-WebDAV-MiniRedir/DavClnt) is a client uploading /webdav/OfficeSupplies.7z, i.e. exfiltration, not a server coercing the… |
| T1212 Exploitation for Credential Access | malicious | Post-exploitation credential access via PowerShell on scranton/nashua. |
| T1539 Steal Web Session Cookie | not_observed | No access to or exfiltration of browser cookie stores. The 162 sysmon file-create hits matching *Cookies*/*Login Data*/*Web Data* resolve to Windows lastalive*.dat service-state files (svchost.exe) and GroupPolicy DataSt… |
| T1552 Unsecured Credentials | malicious | A staged credential-harvesting toolkit (Invoke-Discovery, accesschk passwordsDB, Get-PrivateKeys, Invoke-Exfil) ran as pbeesly on scranton.dmevals.local, followed by reuse of harvested credentials via PsExec64 to NASHUA. |
| T1552.001 Credentials In Files | malicious | Nashua PowerShell harvested *pass*/*login*/*admin* files into working.zip. |
| T1552.002 Credentials in Registry | malicious | hostui.exe ran Invoke-Expression on HKLM Javasoft registry value. |
| T1552.003 Shell History | not_observed | No command lines referencing ConsoleHost_history.txt or other shell history files in sysmon process creation. |
| T1552.004 Private Keys | malicious | Get-PrivateKeys exported LocalMachine cert keys to .pfx on scranton. |
| T1552.006 Group Policy Preferences | benign | Only svchost.exe Group Policy client writes of cached gpt.ini were seen; no GPP Preferences files with cpassword were accessed. |
| T1555 Credentials from Password Stores | malicious | Cert private-key export plus lsass access on scranton. |
| T1555.003 Credentials from Web Browsers | malicious | User profile/Downloads archives staged and exfiltrated from scranton. |
| T1555.004 Windows Credential Manager | suspicious | No cmdkey/vaultcmd/Credential Manager or Vault file activity, but PowerShell read lsass memory with full access on scranton; LSASS memory access is the credential-store-adjacent behaviour present. |
| T1555.005 Password Managers | not_observed | Zero hits for password-manager processes, .kdbx/.opvault/.agilekeychain files, process access to password managers, or password-manager strings in PowerShell. |
| T1556 Modify Authentication Process | suspicious | PowerShell.exe (PID 2976) on scranton opened lsass.exe with 0x1FFFFF/0x1f3fff and an UNKNOWN call-trace module at 03:05:16Z during a confirmed hands-on-keyboard intrusion, but no LSA/SecurityProviders registry modificati… |
| T1556.001 Domain Controller Authentication | benign | 326 LSASS handle opens are svchost (0x1000), Azure antimalware/telemetry (0x1400) and system processes; lsass image load is Microsoft-signed and valid; no LogonType 9, no 4657 LSA changes, no dcsync/ntds script blocks. |
| T1556.002 Password Filter DLL | benign | Only file creation is accesschk.exe writing 'passwordsDB' in the SysinternalsSuite folder; no Notification Packages registry write, no 4657, no non-standard DLL loaded into lsass. |
| T1556.005 Reversible Encryption | not_observed | No 4739, no reversible-encryption script blocks or command lines, no matching windows.other messages. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739/4730/4662 events and no MFA configuration changes in any dataset. |
| T1556.007 Hybrid Identity | not_observed | No 5136/5137/5138/5139/5141 directory-service change events; dsregcmd only loads cryptdll.dll normally. |
| T1556.008 Network Provider DLL | not_observed | No 4657/4697 in windows.other and no SecurityProviders/NetworkProvider registry writes in sysmon; LSA registry writes seen are by lsass.exe itself. |
| T1557 Adversary-in-the-Middle | malicious | L2 evidence shows one MAC (12:34:56:78:9a:bc) acting as responder for all off-subnet destinations and for the intra-subnet SMB session, plus self-signed-cert notices on intercepted flows - an established AiTM position. T… |
| T1557.001 Name Resolution Poisoning and SMB Relay | suspicious | All 45 SMB/445 flows from 10.0.1.4 to 10.0.1.6 were delivered by the rogue MAC rather than NASHUA's own NIC, with SAMR/LSAR enumeration and unknown_dce_rpc_auth_type weirds; relay is inferred from L2 evidence, not direct… |
| T1557.002 ARP Cache Poisoning | malicious | Single MAC 12:34:56:78:9a:bc is resp_l2_addr for 10.0.0.4, 192.168.0.4 and 192.168.0.5 simultaneously - impossible for a legitimate gateway, indicating ARP cache poisoning. |
| T1557.003 DHCP Spoofing | not_observed | No DHCP traffic (no UDP 67/68), no DHCP server event codes 1341/1342/1020/1063, no DHCP cmdlets in PowerShell, and no rogue DHCP binaries in process creation. |
| T1558 Steal or Forge Kerberos Tickets | suspicious | Kerberos ticket events themselves are normal (28 successful AES256 4769s on newyork, no service-account targets), but the same window contains a confirmed intrusion on scranton.dmevals.local where PowerShell opened lsass… |
| T1558.001 Golden Ticket | suspicious | PowerShell.exe (PID 2976) accessed lsass.exe with 0x1f3fff and 0x1fffff at 03:05:16 on scranton.dmevals.local inside a malicious .scr -> cmd -> powershell -> IEX/csc -> sdelete chain; consistent with LSASS ticket/hash ha… |
| T1558.002 Silver Ticket | not_observed | No 4769 for any user service account, all tickets AES256 with Failure Code 0x0, and no silver/Rubeus/kirbi script blocks; the wsmprovhost lsass access on nashua shows a managed PowerShell call trace with no forged servic… |
| T1558.003 Kerberoasting | not_observed | No RC4 (0x17) service-ticket requests, no user service-account TGS requests, and no Kerberoasting tooling in PowerShell script blocks. |
| T1558.004 AS-REP Roasting | not_observed | All 14 4768 AS-REQs (pbeesly and SCRANTON$) used PreAuthType 2 with Status 0x0; no pre-auth-less TGT request and no AS-REP roasting tooling. |
| T1606 Forge Web Credentials | not_observed | No forged web credential artifacts; all 4624 logons use Kerberos/Negotiate/NTLM with only a User32 type-10, NtLmSsp type-3 and a boot-time type-0 SYSTEM logon as rare values, and rare lsass handle masks belong to csrss/w… |
| T1606.001 Web Cookies | suspicious | Only cookie activity is rundll32 davclnt.dll,DavSetCookie to 192.168.0.4/webdav by pbeesly on scranton, matching the Invoke-Exfil WebDAV exfiltration script; this is WebDAV auth for exfil, not cookie forgery, and the sol… |
| T1606.002 SAML Tokens | not_observed | Zero SAML/ADFS/token-signing references in PowerShell script blocks, windows.other messages or security object/service events; the only token-related items are a benign SE_GROUP_* attribute helper script and the svchost … |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | 4 planned checks, all with zero hits |
| T1649 Steal or Forge Authentication Certificates | malicious | Certificate private keys exported to .pfx on scranton. |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 0 hits | 0 hits | 5797 hits | 773 hits | 35 hits |
| T1003.001 LSASS Memory | 0 hits | 0 hits | 947 hits | 656 hits | GAP: n/a refused (time window … |
| T1003.002 Security Account Manager | 1 hits | 0 hits | 0 hits | 10 hits | GAP: n/a refused (time window … |
| T1003.003 NTDS | 0 hits | 0 hits | 0 hits | 0 hits | GAP: n/a refused (time window … |
| T1003.004 LSA Secrets | 0 hits | 0 hits | 934 hits | 354 hits | GAP: n/a refused (time window … |
| T1003.005 Cached Domain Credentials | 0 hits | 0 hits | 934 hits | 6956 hits | GAP: n/a refused (time window … |
| T1003.006 DCSync | 5 hits | 0 hits | 14 hits | 1 hits | n/a |
| T1040 Network Sniffing | 5 hits | 0 hits | 460 hits | 0 hits | n/a |
| T1056 Input Capture | 5 hits | 3 hits | 10977 hits | 652 hits | n/a |
| T1056.001 Keylogging | 5 hits | 0 hits | 10977 hits | 1683 hits | n/a |
| T1056.002 GUI Input Capture | 5 hits | 5494 hits | 460 hits | 447 hits | n/a |
| T1056.003 Web Portal Capture | 5 hits | 4 hits | 5337 hits | 1657 hits | n/a |
| T1056.004 Credential API Hooking | 0 hits | 0 hits | 6 hits | 21006 hits | n/a |
| T1110 Brute Force | 0 hits | 3 hits | 0 hits | 31 hits | n/a |
| T1110.001 Password Guessing | 2 hits | 0 hits | 0 hits | 30 hits | n/a |
| T1110.002 Password Cracking | 1 hits | 10 hits | 10977 hits | 327 hits | n/a |
| T1110.003 Password Spraying | 0 hits | 0 hits | 15 hits | 30 hits | n/a |
| T1110.004 Credential Stuffing | 2 hits | 2 hits | 0 hits | 30 hits | n/a |
| T1111 Multi-Factor Authentication Interception | 0 hits | 1 hits | 312 hits | 332 hits | 35 hits |
| T1187 Forced Authentication | 0 hits | 11 hits | 11140 hits | 69 hits | 86 hits |
| T1212 Exploitation for Credential Access | 0 hits | 0 hits | 42 hits | 327 hits | 35 hits |
| T1539 Steal Web Session Cookie | 3 hits | 0 hits | 4 hits | 162 hits | 0 hits |
| T1552 Unsecured Credentials | 2 hits | 4 hits | 0 hits | 26 hits | 12 hits |
| T1552.001 Credentials In Files | 0 hits | 1 hits | 312 hits | 496 hits | 12 hits |
| T1552.002 Credentials in Registry | n/a | 0 hits | 5331 hits | 6 hits | n/a |
| T1552.003 Shell History | n/a | 0 hits | n/a | 0 hits | n/a |
| T1552.004 Private Keys | n/a | 1 hits | 0 hits | 0 hits | n/a |
| T1552.006 Group Policy Preferences | n/a | 0 hits | 0 hits | 0 hits | n/a |
| T1555 Credentials from Password Stores | n/a | 0 hits | 5331 hits | 652 hits | n/a |
| T1555.003 Credentials from Web Browsers | n/a | 0 hits | 0 hits | 0 hits | n/a |
| T1555.004 Windows Credential Manager | 2 hits | 4 hits | 0 hits | 652 hits | n/a |
| T1555.005 Password Managers | 14 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556 Modify Authentication Process | 0 hits | 0 hits | 0 hits | 692 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | 0 hits | 233 hits | 373 hits | n/a |
| T1556.002 Password Filter DLL | 0 hits | 0 hits | 0 hits | 2 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 5494 hits | 0 hits | 0 hits | n/a |
| T1556.006 Multi-Factor Authentication | 0 hits | 0 hits | 41002 hits | 0 hits | n/a |
| T1556.007 Hybrid Identity | 0 hits | 0 hits | 0 hits | 20259 hits | n/a |
| T1556.008 Network Provider DLL | 0 hits | 0 hits | 36 hits | 20259 hits | n/a |
| T1557 Adversary-in-the-Middle | 0 hits | 0 hits | 10977 hits | 1229 hits | 613 hits |
| T1557.001 Name Resolution Poisoning and SMB Relay | 0 hits | 0 hits | 36 hits | 0 hits | 108 hits |
| T1557.002 ARP Cache Poisoning | 0 hits | 0 hits | 5373 hits | 1229 hits | 613 hits |
| T1557.003 DHCP Spoofing | 216 hits | 0 hits | 297 hits | 447 hits | 62 hits |
| T1558 Steal or Forge Kerberos Tickets | 1 hits | 0 hits | 448 hits | 652 hits | 35 hits |
| T1558.001 Golden Ticket | 1 hits | 0 hits | 476 hits | 326 hits | 35 hits |
| T1558.002 Silver Ticket | 1 hits | 0 hits | 476 hits | 326 hits | 35 hits |
| T1558.003 Kerberoasting | 1 hits | 0 hits | 565 hits | 326 hits | 35 hits |
| T1558.004 AS-REP Roasting | 1 hits | 0 hits | 28 hits | 447 hits | 35 hits |
| T1606 Forge Web Credentials | 0 hits | 1 hits | 594 hits | 326 hits | n/a |
| T1606.001 Web Cookies | 0 hits | 0 hits | 312 hits | 1 hits | n/a |
| T1606.002 SAML Tokens | 0 hits | 0 hits | 312 hits | 326 hits | n/a |
| T1621 Multi-Factor Authentication Request Generatio… | 0 hits | 0 hits | 0 hits | n/a | n/a |
| T1649 Steal or Forge Authentication Certificates | 0 hits | 1 hits | 64 hits | 1 hits | n/a |

Cells: 265, gaps: 5.

## Queries

Every MCP tool call of this run (1212), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-306aafbfe0 | scope | list_data_sources | {} | None |  |
| q-e3a6cf2275 | scope | get_registry | {} | None |  |
| q-40c1f5a7b8 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-093efd87cd | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-d3cecb0613 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-901e05dc74 | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-8c3fd69919 | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-e0626f0b0f | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-273c817911 | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-12a934e52c | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5337 |  |
| q-0f13dcb521 | check C004 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-e47a4b98fc | check C005 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*lsass* OR *MiniDump* OR *procdump* OR *mimikatz* OR *sekurlsa* OR *ntds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.cod… | 0 |  |
| q-a75b18a478 | check C006 | search | {"dataset": "windows.other", "query": "message:(*lsass* OR *MiniDump* OR *procdump* OR *mimikatz* OR *ntds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 0 |  |
| q-75d72dd318 | check C007 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-d601283982 | check C008 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-12bfce57d0 | check C009 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:(*lsass* OR *MiniDump* OR *comsvcs* OR *procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 1 |  |
| q-59f52ae130 | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:(*.dmp OR *lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comma… | 2 |  |
| q-07af6f7862 | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-a3d44ed921 | check C012 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 13 |  |
| q-a607547952 | check C013 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 934 |  |
| q-4754517f56 | check C014 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*lsass* OR *MiniDump* OR *sekurlsa* OR *Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", … | 0 |  |
| q-4821bf1604 | check C015 | search | {"dataset": "windows.other", "query": "message:(*lsass* OR *MiniDump* OR *comsvcs*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-264a9e9107 | check C016 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:(*SAM* OR *SECURITY* OR *SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable",… | 3 |  |
| q-6a0ec2ff2e | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:(*reg*save* OR *reg*export* OR *esentutl* OR *vssadmin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 0 |  |
| q-f94c34ab71 | check C018 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND file.path:(*SAM* OR *SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.com… | 0 |  |
| q-732868a737 | check C019 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND registry.path:(*SAM* OR *SECURITY*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 7 |  |
| q-57900698e3 | check C020 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND process.command_line:(*reg*save* OR *esentutl* OR *vssadmin* OR *ntds*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-31563e67e8 | check C021 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectName:(*SAM* OR *SECURITY*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-629c7d9ac4 | check C022 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*reg*save* OR *esentutl* OR *SAM* OR *vssadmin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 0 |  |
| q-3f2727710d | check C023 | search | {"dataset": "windows.other", "query": "message:(*reg*save* OR *esentutl* OR *SAM* OR *vssadmin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 1 |  |
| q-8aadc8ee9c | check C024 | search | {"dataset": "windows.other", "query": "message:(*ntds* OR *vssadmin* OR *shadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 0 |  |
| q-4c7aa73731 | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:(*ntds* OR *vssadmin* OR *ntdsutil* OR *diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user… | 0 |  |
| q-78760dce51 | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:(*ntds* OR *.dit*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comma… | 0 |  |
| q-33c32af9e4 | check C027 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND file.path:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-65d449d6c6 | check C028 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND process.command_line:(*ntds* OR *vssadmin* OR *diskshadow*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-ea5f1dc3e2 | check C029 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectName:*ntds*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-3b9c8bb77f | check C030 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*ntds* OR *vssadmin* OR *diskshadow* OR *ntdsutil*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proce… | 0 |  |
| q-20ed3a5805 | check C031 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-b58461426a | check C032 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:(*SECURITY*Policy*Secrets* OR *reg*save* OR *lsadump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 0 |  |
| q-5ac2ec1922 | check C033 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND registry.path:(*SECURITY* OR *Secrets*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5 |  |
| q-bd59bc425a | check C034 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:(*lsass* OR *samlib* OR *vaultcli*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 23 |  |
| q-faa41f4189 | check C035 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectName:(*SECURITY* OR *Secrets*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-166afa4a02 | check C036 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 934 |  |
| q-fa20aa0da0 | check C037 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*lsadump* OR *Secrets* OR *SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-c87e71f2d6 | check C038 | search | {"dataset": "windows.other", "query": "message:(*lsadump* OR *Secrets* OR *lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 0 |  |
| q-34a7e7a679 | check C039 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-a02764449b | check C040 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:(*cache* OR *dcc2* OR *mscache* OR *lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 5 |  |
| q-42afc65e4a | check C041 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND registry.path:(*Cache* OR *SECURITY*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 6625 |  |
| q-20cb5612f6 | check C042 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectName:(*Cache* OR *SECURITY*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-e0f4410c38 | check C043 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 934 |  |
| q-3172d75bc5 | check C044 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*cache* OR *dcc2* OR *mscache* OR *lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execut… | 0 |  |
| q-284f0a3222 | check C045 | search | {"dataset": "windows.other", "query": "message:(*cache* OR *dcc2* OR *mscache* OR *lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 0 |  |
| q-f6b34ceddf | check C046 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-d491ab6c59 | check C047 | aggregate | {"dataset": "windows.security", "field": "win.Properties", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-84490cfc29 | check C048 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsass* OR process.command_line:*ntds*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-1daa18aeba | check C049 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*DCSync* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*lsadump* OR win.ScriptBlockText:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-bb23278fc8 | check C050 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-da74e8ddb5 | check C051 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-c4ef12125d | check C052 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*netsh\\ trace* OR process.command_line:*RawCap*)", "time_from": null, "tim… | 0 |  |
| q-71c3ff1065 | check C053 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-d7c010d2f6 | check C054 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*pcap* OR win.ImageLoaded:*npcap* OR win.ImageLoaded:*wpcap*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a6e2365677 | check C055 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*pktmon* OR win.ScriptBlockText:*netsh* OR win.ScriptBlockText:*capture*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.d… | 0 |  |
| q-12b893da4b | check C056 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-d7e4e32cd6 | check C057 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-3a53cf9e64 | check C058 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-aa9a4abcd7 | check C059 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SetWindowsHookEx* OR win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*keylog*)", "time_from": null, "time_to": null, "fields… | 3 |  |
| q-943cb07aa7 | check C060 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-5f806ac366 | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetObject", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*CurrentControlSet\\\\Services*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1357 |  |
| q-9d048957de | check C062 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-f1a1a3d214 | check C063 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-b5ba3f4af4 | check C064 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-68143f32b8 | check C065 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*SetWindowsHookEx* OR win.ScriptBlockText:*keylog*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obse… | 0 |  |
| q-8e732fe311 | check C066 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 200, "sub_field": null} | 447 |  |
| q-52355ebec3 | check C067 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*CredentialPrompt* OR win.ScriptBlockText:*Get-Credential* OR win.ScriptBlockText:*WindowsIdentity* OR win.ScriptBlockText:*CredUIPrompt*)", "time_from": null, "time_to": null… | 0 |  |
| q-749f2f4f39 | check C068 | search | {"dataset": "windows.powershell", "query": "event.code:4103 OR event.code:4104", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 5494 |  |
| q-bce2edb68f | check C069 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-e8babfcb05 | check C070 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-50aa98d4c6 | check C071 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 200, "sub_field": null} | 1649 |  |
| q-4cf9781c94 | check C072 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*login* OR win.TargetFilename:*logon* OR win.TargetFilename:*.aspx OR win.TargetFilename:*.php OR win.TargetFilename:*.asp)", "time_from": null, "time_to": null, "fields": ["@timesta… | 8 |  |
| q-055ee869b4 | check C073 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5337 |  |
| q-8cd987896d | check C074 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*login* OR win.ScriptBlockText:*credential* OR win.ScriptBlockText:*Set-Content* OR win.ScriptBlockText:*Out-File*)", "time_from": null, "time_to": null, "fields": ["@timestam… | 4 |  |
| q-122ccf8c88 | check C075 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-a00be31bb3 | check C076 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e2f5e590f7 | check C077 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a2def61d3b | check C078 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-1b2fe40fee | check C079 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:8", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 95 |  |
| q-c8f1acb731 | check C080 | aggregate | {"dataset": "windows.security", "field": "win.TargetProcessName", "query": "event.code:4663 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-d957374d1e | check C081 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*comsvcs*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 0 |  |
| q-44c0c46e06 | check C082 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*MiniDump* OR message:*comsvcs*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 0 |  |
| q-7aa4e096dc | check C083 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-22c9f072e8 | check C084 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-bc65bd648e | check C085 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-ca291b1333 | check C086 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*user* OR process.command_line:*password*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 31 |  |
| q-4b3228c10a | check C087 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*password* OR win.ScriptBlockText:*Brute* OR win.ScriptBlockText:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 3 |  |
| q-22fa18f009 | check C088 | search | {"dataset": "windows.other", "query": "message:*logon* AND message:*fail*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-4f217899e5 | check C089 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-faa242d514 | check C090 | count | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null} | 0 |  |
| q-ef7bf250ed | check C091 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-b61d94304b | check C092 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*net*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 30 |  |
| q-8b21a96d3b | check C093 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 0 |  |
| q-889cd68375 | check C094 | search | {"dataset": "windows.other", "query": "message:*4625* OR message:*failed*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 2 | F16 |
| q-2fda863852 | check C095 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-95295b1e1d | check C096 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-7a043391d7 | check C097 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*sam* OR process.command_line:*ntds* OR process.command_line:*hash*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-bd36fe1c2d | check C098 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*sam* OR win.TargetFilename:*ntds* OR win.TargetFilename:*hash*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-6e2214ac7a | check C099 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-54cb750bf4 | check C100 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*hash* OR win.ScriptBlockText:*crack* OR win.ScriptBlockText:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "use… | 10 |  |
| q-894619c095 | check C101 | search | {"dataset": "windows.other", "query": "message:*sam* OR message:*ntds* OR message:*hash*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.com… | 1 |  |
| q-26d264b41c | check C102 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625 OR event.code:4771 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-7678b3fe4a | check C103 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625 OR event.code:4771", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-570f23d60c | check C104 | timeline | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-14abd09583 | check C105 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*net*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 30 |  |
| q-eb18d5fc84 | check C106 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*spray* OR win.ScriptBlockText:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 0 |  |
| q-10358fa70a | check C107 | search | {"dataset": "windows.other", "query": "message:*4771* OR message:*4625*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 0 |  |
| q-6b3c829cfe | check C108 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-5c41637aeb | check C109 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-01b7705640 | check C110 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-b190cd7842 | check C111 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*net*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 30 |  |
| q-a8696bb8a7 | check C112 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*password* OR win.ScriptBlockText:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exe… | 2 | F18 |
| q-6cd4ad9aa1 | check C113 | search | {"dataset": "windows.other", "query": "message:*4625* OR message:*failed*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 2 |  |
| q-8fcd8c53ff | check C114 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-fb3a922f3d | check C115 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 15 |  |
| q-9918ddb3a2 | check C116 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-de52e8a0a2 | check C117 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*SmartCard* OR registry.path:*SCard* OR registry.path:*Crypto*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 6 |  |
| q-1274833d5c | check C118 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*SmartCard* OR *SCard* OR *MFA* OR *token*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 1 |  |
| q-21f3a957a0 | check C119 | search | {"dataset": "windows.other", "query": "message:(*SmartCard* OR *SCardSvr* OR *Certificate*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-10151b4df2 | check C120 | aggregate | {"dataset": "zeek", "field": "zeek.success", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 10, "sub_field": null} | 35 |  |
| q-eaeb6d7d1e | check C121 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:5145", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 121 |  |
| q-adfc88af80 | check C122 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 42 |  |
| q-a6c360758e | check C123 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 10977 |  |
| q-762b26ef5e | check C124 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*\\\\*.lnk OR win.TargetFilename:*\\\\*.url OR win.TargetFilename:*\\\\*.library-ms)", "time_from": null, "time_to": null, "size": 30, "sub_field": nul… | 3 |  |
| q-068e075471 | check C125 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 66 |  |
| q-1ad19ba059 | check C126 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*WebDAV* OR *PROPFIND* OR *NTLM* OR *\\\\\\\\*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 11 |  |
| q-e7344344d8 | check C127 | search | {"dataset": "windows.other", "query": "message:(*WebDAV* OR *WebClient* OR *DavWWWRoot*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.com… | 0 |  |
| q-c1d5722f35 | check C128 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 50 |  |
| q-efd538f230 | check C129 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:OPTIONS OR http.request.method:MOVE)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 |  |
| q-9882bd4e12 | check C130 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 42 |  |
| q-b041fdd53c | check C131 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-68b6053e31 | check C132 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*sekurlsa* OR process.command_line:*MiniDump*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 1 |  |
| q-a9cb9c8964 | check C133 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*procdump*)", "time_from": null, "time_to": null, "size": 30, "sub_field": nul… | 0 |  |
| q-9db8cc3fd5 | check C134 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*MiniDump* OR *lsass* OR *sekurlsa* OR *Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", … | 0 |  |
| q-6f50dd372a | check C135 | search | {"dataset": "windows.other", "query": "message:(*lsass* OR *MiniDump* OR *comsvcs*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-2f00ceda24 | check C136 | aggregate | {"dataset": "zeek", "field": "zeek.success", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 10, "sub_field": null} | 35 |  |
| q-e608cf7721 | check C137 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*Web Data*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 162 |  |
| q-f1680301f9 | check C138 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 0 |  |
| q-6c5c54b8f7 | check C139 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:2 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 0 |  |
| q-b7b64c813b | check C140 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*Cookies* OR process.command_line:*Login Data* OR process.command_line:*chrome* OR process.command_line:*firefox*)", "time_from": null, "time_to"… | 4 |  |
| q-ad6fb651e3 | check C141 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*Cookies* OR *Login Data* OR *sqlite* OR *chrome*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-cc78ce971c | check C142 | search | {"dataset": "windows.other", "query": "message:(*Cookies* OR *Login Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 3 |  |
| q-c585ce470f | check C143 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*cookie* OR zeek.user_agent:*curl* OR zeek.user_agent:*python*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.… | 0 |  |
| q-2673d3233a | check C144 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential* OR registry.path:*Winlogon*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 24 |  |
| q-096aa2bcb5 | check C145 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*unattend* OR win.TargetFilename:*web.config* OR win.TargetFilename:*.config OR win.TargetFilename:*passwords*)", "time_from": null, "time_to": null, "… | 2 |  |
| q-3db71f06a7 | check C146 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*findstr* OR process.command_line:*password* OR process.command_line:*credential*)", "time_from": null, "time_to": null, "size": 30, "sub_field":… | 0 |  |
| q-0c5b16c779 | check C147 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*password* OR *credential* OR *ConvertTo-SecureString* OR *Get-Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 4 |  |
| q-ee9140cbea | check C148 | search | {"dataset": "windows.other", "query": "message:(*password* OR *credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 2 |  |
| q-01dd3d2e0e | check C149 | aggregate | {"dataset": "zeek", "field": "zeek.filename", "query": "event.action:smb_files", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 12 |  |
| q-a874791066 | check C150 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.ini)", "time_from": null, "time_to": null, "size": 30, "sub_fi… | 49 |  |
| q-1669974da6 | check C151 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*findstr* OR process.command_line:*type * OR process.command_line:*Select-String*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null… | 447 |  |
| q-00a0bbeb4f | check C152 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 15 |  |
| q-ee179598e4 | check C153 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-cd6bc8280a | check C154 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*Get-Content* OR *Select-String* OR *findstr* OR *password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 1 |  |
| q-25590c1e7d | check C155 | search | {"dataset": "windows.other", "query": "message:(*.config* OR *password* OR *unattend*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comma… | 0 |  |
| q-3b1899947a | check C156 | aggregate | {"dataset": "zeek", "field": "zeek.filename", "query": "event.action:smb_files", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 12 |  |
| q-4043055480 | check C157 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*\\\\winlogon*\" OR TO_LOWER(registry.path) LIKE \"*\\\\lsa*\" OR TO_LOWER(registry.path) LIKE \"*\\\\control\\\\securityproviders*\" OR TO_LO… | ERROR |  |
| q-a8d36a4412 | check C157 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*winlogon*\" OR TO_LOWER(registry.path) LIKE \"*lsa*\" OR TO_LOWER(registry.path) LIKE \"*control*securityproviders*\" OR TO_LOWER(registry.pa… | ERROR |  |
| q-29d935b347 | check C158 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*reg* OR process.command_line:*query*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-fec3c4d64d | check C159 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*reg query*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-itemproperty*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*winlogon*\" OR… | ERROR |  |
| q-bc4a8d2499 | check C159 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*reg query*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-itemproperty*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*winlogon*\" OR… | ERROR |  |
| q-cb7ca3f805 | check C160 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectType:Key", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5331 |  |
| q-9d17e7972a | check C161 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*history*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*consolehost_history*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*psreadline*\"… | ERROR |  |
| q-d7af2205f7 | check C161 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*history*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*consolehost_history*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*psreadline*\"… | ERROR |  |
| q-343c504733 | check C162 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*consolehost_history*\" OR TO_LOWER(process.command_line) LIKE \"*psreadline*\" OR TO_LOWER(process.command_line) LIKE \"*history*\") \|… | ERROR |  |
| q-d2cfa9c123 | check C162 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*consolehost_history*\" OR TO_LOWER(process.command_line) LIKE \"*psreadline*\" OR TO_LOWER(process.command_line) LIKE \"*h… | 0 |  |
| q-8bd9d008e7 | check C163 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\") \| KEEP @timestamp, host.name, user.name, process.executable, file.path, _id… | ERROR |  |
| q-aa1756ac64 | check C163 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\") \| KEEP @timestamp, host.name, user.name, process.executable, file.path, _id… | ERROR |  |
| q-90be51d1da | check C164 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*.p12\" OR TO_LOWER(file.path) LIKE \"*.pem\" OR TO_LOWER(file.path) LIKE \"*.key\" OR TO_LOWER(file.path) L… | ERROR |  |
| q-4e2a997866 | check C164 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*.p12\" OR TO_LOWER(file.path) LIKE \"*.pem\" OR TO_LOWER(file.path) LIKE \"*.key\" OR TO_LOWER(file.path) L… | ERROR |  |
| q-ceebd26831 | check C165 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*.pfx\" OR TO_LOWER(process.command_line) LIKE \"*.p12\" OR TO_LOWER(process.command_line) LIKE \"*.pem\" OR TO_LOWER(process.command_li… | ERROR |  |
| q-4322ef8947 | check C165 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*.pfx\" OR TO_LOWER(process.command_line) LIKE \"*.p12\" OR TO_LOWER(process.command_line) LIKE \"*.pem\" OR TO_LOWER(process.command_li… | ERROR |  |
| q-4745b8fa23 | check C166 | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*.pfx\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.p12\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pem\" OR TO_LOWER(win.Rel… | ERROR |  |
| q-b82130adf7 | check C166 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*.pfx\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.p12\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pem\" OR TO_… | 0 |  |
| q-b58cf7e8c5 | check C167 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*.pfx\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*.p12\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*.pem\" OR TO_LOWER(win.ScriptBloc… | ERROR |  |
| q-06bb7715aa | check C167 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*.pfx\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*.p12\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*.pem\" OR TO_LOWER(w… | 1 |  |
| q-3523477f68 | check C168 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*groups.xml*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*gpprefdecrypt*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cpassword*\" OR … | ERROR |  |
| q-37f45df080 | check C168 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*groups.xml*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*gpprefdecrypt*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cpassword*\" OR … | ERROR |  |
| q-0c95bff3e9 | check C169 | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*groups.xml*\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*sysvol*\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*preferences*\") … | ERROR |  |
| q-8845272279 | check C169 (repaired) | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*groups.xml*\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*sysvol*\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*preferences*\") … | ERROR |  |
| q-d459ff28cf | check C170 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR TO_LOWER(process.command_line) LIKE \"*sysvol*\" OR TO_LOWER(process.command_line) LIKE \"*cpassword*\") \| KEEP @time… | ERROR |  |
| q-b4c51625f6 | check C170 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR TO_LOWER(process.command_line) LIKE \"*sysvol*\" OR TO_LOWER(process.command_line) LIKE \"*cpassword*\") \| KEEP @time… | ERROR |  |
| q-0c3175bb83 | check C171 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*groups.xml*\" OR TO_LOWER(file.path) LIKE \"*sysvol*\") \| KEEP @timestamp, host.name, user.name, process.executable, file.path, _id, _index"} | ERROR |  |
| q-e3c6b26b7a | check C171 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*groups.xml*\" OR TO_LOWER(file.path) LIKE \"*sysvol*\") \| KEEP @timestamp, host.name, user.name, process.executable, file.path, _id, _index"} | ERROR |  |
| q-84e70f04f1 | check C172 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND TO_LOWER(win.TargetImage):*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | ERROR |  |
| q-4839f55ec3 | check C172 (repaired) | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-38bd77022d | check C173 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND TO_LOWER(win.TargetImage):*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | ERROR |  |
| q-5875533e6c | check C173 (repaired) | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-4f6354a484 | check C174 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*minidump*\" OR TO_LOWER(process.command_line) LIKE \"*comsvcs*\" OR TO_LOWER(process.command_line) LIKE \"*procdump*\" OR TO_LOWER(proc… | ERROR |  |
| q-23072f9437 | check C174 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*minidump*\" OR TO_LOWER(process.command_line) LIKE \"*comsvcs*\" OR TO_LOWER(process.command_line) LIKE \"*procdump*\" OR TO_LOWER(proc… | ERROR |  |
| q-ddb08c014c | check C175 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectType:File OR win.ObjectType:Key)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5331 |  |
| q-ef976fad02 | check C176 | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*lsass*\" OR TO_LOWER(win.ObjectName) LIKE \"*vault*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE… | ERROR |  |
| q-868c878668 | check C176 (repaired) | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*lsass*\" OR TO_LOWER(win.ObjectName) LIKE \"*vault*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE… | ERROR |  |
| q-3923455b21 | check C177 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*comsvcs*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" OR TO_LOWER(… | ERROR |  |
| q-fbb7ab7d6a | check C177 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*comsvcs*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" OR TO_LOWER(… | ERROR |  |
| q-7ae2677e37 | check C178 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\google\\\\chrome\\\\user data*\" OR TO_LOWER(process.command_line) LIKE \"*… | ERROR |  |
| q-be5a95cd8f | check C178 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*google*chrome*user data*\" OR TO_LOWER(process.command_line) LIKE \"*microsoft*… | ERROR |  |
| q-4c28c01482 | check C179 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*\\\\user data\\\\*\" OR TO_LOWER(file.path) LIKE \"*\\… | ERROR |  |
| q-c584803c59 | check C179 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*user data*\" OR TO_LOWER(file.path) LIKE \"*firefox*pr… | ERROR |  |
| q-a7d49b02f7 | check C180 | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*\\\\user data\\\\*\" OR TO_LOWER(wi… | ERROR |  |
| q-bc30dd781b | check C180 (repaired) | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*user data*\" OR TO_LOWER(win.Object… | ERROR |  |
| q-081c95f66a | check C181 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*login data*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*logins.json*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*\\\\user data\\\\*… | ERROR |  |
| q-cd9b93150a | check C181 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*login data*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*logins.json*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*user data*\" OR TO… | ERROR |  |
| q-c459580218 | check C182 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*vault* OR process.command_line:*credential* OR process.command_line:*cmdkey* OR process.command_line:*CredMan*)", "time_from": null, "time_to": null,… | 0 |  |
| q-d44dd8cd20 | check C183 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-0d2b4587e7 | check C184 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-5c5ff091b9 | check C185 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*\\Microsoft\\Credentials* OR win.TargetFilename:*\\Vault* OR win.TargetFilename:*.vault*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name"… | 0 |  |
| q-3ade6a82e6 | check C186 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*cmdkey* OR process.command_line:*credential*)", "time_from": null, "time_to": null, "size": 50, "sub_field": nul… | 0 |  |
| q-216a114038 | check C187 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Vault* OR win.ScriptBlockText:*cmdkey* OR win.ScriptBlockText:*ConvertTo-SecureString*)", "time_from": null, "time_to": null, "fields": ["… | 4 | F30 |
| q-cf3a5b279d | check C188 | search | {"dataset": "windows.other", "query": "message:*Vault* OR message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 |  |
| q-9aec13c38b | check C189 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*lastpass* OR process.command_line:*bitwarden* OR process.command_line:*password… | 0 |  |
| q-c10aaf07d0 | check C190 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.kdbx OR win.TargetFilename:*.opvault OR win.TargetFilename:*.agilekeychain OR win.TargetFilename:*1password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-8d217dc797 | check C191 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*lastpass* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 0 |  |
| q-118ebbf35f | check C192 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*lastpass* OR process.command_line:*bitwarden*)", "time_from": null, "time_… | 0 |  |
| q-6c9aa078d8 | check C193 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*kdbx* OR win.ScriptBlockText:*keepass* OR win.ScriptBlockText:*1password* OR win.ScriptBlockText:*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 0 |  |
| q-58a99f44e4 | check C194 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*1password* OR message:*password manager*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exec… | 14 | F33 |
| q-21526f12aa | check C195 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*sam* OR win.TargetImage:*cryptdll*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-c518d3a899 | check C196 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*password*)", "time_from": null, "time_to": null, "size": 50, "sub_field": n… | 73 |  |
| q-00140eeb72 | check C197 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*\\Control\\Lsa* OR registry.path:*\\Control\\SecurityProviders* OR registry.path:*\\Control\\Lsa\\Notification Packages*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 293 |  |
| q-e5817be61f | check C198 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*\\Control\\Lsa* OR win.ObjectName:*SecurityProviders* OR win.ObjectName:*Notification Packages*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observe… | 0 |  |
| q-ff19513eea | check C199 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:9", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-1766bb50c8 | check C200 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-7be1471465 | check C201 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll* OR message:*Lsa*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proces… | 0 |  |
| q-c4302a9740 | check C202 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND (win.LogonType:3 OR win.LogonType:9)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 218 |  |
| q-c56aa277a0 | check C203 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-9a4aae513d | check C204 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*ntds*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 47 |  |
| q-dc09226aff | check C205 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*ntds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exec… | 326 | F35, F39 |
| q-e5290193d5 | check C206 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll* OR message:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proce… | 0 |  |
| q-bfe4e9349c | check C207 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*ntds* OR win.ScriptBlockText:*dcsync* OR win.ScriptBlockText:*golden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-d16d9252ca | check C208 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*\\System32\\*.dll OR win.TargetFilename:*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user… | 1 | F36 |
| q-8435993808 | check C209 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*Notification Packages*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proc… | 0 |  |
| q-183df1aa1c | check C210 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*password*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-8a04543140 | check C211 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*Notification Packages*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", … | 0 |  |
| q-8abef76fe4 | check C212 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Notification Packages* OR win.ScriptBlockText:*password filter* OR win.ScriptBlockText:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "o… | 0 |  |
| q-9daa2a9dae | check C213 | search | {"dataset": "windows.other", "query": "message:*Notification Packages* OR message:*password filter*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-b5c8715c4c | check C214 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-46b167e7ef | check C215 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*AllowReversiblePasswordEncryption* OR win.ScriptBlockText:*ReversibleEncryption* OR win.ScriptBlockText:*Set-ADAccountControl*)", "time_from": null, "time_to": null, "fields"… | 0 |  |
| q-0c66fffb3e | check C216 | search | {"dataset": "windows.powershell", "query": "event.code:4103 OR event.code:4104", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 5494 |  |
| q-ae042719e1 | check C217 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADAccountControl* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "size": 50, "sub_… | 0 |  |
| q-7953356296 | check C218 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*password encryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-35edec3a88 | check C219 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthenticationrequired*\"… | ERROR |  |
| q-af2748a80a | check C219 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthenticationrequired*\"… | ERROR |  |
| q-4ec82d1962 | check C220 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 41002 |  |
| q-8eeb8f7b8b | check C221 | search | {"dataset": "windows.other", "query": "event.code:4739 OR event.code:4730 OR event.code:4662", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-b7e453dd10 | check C222 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LIKE \"*dsacls*… | ERROR |  |
| q-b963cf99bd | check C222 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LIKE \"*dsacls*… | ERROR |  |
| q-8997a42f42 | check C223 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:5136 OR event.code:5137 OR event.code:5138 OR event.code:5139 OR event.code:5141", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-05740e5fce | check C224 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-285d85daec | check C225 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aadconnect*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*adfs*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*c… | ERROR |  |
| q-c2e4a943f8 | check C225 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aadconnect*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*adfs*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*c… | ERROR |  |
| q-2724502819 | check C226 | search | {"dataset": "windows.other", "query": "event.code:5136 OR event.code:5137 OR event.code:5138 OR event.code:5139 OR event.code:5141", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user… | 0 |  |
| q-43d6b77799 | check C227 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*\\\\system32\\\\*\" OR TO_LOWER(file.path) LIKE \"*networkprovider*\" OR TO_LOWER(file.path) LIKE \"*\\\\providers*\") \| KEEP @timestamp, host.n… | ERROR |  |
| q-e8fdc28863 | check C227 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*system32*\" OR TO_LOWER(file.path) LIKE \"*networkprovider*\" OR TO_LOWER(file.path) LIKE \"*providers*\") \| KEEP @timestamp, host.name, user.na… | ERROR |  |
| q-256a67acd7 | check C228 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, user.name, win.SourceImage, win.GrantedAccess, win.TargetImage, _id, _index"} | ERROR |  |
| q-b23a670a72 | check C228 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, user.name, win.SourceImage, win.GrantedAccess, win.TargetImage, _id, _index"} | ERROR |  |
| q-38174881e2 | check C229 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-6508ecdac6 | check C230 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 36 |  |
| q-1bc49ee972 | check C231 | search | {"dataset": "windows.other", "query": "event.code:4657 OR event.code:4697", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-fc6359ebb4 | check C232 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*\\\\system32\\\\*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*reg add*\" \| KEEP @timestamp, host.… | ERROR |  |
| q-cb9adf2f53 | check C232 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*system32*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*reg add*\" \| KEEP @timestamp, host.name, us… | ERROR |  |
| q-29396cf0f5 | check C233 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-0b38074d4f | check C234 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"22\" \| KEEP @timestamp, host.name, user.name, dns.question.name, win.QueryResults, process.executable, _id, _index"} | ERROR |  |
| q-35099372e7 | check C234 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"22\" \| KEEP @timestamp, host.name, user.name, dns.question.name, win.QueryResults, process.executable, _id, _index"} | ERROR |  |
| q-168d1862e0 | check C235 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-6378492a19 | check C236 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-72d511f9e1 | check C237 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*n… | ERROR |  |
| q-59ce0edf1a | check C237 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*n… | ERROR |  |
| q-bbacec848e | check C238 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-b7dd7bd36a | check C239 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:5355 OR destination.port:137 OR destination.port:138 OR destination.port:445)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 55 |  |
| q-bacd8f8c7f | check C240 | esql | {"query": "FROM zeek METADATA _id, _index \| WHERE event.action == \"dns\" \| KEEP @timestamp, source.ip, destination.ip, dns.question.name, dns.response_code, _id, _index"} | ERROR |  |
| q-ac6b6ea211 | check C240 (repaired) | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"dns\" \| KEEP @timestamp, source.ip, destination.ip, dns.question.name, dns.response_code, _id, _index"} | 53 |  |
| q-380172905d | check C241 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"22\" AND (TO_LOWER(dns.question.name) LIKE \"*wpad*\" OR TO_LOWER(dns.question.name) LIKE \"*isatap*\" OR TO_LOWER(dns.question.name) LIKE \"*localhost*\") \| KEEP @timestamp, host.na… | ERROR |  |
| q-aa85d3a454 | check C241 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"22\" AND (TO_LOWER(dns.question.name) LIKE \"*wpad*\" OR TO_LOWER(dns.question.name) LIKE \"*isatap*\" OR TO_LOWER(dns.question.name) LIKE \"*localhost*\") \| KEEP @timestamp, host.na… | ERROR |  |
| q-e249cad3fb | check C242 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 36 |  |
| q-baef7332db | check C243 | search | {"dataset": "windows.other", "query": "event.code:4697 OR event.code:4657", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-a18c78a941 | check C244 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*enablemulticast*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) L… | ERROR |  |
| q-9489d7fe7d | check C244 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*enablemulticast*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) L… | ERROR |  |
| q-255e69473a | check C245 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-d2b4b26139 | check C246 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"22\" \| KEEP @timestamp, host.name, dns.question.name, win.QueryResults, _id, _index"} | ERROR |  |
| q-3f2e8a9662 | check C246 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"22\" \| KEEP @timestamp, host.name, dns.question.name, win.QueryResults, _id, _index"} | ERROR |  |
| q-1a476ae9cd | check C247 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657 OR event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5373 |  |
| q-1fc88fa16b | check C248 | search | {"dataset": "windows.other", "query": "event.code:4657 OR event.code:4663", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-881fa6f3e3 | check C249 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*netsh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*route add*\" \| KEEP @timestamp, host.name, user.name, win.… | ERROR |  |
| q-6048e54408 | check C249 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*netsh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*route add*\" \| KEEP @timestamp, host.name, user.name, win.… | ERROR |  |
| q-18a64454b9 | check C250 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-0c4c287434 | check C251 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-7da9135c18 | check C252 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 216 |  |
| q-acb46504ce | check C253 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-d7e1b6d031 | check C254 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-bf2a0deac6 | check C255 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*DhcpServer* OR *New-DhcpServer* OR *Add-DhcpServerv4OptionValue* OR *rogue*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 0 |  |
| q-68b718d0c6 | check C256 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND network.transport:udp", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 62 |  |
| q-37ccf172d5 | check C257 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-16164820af | check C258 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 236 |  |
| q-2a3603a5d2 | check C259 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-a6e6ee57bf | check C260 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-b834020acc | check C261 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*kerberos* OR *kirbi* OR *ticket* OR *Rubeus* OR *Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 0 |  |
| q-b8cff2d2d1 | check C262 | search | {"dataset": "windows.other", "query": "message:(*Kerberos* OR *ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 1 | F45 |
| q-1d1c524da8 | check C263 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-6fc876d3d0 | check C264 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-22a9ecc33f | check C265 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-bd7faa22ec | check C266 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 236 |  |
| q-e99846d8f6 | check C267 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-618eca2c63 | check C268 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*krbtgt* OR *golden* OR *Mimikatz* OR *kerberos::golden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", … | ERROR |  |
| q-a3e092bdff | check C268 (repaired) | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*krbtgt* OR *golden* OR *Mimikatz* OR *kerberos\\:\\:golden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 0 |  |
| q-d230849351 | check C269 | search | {"dataset": "windows.other", "query": "message:(*krbtgt* OR *Kerberos*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 1 |  |
| q-5d5b1e282d | check C270 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-afca6c39ba | check C271 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-1a5679a6d5 | check C272 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-f8f5a45bdc | check C273 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 236 |  |
| q-b6b758378e | check C274 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-cd6f0b3408 | check C275 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*silver* OR *kerberos::ptt* OR *Rubeus* OR *kirbi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proce… | ERROR |  |
| q-1595c55482 | check C275 (repaired) | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*silver* OR *Rubeus* OR *kirbi*) OR win.ScriptBlockText:*kerberos*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "use… | 0 |  |
| q-d8401ba1d5 | check C276 | search | {"dataset": "windows.other", "query": "message:(*Kerberos* OR *ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 1 |  |
| q-7ce215c9b3 | check C277 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-9b0f515f95 | check C278 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-c401e41670 | check C279 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-09782b31a2 | check C280 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-f219292a3c | check C281 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 297 |  |
| q-3885c3d8a5 | check C282 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-4bf2bbb980 | check C283 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*kerberoast* OR *Invoke-Kerberoast* OR *Rubeus* OR *GetUserSPNs*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user… | 0 |  |
| q-8eedfff0ef | check C284 | search | {"dataset": "windows.other", "query": "message:(*Kerberos* OR *SPN* OR *ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-7d813deb4c | check C285 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-ebfeb107e8 | check C286 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-b1dd2ca39a | check C287 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-82c9163fed | check C288 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-1daccdff98 | check C289 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*asreproast* OR *GetNPUsers* OR *Rubeus* OR *asrep*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-c6547cb988 | check C290 | search | {"dataset": "windows.other", "query": "message:(*Kerberos* OR *preauth* OR *pre-auth*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comma… | 1 |  |
| q-4d059431eb | check C291 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-80db9f5852 | check C292 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-f38ebe4968 | check C293 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-d77f4c3b66 | check C294 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e505155957 | check C295 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*token* OR win.ScriptBlockText:*cookie* OR win.ScriptBlockText:*SAML*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "u… | 1 |  |
| q-b6394515a7 | check C296 | search | {"dataset": "windows.other", "query": "message:*token* OR message:*cookie* OR message:*SAML*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-fa80ba4fb3 | check C297 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-cd6aa2a85b | check C298 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-9ccea94579 | check C299 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-1e1915977a | check C300 | search | {"dataset": "windows.other", "query": "message:*cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destina… | 0 |  |
| q-8dd9ba9dca | check C301 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-fc8c15390b | check C302 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*SAML* OR win.ScriptBlockText:*NotOnOrAfter* OR win.ScriptBlockText:*token-signing*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 0 |  |
| q-c16a23d461 | check C303 | search | {"dataset": "windows.other", "query": "message:*SAML* OR message:*ADFS*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 0 |  |
| q-29437422f9 | check C304 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-89ea55ce88 | check C305 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-7058e1b3ae | check C306 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-3d57025042 | check C307 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*MFA* OR win.ScriptBlockText:*2FA* OR win.ScriptBlockText:*Authenticator*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code"… | 0 |  |
| q-e9a0d737ef | check C308 | search | {"dataset": "windows.other", "query": "message:*MFA* OR message:*2FA*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source… | 0 |  |
| q-186ba517ac | check C309 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-bfc1e8d6b4 | check C310 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-9e6e3bdc49 | check C311 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-9cc331e77a | check C312 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.pfx OR win.TargetFilename:*.p12 OR win.TargetFilename:*.cer OR win.TargetFilename:*.pvk)", "time_from": null, "time_to": null, "size": 50, "sub_field… | 1 |  |
| q-5521ab44db | check C313 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*certutil* OR win.ScriptBlockText:*Cert:\\*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datas… | ERROR |  |
| q-6c94e44b6d | check C313 (repaired) | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*certutil* OR win.ScriptBlockText:*Cert\\\\*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 1 | F53 |
| q-f74f1de902 | check C314 | search | {"dataset": "windows.other", "query": "message:*certificate* OR message:*Certificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comma… | 0 |  |
| q-a76e226168 | check C315 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-231c467015 | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND NOT win.GrantedAccess:(0x1000 OR 0x1400)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.SourceImage", "win.GrantedAccess", "win.TargetImage"… | 9 | F01, F05 |
| q-d57a56cb74 | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.SourceImage:(*PowerShell* OR *wsmprovhost* OR *wininit* OR *csrss* OR *services*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.SourceI… | 9 |  |
| q-dab0e987dc | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F01 |
| q-536fb167dc | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None | F01 |
| q-ca28dcbab9 | triage T1003 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (win.ProcessId:2976 OR win.ProcessId:7720 OR process.pid:2976 OR process.pid:7720)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line"… | 2 |  |
| q-baa1e53f33 | triage T1003 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*procdump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*Dump* O… | 3 |  |
| q-07f1f85634 | triage T1003 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:(*SAM* OR *SECURITY* OR *Cache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "registry.path", "registry.data.strings", "process.executable", "… | 6627 |  |
| q-121adc756f | triage T1003 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:(HKLM\\\\SECURITY\\\\Cache\\\\NL$1 OR HKLM\\\\SAM\\\\SAM\\\\Domains\\\\Account\\\\F)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "registry.pat… | 6 | F03, F04, F06 |
| q-ab0c774346 | triage T1003 step 4 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663) AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ObjectName", "win.ProcessName", "win.AccessMask", "win.SubjectUserName… | 19 | F01 |
| q-a6b53512c3 | triage T1003 step 5 | search | {"dataset": "windows.security", "query": "event.code:4662 AND (win.Properties:*1131f6aa* OR win.Properties:*1131f6ad* OR win.Properties:*Replicating*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ObjectName", "… | 1 | F07 |
| q-1959578d7f | triage T1003 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (process.executable:*PowerShell* OR process.executable:*wsmprovhost* OR process.executable:*control.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "file.p… | 474 |  |
| q-605a3190fa | triage T1003 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:(*.dmp OR *.zip OR *.rar OR *.7z OR *.txt) OR win.TargetFilename:(*.dmp OR *.zip)) AND NOT process.executable:*WerFault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 26 | F02 |
| q-02b502ddf5 | triage T1003 step 6 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*sekurlsa* OR process.command_line:*Dump… | 0 |  |
| q-82c5a0ea42 | triage T1003 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None | F01 |
| q-e2adf83cfb | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-d5a4451437 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-9447185021 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-f63a0a8f21 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-97074a200f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yf"} | None |  |
| q-5be867bb0d | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72YQ"} | None |  |
| q-7b10ba54ce | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-44bb4b7a9f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hjk9tr"} | None |  |
| q-0edc9dd29b | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hbcHpK"} | None |  |
| q-3e0fc4b70f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKxF"} | None |  |
| q-1d034deb9f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKxF"} | None |  |
| q-0f21ecdb36 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKxF"} | None |  |
| q-3cb127287b | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cyrL9g"} | None |  |
| q-c8a1a42154 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OiA"} | None |  |
| q-c6f484b4d8 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OiA"} | None |  |
| q-a16427d482 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nhwFD7"} | None |  |
| q-37194eea37 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nhwFD7"} | None |  |
| q-3cba393491 | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.executable:*NetworkWatcher* OR process.executable:*logman* OR process.executable:*python.exe OR process.executable:*PsExec64* OR process.executable:*PSEXESVC*)", "time_from": null, "time_to… | 24 | F09 |
| q-4efb93f4cd | triage T1040 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*capture* OR process.command_line:*sniff* OR process.command_line:*pktmon* OR process.command_line:*netsh* OR process.command_line:*dump* OR process.c… | 2 |  |
| q-8a0974c63c | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*netsh.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executable", "process.… | 2 | F08 |
| q-0b64f8aa27 | triage T1040 step 2 | search | {"dataset": "windows.security", "query": "event.code:4688 AND process.executable:*NetworkWatcher*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executable"… | 4 | F08 |
| q-66ecb98c20 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*python.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executable", "win.Tar… | 5 |  |
| q-dbe898ada6 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*raw OR process.command_line:*socket* OR process.command_line:*scapy* OR process.command_line:*sniff* OR process.command_line:*pcap*)", "time_from": null, "time_to": null, "fields":… | 0 |  |
| q-8e2348c048 | triage T1040 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND process.executable:*python.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "destination.ip", "destination.port", "source.ip", "source.po… | 348 |  |
| q-eb858ca74a | triage T1040 step 4 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:3", "time_from": null, "time_to": null, "size": 40, "sub_field": null} | 1229 |  |
| q-7857d0958c | triage T1040 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None | F08 |
| q-65befba27f | triage T1040 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.etl OR win.TargetFilename:*.pcap OR win.TargetFilename:*.cap OR win.TargetFilename:*.pcapng)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name"… | 38 |  |
| q-4aed9745ab | triage T1040 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*sniff*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*pcap*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*netsh*\" OR TO_LO… | 0 |  |
| q-093a7a9f21 | triage T1040 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND process.executable:*python.exe AND destination.port:8443", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "destination.ip", "destination.port… | 348 | F09 |
| q-48f33a1043 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-9559e9ea3d | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-aefba40111 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cjZNnV"} | None |  |
| q-9b517bb31a | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItI"} | None |  |
| q-07e1a63ccb | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNv3"} | None |  |
| q-56671cbf41 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-5f01b776e1 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-e5d1d507e4 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncsZp3"} | None |  |
| q-04b2c67fea | triage T1056 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (process.executable:*powershell.exe OR process.executable:*wsmprovhost.exe OR win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x101001 OR win… | 11 | F14 |
| q-845840d218 | triage T1056 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*python.exe OR process.executable:*rundll32.exe OR process.executable:*LogonUI.exe OR process.executable:*consent.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 18 | F12, F13 |
| q-03b4deddd6 | triage T1056 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None | F10, F14 |
| q-6464b07b38 | triage T1056 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None | F14 |
| q-602d3cf13d | triage T1056 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-7dae3871ef | triage T1056 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND (process.pid == 2976 OR process.parent.pid == 2976) \| KEEP @timestamp, event.code, process.executable, process.command_line, process.parent.e… | 40 |  |
| q-fd3365d533 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(process.executable) LIKE \"*python*\" OR TO_LOWER(win.TargetFilename) LIKE \"*python*\" OR TO_LOWER(process.command_line) LIKE \"*keylog*\" OR TO_LOWER(process.command_line) LIK… | 40 |  |
| q-06cd3bf394 | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None | F10 |
| q-ded022af5c | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03AJQ"} | None |  |
| q-ebe857c546 | triage T1056 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (TO_LOWER(win.ScriptBlockText) LIKE \"*monkey*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*keylog*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*getasynckeystate*\… | ERROR |  |
| q-492de80606 | triage T1056 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*monkey*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.png\" OR TO_LOWER(win.TargetFile… | ERROR |  |
| q-c5748841dc | triage T1056 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*monkey*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*keylog*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*getasynckeysta… | 2 | F11 |
| q-26deffb55c | triage T1056 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*monkey*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.png\" OR TO_LOWER(win.Target… | 20 | F10 |
| q-22dec9122a | triage T1056 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCuG"} | None | F11 |
| q-fc324305d2 | triage T1056 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(process.executable) LIKE \"*victim*\" OR TO_LOWER(process.command_line) LIKE \"*victim*\" OR TO_LOWER(win.TargetFilename) LIKE \"*victim*\" \| KEEP @timestamp, host.name, event.… | 25 |  |
| q-3f23915660 | triage T1056 step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None | F10 |
| q-71e4269bc0 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-6d55c08a34 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-c39a660d58 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-aea0658816 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-e0fc6d5ab0 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqdH"} | None |  |
| q-a05dc0148e | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCuG"} | None |  |
| q-0dda7e36b7 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCuG"} | None |  |
| q-2fa0cae607 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-60803291f4 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c0sdf6"} | None |  |
| q-542b8b5fd1 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7huwtOr"} | None |  |
| q-621500ee10 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-48YI"} | None |  |
| q-4e5b8353e8 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c93dwd"} | None |  |
| q-6306b222a2 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-7c6d8f505a | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-a72430951d | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-0fc139347f | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-de2095d0cd | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyU"} | None |  |
| q-1fb083b13f | triage T1110 step 1 | search | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4648 OR event.code:4771", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "win.SubjectUserName", "source.ip", "win.IpAddress",… | 15 | F15, F18 |
| q-ecb97cc043 | triage T1110 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F15 |
| q-6a18606b56 | triage T1110 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F17 |
| q-17ad45dca5 | triage T1110 step 2 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F16, F19 |
| q-2f781bbc91 | triage T1110 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*Invoke-Mimikatz* OR process.command_line:*sekurlsa* OR process.command_line:*procdump* OR process.command_line:*c… | 1 |  |
| q-8c4f2a7cc9 | triage T1110 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*PowerShell.exe AND (process.command_line:*lsass* OR process.command_line:*Credential* OR process.command_line:*Dump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 0 |  |
| q-48295aad56 | triage T1110 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND win.ProcessId:2976", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executable", "user.name", "win.ProcessGuid"], … | 1 |  |
| q-114ac85943 | triage T1110 step 4 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.TargetUserName"} | 297 |  |
| q-7fc09043c7 | triage T1110 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None | F17 |
| q-246cc1c959 | triage T1110 step 5 | count | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776 OR event.code:529 OR event.code:530", "time_from": null, "time_to": null} | 1 |  |
| q-5b86a8aeef | triage T1110 step 6 | search | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776 OR event.code:529 OR event.code:530", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "win.SubjectUser… | 1 | F15, F19 |
| q-755bd00e0c | triage T1110 step 6 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:SAM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ObjectName", "win.ProcessName", "win.SubjectUserName", "win.AccessMask", "win.Access… | 0 |  |
| q-9b48deae40 | triage T1110 step 7 | search | {"dataset": "windows.security", "query": "win.ObjectName:SAM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ObjectName", "win.ProcessName", "win.SubjectUserName", "win.AccessMask", "win.AccessList"], "size": 15, … | 10 | F17 |
| q-13d3e84c7c | triage T1110 step 7 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-91d1c0c876 | triage T1110 step 8 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.SourceImage:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.SourceImage", "win… | 4 | F17 |
| q-beb8483fea | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-c4695e9b4e | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-e71a26b6dc | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-7fd2117464 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-241e787aae | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuAn"} | None |  |
| q-1d9980510d | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCH"} | None |  |
| q-e19e152ac5 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-2c8b5d333a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-aff16d14c1 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-7896bb5da8 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-42ff2d18a8 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-4ee1e41302 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-58c46437b1 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-2fa3ebdafe | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niydsP"} | None |  |
| q-54831c556e | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niydsP"} | None |  |
| q-cb41ede4ca | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVtv"} | None |  |
| q-b950b07cff | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-93b5b891f5 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-1d01584b0c | triage T1111 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F20 |
| q-85feba3c27 | triage T1111 step 1 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.TargetUserName", "win.TargetServerName", "win.ProcessName", "win.SubjectUserName", "win.IpAddress"], "size":… | 15 | F21 |
| q-e1d4f4337e | triage T1111 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F21 |
| q-9ec8f6c5ad | triage T1111 step 2 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None | F20 |
| q-0ca1ce1400 | triage T1111 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (process.command_line LIKE \"*readme.ps1*\" OR process.command_line LIKE \"*SysinternalsSuite*\" OR process.command_line LIKE \"*lsass*\" OR process.command_line LIKE… | ERROR |  |
| q-cb73e12326 | triage T1111 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*OpenProcess*\" OR win.ScriptBlockText LIKE \"*Token*\" OR win.ScriptBlockText LIKE \"*Cred… | ERROR |  |
| q-2b631686d8 | triage T1111 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*readme.ps1*\" OR process.command_line LIKE \"*SysinternalsSuite*\" OR process.command_line LIKE \"*lsass*\" OR process.command_line … | 10 | F20 |
| q-76a44db590 | triage T1111 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*OpenProcess*\" OR win.ScriptBlockText LIKE \"*Token*\" OR win.ScriptBlockText LIKE \"*… | 3 |  |
| q-3993fd8f02 | triage T1111 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F20 |
| q-c1a554e649 | triage T1111 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-94166edf97 | triage T1111 step 6 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-16929681fd | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-d4c611a00d | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-93c8f60c57 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-18a0198004 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-d7eeeb8d2e | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-658310383e | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-008566e9ab | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-12841a1a9f | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-30011f50d2 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-0965c45f0f | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-74a3a44b10 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-22c26b991d | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncsJoZ"} | None |  |
| q-0c2e8fdf8a | triage T1187 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1br"} | None |  |
| q-fb1ed44b19 | triage T1187 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YZ"} | None |  |
| q-ac4f702773 | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "http.request.method", "query": "event.action:http", "time_from": null, "time_to": null, "size": 20, "sub_field": "destination.ip"} | 62 |  |
| q-bd4e50fe37 | triage T1187 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND win.TargetFilename LIKE \"*hostui.lnk\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, win.TargetFilename, _id, _index"} | ERROR |  |
| q-c38837d76d | triage T1187 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND win.TargetFilename LIKE \"*hostui.lnk\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, win.TargetFilename, _id, _index"} | 1 | F22 |
| q-13b4e3854a | triage T1187 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == \"445\" OR destination.port == \"139\") \| KEEP @timestamp, host.name, user.name, process.executable, destination.ip, destination.port, _id, … | ERROR |  |
| q-29e8606eae | triage T1187 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5140\" \| KEEP @timestamp, host.name, user.name, win.ShareName, win.IpAddress, win.SubjectUserName, _id, _index"} | 42 | F23 |
| q-51c6a22646 | triage T1187 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrG"} | None |  |
| q-21f7195cdb | triage T1187 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 139) \| KEEP @timestamp, host.name, user.name, process.executable, destination.ip, destination.port, _id, _index"} | 66 |  |
| q-06fb11dcca | triage T1187 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" AND destination.ip == \"192.168.0.4\" \| KEEP @timestamp, source.ip, destination.ip, http.request.method, url.original, user_agent.original, http.response.status_code, _id… | 62 | F22 |
| q-edba1a1797 | triage T1187 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*webclient*\" OR TO_LOWER(registry.path) LIKE \"*networkprovider*\") \| KEEP @timestamp, host.name, process.executable, registry.… | 0 |  |
| q-c6de4e7305 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YZ"} | None |  |
| q-9b1ebea585 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1br"} | None |  |
| q-7805416984 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YN"} | None |  |
| q-146458e848 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YN"} | None |  |
| q-cfc1482163 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YN"} | None |  |
| q-99825c0186 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrG"} | None |  |
| q-2cd08b6e42 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nftACH"} | None |  |
| q-f75dcdabd9 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nftACH"} | None |  |
| q-c8d346abf8 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7b6uGkC"} | ERROR |  |
| q-0389f11cfd | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7b6uGkC"} | ERROR |  |
| q-0224ae1859 | triage T1187 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7b6uGkC"} | ERROR |  |
| q-28e4b67843 | triage T1187 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 139) \| KEEP @timestamp, host.name, process.executable, destination.ip, destination.port, _id, _index \| SORT @tim… | 5 | F23 |
| q-f0b29e4b95 | triage T1212 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.SourceImage:*PowerShell* OR win.SourceImage:*wsmprovhost* OR win.SourceImage:*wininit* OR win.SourceImage:*csrss* OR win.SourceImage:*services.exe)", "time_from": null, … | 9 | F24 |
| q-6d25a4fc3a | triage T1212 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*sekurlsa* OR process.command_line:*MiniDump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "pro… | 1 |  |
| q-7af755684d | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None | F24 |
| q-40015b3135 | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None | F24 |
| q-5f50addad2 | triage T1212 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText… | 3 | F24 |
| q-661d543a05 | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F24 |
| q-233a37f7d0 | triage T1212 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.pid:2976 OR process.pid:3876 OR process.command_line:*psversion* OR process.command_line:*Invoke-Exfil* OR process.command_line:*Exfil*)", "time_from": null, "time_to": null, "fields": ["@timest… | 3 | F24 |
| q-ef9cd2645d | triage T1212 step 4 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.TargetUserName:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "win.SubjectUserName", "win.LogonType", "win.IpAddress", "w… | 30 | F24 |
| q-254a826325 | triage T1212 step 4 | search | {"dataset": "windows.security", "query": "event.code:7045 OR event.code:4697 OR (event.code:4663 AND win.ObjectName:*lsass*) OR (event.code:4656 AND win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code… | 42 | F24 |
| q-967cda2b84 | triage T1212 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*javamtsup* OR process.command_line:*PSEXESVC* OR process.command_line:*Get-Process* OR process.command_line:*lsass* OR process.command_line:*Credential* OR process.command_line:*Du… | 6 |  |
| q-8f4fb35a43 | triage T1212 step 5 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040 OR event.code:7036", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ServiceName", "win.ImagePath", "win.ServiceType", "win.StartType", "mess… | 17 | F24 |
| q-1b161c5785 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-7b5ad9be6f | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-2feec760e4 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-beec2a9b54 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-035944f079 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-ce6eec961d | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-1d6aa2cde0 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-c110f26f72 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-c68e5d5571 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-455384f0a5 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-0bed508621 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-fd2afcbe09 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-4451144094 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-a805959735 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-fefcc28828 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-fcbd47c9c0 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuT"} | None |  |
| q-6099f24c72 | triage T1539 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*Web Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetFilename", "proc… | 162 | F25 |
| q-7d4b68d7ee | triage T1539 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Cookies* OR process.command_line:*Login Data* OR process.command_line:*chrome* OR process.command_line:*firefox*)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 4 | F25 |
| q-aaa59e0247 | triage T1539 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*Web Data*) AND NOT win.TargetFilename:*lastalive* AND NOT win.TargetFilename:*GroupPolicy*", "time_from": null, "t… | 1 |  |
| q-9c5e52935f | triage T1539 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*Web Data*) AND (win.TargetFilename:*Edge* OR win.TargetFilename:*Chrome* OR win.TargetFilename:*Firefox* OR win.Ta… | 1 |  |
| q-305300a2a9 | triage T1539 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None | F25 |
| q-d4e01e72cd | triage T1539 step 3 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*Cookies* OR win.ObjectName:*Login Data* OR win.ObjectName:*Web Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "process.executab… | 0 |  |
| q-b7b8b74f14 | triage T1539 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*MicrosoftEdge* OR process.executable:*iexplore* OR process.executable:*chrome* OR process.executable:*firefox*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 3 | F25 |
| q-f384d77ea3 | triage T1539 step 4 | search | {"dataset": "zeek", "query": "event.action:http", "time_from": null, "time_to": null, "fields": ["@timestamp", "url.domain", "url.original", "user_agent.original", "http.request.method", "source.ip", "destination.ip"], "size": 20, "sort": "asc"} | 62 | F25 |
| q-ed48e15076 | triage T1539 step 5 | aggregate | {"dataset": "zeek", "field": "user_agent.original", "query": "event.action:http", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 62 |  |
| q-e4b2af7c20 | triage T1539 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*INetCookies* OR win.TargetFilename:*Cookies\\\\* OR win.TargetFilename:*cookies.sqlite* OR win.TargetFilename:*Login Data For Account*)", "time_from": null, "time_to": null, "fields… | 0 |  |
| q-dc2483876e | triage T1539 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*AppData\\\\Local\\\\Microsoft\\\\Edge* OR process.command_line:*AppData\\\\Roaming\\\\Mozilla* OR process.command_line:*AppData\\\\Local\\\\Google* OR process.command_line:*INetCoo… | 0 |  |
| q-14ceacd48e | triage T1539 step 6 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*Edge* OR win.ObjectName:*Mozilla* OR win.ObjectName:*Google\\\\Chrome*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "process.execut… | 0 |  |
| q-23c2a4cee5 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy1EsG"} | None |  |
| q-fc50a7908a | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-fdbbfb1a59 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-6e9f813335 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b-xybj"} | None |  |
| q-65e1dcf552 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b-xybj"} | None |  |
| q-f1c9f498fe | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxETLY"} | None |  |
| q-9034373094 | triage T1539 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1br"} | None |  |
| q-be0a603b7d | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None | F26 |
| q-8bf5bf3fb5 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F27 |
| q-ebb1c88d89 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSytV"} | None | F27 |
| q-5434085036 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.p12\" OR TO_LOWER(win.TargetFilename) LIKE \"*.7z\" OR TO_LOWER(win.Target… | 5 | F26, F27 |
| q-18516266eb | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sysinternals*\" OR TO_LOWER(process.executable) LIKE \"*sysinternals*\" OR TO_LOWER(process.command_line) LIKE \"*readme.p… | 11 | F27 |
| q-80a3ffd500 | triage T1552 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None | F27 |
| q-972423b574 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectType == \"Key\" AND (TO_LOWER(win.ObjectName) LIKE \"*lsa*\" OR TO_LOWER(win.ObjectName) LIKE \"*winlogon*\" OR TO_LOWER(win.ObjectName) LIKE \"*pr… | 20 |  |
| q-072a42657e | triage T1552 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectType == \"Key\" AND win.ProcessName LIKE \"*powershell.exe\" \| KEEP @timestamp, host.name, win.ObjectName, win.ProcessName, win.AccessMask, win.Su… | 15 | F28 |
| q-93e52cf67f | triage T1552 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, win.TargetUserName, win.SubjectUserName, win.ProcessName, win.IpAddress, _id, _index \| SORT @timestamp ASC"} | 15 | F27 |
| q-a25cb9f1de | triage T1552 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND TO_LOWER(win.TargetFilename) LIKE \"*gpt.ini*\" \| KEEP @timestamp, host.name, process.executable, win.TargetFilename, _id, _index"} | 3 | F29 |
| q-9dfbaf51f6 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-f6353043cc | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-0d4dcf9025 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-12521c4cfe | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-cb45cdae37 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-9cc4df3cf8 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None |  |
| q-b6c8fcc729 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None |  |
| q-07c1d7b533 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-8258dc6ac8 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSytV"} | None |  |
| q-f3ba734cc4 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c_44mH"} | None |  |
| q-d6fdc8bad2 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03AIc"} | None |  |
| q-a1eeff9c67 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-11d42ccd38 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFDK4"} | None |  |
| q-0b756f5fb7 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFDKr"} | None |  |
| q-1bb9b19814 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFDKr"} | None |  |
| q-9dfe8148e2 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cZN9Bo"} | None |  |
| q-bacde1e2c8 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cZN9Bo"} | None |  |
| q-f3c64892ee | triage T1555 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F30 |
| q-57b86b7038 | triage T1555 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Login\\\\ Data* OR win.TargetFilename:*logins.json OR win.TargetFilename:*key4.db OR win.TargetFilename:*key3.db OR win.TargetFilename:*Cookies* OR win.TargetFilename:*Web Data* OR … | 0 |  |
| q-617edb4894 | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None | F30, F31 |
| q-d9a09ebdb0 | triage T1555 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*DumpCred* OR win.ScriptBlockText:*Get-Process* OR win.ScriptBlockText:*Out-Minidump* OR win.ScriptBlockText:*… | 3 | F31 |
| q-121ec10a95 | triage T1555 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:00:00.000Z TO 2020-05-02T03:10:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "eve… | 99 |  |
| q-75e5071c13 | triage T1555 step 3 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*Login* OR win.ObjectName:*logins.json OR win.ObjectName:*key4.db OR win.ObjectName:*key3.db OR win.ObjectName:*Cookies OR win.ObjectName:*Web Data OR win.ObjectName:*Local State OR … | 0 |  |
| q-bc63ebdaeb | triage T1555 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:03:00.000Z TO 2020-05-02T03:08:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "eve… | 52 |  |
| q-92428f6296 | triage T1555 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None | F30 |
| q-c3a02648c3 | triage T1555 step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:04:30.000Z TO 2020-05-02T03:07:30.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "eve… | 29 | F30 |
| q-9fa8b50713 | triage T1555 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND host.name:scranton.dmevals.local AND (win.TargetFilename:*.dmp OR win.TargetFilename:*.pfx OR win.TargetFilename:*Downloads*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 315 | F32 |
| q-e81312634e | triage T1555 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.dmp OR win.TargetFilename:*.pfx)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetFilename", "process.executable", "process.comm… | 3 | F30 |
| q-1174ef8c99 | triage T1555 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:04:00.000Z TO 2020-05-02T03:07:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.e… | 19 |  |
| q-a097ef2f19 | triage T1555 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None | F31 |
| q-023ee5e3e6 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-2e304f99ae | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-a99563b947 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSsN"} | None |  |
| q-2248b1c091 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-64557e0a56 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-296fc636bf | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-864a782f78 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-bf8d1b8ca7 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-c031d2b89a | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-b53015d6b7 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hjk9tr"} | None |  |
| q-ec78b120cc | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuD8"} | None |  |
| q-525bc1ad5e | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-b5483fba45 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:7 AND (win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*samlib* OR win.ImageLoaded:*samsrv* OR win.ImageLoaded:*samcli* OR win.ImageLoaded:*apisampling*)", "time_from": null, "time… | 72 |  |
| q-ea9bc7dcf6 | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (process.executable:*PowerShell.exe OR process.executable:*wsmprovhost.exe OR win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff)", "time_from": null, "time_to": null, … | 5 | F34, F35 |
| q-040a52641b | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.ImageLoaded", "win.Signed", "win.Signature", "win.SignatureStatus", "win.Com… | 1 | F35 |
| q-b148f73298 | triage T1556 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*sekurlsa* OR process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*password*… | 1 |  |
| q-69942f80e5 | triage T1556 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*procdump* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*password* OR win.ScriptBlockText:*credenti… | 2 |  |
| q-ed8efb3a32 | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F34 |
| q-8d3e1ba51f | triage T1556 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND process.executable:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.par… | 11 | F34 |
| q-673da4f2d6 | triage T1556 step 5 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:4104 AND @timestamp:[2020-05-02T03:00:00.000Z TO 2020-05-02T03:10:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "us… | 99 |  |
| q-a212746ed8 | triage T1556 step 5 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4673 OR event.code:4674 OR event.code:4670 OR event.code:4703 OR event.code:4945 OR event.code:5447 OR event.code:5441 OR event.code:5446", "time_from": null, "time_to": null, "size": … | 5794 |  |
| q-e6e029ff69 | triage T1556 step 6 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:4104 AND @timestamp:[2020-05-02T03:02:00.000Z TO 2020-05-02T03:10:00.000Z] AND NOT win.ScriptBlockText:prompt", "time_from": null, "time_to": null, "fields": ["@timesta… | 61 | F34, F37, F38 |
| q-90be27f013 | triage T1556 step 6 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*Lsa* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.… | 1479 |  |
| q-27f0d73beb | triage T1556 step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*\\\\Control\\\\Lsa\\\\* OR registry.path:*SecurityProviders* OR registry.path:*Notification* OR registry.path:*\\\\Lsa\\\\* )", "time_from": null, "time_to": null, "fields": ["@timestamp… | 445 |  |
| q-8e8e3e3860 | triage T1556 step 7 | search | {"dataset": "windows.security", "query": "event.code:4663 AND process.executable:*cod.3aka3.scr*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "process.executable", "win.ObjectName", "win.AccessMask", "w… | 1 |  |
| q-382c5bd8a0 | triage T1556 step 8 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*ControlSet*Control\\\\Lsa* OR registry.path:*\\\\CurrentControlSet\\\\Control\\\\Lsa* OR registry.path:*\\\\SAM\\\\* OR registry.path:*\\\\SECURITY\\\\*)", "time_from": null, "time_to": … | 9 | F40 |
| q-6bda18fb9e | triage T1556 step 8 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*) AND NOT win.ObjectName:*Lsa*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "process.execu… | 0 |  |
| q-d604a65031 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-fdb8f9bf3a | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-abe8a4769d | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-9b89140462 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-92009763a5 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-0c3116a47a | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cjZNk-"} | None |  |
| q-6dc8455e6d | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-2b193fa5d7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0W8_"} | None |  |
| q-9e94884a80 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None |  |
| q-0639774016 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None |  |
| q-b0fdddb077 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysW"} | None |  |
| q-bea6f228b4 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSsN"} | None |  |
| q-74a9339d98 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0W8_"} | None |  |
| q-77c0c39d2d | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyX"} | None |  |
| q-46ba6852b8 | triage T1557 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*arp.exe\" OR TO_LOWER(process.executable) LIKE \"*route.exe\" OR TO_LOWER(process.executable) LIKE \"*ipconfig*\" OR TO_LOWE… | 11 | F43 |
| q-0d6f8738e9 | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND destination.port == 445 \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.orig_l2_addr, zeek.resp_l2_addr, zeek.duration, zeek.conn_state, _id, _in… | 45 |  |
| q-f5b49a07cf | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action IN (\"smb_files\",\"smb_mapping\",\"dce_rpc\",\"notice\",\"weird\") \| KEEP @timestamp, event.action, source.ip, destination.ip, zeek.orig_l2_addr, zeek.resp_l2_addr, zeek.path, zeek.… | 160 | F42 |
| q-6f5e1af0b0 | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" \| STATS cnt = COUNT(*) BY source.ip, destination.ip, zeek.orig_l2_addr, zeek.resp_l2_addr \| SORT cnt DESC"} | 9 |  |
| q-bdc766645b | triage T1557 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action IN (\"smb_files\",\"smb_mapping\",\"notice\",\"weird\") \| KEEP @timestamp, event.action, source.ip, destination.ip, zeek.path, zeek.name, zeek.share_type, zeek.filename, zeek.note, z… | 37 | F41, F42, F43 |
| q-21b99591ab | triage T1557 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" OR event.code == \"5140\" \| STATS cnt = COUNT(*) BY host.name, win.ShareName, win.RelativeTargetName, win.SubjectUserName, source.ip \| SORT cnt DESC"} | 67 |  |
| q-2c9073608a | triage T1557 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*psexec*\" OR TO_LOWER(process.executable) LIKE \"*psexesvc*\" OR TO_LOWER(process.executable) LIKE \"*python*\" OR TO_LOWER(… | 19 | F42 |
| q-94cbd391db | triage T1557 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonProcessName LIKE \"*NtLmSsp*\" OR (event.code == \"4624\" AND win.LogonType == \"3\") \| KEEP @timestamp, host.name, win.TargetUserName, win.LogonTy… | 218 |  |
| q-94a2b6e8ed | triage T1557 step 5 | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1aD"} | None | F41, F42, F43 |
| q-ce4a08a367 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code IN (\"7045\",\"7040\",\"2004\",\"2006\",\"1500\",\"10148\",\"10149\",\"1074\",\"98\",\"20\",\"32\",\"55\",\"258\",\"263\") \| KEEP @timestamp, host.name, event.code, win.Servic… | 41 | F44 |
| q-28e2d67f5c | triage T1557 step 6 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND destination.ip IN (\"192.168.0.4\",\"192.168.0.5\") \| STATS cnt = COUNT(*) BY source.ip, destination.ip, destination.port, zeek.orig_l2_addr, zeek.resp_l2_addr \| SOR… | 6 |  |
| q-7ac43884a1 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1aD"} | None |  |
| q-4c3006f7cd | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1aD"} | None |  |
| q-850ae10494 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1aD"} | None |  |
| q-16505a4a1d | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlbm"} | None |  |
| q-296e45a1c6 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qUct2z"} | None |  |
| q-f727d9d70f | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1aD"} | None |  |
| q-b00e75776f | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1aD"} | None |  |
| q-ee75b597c6 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bM"} | None |  |
| q-6c50595363 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1Zv"} | None |  |
| q-f0895c2586 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlbb"} | None |  |
| q-891cab7f9e | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03AIc"} | None |  |
| q-2b33b89d62 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1aD"} | None |  |
| q-3a3bae2469 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlbm"} | None |  |
| q-b650b56b7f | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cREvLs"} | None |  |
| q-f37316a1a9 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cREvLs"} | None |  |
| q-6b706cbc6d | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-c92c3dda45 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDx"} | None |  |
| q-98c3b9751a | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-302328c10e | triage T1558 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4769 \| KEEP @timestamp, host.name, user.name, source.ip, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.Status, win.TargetUserName, win.IpAddress, _id… | ERROR |  |
| q-eb7a39a941 | triage T1558 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass.exe\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.na… | ERROR |  |
| q-fc0e5db396 | triage T1558 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" \| KEEP @timestamp, host.name, user.name, source.ip, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.Status, win.TargetUserName, win.IpAddress,… | 28 | F45, F47, F48 |
| q-1cd83643fb | triage T1558 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass.exe\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, hos… | 33 | F46 |
| q-03892e53f6 | triage T1558 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F46 |
| q-580e1c2bb9 | triage T1558 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, process.executable, process.command_line, process.parent.executable, user.name, _id, _index \| SORT @t… | 359 | F46 |
| q-f6f264ce90 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 146 | F46 |
| q-00cff726d8 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4624\",\"4672\",\"4768\",\"4769\",\"4776\") AND (win.TargetUserName LIKE \"*pbeesly*\" OR win.TargetUserName LIKE \"*wardog*\" OR win.TargetUserName LIKE \"*krbtgt*\")… | 55 |  |
| q-e28a668eae | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4768\" \| KEEP @timestamp, host.name, win.TargetUserName, win.IpAddress, win.PreAuthType, win.TicketEncryptionType, win.Status, win.TicketOptions, _id, _index \| SORT @… | 14 | F49 |
| q-53c264f661 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE win.TargetUserName LIKE \"*wardog*\" OR win.SubjectUserName LIKE \"*wardog*\" \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.SubjectUserName, win.LogonType, win.IpA… | 17 |  |
| q-4062afce6a | triage T1558 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" AND win.ServiceName NOT LIKE \"*$\" AND win.ServiceName != \"krbtgt\" \| KEEP @timestamp, host.name, win.TargetUserName, win.ServiceName, win.TicketEncryptionTyp… | 0 |  |
| q-4408af664c | triage T1558 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" \| STATS c = COUNT(*) BY host.name, win.SubjectUserName \| SORT c DESC"} | 12 |  |
| q-b636104030 | triage T1558 step 7 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None | F45 |
| q-e87626351c | triage T1558 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None | F47 |
| q-a46ca98765 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None |  |
| q-0eaf4bdd28 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None |  |
| q-e0f1201a8f | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzGpUD"} | None |  |
| q-d73a8317a5 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuAv"} | None |  |
| q-c759b529b4 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-b42b4f226a | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-d97153e33f | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-3c8655d696 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-df2aa56d76 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVSlm"} | None |  |
| q-ae617b859e | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-61c5cc9a94 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72bs"} | None |  |
| q-a7df63726a | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72bs"} | None |  |
| q-1e795f5972 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-be97ee591f | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-0bdda11414 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytvM"} | None |  |
| q-0e55b97a9d | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytvM"} | None |  |
| q-233beca7e8 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nSlAli"} | None |  |
| q-a6bded30a2 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-9cc39373ca | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5pb"} | None |  |
| q-68969fd84a | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhIsr"} | None |  |
| q-e69dd1106e | triage T1606 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\", \"0x101001\", \"0x1f3fff\", \"0x1000000\", \"0x3000\") \| KEEP @timestamp, host.na… | ERROR |  |
| q-a27f7b8dc9 | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None | F52 |
| q-c31fa155d7 | triage T1606 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\", \"0x101001\", \"0x1f3fff\", \"0x1000000\", \"0x3000\") \| KEEP @timestamp, hos… | 9 | F50, F52 |
| q-a25db5dc7e | triage T1606 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| STATS c = COUNT(*) BY win.SourceImage, win.GrantedAccess \| SORT c DESC"} | 15 |  |
| q-f486d2831f | triage T1606 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-19f5bdc9bf | triage T1606 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-af9fb79da2 | triage T1606 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| STATS c = COUNT(*) BY win.Path, host.name \| SORT c DESC"} | 16 |  |
| q-4dfb5bfcf7 | triage T1606 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*comsvcs*\" OR… | 5 |  |
| q-bae66737ef | triage T1606 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRCsS"} | None |  |
| q-5be83ce4b5 | triage T1606 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F51 |
| q-cc316aa1c9 | triage T1606 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE TO_LOWER(win.ObjectName) LIKE \"*adfs*\" OR TO_LOWER(win.ServiceName) LIKE \"*adfs*\" OR TO_LOWER(win.TargetName) LIKE \"*adfs*\" OR TO_LOWER(win.ProcessName) LIKE \"*adfs*\" OR TO_LOW… | 0 |  |
| q-7c97cbbc6b | triage T1606 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND TO_LOWER(win.TargetFilename) LIKE \"*cookie*\" \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetFilename, _id, _index"} | 1 | F51 |
| q-c9c1bfb25c | triage T1606 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND (win.LogonProcessName == \"-\" OR win.LogonProcessName == \"NtLmSsp \" OR win.LogonProcessName == \"User32 \") \| KEEP @timestamp, host.name, win.LogonProces… | 4 | F50 |
| q-1d44ee9411 | triage T1606 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookie*\" OR TO_LOWER(process.command_line) LIKE \"*saml*\" OR TO_LOWER(process.command_line) LIKE \"*adfs*\" OR TO_LOWER(… | 7 | F51, F52 |
| q-26fa846ba6 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-eb41be63a1 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-be08ddbe1f | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cTFCiC"} | None |  |
| q-974040e030 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-a8719b9a24 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncsZpc"} | None |  |
| q-c4f08c39b6 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c93Nx4"} | None |  |
| q-da6f393fc6 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-44ecfa31a2 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-6a6ea1d2ce | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-618d25beb7 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_zRVX"} | None |  |
| q-034a617666 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-1d4067792d | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-47325f4ea1 | triage T1649 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*pfx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.TargetFilename", "process.executable", "process.command_line", "win.Image"], "size"… | 1 |  |
| q-4616cf320d | triage T1649 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None | F53 |
| q-90d57f3b7b | triage T1649 step 2 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ObjectName", "win.ObjectValueName", "win.NewValue", "win.OperationTy… | 1 |  |
| q-d0b18be0b0 | triage T1649 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*readme.ps1* OR process.command_line:*Get-PrivateKeys* OR process.command_line:*Export-PfxCertificate* OR process.command_line:*certutil*)", "time_from": null, "time_to": null, "fie… | 0 |  |
| q-d51266965e | triage T1649 step 3 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pfx* OR process.command_line:*certutil* OR process.command_line:*readme.ps1*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.c… | 0 |  |
| q-2fa6ff2eb6 | triage T1649 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, process.executable, process.command_line, process.parent.executable, process.parent.command… | 359 |  |
| q-fec88a2ccd | triage T1649 step 4 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*cert* OR win.ScriptBlockText:*Cert* OR win.ScriptBlockText:*pfx* OR win.ScriptBlockText:*PrivateKey*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "even… | 5 | F53 |
| q-f22fa183ab | triage T1649 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-63d42002da | triage T1649 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-3225609165 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-0a0e6fd544 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-8da5c44f41 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-6c82be2e9b | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-d3b05b13ed | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-e42ada919f | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-6323428e9d | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-5009ce06cf | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-daa01d3d3a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-28eb3b2bbb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-5a7d2050fa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-2da143ee4b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-ad962304f5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yf"} | None |  |
| q-6a10653266 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72YQ"} | None |  |
| q-c519c4a46d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-71cb1b7044 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hjk9tr"} | None |  |
| q-dde4778d7c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hbcHpK"} | None |  |
| q-83ad984fb6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKxF"} | None |  |
| q-dd60d6d11d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKxF"} | None |  |
| q-50595ba1c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKxF"} | None |  |
| q-9dd37d3a12 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cyrL9g"} | None |  |
| q-6136a514cd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OiA"} | None |  |
| q-27a81e831c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OiA"} | None |  |
| q-daae3fa70f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nhwFD7"} | None |  |
| q-004148d3a1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nhwFD7"} | None |  |
| q-69a4da2f28 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-34070a4231 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-2e4bb7050c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cjZNnV"} | None |  |
| q-5403ad3a3a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItI"} | None |  |
| q-3bc5cc3d66 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNv3"} | None |  |
| q-ad0a03d3f9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-49204de61a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-c8a06b524f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncsZp3"} | None |  |
| q-ba231965a1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-a390ff5829 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-88dca081e0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-9cd66c0402 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-5efb172bfd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqdH"} | None |  |
| q-6efa591afe | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCuG"} | None |  |
| q-fa9d5393c7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCuG"} | None |  |
| q-53fbc861ba | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-b9a94be5a2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c0sdf6"} | None |  |
| q-b7516eae44 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7huwtOr"} | None |  |
| q-96837b6a9d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-48YI"} | None |  |
| q-dc34286038 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c93dwd"} | None |  |
| q-d1bf22448e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-5e81cf936c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-4089702d70 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-6926d7c85a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-46366f8ca9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyU"} | None |  |
| q-268f111048 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-75e3eeabcf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-4e00cb4beb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-b1f27ea77b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-a430a08098 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuAn"} | None |  |
| q-2fa9fe911b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCH"} | None |  |
| q-2b272ac3f0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-cdfafa207f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-c1d603ca97 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-6ad4295e56 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-02fb4cd9d0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-4870961115 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-10cdbb41d8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-348958993f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niydsP"} | None |  |
| q-ed804bf84f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niydsP"} | None |  |
| q-553a229047 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVtv"} | None |  |
| q-6ec6c9ebb3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-39761b8cc9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-c84015478e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-05658e22cf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-4cb06ff0cc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-e94b1b9592 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-ccbec1d097 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-bd73ac37b0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-6385770abb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-c644bf3d2f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-b01320602c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-1dd3427d11 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-c64d0afab0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-d5b120789a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncsJoZ"} | None |  |
| q-540190c26c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YZ"} | None |  |
| q-db2e45c8ed | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1br"} | None |  |
| q-216f2e8ba3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YN"} | None |  |
| q-9eec6837ba | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YN"} | None |  |
| q-81c14d945c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YN"} | None |  |
| q-2735e725cf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrG"} | None |  |
| q-c498a4bd2e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nftACH"} | None |  |
| q-38a6e4327f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nftACH"} | None |  |
| q-6469bda7ed | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVykL"} | None |  |
| q-d25441210e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVykL"} | None |  |
| q-29cf479913 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqfh"} | None |  |
| q-587215158d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-b42b90849d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-3148b63a49 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-27aa68a98e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-df899a9771 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-888cec2a4e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-0174a3e1fc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-e9d52ce5f4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-56ee818fdc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-b6f4e6b632 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-b49dbc606c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-5d054f4df6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-111b6451b3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-0cd8b6c5e1 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-8dc4bcb242 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-027d21e3e0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuT"} | None |  |
| q-003514e62f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy1EsG"} | None |  |
| q-cd816c1433 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-785b483f75 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-685ca1ba98 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b-xybj"} | None |  |
| q-a111cc04f0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b-xybj"} | None |  |
| q-7a080f9a46 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxETLY"} | None |  |
| q-8f6c33da79 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1br"} | None |  |
| q-c80114edc7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-8ec7e53981 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-d635032296 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-c15a49e26b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-7d0976899d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-66ce91ba0f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None |  |
| q-dec9b89642 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None |  |
| q-196ac113a4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-03f9003215 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSytV"} | None |  |
| q-5f98e7954d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c_44mH"} | None |  |
| q-88a14efb00 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03AIc"} | None |  |
| q-448e25c612 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-7d2a19aa67 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFDK4"} | None |  |
| q-60e11db7fa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFDKr"} | None |  |
| q-f4096ab55c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFDKr"} | None |  |
| q-fdca0c6f37 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cZN9Bo"} | None |  |
| q-d719b4da63 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cZN9Bo"} | None |  |
| q-39805574f7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-16f9ecef1f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-49a2879355 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSsN"} | None |  |
| q-f773eea962 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-07758be035 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-b008ff1fc9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-1a2c37cc87 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-ef6e2be6af | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-bfa914e2a9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-767f06314e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hjk9tr"} | None |  |
| q-de8d022d38 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuD8"} | None |  |
| q-4cd9126667 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-259e60b91b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-4388a49920 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-c462410236 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-4f9e9324d5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-7524941b9b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cjZNk-"} | None |  |
| q-5a26c2b262 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-30e8e310ac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0W8_"} | None |  |
| q-6479767bdb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None |  |
| q-a3b8752050 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None |  |
| q-a8ef39f62b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysW"} | None |  |
| q-68cba32dfb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSsN"} | None |  |
| q-2f36b59479 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0W8_"} | None |  |
| q-ce83c2fce0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyX"} | None |  |
| q-a2589620bf | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1aD"} | None |  |
| q-7920218f48 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1aD"} | None |  |
| q-fc5b7b892a | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1aD"} | None |  |
| q-9b70411d04 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlbm"} | None |  |
| q-f1b9ea1760 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qUct2z"} | None |  |
| q-0c64752707 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1aD"} | None |  |
| q-b6e4c1f2a5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1aD"} | None |  |
| q-12012c403d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bM"} | None |  |
| q-38d0f5269b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1Zv"} | None |  |
| q-7a8f3b63ba | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlbb"} | None |  |
| q-e6f847ef3b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03AIc"} | None |  |
| q-a8e0db6077 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1aD"} | None |  |
| q-791b655cb9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlbm"} | None |  |
| q-762e0c44d6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cREvLs"} | None |  |
| q-c392de5c5d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cREvLs"} | None |  |
| q-82cfb19998 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-a0590cefa9 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDx"} | None |  |
| q-687d438a5d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-6c81d6f811 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None |  |
| q-1923cdf244 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None |  |
| q-df761c82a6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzGpUD"} | None |  |
| q-f539e68d31 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuAv"} | None |  |
| q-8c0d73056a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-1ea927cd27 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-f937889fc5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-8cf292d9cb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-b1031b79ba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVSlm"} | None |  |
| q-6f6518076c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-8d3b3c1bfa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72bs"} | None |  |
| q-72a2b50305 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72bs"} | None |  |
| q-070d30ad00 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-3d3c3f0da9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-96d662ce6d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytvM"} | None |  |
| q-c73268e39a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytvM"} | None |  |
| q-cbd618fe92 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nSlAli"} | None |  |
| q-f24eaaa855 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-2f45cbde9d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5pb"} | None |  |
| q-5c00846e0d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhIsr"} | None |  |
| q-3ad1cdaed2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-a7eb8cad02 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-83d82d0a3c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cTFCiC"} | None |  |
| q-6559c96356 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-f26ddfcaa1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncsZpc"} | None |  |
| q-838289fceb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c93Nx4"} | None |  |
| q-876dc6ff7f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-4f49aca6b9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-4c9d92b9ec | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-a2e542cd24 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_zRVX"} | None |  |
| q-2c2a0b367e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-102628004b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-972f50dad3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-f016bb32aa | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-30b6ae8034 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:26:40+00:00", "size": 100, "sub_field": "process.parent.executable"… | 61 |  |
| q-7107b9b6a8 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:26:40+00:00", "size": 100, "sub_field": "process.executable"} | 248 |  |
| q-60cfd59fad | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:26:40+00:00", "size": 100, "sub_field": "process.parent.execut… | 63 |  |
| q-3bf66f9eac | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:26:40+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-3ab9447119 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:05.681000+00:00", "size": 100, "sub_field": "process.pa… | 359 |  |
| q-a5b1cd9021 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:05.681000+00:00", "size": 100, "sub_field": "process.executable… | 1276 |  |
| q-de35fbe467 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:05.681000+00:00", "size": 100, "sub_field": "proce… | 370 |  |
| q-08988f8c8d | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:05.681000+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-1724c4a0bf | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*SysinternalsSuite*\" OR process.executable LIKE \"*\\\\\\\\Temp\\\\\\\\*\" OR process.executable LIKE \"*victim*\" OR process.executab… | 24 | F54, F57, F58, F61, F63 |
| q-c42d198316 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*Sysinternals*\" OR file.path LIKE \"*victim*\" OR file.path LIKE \"*.pfx\" OR file.path LIKE \"*.zip\" OR file.path LIKE \"*.rar\" OR file.pat… | 497 | F61 |
| q-3511a24421 | pivot step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (powershell.file.script_block_text LIKE \"*PrivateKey*\" OR powershell.file.script_block_text LIKE \"*pfx*\" OR powershell.file.script_block_text LIKE \"*l… | ERROR |  |
| q-f80bbbd2c9 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*.pfx\" OR file.path LIKE \"*.zip\" OR file.path LIKE \"*.dmp\" OR file.path LIKE \"*Draft*\" OR file.path LIKE \"*working*\" OR file.path LIKE… | 13 | F55, F57, F58, F59 |
| q-a68893ee9a | pivot step 3 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-dda74cf532 | pivot step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*python*\" OR process.executable LIKE \"*Rar*\" OR process.executable LIKE \"*sdelete*\" OR p… | 14 | F54 |
| q-86f0624877 | pivot step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*PrivateKey*\" OR win.ScriptBlockText LIKE \"*pfx*\" OR win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*Cre… | 7 | F55 |
| q-9486995ba4 | pivot step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F55 |
| q-e418e314bd | pivot step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*.7z\" OR file.path LIKE \"*.bmp\" OR file.path LIKE \"*.pfx\" OR file.path LIKE \"*OfficeSupplies*\" OR file.path LIKE \"*\\\\\\\\Downloads\\\… | 317 |  |
| q-01993b0b23 | pivot step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 11 | F54 |
| q-05388df760 | pivot step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\") AND (win.ObjectName LIKE \"*lsass*\" OR win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*SECURITY*\" OR win.ObjectName LIKE \"*Crypto*\" OR win… | 29 | F56 |
| q-8928cfec68 | pivot step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC92"} | None |  |
| q-d5f537ab3a | pivot step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, process.executable, destination.ip, destination.port, network.direction, _id, _index \| SORT @timestamp … | ERROR |  |
| q-818308767d | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, process.executable, destination.ip, destination.port, _id, _index \| SORT @timestamp ASC"} | 428 |  |
| q-b65f05e313 | pivot step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND host.name == \"nashua.dmevals.local\" AND (process.command_line LIKE \"*python*\" OR process.command_line LIKE \"*Rar*\" OR process.command_line LIKE \"*sdel… | 13 |  |
| q-c60ca45392 | pivot step 9 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND process.executable LIKE \"*powershell.exe\" \| KEEP @timestamp, user.name, process.command_line, process.parent.execut… | 11 | F59, F60, F62 |
| q-973fc32271 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC92"} | None |  |
| q-bf9e29449c | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None |  |
| q-fe0713ce51 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7culihF"} | None |  |
| q-64a8f68a60 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-4bad588a69 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-60affe4534 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-7b2c6798aa | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-cbab061798 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-81e2be4643 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwzKeY"} | None |  |
| q-42f24679de | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hUTVpm"} | None |  |
| q-66165e777d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-8c0c6b1b68 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-e46a118cc3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-102e0d7d5e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-3fa7aa04db | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yf"} | None |  |
| q-e8f993918f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72YQ"} | None |  |
| q-2b78448fcc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-cd731b8ac9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hjk9tr"} | None |  |
| q-f16fdf438f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hbcHpK"} | None |  |
| q-5c57c96bae | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKxF"} | None |  |
| q-8b505b7eed | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKxF"} | None |  |
| q-556c8f1b4b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKxF"} | None |  |
| q-badd415d36 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cyrL9g"} | None |  |
| q-adb49a1ef6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OiA"} | None |  |
| q-f814ad7e94 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OiA"} | None |  |
| q-306b98e92d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nhwFD7"} | None |  |
| q-f7537b8953 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nhwFD7"} | None |  |
| q-a43c84eba9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-f5410ec663 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-c9e2055104 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cjZNnV"} | None |  |
| q-3f66cce145 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItI"} | None |  |
| q-6128ae5692 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNv3"} | None |  |
| q-44854735e0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-7837a27469 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-d04ff8ce43 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncsZp3"} | None |  |
| q-822e097753 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-9333f2ea8f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-585fd2dc6c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-3ed37a756d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-40ba20b838 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqdH"} | None |  |
| q-70d69e45d0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCuG"} | None |  |
| q-6e8f09020a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCuG"} | None |  |
| q-90673b3242 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-64b36d81df | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c0sdf6"} | None |  |
| q-64a478df3a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7huwtOr"} | None |  |
| q-b0029b5a3b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-48YI"} | None |  |
| q-be3e28f7a2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c93dwd"} | None |  |
| q-91653de6c8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-41ba71d48b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-460663aae1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-90f9fb4b73 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-381480ca31 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyU"} | None |  |
| q-141b22cc2b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-df595195db | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-fe2424cac4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-4e1030e5d0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-0ac8d7f2bf | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuAn"} | None |  |
| q-1c3c5278bf | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCH"} | None |  |
| q-582593935e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-aa6070f5b4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-5251317181 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-2b4823deaf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-0b850c2174 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-a43a9ac522 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-59a93d84b6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-7fe0c00cda | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niydsP"} | None |  |
| q-04e0643885 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niydsP"} | None |  |
| q-a71a19d33f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVtv"} | None |  |
| q-2a5194b9aa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-f3deb5fbae | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-d11d3315b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-e1a4d09baf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-333a2c4b86 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-3faf0771fc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-420c3dc71d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-ffe19df860 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-ca580c23a6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-9e4cac1df7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-5061f8404e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-bf4ec923d9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-33b691c5a3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-01391e34a4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncsJoZ"} | None |  |
| q-81f8d0680b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YZ"} | None |  |
| q-4f069296f0 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1br"} | None |  |
| q-6084954cd0 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YN"} | None |  |
| q-40eb2ada56 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YN"} | None |  |
| q-50a9e62f4b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YN"} | None |  |
| q-0f632d3aad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrG"} | None |  |
| q-45ff988a09 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nftACH"} | None |  |
| q-e6398fd2b5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nftACH"} | None |  |
| q-5df3952e87 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVykL"} | None |  |
| q-e3180f7c47 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVykL"} | None |  |
| q-69dbb4b159 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqfh"} | None |  |
| q-31ef8e39ea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-6bfc4534c1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-3f8e1188bb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-799f36cec8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-8537a919bd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-469388253f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-1ce569a858 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-151f57ac83 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-0bbd5ee9fb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-f43d0b1f67 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-8f950aa079 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-a9b382dd1e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-50313869b5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-975a9b1f82 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-93300f2443 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-fb604b43eb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuT"} | None |  |
| q-6b84e8146a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy1EsG"} | None |  |
| q-0cda6a2f15 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-cd3bc1d45e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-e7f4be9f1e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b-xybj"} | None |  |
| q-13aa65e1d9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b-xybj"} | None |  |
| q-8079b55064 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxETLY"} | None |  |
| q-8e49884cb7 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1br"} | None |  |
| q-06d34501ac | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-f2352d7a57 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-da40201ee0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-df02132046 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-92ca514447 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-a7f36a5fd5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None |  |
| q-7b03cf3595 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None |  |
| q-e5fb40dc5f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-eef81ba80b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSytV"} | None |  |
| q-0f7c27ce63 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c_44mH"} | None |  |
| q-9339270126 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03AIc"} | None |  |
| q-95d630ce01 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-c3231d1050 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFDK4"} | None |  |
| q-1bd91c69f5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFDKr"} | None |  |
| q-d73d04570f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFDKr"} | None |  |
| q-0f9d520e07 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cZN9Bo"} | None |  |
| q-bb00acb66b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cZN9Bo"} | None |  |
| q-f88d49730d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-5a9a00e274 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-30320553e1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSsN"} | None |  |
| q-deb947deb6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-69d3e861a9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-e9ad2ebc29 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-4b89905f32 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-fcec6a9f18 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-ea00d87a01 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-534480c556 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hjk9tr"} | None |  |
| q-48527301c7 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuD8"} | None |  |
| q-cf58ec23d6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-1d7d73ea60 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-2b59ff9707 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-b85578b6d3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-99ec460876 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-9a61a6f317 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cjZNk-"} | None |  |
| q-cdcf51b05a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-f519b9c571 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0W8_"} | None |  |
| q-7723b716aa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None |  |
| q-c4e1324459 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None |  |
| q-6b1fdf5983 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysW"} | None |  |
| q-53d00da4d6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSsN"} | None |  |
| q-76b5079458 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0W8_"} | None |  |
| q-145d4ed504 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyX"} | None |  |
| q-b47283bd45 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1aD"} | None |  |
| q-645ebb54c4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1aD"} | None |  |
| q-323da172a4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1aD"} | None |  |
| q-5a436e11cd | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlbm"} | None |  |
| q-e6545395ad | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qUct2z"} | None |  |
| q-048defd7cb | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1aD"} | None |  |
| q-a4ffe5237e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1aD"} | None |  |
| q-85bf8e7cd8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bM"} | None |  |
| q-e1c62f54b5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1Zv"} | None |  |
| q-ed96cbaff8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlbb"} | None |  |
| q-02aefb15bd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03AIc"} | None |  |
| q-6ffd51fc8d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1aD"} | None |  |
| q-97aaa3c721 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlbm"} | None |  |
| q-1006a8d8ff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cREvLs"} | None |  |
| q-1afd82aa32 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cREvLs"} | None |  |
| q-1c4ac5ddce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-78ab8fbaea | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDx"} | None |  |
| q-7cb3891956 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-fd5b12f101 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None |  |
| q-8e1f6afc52 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None |  |
| q-755a8b0c69 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzGpUD"} | None |  |
| q-9005a24101 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuAv"} | None |  |
| q-1dab9fcca1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-1acac143e9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-a2ca678428 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-26d794612e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-985755831c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVSlm"} | None |  |
| q-cd92d6be58 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-9bf2cde7a4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72bs"} | None |  |
| q-2c369d7ac7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72bs"} | None |  |
| q-8532ad1d09 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-f9413f428d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-97438e93fe | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytvM"} | None |  |
| q-2b0af9cb2e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytvM"} | None |  |
| q-cb45fe6165 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nSlAli"} | None |  |
| q-93e5ceb528 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-1be58dddd6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5pb"} | None |  |
| q-aba68b7c13 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhIsr"} | None |  |
| q-e65552efb5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-bb5ecb5f32 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-c406bdcd0c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cTFCiC"} | None |  |
| q-f868466ac6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-e4543b0f12 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncsZpc"} | None |  |
| q-860222eda9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c93Nx4"} | None |  |
| q-af2616f44c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-0c9715590d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-66c9e635db | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-c8defd6073 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_zRVX"} | None |  |
| q-a121923c9d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-4d87d257a8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-c886a84bf6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-66ae3af91e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-fa35d12682 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC92"} | None |  |
| q-394fbaf0c3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None |  |
| q-cfde1ec123 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7culihF"} | None |  |
| q-df64926027 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-bc406d27b1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-3ddc47ff6f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-e6c05a5695 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-d175a65c0f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-5079c7e58a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwzKeY"} | None |  |
| q-c0f8ced00c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hUTVpm"} | None |  |
| q-560b5c1151 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-5842d820f3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNS"} | None |  |
| q-d1d0119800 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-4d9e6f2abd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqdH"} | None |  |
| q-d0c271018b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YJ9aYA"} | None |  |
| q-b401ff9064 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7b8wDMC"} | ERROR |  |
| q-f4fd9a4fb0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htvuyY"} | None |  |
| q-45a41f3980 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htvuyT"} | None |  |
| q-231a5653a5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0W8y"} | None |  |
| q-40feca9914 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0W8y"} | None |  |
| q-bfab11ba33 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7huwtP3"} | None |  |
| q-f1ca227967 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7huwtP3"} | None |  |

## Verification

Evidence items cited: 222; confirmed against the stored events: 220; rejected: 2. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 5 item(s) in 4 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
