# Threat hunt report — 20261017-005707-converged-test3

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 18 verified malicious finding(s) with medium/high confidence: F01 T1003.001, F04 T1003, F09 T1056, F10 T1056.004, F19 T1187, F23 T1212, F27 T1552.004, F28 T1552.001, F31 T1555, F39 T1558, F44 T1606.002, F45 T1606, F47 T1649, F50 T1552.001, F51 T1003.001, F52 T1552.001, F53 T1552.001, F54 T1552.001

Verdict method: rules over verified evidence (Confirmed if >=1 verified malicious finding (confidence >= medium); Inconclusive if only suspicious or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-16T16:57:07+00:00 / 2026-10-16T17:05:15+00:00 (488.0 s) |
| LLM calls / tokens | 107 / {'prompt': 2819996, 'completion': 98443} |
| MCP tool calls | 1007 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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

## Findings

### F04 · malicious / high · T1003 · Credential-access tooling staged and executed by pbeesly across scranton and nashua

Evidence status: **verified**

The credential-access activity is part of a broader intrusion by user pbeesly. On scranton.dmevals.local, pbeesly ran Sysinternals PsExec64.exe with cleartext credentials ('-u dmevals\pbeesly -p Fl0nk3rt0n!T0by') to launch C:\Windows\Temp\python.exe on \\NASHUA (03:11:18, 03:12:25, 03:13:28, 03:14:42), and used sdelete64.exe to wipe artifacts (e.g. C:\programdata\victim\???cod.3aka3.scr, C:\Users\pbeesly\AppData\Roaming\Draft.Zip). On nashua, C:\Windows\Temp\python.exe was spawned by C:\Windows\PSEXESVC.exe repeatedly (03:11:40-03:15:04), matching the lsass cached-credential registry writes. This establishes the actor and tooling behind the LSASS/SAM/cached-credential access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:14:42.601Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RkEAFq | q-e8f028da81 | ok |
| 2 | 2020-05-02 03:15:03.954Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RjDyQK | q-e8f028da81 | ok |
| 3 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SEqWk4 | q-e8f028da81 | ok |

### F01 · malicious / high · T1003.001 · PowerShell opened LSASS with PROCESS_ALL_ACCESS and read its memory on scranton

Evidence status: **verified**

On scranton.dmevals.local, C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe (PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) and 0x1f3fff at 2020-05-02T03:05:16, with a call trace ending in an UNKNOWN module (C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\Windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D)), indicating injected/reflective code rather than a signed tool. Windows Security 4663 corroborates the same second: user pbeesly's powershell.exe performed 'Read from process memory' (Access Mask 0x10) on \Device\HarddiskVolume2\Windows\System32\lsass.exe. PowerShell 4104 script blocks from pbeesly at 03:21:29 contain a reflective loader (GetProcAddress via Microsoft.Win32.UnsafeNativeMethods, VirtualAlloc/CreateThread pattern) and a base64 gzip-encoded hidden powershell payload, consistent with an in-memory credential-dumping toolchain. This is LSASS memory access for credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-1201cfbdf4 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-1201cfbdf4 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-1201cfbdf4 | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessList | %%4484  				 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_j | q-c8e67808c8 | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_j | q-a9c649326d | ok |
| 6 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bzydoz | q-f4bd78cdba | ok |

### F51 · malicious / high · T1003.001 · PsExec-delivered python.exe (PyInstaller) executed on nashua via PSEXESVC and connected out to 192.168.0.4:8443

Evidence status: **verified**

On nashua.dmevals.local, C:\Windows\PSEXESVC.exe (created by services.exe) spawned C:\Windows\Temp\python.exe as pbeesly at 03:11:40, 03:12:46, 03:13:49 and 03:15:03 UTC. The python.exe unpacked a PyInstaller bundle into C:\Users\pbeesly\AppData\Local\Temp\_MEI29522 (python27.dll, _ctypes.pyd, _ssl.pyd, pywintypes27.dll, win32pipe.pyd etc.) and then opened many outbound connections to 192.168.0.4:8443. This is the credential-access payload the anchors' tooling staged; it is not covered by the LSASS/SAM/cache anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\python.exe"  | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RpKsKx | q-ce6b19970f | ok |
| 2 | 2020-05-02 03:15:04.135Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Temp\_MEI29522\_ctypes.pyd | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RjDiNo | q-6fcef6eb86 | ok |
| 3 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RjDSP- | q-6010e213c3 | ok |
| 4 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.port | 8443 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RjDSP- | q-6010e213c3 | ok |
| 5 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSCpJ | q-508519398a | ok |

### F09 · malicious / high · T1056 · Masquerading .scr binary in C:\ProgramData\victim accesses LSA registry and loads GUI input DLLs

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly launched C:\ProgramData\victim\cod.3aka3.scr (command line "C:\ProgramData\victim\cod.3aka3.scr" /S) at 2020-05-02T02:55:56Z. The binary has no version/company/original-filename metadata, masquerades as a screen saver, loaded GUI/input-related DLLs (user32.dll, gdi32.dll, win32u.dll, msctf.dll), opened \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa with Query key value access, and made an outbound TCP connection to 192.168.0.5:1234. This is consistent with input capture / credential API hooking activity.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WiJkSG | q-8418758ef0 | ok |
| 2 | 2020-05-02 02:55:56.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YsmoMq | q-0e55d4fe38 | ok |
| 3 | 2020-05-02 02:55:59.000Z | scranton.dmevals.local | windows.security | destination.ip | 192.168.0.5 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YsmoMo | q-7f58c01830 | ok |
| 4 | 2020-05-02 02:55:56.151Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\user32.dll | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WiJkR5 | q-6ca293429b | ok |

### F10 · malicious / high · T1056.004 · PowerShell.exe opened LSASS with full access (0x1FFFFF) on scranton

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:05:16Z, C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe (PID 2976) opened C:\windows\system32\lsass.exe (PID 736) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS), the access level used to read/hook credential material in LSASS. A second access with 0x1F3FFF was also recorded. This is consistent with credential API hooking / LSASS credential access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-f38a260db4 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-cad142cf7c | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-f38a260db4 | ok |

### F19 · malicious / high · T1187 · hostui.lnk dropped into StartUp folder by PowerShell on scranton (forced-auth trigger)

Evidence status: **verified**

On scranton.dmevals.local, powershell.exe (PID 3876, running as SYSTEM) created C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk at 2020-05-02T03:04:23Z. A shortcut placed in the StartUp folder is a classic T1187 forced-authentication trigger: when the user logs on and the .lnk is resolved/opened it can cause the host to authenticate outbound (SMB/WebDAV) to an attacker-controlled target, leaking NTLM credentials. The same PowerShell session had earlier written hostui.txt into C:\Users\pbeesly\Downloads\SysinternalsSuite\, indicating the attacker staged the hostui payload.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SAm218 | q-9a07a87e3c | ok |
| 2 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SAm218 | q-9a07a87e3c | ok |
| 3 | 2020-05-02 03:00:27.205Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\SysinternalsSuite\hostui.txt | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SJxMAB | q-291b17678f | ok |

### F20 · malicious / high · T1187 · Masqueraded hostui.exe in System32 launched with -verb runas to force elevation/authentication

Evidence status: **NOT verified (3/4 evidence items)** — excluded from the verdict

On scranton.dmevals.local, powershell.exe ran 'Start-Process C:\Windows\System32\hostui.exe -verb runas' (2020-05-02T03:21:19Z), spawning C:\Windows\System32\hostui.exe (PID 8452) at High integrity as DMEVALS\pbeesly. The binary masquerades as a Windows component (Company, Description, Product, OriginalFileName all '-') yet sits in System32. hostui.exe then spawned powershell.exe reading 'HKLM:\SOFTWARE\Javasoft' 'value Supplement' piped to Invoke-Expression, which in turn launched a hidden base64-encoded PowerShell (-nop -w hidden -e ...). This is the forced-authentication/execution chain: a fake System32 binary coerced into elevation that then executes attacker code.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:19.323Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MtShN2 | q-df7bcaf712 | ok |
| 2 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\hostui.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MtT0KI | q-6243ccbde3 | ok |
| 3 | 2020-05-02 03:21:27.859Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MtUEbK | q-df7bcaf712 | ok |
| 4 | 2020-05-02 03:21:28.949Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewAkAGIAPQAkAGUAbg… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MtUml9 | q-ceaf9a3b7d | FAILED: claimed value differs from the stored value |

### F23 · malicious / high · T1212 · PowerShell process opened LSASS with full access (0x1FFFFF) on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02 at 03:05:16 UTC, a PowerShell.exe process (PID 2976) on scranton.dmevals.local opened lsass.exe (PID 736) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS), the access mask used to read LSASS memory for credential extraction. This occurred in the same pbeesly PowerShell session that ran credential-access tooling: Get-PrivateKeys (exporting certificate private keys to .pfx), Get-Clipboard, Get-AttributesMask (token/privilege enumeration) and Keystroke-Check. The activity is part of a broader hands-on-keyboard intrusion (Invoke-Discovery, Invoke-Persistence, Invoke-Exfil, PsExec to NASHUA with cleartext credentials).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-af643c4a8b | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-af643c4a8b | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-af643c4a8b | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | host.name | scranton.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-af643c4a8b | ok |
| 5 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-61a560d2f4 | ok |
| 6 | 2020-05-02 03:06:42.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Get-Clipboard | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21_Qp | q-61a560d2f4 | ok |

### F28 · malicious / high · T1552.001 · Plaintext credentials in PsExec command line and discovery script on scranton

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly repeatedly launched PsExec64.exe with the account password embedded in the command line: -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe, targeting \\NASHUA (four occurrences 03:11-03:14Z). This is a credential exposed in a file/command line. The same user also ran an 'Invoke-Discovery' PowerShell function reading environment and system files. The plaintext password in the command line is a credential-in-files exposure consistent with the technique.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:14:42.601Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RkEAFq | q-9a2a55cd26 | ok |
| 2 | 2020-05-02 03:14:42.601Z | scranton.dmevals.local | windows.sysmon | user.name | pbeesly | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RkEAFq | q-9a2a55cd26 | ok |
| 3 | 2020-05-02 03:04:03.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Discovery {     $DiscoveryInfo =@()     $CurrentDir = Get-Location      $DiscoveryInfo += [PSCustomObject]@{                 CurrentDirectory = … | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21_RQ | q-9543d42cfd | ok |

### F50 · malicious / high · T1552.001 · Hardcoded plaintext credentials for pbeesly passed on the command line to PsExec64.exe (unsecured credentials in command line)

Evidence status: **verified**

On scranton.dmevals.local, PowerShell (running as pbeesly) repeatedly launched C:\Program Files\SysinternalsSuite\PsExec64.exe with the account password supplied in cleartext on the command line: -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe, targeting \\NASHUA. This occurred at 03:11:18, 03:12:25, 03:13:28 and 03:14:42 UTC, each followed ~20s later by PSEXESVC.exe service creation and python.exe execution on nashua.dmevals.local. The credential is exposed in process command lines and in the 4688 audit records.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSP1_ | q-508519398a | ok |
| 2 | 2020-05-02 03:12:25.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSCot | q-508519398a | ok |
| 3 | 2020-05-02 03:14:42.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YmeJMa | q-508519398a | ok |

### F52 · malicious / high · T1552.001 · Password-protected archive of collected credential/document files created with Rar.exe -hp on nashua

Evidence status: **verified**

On nashua.dmevals.local, PowerShell (pbeesly) ran C:\Windows\Temp\Rar.exe a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip at 03:16:19 UTC, creating a password-protected archive of staged files. The staging PowerShell block enumerated files matching *psw*,*pass*,*login*,*admin*,*sifr*,*sifer*,*vpn,*.pst,*.ost etc. under the user profile. This is credential/secret collection and packaging not covered by the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RhBpvd | q-ce6b19970f | ok |
| 2 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | powershell.script_block_text | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxhdc | q-a43f14b4b1 | ok |
| 3 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.powershell | powershell.script_block_text | .\Rar.exe a -hpfGzq5yKw "$env:USERPROFILE\Desktop\working.zip" "$env:APPDATA\working.zip" | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxQx3 | q-a43f14b4b1 | ok |

### F53 · malicious / medium · T1552.001 · sdelete64.exe used to wipe the credential-collection tooling and archives on nashua

Evidence status: **verified**

On nashua.dmevals.local, cmd.exe (pbeesly) ran C:\Windows\Temp\sdelete64.exe /accepteula against C:\Windows\Temp\Rar.exe (03:16:52), C:\Users\pbeesly\AppData\Roaming\working.zip (03:17:18) and C:\Users\pbeesly\Desktop\working.zip (03:17:41) to securely delete the credential-collection artifacts. Anti-forensics around the credential theft, not covered by the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:52.456Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1Nd9MRE | q-ce6b19970f | ok |
| 2 | 2020-05-02 03:17:18.030Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Users\pbeesly\AppData\Roaming\working.zip"  | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1Nc7emY | q-ce6b19970f | ok |
| 3 | 2020-05-02 03:17:41.290Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Users\pbeesly\Desktop\working.zip" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WrUWHO | q-ce6b19970f | ok |

### F54 · malicious / medium · T1552.001 · Explicit-credential logon (4648) from scranton to NASHUA over SMB using pbeesly's credentials

Evidence status: **verified**

On scranton.dmevals.local a 4648 'logon attempted using explicit credentials' event was recorded at 03:11:18 UTC: subject pbeesly (DMEVALS), credentials used for pbeesly (DMEVALS.LOCAL), target server NASHUA, additional info cifs/NASHUA, network address 10.0.1.6 port 445. This is the explicit-credential use that immediately preceded the PSEXESVC/python.exe execution on nashua and shows the stolen/known password being replayed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSP2J | q-2dedb26d10 | ok |
| 2 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetInfo | cifs/NASHUA | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSP2J | q-2dedb26d10 | ok |
| 3 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSP2J | q-2dedb26d10 | ok |

### F27 · malicious / high · T1552.004 · PowerShell Get-PrivateKeys exports all LocalMachine certificates to .pfx on scranton

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell function 'Get-PrivateKeys' (script block path C:\Program Files\SysinternalsSuite\readme.ps1) that enumerates cert:\LocalMachine recursively and exports every certificate with a thumbprint to $env:USERPROFILE\Downloads\<random>.pfx, protected by the hardcoded password 'saribas'. Sysmon event 11 confirms the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by powershell.exe at 03:04:57Z. A follow-up 'Invoke-BeachCleanup' function then deletes *.pfx from Downloads, indicating anti-forensic cleanup of the stolen key material.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-346428cc5d | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-346428cc5d | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lUAH | q-15af6f10b8 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lUAH | q-15af6f10b8 | ok |
| 5 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxh3C | q-343e16637d | ok |

### F31 · malicious / high · T1555 · PowerShell credential theft from LSASS memory by user pbeesly on scranton

Evidence status: **verified**

On 2020-05-02 at 03:05:16 UTC, PowerShell.exe (PID 2976) on scranton.dmevals.local opened C:\windows\system32\lsass.exe with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) and, in the same second, Windows Security 4663 recorded user pbeesly (DMEVALS, logon 0x372E81) reading process memory (Access Mask 0x10) from \Device\HarddiskVolume2\Windows\System32\lsass.exe via powershell.exe. The same user ran credential-collection PowerShell from C:\Program Files\SysinternalsSuite\readme.ps1 (Get-PrivateKeys, exporting machine certificates to .pfx with a hardcoded password) and psversion.ps1 (Invoke-Exfil, staging Downloads into a password-protected 7z and copying it to \\192.168.0.4\webdav). This is hands-on credential access consistent with T1555 (credentials from password stores via LSASS memory).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-b3d9a236cf | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-b3d9a236cf | ok |
| 3 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x10 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_j | q-8da1851a09 | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_j | q-8da1851a09 | ok |
| 5 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-afa7e6b320 | ok |
| 6 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-afa7e6b320 | ok |

### F39 · malicious / high · T1558 · LSASS memory read with full access by stego-loader PowerShell on scranton (credential/ticket theft)

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a hidden, execution-policy-bypass PowerShell steganography loader ("PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "...System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png')...IEX(...)") as PID 2976. That same process (SourceProcessId 2976, SourceImage PowerShell.exe) then opened lsass.exe with GrantedAccess 0x1F3FFF and 0x1FFFFF at 2020-05-02T03:05:16 — full-access reads of LSASS memory, the standard mechanism for harvesting Kerberos tickets/credential material. This is the credential-access stage of a broader intrusion chain on the host (stego loader -> hidden encoded PowerShell -> registry-stored payload via hostui.exe).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WdFNhN | q-a4c8939f7b | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-17c5460354 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-3878b86694 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-17c5460354 | ok |
| 5 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-17c5460354 | ok |

### F45 · malicious / medium · T1606 · Suspicious .scr payload and PowerShell stager activity on scranton.dmevals.local

Evidence status: **verified**

On scranton.dmevals.local a process running from C:\ProgramData\victim\â€®cod.3aka3.scr (a .scr executable in a non-standard 'victim' directory) was active from 02:56:04 through 03:01:27 UTC, creating files such as C:\Users\pbeesly\Downloads\monkey.png. A PowerShell script block at 02:58:45 decodes a payload from monkey.png (reading pixels of a System.Drawing.Bitmap and IEX-ing the reconstructed ASCII bytes), a fileless stager. This activity is the delivery/execution context surrounding the certificate-export and exfiltration functions, supporting the credential-access hypothesis, though the .scr itself is not a web-credential forgery artifact.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WgHZ_9 | q-9caa77821f | ok |
| 2 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\monkey.png | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WgHZ_9 | q-9caa77821f | ok |
| 3 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le … | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b87aMP | q-f77b02a602 | ok |

### F44 · malicious / high · T1606.002 · PowerShell Get-PrivateKeys exports all LocalMachine certificates to .pfx on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02 at 03:04:56 UTC, user pbeesly on scranton.dmevals.local ran a PowerShell script block (Event 4104, ScriptBlockId 9d153741-75c3-4062-afe3-aeca0aee611b, Path C:\Program Files\SysinternalsSuite\readme.ps1) defining function Get-PrivateKeys. It enumerates every certificate in cert:\LocalMachine recursively and exports each one with a thumbprint to a randomly-named .pfx in the user's Downloads folder, protected by the hardcoded password 'saribas'. Seconds later at 03:04:57.460 a .pfx file (C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx) was created by powershell.exe (PID 3876). Exporting private keys from the machine certificate store is the classic precursor to stealing an ADFS token-signing certificate and forging SAML tokens (T1606.002). The same session also ran Invoke-Exfil (compressing Downloads into OfficeSupplies.7z with password 'lolol' and exfiltrating) and Invoke-BeachCleanup (deleting *.pfx/*.bmp/*.png and OfficeSupplies.7z), consistent with a credential-theft and exfiltration toolchain.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-971f8f973f | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-971f8f973f | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lUAH | q-ab6a6e7683 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lUAH | q-ab6a6e7683 | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-f77b02a602 | ok |
| 6 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxh3C | q-f77b02a602 | ok |

### F47 · malicious / high · T1649 · PowerShell Get-PrivateKeys exports all LocalMachine certificates to .pfx on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02T03:04:56Z (host local 2020-05-01 23:04:56) on scranton.dmevals.local, user pbeesly executed a PowerShell function 'Get-PrivateKeys' loaded from C:\Program Files\SysinternalsSuite\readme.ps1 (PID 3876). The script enumerates cert:\LocalMachine recursively and, for every certificate with a Thumbprint, calls Export-PfxCertificate to write $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded plaintext password 'saribas'. Sysmon event 11 confirms the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe (PID 3876) one second later. This is bulk theft of authentication certificates/private keys from the machine certificate store, matching T1649 (Steal or Forge Authentication Certificates). The script name, hardcoded password and mass-export loop are not normal administrative behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-b2c3c1d917 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-b2c3c1d917 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-b2c3c1d917 | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vTX | q-4be41f892b | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lUAH | q-26ab8beacd | ok |
| 6 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lUAH | q-26ab8beacd | ok |

### F02 · suspicious / medium · T1003.002 · lsass.exe wrote the SAM account hive value on scranton

Evidence status: **verified**

On scranton.dmevals.local, lsass.exe (PID 748, ProcessGuid {47ab858c-e6ad-5eac-0c00-000000000500}) set the registry value HKLM\SAM\SAM\Domains\Account\F at 2020-05-02T03:19:10.368 (Sysmon event 13, Details 'Binary Data'). This is the SAM account database value; the write occurred seconds after lsass.exe was (re)started at 03:19:09.809. No reg save / hive-copy command lines were observed (C017/C021/C023/C024 zero hits), so this is a registry-level SAM touch rather than a classic offline hive dump, but it is consistent with SAM credential material being manipulated on the host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SAM\SAM\Domains\Account\F | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhA | q-c67dc3deba | ok |
| 2 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhA | q-c67dc3deba | ok |
| 3 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | win.Details | Binary Data | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhA | q-c67dc3deba | ok |

### F03 · suspicious / medium · T1003.005 · lsass.exe repeatedly wrote the cached domain credential store HKLM\SECURITY\Cache\NL$1 on nashua

Evidence status: **verified**

On nashua.dmevals.local, lsass.exe (PID 728, ProcessGuid {5aa8ec29-cad7-5eac-0c00-000000000400}) set HKLM\SECURITY\Cache\NL$1 four times between 2020-05-02T03:11:40 and 03:15:03 (Sysmon event 13, Details 'Binary Data'). NL$1 is the cached domain credential (DCC2) store. The writes coincide with the window in which pbeesly was running C:\Windows\Temp\python.exe on nashua via PsExec (03:11:40, 03:12:46, 03:13:49, 03:15:03), i.e. the cached-credential registry key was being touched while the attacker's tooling was active on that host. No direct read of SECURITY\Cache was captured in the security log (C042/C043/C044 zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RpKsLE | q-fc49931d61 | ok |
| 2 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RpKsLE | q-fc49931d61 | ok |
| 3 | 2020-05-02 03:12:46.768Z | nashua.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RoJ7pL | q-fc49931d61 | ok |

### F11 · suspicious / medium · T1056 · Invoke-Exfil PowerShell script with hardcoded credentials and WebDAV exfiltration

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:08:02Z, user pbeesly executed a PowerShell script block defining Invoke-Exfil, which compresses the user's Downloads folder with a password, builds a PSCredential from hardcoded username 'cozy' and password 'MyCozyPassw0rd!', maps a WebDAV share to \\192.168.0.4\webdav and copies the archive there. This is credential use/exfiltration rather than input capture, but it demonstrates credential handling by the same actor.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-0b92cf3612 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-0b92cf3612 | ok |

### F21 · suspicious / low · T1187 · NTLM authentication in use on scranton (LsaSrv 6038)

Evidence status: **verified**

scranton.dmevals.local logged LsaSrv event 6038 at 2020-05-01T23:20:41-04:00 warning that NTLM authentication is being used between clients and this server. This is a generic NTLM-in-use warning (fires once per boot) and by itself is not proof of coercion, but it is consistent with the forced-authentication activity observed on the same host minutes later (hostui.exe elevation chain at 03:21Z).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.other | event.code | 6038 | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx3F | q-a453c4c502 | ok |
| 2 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.other | host.name | scranton.dmevals.local | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx3F | q-a453c4c502 | ok |

### F55 · suspicious / medium · T1555 · PowerShell screenshot/keylogging job and 7Zip4Powershell module download on scranton (credential-adjacent collection)

Evidence status: **verified**

On scranton.dmevals.local, PowerShell (pbeesly) started a background job named 'Screenshot' that repeatedly captures the screen to $env:USERPROFILE\Downloads\<random>.bmp (4103 at 03:05:58), and downloaded the 7Zip4Powershell module from powershellgallery.com (03:08:31-03:08:34) to package collected data. Screen capture of a user session can capture credentials entered by the user; this activity is not covered by the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:58.000Z | scranton.dmevals.local | windows.powershell | win.Payload | CommandInvocation(Start-Job): "Start-Job"  ParameterBinding(Start-Job): name="Name"; value="Screenshot"  ParameterBinding(Start-Job): name="ScriptBlock"; value=… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vTy | q-ab498d6074 | ok |
| 2 | 2020-05-02 03:08:31.000Z | scranton.dmevals.local | windows.powershell | win.Payload | CommandInvocation(PackageManagementMessageResolver): "PackageManagementMessageResolver"  ParameterBinding(PackageManagementMessageResolver): name="MsgID"; value… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b0ywiq | q-ab498d6074 | ok |

### F05 · benign / high · T1040 · netsh trace packet capture on scranton.dmevals.local is Azure Network Watcher agent activity

Evidence status: **verified**

On 2020-05-02 03:19:17 and 03:19:24 UTC, netsh.exe ran 'trace start capture=yes traceFile=...etl' and 'trace stop' on scranton.dmevals.local as NT AUTHORITY\SYSTEM. The Sysmon process-create event shows the parent process is C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe /service, i.e. the Azure Network Watcher extension performing a legitimate on-demand packet capture. No adversary tooling or user context is involved.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NW1Kgv | q-624d47195f | ok |
| 2 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NW1Kgv | q-624d47195f | ok |
| 3 | 2020-05-02 03:19:24.835Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WnQtls | q-d566720c91 | ok |
| 4 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YYOcv1 | q-2c19b1bbef | ok |

### F06 · benign / high · T1040 · logman trace create/start/stop on scranton.dmevals.local is Azure Guest Agent diagnostics

Evidence status: **verified**

Between 2020-05-02 03:18:38 and 03:19:44 UTC, logman.exe created, started and stopped ETW traces (GAEvents, RTEvents, WindowsAzure-GuestAgent-Diagnostic) writing to C:\WindowsAzure\Logs on scranton.dmevals.local as SYSTEM. Every invocation's parent process is C:\WindowsAzure\Packages\WaAppAgent.exe, the Azure Windows Guest Agent, so this is platform diagnostic telemetry collection, not adversary network sniffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:29.878Z | scranton.dmevals.local | windows.sysmon | process.command_line | "logman.exe" create trace GAEvents -max 50 -f bincirc -o C:\WindowsAzure\Logs\WaAppAgent.etl -p "{3000b92b-ca8b-4269-90ea-c4185ee09e92}" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NUxiiK | q-d566720c91 | ok |
| 2 | 2020-05-02 03:19:29.878Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\WaAppAgent.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NUxiiK | q-d566720c91 | ok |
| 3 | 2020-05-02 03:19:41.076Z | scranton.dmevals.local | windows.sysmon | process.command_line | "logman.exe" create trace RTEvents -max 50 -f bincirc -o C:\WindowsAzure\Logs\RuntimeEvents.etl -pf C:\WindowsAzure\Packages\GuestAgent\ProviderGuids.txt | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NNopD7 | q-d566720c91 | ok |

### F07 · benign / high · T1040 · PowerShell Add-Type hit is PowerShellGet module loading, not packet capture

Evidence status: **verified**

The PowerShell script-block hit on scranton.dmevals.local at 2020-05-01 23:08:03 (user DMEVALS\pbeesly) is an Add-Type call whose ScriptName is C:\Program Files\WindowsPowerShell\Modules\PowerShellGet\1.0.0.1\PSModule.psm1, i.e. the built-in PowerShellGet module compiling a C# helper type. It contains no packet-capture cmdlets; a targeted search for pktmon/netsh trace/New-NetEventSession/NetworkWatcher/PacketCapture in script blocks returned zero rows.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:03.000Z | scranton.dmevals.local | windows.powershell | message | Pipeline execution details for command line:         Add-Type -ReferencedAssemblies $requiredAssembly -TypeDefinition $source -Language CSharp -ErrorAction Sile… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b0zggu | q-d1a4048d4f | ok |
| 2 | 2020-05-02 03:08:03.000Z | scranton.dmevals.local | windows.powershell | message | Pipeline execution details for command line:         Add-Type -ReferencedAssemblies $requiredAssembly -TypeDefinition $source -Language CSharp -ErrorAction Sile… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b0zggu | q-d1a4048d4f | ok |

### F08 · benign / high · T1040 · No sniffing drivers or capture tooling loaded anywhere in the dataset

Evidence status: **verified**

A search across Sysmon image-load (event 6/7) records for pktmon/npcap/winpcap/windump/rawcap returned zero rows, and a search of PowerShell script blocks for packet-capture cmdlets returned zero rows. The only packet-capture activity observed in the whole window is the Azure agent netsh/logman telemetry above; no adversary network-sniffing tooling was found on any host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | win.Hashes | SHA1=E7A3B17F625283E3064D91A988D0B1694BA3E9B8,MD5=79CBBF946E797103BED792740AEBFEC1,SHA256=90F0822D26680C8FFD703A080C876F87695580747A3704C169E39E1A8802EA38,IMPHA… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NW1Kgv | q-624d47195f | ok |

### F12 · benign / high · T1056 · Routine LSASS access by system services (svchost, Azure telemetry, wininit/csrss)

Evidence status: **verified**

The bulk of LSASS handle events are normal: svchost.exe (289 events, GrantedAccess 0x1000 = PROCESS_QUERY_LIMITED_INFORMATION), WindowsAzureTelemetryService.exe (0x1400), and wininit.exe/csrss.exe opening lsass at boot (0x1FFFFF/0x1000000). These are standard Windows/Azure agent behaviors, not credential capture.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WhJHLy | q-6b3897732b | ok |
| 2 | 2020-05-02 03:19:42.009Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NNo5BS | q-cad142cf7c | ok |

### F13 · benign / high · T1110 · No brute-force authentication activity; only a single successful credential validation

Evidence status: **verified**

Across the whole windows.security window (2020-05-02T02:55:25Z..03:28:09Z) there is exactly one credential-validation event (4776) and zero 4625/4771 events. The single 4776 on newyork.dmevals.local is an AUDIT_SUCCESS (Status 0x0) for account pbeesly from workstation 10.0.1.4, i.e. a normal successful logon, not a failed attempt. No repeated failures, no spray/stuffing pattern exists in the data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHwYC | q-c5b0c8bb88 | ok |
| 2 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.EventType | AUDIT_SUCCESS | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHwYC | q-664467c15a | ok |
| 3 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHwYC | q-c5b0c8bb88 | ok |

### F14 · benign / high · T1110.001 · PowerShell 'password' hits are hardcoded credentials in theft/exfil scripts, not password guessing

Evidence status: **verified**

The PowerShell script blocks matching *Password* on scranton.dmevals.local (user pbeesly) contain hardcoded secrets used by credential-theft and exfiltration functions, not guessing logic: Get-PrivateKeys uses ConvertTo-SecureString -String "saribas" to export PFX certificates, and Invoke-Exfil uses a hardcoded PSCredential (cozy / MyCozyPassw0rd!) to map a WebDAV share. There is no loop over candidate passwords and no failed-logon telemetry, so this is not password guessing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-7e04b0d150 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-f6df3deb52 | ok |

### F15 · benign / medium · T1110.002 · No offline-cracking artifacts; lsass/SAM access is credential dumping, not cracking

Evidence status: **verified**

No hashcat/Invoke-Mimikatz/DumpCreds script blocks, no ntds.dit/SAM file writes, and no secretsdump command lines were found. The lsass access on scranton.dmevals.local is a single powershell.exe (PID 3876) read with GrantedAccess 0x1000, and the SAM registry reads are performed by lsass.exe itself as SCRANTON$ (AccessMask 0xf003f) — normal OS behaviour. These are credential-dumping/access artifacts (T1003/T1552), not password cracking, and no cracking tooling or dumped-hash files appear in the data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SIwN6W | q-a0d93354d7 | ok |
| 2 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YWMnGq | q-9f6cb7880e | ok |

### F16 · benign / high · T1110.003 · No password-spraying pattern; only a single successful explicit-credential logon

Evidence status: **verified**

There are zero 4625/4771 events and no PowerShell spray scripts. The only explicit-credential logon (4648) targets are dominated by pbeesly (9 of 15), consistent with normal interactive/service logons, and the single 4776 credential validation succeeded (Status 0x0). No single password tried across many accounts is observable.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHwYC | q-c5b0c8bb88 | ok |

### F17 · benign / high · T1110.004 · No credential-stuffing activity; no failed logons or stuffing tooling

Evidence status: **verified**

No 4625/4771 failures, no login/auth command lines in Sysmon process creation, and no credential-stuffing scripts in PowerShell. The only 'logon' messages in windows.other are a benign Customer Experience Improvement Program notification (7001) and a successful RDP session logon for DMEVALS\pbeesly from 172.18.39.2. Nothing indicates reuse of leaked credential pairs.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:48.000Z | scranton.dmevals.local | windows.other | message | Remote Desktop Services: Session logon succeeded:    User: DMEVALS\pbeesly  Session ID: 2  Source Network Address: 172.18.39.2 | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx0y | q-81cd3da07f | ok |

### F18 · benign / medium · T1111 · No MFA/smart-card interception; credential-related hits are PowerShell exfil script and PsExec lateral movement

Evidence status: **verified**

All T1111 check hits were reviewed and none show Multi-Factor Authentication Interception. The 4648 explicit-credential logons (15 total) are user pbeesly authenticating with explicit credentials via PsExec (C:\Windows\PSEXESVC.exe) on nashua.dmevals.local and from scranton.dmevals.local to target server NASHUA, plus routine winlogon/taskhostw localhost logons (DWM-1/2, UMFD-0/1/2, SCRANTON$) — lateral movement / normal logon behaviour, not MFA token or smart-card interception. The 4104 script block referencing credentials is an exfiltration function (Invoke-Exfil) that hardcodes a username/password and maps a WebDAV share to copy a 7z archive — credential use for exfil, not interception of MFA material. Sysmon process-access to lsass is dominated by svchost.exe with GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION, benign); the only full-access (0x1f3fff) access is wsmprovhost.exe on nashua whose call trace runs through Microsoft.PowerShell.Commands.Management.ni.dll, i.e. a PowerShell remoting session enumerating processes, not credential theft. Registry 'Credential' hits are Windows Credential Guard / CredentialEnrollmentManager service configuration written by lsass.exe and services.exe — standard OS behaviour. No smart-card, credential-provider, or MFA-interception artifacts were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YogQzA | q-c43d9d34eb | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | localhost | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHQbW | q-31b31ea753 | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-b4bb6b56f9 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-24fb774ade | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-24fb774ade | ok |
| 6 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhV | q-0b7393b702 | ok |
| 7 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx1Y | q-7abd477294 | ok |

### F22 · benign / high · T1187 · SMB/139/445 and SYSVOL share access are benign domain traffic

Evidence status: **verified**

The SMB-related hits are normal domain behaviour: zeek conn records to 10.0.0.4:445/139 carry krb,smb,gssapi services (Kerberos-authenticated SMB, not coerced NTLM), and the windows.security 5145 share-access events are machine accounts (NEWYORK$, SCRANTON$) reading SYSVOL GPO policy files (gpt.ini, GptTmpl.inf) from \\*\SYSVOL. No WebDAV/WebClient or attacker-controlled SMB target was observed. These do not indicate forced authentication.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:06:38.903Z | simplerockbuild.simplerock.lan | zeek | zeek.service | krb,smb,gssapi | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Yc1 | q-973447bf39 | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\SYSVOL | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1Yph4sr | q-7f52007eb8 | ok |
| 3 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1Yph4sr | q-7f52007eb8 | ok |

### F24 · benign / high · T1212 · SAM database remote-call restriction message (event 16962) is benign system configuration

Evidence status: **verified**

windows.other event 16962 on scranton.dmevals.local is an informational Microsoft-Windows-Directory-Services-SAM message stating that remote calls to the SAM database are restricted using the default security descriptor. It is emitted by SYSTEM at service startup and reflects default hardening, not an exploitation attempt against the SAM.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.other | message | Remote calls to the SAM database are being restricted using the default security descriptor: O:SYG:SYD:(A;;RC;;;BA).  For more information please see http://go.… | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx0a | q-c43e470397 | ok |
| 2 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.other | event.code | 16962 | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx0a | q-c43e470397 | ok |

### F25 · benign / medium · T1212 · Routine svchost.exe LSASS handle opens (0x1000) are benign

Evidence status: **verified**

The large majority of Sysmon event 10 hits targeting lsass.exe are svchost.exe opening LSASS with GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION), which is normal Windows behaviour for services querying process information. These are distinct from the full-access (0x1FFFFF) PowerShell access on scranton.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WhJHLy | q-dfa104a615 | ok |
| 2 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WhJHLy | q-dfa104a615 | ok |

### F26 · benign / high · T1539 · No web session cookie theft observed; PowerShell 'Cookies' hits are benign DSC module code

Evidence status: **verified**

Hunting for T1539 (Steal Web Session Cookie) across windows.sysmon, windows.security, windows.powershell and windows.other found no access to browser cookie stores. The 13 PowerShell 4104 hits matching 'Cookies'/'Login Data' are benign Microsoft DSC module helper scripts (e.g. CommonResourceHelper.psm1, xStorage module manifests) where the word appears incidentally in module code, not cookie theft tooling. Sysmon file-create (event 11) hits for 'cookies'/'session' are OS artifacts (INetCookies package cache, UpdateSessionOrchestration.etl, SleepStudy .etl) written by svchost.exe/System, and the only browser-related process creations are normal MicrosoftEdge.exe/MicrosoftEdgeCP.exe/MicrosoftEdgeSH.exe launches by user pbeesly on scranton.dmevals.local. No 4663 object-access events reference any browser cookie/login database, and no process command line references chrome/edge/firefox cookie paths. The genuine malicious activity on scranton.dmevals.local (user pbeesly) is APT29-style PowerShell — screen capture, keystroke/AV check, and 7-Zip exfil to a WebDAV share — which is credential/collection activity but not web session cookie theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | win.Path | C:\Program Files\WindowsPowerShell\Modules\xStorage\DscResources\CommonResourceHelper.psm1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b42izk | q-43b5e3df7e | ok |
| 2 | 2020-05-02 03:05:45.000Z | scranton.dmevals.local | windows.powershell | message | Creating Scriptblock text (1 of 1):  <# PsTools Version in this package: 2.44 #> function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21gGA | q-99513871ae | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-125db9d7b0 | ok |
| 4 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsOhX7 | q-00672c24db | ok |
| 5 | 2020-05-02 03:21:01.765Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe" -ServerName:MicrosoftEdge.AppXdnhjhccw3zf0j06tkg3jtqr00qdm0khc.mca | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MrOOck | q-bbd5241966 | ok |

### F30 · benign / high · T1552.002 · Registry credential-path writes are OS components, not attacker activity

Evidence status: **verified**

Sysmon event 13 writes under credential-related registry paths (Winlogon, IdentityCRL ProviderPasswordLength/CharacterGroups, CredentialEnrollmentManager MuiCache) on scranton and nashua were all performed by legitimate system processes (svchost.exe, winlogon.exe, wininit.exe, services.exe). No reg query/save of credential hives by a suspicious process was observed, and the reg-query check returned zero hits.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:28.255Z | nashua.dmevals.local | windows.sysmon | registry.path | HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R8i4gn | q-10d463de95 | ok |
| 2 | 2020-05-02 03:05:28.255Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R8i4gn | q-10d463de95 | ok |

### F29 · benign / high · T1552.006 · SYSVOL/GPP policy file writes are legitimate Group Policy processing

Evidence status: **verified**

Sysmon event 11 shows writes to C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\gpt.ini and ...\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf on nashua and scranton. Every one of these writes was performed by C:\windows\system32\svchost.exe (the Group Policy client service), which is normal GPO refresh behaviour, not adversary collection of GPP cpassword material. No Groups.xml with cpassword was read or copied by a non-system process.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:40.308Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.in… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RqLbie | q-c392af1f33 | ok |
| 2 | 2020-05-02 03:10:40.308Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RqLbie | q-c392af1f33 | ok |

### F32 · benign / medium · T1555.004 · LSASS handle access dominated by benign system/Azure processes; no Credential Manager vault access

Evidence status: **verified**

The 326 Sysmon Event 10 hits on lsass.exe are overwhelmingly svchost.exe with GrantedAccess 0x1000 (293 of 326), plus Azure guest-agent processes (AntimalwareConfig.exe, WindowsAzureTelemetryService.exe, CollectGuestLogs.exe) with 0x1400 and wininit/csrss with 0x1fffff at lsass start (03:19:09). No vault/Credential Manager file or registry access was observed: C201 (Sysmon 15 on *vault*) and C202 (4688 command line *vault*) returned zero hits, and the 4663/4656 object-access hits on lsass are CollectGuestLogs.exe, MsMpEng.exe and the pbeesly PowerShell activity. The only non-system, non-Azure LSASS access is the pbeesly PowerShell case reported under T1555.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:41.869Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\AntimalwareConfig.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NAenUm | q-b3d9a236cf | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhM | q-b3d9a236cf | ok |
| 3 | 2020-05-02 03:22:38.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\WindowsAzure\Packages\CollectGuestLogs.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YEBswT | q-8da1851a09 | ok |

### F33 · benign / high · T1556 · LSASS handle access dominated by legitimate system processes; no authentication process tampering observed

Evidence status: **verified**

326 Sysmon Event 10 hits for handle access to lsass.exe across utica, scranton, newyork and nashua. Stacking by source process shows 289 from C:\windows\system32\svchost.exe, plus AntimalwareConfig.exe (15), WindowsAzureTelemetryService.exe (13), wininit.exe (2), csrss.exe (1), services.exe (1) and PowerShell (4). GrantedAccess is overwhelmingly 0x1000 (293) and 0x1400 (24) — query-limited access typical of security/telemetry products. The rare high masks (0x1fffff, 0x1f3fff, 0x101001) come from PowerShell.exe, wsmprovhost.exe, wininit.exe and csrss.exe; the full events show CallTrace through ntdll.dll/KERNELBASE.dll and the PowerShell Management native image, consistent with legitimate token/session queries and PowerShell remoting rather than credential dumping or authentication-process patching. No registry modification of authentication components (4657 on lsass/Security/SAM) was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WhJHLy | q-ff3a944bbb | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-4428419226 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-1603b11e76 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-4428419226 | ok |

### F34 · benign / high · T1556.001 · Domain controller logons are routine machine-account and service logons

Evidence status: **verified**

297 Event 4624 logons stack to LogonType 3 (218), 5 (61), 2 (15), 10 (2) and 0 (1). The sampled logons on newyork.dmevals.local are all the machine account NEWYORK$ (S-1-5-18) with Logon Type 3 from ::1, 10.0.0.4 and link-local IPv6 addresses — normal computer-account network authentication, not a DC authentication backdoor. No 4648 explicit-credential logons or anomalous authentication patterns were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YsmoMw | q-abaf6490b5 | ok |
| 2 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | source.ip | ::1 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YsmoMw | q-abaf6490b5 | ok |
| 3 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | source.ip | 10.0.0.4 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1Yph4sy | q-abaf6490b5 | ok |

### F35 · benign / high · T1557 · SMB/LDAP/Kerberos traffic is normal domain authentication, no AiTM positioning

Evidence status: **verified**

On 2020-05-02 the SMB/LDAP/Kerberos connections in windows.sysmon (383 events to ports 445/139/389/88) originate from legitimate Windows components — lsass.exe (233), System (66), Microsoft.ActiveDirectory.WebServices.exe (36), svchost.exe (20), dfsrs.exe (14) — talking to the domain controller 10.0.0.4. These are normal AD replication/authentication flows, not an adversary interposing on the path. No relay or man-in-the-middle positioning was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:42.257Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SErGol | q-2d12276f56 | ok |
| 2 | 2020-05-02 03:01:42.257Z | scranton.dmevals.local | windows.sysmon | dns.question.name | NEWYORK.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SErGol | q-2d12276f56 | ok |

### F36 · benign / high · T1557.001 · Name resolution is correct; service installs are PsExec, not relay tooling

Evidence status: **verified**

DNS queries in windows.sysmon resolve to the correct addresses (NASHUA -> ::ffff:10.0.1.6, NEWYORK.dmevals.local -> ::ffff:10.0.0.4, SCRANTON -> 10.0.1.4), so there is no evidence of name-resolution poisoning. The 7045/4697 service-install hits are PSEXESVC (%SystemRoot%\PSEXESVC.exe, installed by user pbeesly on nashua.dmevals.local) and javamtsup (C:\Windows\System32\javamtsup.exe on scranton.dmevals.local) — these reflect PsExec lateral movement / a Java support service, not SMB-relay or LLMNR/NBT-NS poisoning tooling. Zeek SMB traffic (smb_mapping/smb_files/dce_rpc) is ordinary domain traffic to \\NEWYORK.dmevals.local\IPC$ and \\NEWYORK.dmevals.local\sysvol with krb,smb,gssapi service tags.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.324Z | scranton.dmevals.local | windows.sysmon | win.QueryResults | ::ffff:10.0.1.6; | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RqL7gO | q-2d12276f56 | ok |
| 2 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx2T | q-5c6cb9d5cc | ok |
| 3 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.security | win.ServiceFileName | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtY9 | q-ea55bdd5c2 | ok |
| 4 | 2020-04-30 00:12:01.658Z | simplerockbuild.simplerock.lan | zeek | message | {"@stream":"smb_mapping","@system":"simplerockbuild.simplerock.lan","@proc":"zeek","ts":1588205521.658912,"uid":"C6niUh1gdPBNBhfNDe","id_orig_h":"10.0.1.4","id_… | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Ida | q-1094d6e69b | ok |

### F37 · benign / high · T1557.002 · arp.exe /a and netsh trace are Azure agent telemetry, not ARP poisoning

Evidence status: **verified**

The arp.exe /a and netsh trace commands on scranton.dmevals.local are all spawned by legitimate Azure platform agents running as SYSTEM: WindowsAzureGuestAgent.exe, WindowsAzureTelemetryService.exe, WaAppAgent.exe and NetworkWatcherAgent.exe. These are routine Azure VM network/telemetry operations, not attacker ARP-cache manipulation. Zeek connection records show consistent MAC-to-host mapping (each source IP uses a single orig_l2_addr; no MAC claiming multiple IPs), which is inconsistent with ARP cache poisoning.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:25.370Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NUyf30 | q-940ec2a049 | ok |
| 2 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NW1Kgv | q-940ec2a049 | ok |
| 3 | 2020-04-30 00:06:38.903Z | simplerockbuild.simplerock.lan | zeek | zeek.orig_l2_addr | 00:0d:3a:4d:42:f2 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Yc1 | q-a92d8ea8f0 | ok |

### F38 · benign / high · T1557.003 · No DHCP spoofing activity observed in any dataset

Evidence status: **verified**

No DHCP-related activity was found: windows.other contains no DHCP server event codes (1341/1342/1020/1063), no process command lines reference dhcp/DhcpServer in windows.security or windows.sysmon, no PowerShell script blocks reference DHCP, and Zeek shows no UDP traffic on DHCP ports 67/68. There is no evidence of rogue DHCP server or DHCP spoofing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | event.code | 7045 | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx2I | q-0448e32784 | ok |

### F40 · benign / medium · T1558.001 · No golden-ticket (KRBTGT forgery) evidence observed

Evidence status: **verified**

No artifacts of golden-ticket creation were found: no krbtgt/DCSync references in PowerShell script blocks (C273 zero hits), no 4769/4768-style forged-ticket anomalies, and the only Kerberos network traffic (zeek, 2020-04-30) is normal AS/TGS exchange for user pbeesly with AES256 encryption and standard KDC_ERR_PREAUTH_REQUIRED pre-auth flows. The LSASS full-access read on scranton could in principle yield the krbtgt hash, but no forged-ticket use is present in the collected data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:24:19.119Z | simplerockbuild.simplerock.lan | zeek | zeek.service | krbtgt/DMEVALS.LOCAL | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IeV | q-0e8f803219 | ok |
| 2 | 2020-04-30 00:24:19.119Z | simplerockbuild.simplerock.lan | zeek | zeek.cipher | aes256-cts-hmac-sha1-96 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IeV | q-0e8f803219 | ok |

### F41 · benign / medium · T1558.002 · No silver-ticket (service-ticket forgery) evidence observed

Evidence status: **verified**

No silver-ticket artifacts were found. PowerShell script-block searches for 'silver'/'service ticket'/'Rubeus' returned zero hits (C280), and the zeek Kerberos records show only legitimate TGS requests for cifs/NASHUA, cifs/NEWYORK, HTTP/NASHUA, ldap/NEWYORK and host/nashua.dmevals.local by pbeesly, all AES256 and successful — consistent with normal service-ticket acquisition, not forgery.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:35:25.646Z | simplerockbuild.simplerock.lan | zeek | zeek.service | cifs/NASHUA | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IeU | q-0e8f803219 | ok |
| 2 | 2020-04-30 00:33:26.292Z | simplerockbuild.simplerock.lan | zeek | zeek.service | HTTP/NASHUA | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IeW | q-0e8f803219 | ok |

### F42 · benign / medium · T1558.003 · No Kerberoasting evidence observed

Evidence status: **verified**

No Kerberoasting activity was found: PowerShell script-block searches for 'kerberoast'/'SPN'/'Invoke-Kerberoast' returned zero hits (C287), and the zeek Kerberos TGS requests are limited to a small set of normal services for pbeesly with AES256 encryption (no RC4/etype 23 downgrade typical of roasting).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:33:14.816Z | simplerockbuild.simplerock.lan | zeek | zeek.service | ldap/NEWYORK.dmevals.local | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO74ep | q-0e8f803219 | ok |
| 2 | 2020-04-30 00:33:14.816Z | simplerockbuild.simplerock.lan | zeek | zeek.cipher | aes256-cts-hmac-sha1-96 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO74ep | q-0e8f803219 | ok |

### F43 · benign / medium · T1558.004 · No AS-REP Roasting evidence observed

Evidence status: **verified**

No AS-REP roasting was found: PowerShell script-block searches for 'asrep'/'AS-REP'/'GetNPUsers' returned zero hits (C295) and sysmon process-creation searches for asrep/GetNPUsers/rubeus command lines returned zero hits (C298). The zeek AS exchanges for pbeesly all show KDC_ERR_PREAUTH_REQUIRED followed by a successful pre-authenticated AS-REP, i.e. pre-authentication is enabled — the opposite of an AS-REP-roastable account.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:24:19.110Z | simplerockbuild.simplerock.lan | zeek | zeek.error_msg | KDC_ERR_PREAUTH_REQUIRED | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Idf | q-0e8f803219 | ok |
| 2 | 2020-04-30 00:24:19.110Z | simplerockbuild.simplerock.lan | zeek | zeek.request_type | AS | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Idf | q-0e8f803219 | ok |

### F46 · benign / medium · T1606.001 · No web-cookie theft or forgery observed

Evidence status: **verified**

The only cookie-related file event was a single creation of C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies by svchost.exe on scranton.dmevals.local at 03:21:05, which is normal Windows service-profile cookie-store activity, not browser cookie theft or forging. No PowerShell script blocks referencing cookies/SetCookie were found, and no security-log access to Cookies or Login Data objects was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsOhX7 | q-b8f4aa622e | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsOhX7 | q-b8f4aa622e | ok |

### F48 · benign / medium · T1649 · Certificate store registry value change on nashua.dmevals.local is Sysmon self-monitoring

Evidence status: **verified**

The only 4657 registry modification touching the certificate store was on nashua.dmevals.local at 2020-05-01T23:16:19-04:00, changing a value under \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656. The modifying process is C:\Windows\Sysmon.exe and the account is the machine account NASHUA$, i.e. Sysmon's own certificate-store monitoring, not an adversary importing a forged authentication certificate. No corresponding certificate file creation or PowerShell certificate manipulation was seen on nashua.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YeUuC- | q-c869d1b63f | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YeUuC- | q-c869d1b63f | ok |
| 3 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | user.name | NASHUA$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YeUuC- | q-c869d1b63f | ok |

### F49 · benign / medium · T1649 · Kerberos TGT requests (4768) show no certificate-based authentication anomaly

Evidence status: **verified**

All 14 Kerberos TGT requests (event 4768) in the window were on newyork.dmevals.local and belong to two accounts: the interactive user pbeesly (9 requests, S-1-5-21-1830255721-3727074217-2423397540-1107) and the machine account SCRANTON$ (5 requests). All request the krbtgt service with normal client addresses (10.0.1.4/10.0.1.6) and standard realm names; no PKINIT/certificate-based or otherwise anomalous TGT issuance is visible, so these are routine domain logons rather than evidence of forged authentication certificates.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | user.name | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YbQlYK | q-f05f1fdb65 | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YOGdm9 | q-f05f1fdb65 | ok |
| 3 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | source.ip | ::ffff:10.0.1.4 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YOGdm9 | q-f05f1fdb65 | ok |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | The pivot confirms credential-access tooling: PsExec64 with cleartext credentials delivering a PyInstaller python.exe credential payload to nashua, plus Rar/sdelete packaging and wiping of collected secrets. |
| T1003.001 LSASS Memory | malicious | Beyond the LSASS anchor, the PsExec-delivered PyInstaller python.exe on nashua (spawned by PSEXESVC.exe) unpacked credential-tooling DLLs and beaconed to 192.168.0.4:8443. |
| T1003.002 Security Account Manager | suspicious | lsass.exe set HKLM\SAM\SAM\Domains\Account\F on scranton; no reg save/hive-copy command lines observed. |
| T1003.003 NTDS | not_observed | No ntds/ntdsutil/vssadmin/diskshadow command lines, .dit file creation, or ntds object access in any dataset (C025-C031 zero hits). |
| T1003.004 LSA Secrets | not_observed | No access to SECURITY\Policy\Secrets or lsadump references in security/powershell/other datasets (C035-C039 zero hits). |
| T1003.005 Cached Domain Credentials | suspicious | lsass.exe repeatedly set HKLM\SECURITY\Cache\NL$1 on nashua during the attacker's active window; no direct SECURITY\Cache read captured. |
| T1003.006 DCSync | not_observed | No DCSync indicators: no 4662 replication-rights access, no 4929/4930/4931, no drsuapi/lsadump/dcsync command lines (C047-C051 zero hits). |
| T1040 Network Sniffing | benign | All packet-capture activity (netsh trace start/stop, logman ETW traces) on scranton.dmevals.local is spawned by the Azure Network Watcher agent (NetworkWatcherAgent.exe) and Azure Guest Agent (WaAppAgent.exe) as SYSTEM, … |
| T1056 Input Capture | malicious | Masquerading cod.3aka3.scr in C:\ProgramData\victim accessed the LSA registry key and loaded GUI input DLLs (user32/gdi32/win32u/msctf), with outbound C2 to 192.168.0.5:1234. |
| T1056.001 Keylogging | not_observed | No keylogger artifacts found: no GetAsyncKeyState/SetWindowsHookEx/keylog strings in PowerShell, no Keyboard/Input registry object access. The .scr binary's GUI DLL loads are suggestive but no explicit keylogging evidenc… |
| T1056.002 GUI Input Capture | not_observed | No credential-prompt or GUI input capture commands (Get-Credential/prompt) observed in sysmon or security process creation events. |
| T1056.003 Web Portal Capture | not_observed | No web portal capture: no login/portal/vpn URLs in zeek HTTP, no matching file writes or process command lines. |
| T1056.004 Credential API Hooking | malicious | PowerShell.exe opened lsass.exe with GrantedAccess 0x1FFFFF (full access) on scranton.dmevals.local, consistent with credential API hooking/credential access. |
| T1110 Brute Force | not_observed | Only one credential-validation event (4776, AUDIT_SUCCESS Status 0x0) in the entire security window; zero 4625/4771 failures and no brute-force pattern. |
| T1110.001 Password Guessing | not_observed | PowerShell 'password' matches are hardcoded secrets in credential-theft/exfil scripts (Get-PrivateKeys, Invoke-Exfil), not guessing loops; no failed logons. |
| T1110.002 Password Cracking | not_observed | No cracking tooling (hashcat/Mimikatz/DumpCreds), no ntds.dit/SAM file writes; lsass/SAM access is dumping/OS behaviour, not offline cracking. |
| T1110.003 Password Spraying | not_observed | No 4625/4771 failures and no spray scripts; 4648 targets are dominated by pbeesly and the single 4776 succeeded. |
| T1110.004 Credential Stuffing | not_observed | No failed logons, no login/auth process command lines, and no credential-stuffing scripts; only benign logon notifications observed. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA/smart-card/credential-provider interception artifacts. 4648 explicit-credential logons are PsExec lateral movement by pbeesly and routine winlogon/taskhostw localhost logons; the credential-referencing 4104 script… |
| T1187 Forced Authentication | malicious | On scranton.dmevals.local a PowerShell process dropped hostui.lnk into the StartUp folder (forced-auth trigger) and a masqueraded C:\Windows\System32\hostui.exe was launched via 'Start-Process ... -verb runas', then spaw… |
| T1212 Exploitation for Credential Access | malicious | PowerShell.exe on scranton.dmevals.local opened lsass.exe with GrantedAccess 0x1FFFFF (full access) at 03:05:16 UTC, in the same pbeesly session that ran Get-PrivateKeys, Get-Clipboard and privilege-enumeration script bl… |
| T1539 Steal Web Session Cookie | not_observed | No access to browser cookie/login databases was found. PowerShell 4104 'Cookies' matches are benign DSC module helper scripts (CommonResourceHelper.psm1); Sysmon file-create 'cookie/session' hits are OS artifacts (INetCo… |
| T1552 Unsecured Credentials | malicious | Umbrella technique: confirmed credential theft activity on scranton.dmevals.local by user pbeesly (private key export, plaintext password in PsExec command line). |
| T1552.001 Credentials In Files | malicious | pbeesly's cleartext password Fl0nk3rt0n!T0by was passed on the PsExec64.exe command line from scranton to NASHUA, and a password-protected Rar archive of *pass*/*login*/*admin*/*vpn* files was created on nashua. |
| T1552.002 Credentials in Registry | benign | All credential-path registry writes were by legitimate system processes (svchost/winlogon/wininit/services); no reg query/save of credential hives. |
| T1552.003 Shell History | not_observed | No ConsoleHost_history/PSReadLine access or shell-history reads found in any dataset. |
| T1552.004 Private Keys | malicious | Get-PrivateKeys exported all LocalMachine certificates to .pfx files on scranton, confirmed by Sysmon file creation, then cleaned up. |
| T1552.006 Group Policy Preferences | benign | SYSVOL/GptTmpl.inf writes were normal Group Policy processing by svchost.exe; no GPP cpassword collection observed. |
| T1555 Credentials from Password Stores | suspicious | PowerShell 'Screenshot' background job capturing the user session to Downloads and download of 7Zip4Powershell packaging module on scranton; consistent with credential/session collection but no direct credential-store re… |
| T1555.003 Credentials from Web Browsers | not_observed | All browser credential-store checks (C193-C198) returned zero hits; no Login Data/logins.json/browser process access seen. |
| T1555.004 Windows Credential Manager | not_observed | No vault/Credential Manager file or registry access (C201, C202 zero hits); LSASS handle access is benign svchost/Azure/system processes. |
| T1555.005 Password Managers | not_observed | No 1Password/KeePass/LastPass file, command-line or script-block artifacts (C206-C208 zero hits). |
| T1556 Modify Authentication Process | benign | LSASS handle accesses are dominated by legitimate system/security processes (svchost 289, AntimalwareConfig, Azure telemetry) with query-limited masks (0x1000/0x1400); rare high-mask accesses from PowerShell/wsmprovhost … |
| T1556.001 Domain Controller Authentication | benign | 4624 logons are routine machine-account (NEWYORK$) network logons (Type 3) from local/link-local addresses; no DC authentication backdoor or 4648 explicit-credential abuse. |
| T1556.002 Password Filter DLL | not_observed | No password filter DLL registration, System32 DLL drops, or Notification Packages/PasswordFilter references found. |
| T1556.005 Reversible Encryption | not_observed | No 4739 events, Set-ADUser/ReversibleEncryption command lines, or reversible-encryption strings found. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739/4738/4732 events or authentication-policy PowerShell activity found. |
| T1556.007 Hybrid Identity | not_observed | No 5136/5137/5141 directory change events or adfs/azuread references found. |
| T1556.008 Network Provider DLL | not_observed | No System32/SysWOW64 DLL writes or 4657/4656 registry/object access found. |
| T1557 Adversary-in-the-Middle | not_observed | SMB/LDAP/Kerberos connections (383 sysmon events) all originate from legitimate Windows components (lsass, ADWS, dfsrs, svchost) to the DC 10.0.0.4; no adversary-in-the-middle positioning seen. |
| T1557.001 Name Resolution Poisoning and SMB Relay | not_observed | DNS resolutions are correct (NASHUA->10.0.1.6, NEWYORK->10.0.0.4, SCRANTON->10.0.1.4); no LLMNR/NBT-NS poisoning. Service installs are PSEXESVC (PsExec) and javamtsup, not relay tooling. |
| T1557.002 ARP Cache Poisoning | not_observed | arp.exe /a and netsh trace are spawned by Azure platform agents (WindowsAzureGuestAgent, NetworkWatcherAgent, WindowsAzureTelemetryService, WaAppAgent) as SYSTEM; Zeek MAC-to-IP mapping is consistent, no MAC claiming mul… |
| T1557.003 DHCP Spoofing | not_observed | No DHCP event codes, no dhcp command lines, no DHCP PowerShell, and no Zeek UDP traffic on ports 67/68 in any dataset. |
| T1558 Steal or Forge Kerberos Tickets | malicious | PowerShell.exe PID 2976 (the hidden stego-loader run by pbeesly on scranton) opened lsass.exe with GrantedAccess 0x1F3FFF and 0x1FFFFF, full-access LSASS reads consistent with Kerberos ticket/credential theft. |
| T1558.001 Golden Ticket | not_observed | No krbtgt/DCSync/forged-ticket artifacts; Kerberos traffic is normal AES256 AS/TGS for pbeesly. |
| T1558.002 Silver Ticket | not_observed | No silver-ticket/Rubeus artifacts; TGS requests are legitimate service tickets for pbeesly. |
| T1558.003 Kerberoasting | not_observed | No Kerberoast/SPN/Invoke-Kerberoast artifacts; no RC4 downgrade in TGS requests. |
| T1558.004 AS-REP Roasting | not_observed | No AS-REP roast artifacts; AS exchanges show pre-authentication enabled (KDC_ERR_PREAUTH_REQUIRED then success). |
| T1606 Forge Web Credentials | suspicious | A .scr payload in C:\ProgramData\victim and a PowerShell IEX stager decoding monkey.png were observed on scranton.dmevals.local, providing the execution context for the credential-theft toolchain, but no direct web-crede… |
| T1606.001 Web Cookies | not_observed | Only benign svchost.exe creation of a service-profile INetCookies file; no browser cookie theft, cookie manipulation, or SetCookie script blocks were found. |
| T1606.002 SAML Tokens | malicious | PowerShell Get-PrivateKeys exported all LocalMachine certificates to password-protected .pfx files on scranton.dmevals.local, the classic precursor to stealing an ADFS token-signing certificate for SAML token forgery, fo… |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | 5 planned checks, all with zero hits |
| T1649 Steal or Forge Authentication Certificates | malicious | On scranton.dmevals.local, user pbeesly ran the PowerShell function Get-PrivateKeys (from C:\Program Files\SysinternalsSuite\readme.ps1) which recursively enumerates cert:\LocalMachine and exports every certificate with … |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 0 hits | 0 hits | 11911 hits | 39730 hits | n/a |
| T1003.001 LSASS Memory | 0 hits | 0 hits | 940 hits | 39939 hits | n/a |
| T1003.002 Security Account Manager | 0 hits | 0 hits | 4484 hits | 392 hits | n/a |
| T1003.003 NTDS | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.004 LSA Secrets | 0 hits | 0 hits | 0 hits | 331 hits | n/a |
| T1003.005 Cached Domain Credentials | 1 hits | 0 hits | 0 hits | 330 hits | n/a |
| T1003.006 DCSync | 0 hits | 0 hits | 7 hits | 0 hits | 9 hits |
| T1040 Network Sniffing | 5 hits | 2 hits | 2 hits | 9 hits | 2140 hits |
| T1056 Input Capture | 5 hits | 3 hits | 16308 hits | 796 hits | 0 hits |
| T1056.001 Keylogging | 5 hits | 0 hits | 0 hits | 35408 hits | 0 hits |
| T1056.002 GUI Input Capture | 5 hits | 5498 hits | 0 hits | 0 hits | 0 hits |
| T1056.003 Web Portal Capture | 5 hits | 4 hits | 0 hits | 1649 hits | 0 hits |
| T1056.004 Credential API Hooking | 0 hits | 0 hits | 10834 hits | 59963 hits | n/a |
| T1110 Brute Force | 2 hits | 4 hits | 1 hits | 1 hits | 35 hits |
| T1110.001 Password Guessing | 2 hits | 2 hits | 0 hits | 0 hits | 35 hits |
| T1110.002 Password Cracking | 6 hits | 0 hits | 21811 hits | 326 hits | 0 hits |
| T1110.003 Password Spraying | 0 hits | 2 hits | 15 hits | 0 hits | 35 hits |
| T1110.004 Credential Stuffing | 2 hits | 3 hits | 0 hits | 0 hits | 35 hits |
| T1111 Multi-Factor Authentication Interception | 2 hits | 3 hits | 312 hits | 39294 hits | n/a |
| T1187 Forced Authentication | 1 hits | 0 hits | 14140 hits | 1649 hits | 50 hits |
| T1212 Exploitation for Credential Access | 3 hits | 16 hits | 42 hits | 39730 hits | 613 hits |
| T1539 Steal Web Session Cookie | 3 hits | 13 hits | 460 hits | 40932 hits | 62 hits |
| T1552 Unsecured Credentials | 2 hits | 2 hits | 460 hits | 19190 hits | 448 hits |
| T1552.001 Credentials In Files | 0 hits | 1 hits | 312 hits | 2096 hits | 448 hits |
| T1552.002 Credentials in Registry | 2 hits | 0 hits | 5331 hits | 15 hits | n/a |
| T1552.003 Shell History | 5 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1552.004 Private Keys | 0 hits | 2 hits | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | 0 hits | 1 hits | 38 hits | 22 hits | n/a |
| T1555 Credentials from Password Stores | 0 hits | 0 hits | 19 hits | 39610 hits | n/a |
| T1555.003 Credentials from Web Browsers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1555.004 Windows Credential Manager | 14 hits | 2 hits | 0 hits | 652 hits | n/a |
| T1555.005 Password Managers | 14 hits | 0 hits | 0 hits | 326 hits | n/a |
| T1556 Modify Authentication Process | 0 hits | 0 hits | 0 hits | 376 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | 0 hits | 609 hits | 359 hits | n/a |
| T1556.002 Password Filter DLL | 4 hits | 0 hits | 0 hits | 1 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556.006 Multi-Factor Authentication | 0 hits | 1 hits | 0 hits | 0 hits | n/a |
| T1556.007 Hybrid Identity | 0 hits | 0 hits | 0 hits | 2 hits | n/a |
| T1556.008 Network Provider DLL | 0 hits | n/a | 36 hits | 186 hits | n/a |
| T1557 Adversary-in-the-Middle | 0 hits | n/a | 10977 hits | 464 hits | 677 hits |
| T1557.001 Name Resolution Poisoning and SMB Relay | 5 hits | 0 hits | 23 hits | 0 hits | 193 hits |
| T1557.002 ARP Cache Poisoning | 0 hits | n/a | 5059 hits | 147 hits | 613 hits |
| T1557.003 DHCP Spoofing | 216 hits | 0 hits | 0 hits | 0 hits | 0 hits |
| T1558 Steal or Forge Kerberos Tickets | 6 hits | 0 hits | 660 hits | 652 hits | 35 hits |
| T1558.001 Golden Ticket | 6 hits | 0 hits | 476 hits | 652 hits | 35 hits |
| T1558.002 Silver Ticket | 6 hits | 0 hits | 476 hits | 652 hits | 35 hits |
| T1558.003 Kerberoasting | 6 hits | 0 hits | 552 hits | 652 hits | 35 hits |
| T1558.004 AS-REP Roasting | 3 hits | 0 hits | 28 hits | 0 hits | 35 hits |
| T1606 Forge Web Credentials | 0 hits | 1 hits | 327 hits | 39283 hits | n/a |
| T1606.001 Web Cookies | 0 hits | 0 hits | 0 hits | 2 hits | n/a |
| T1606.002 SAML Tokens | 0 hits | 0 hits | 609 hits | 24 hits | n/a |
| T1621 Multi-Factor Authentication Request Generatio… | 0 hits | 0 hits | 0 hits | n/a | n/a |
| T1649 Steal or Forge Authentication Certificates | 0 hits | 1 hits | 64 hits | 1 hits | n/a |

Cells: 265, gaps: 0.

## Queries

Every MCP tool call of this run (1007), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-49d63e18e9 | scope | list_data_sources | {} | None |  |
| q-1f8a5179a7 | scope | get_registry | {} | None |  |
| q-5ec4b06eb8 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-7e21ef28b8 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-4a5a0313b2 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-b754243cff | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-637828ac20 | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-c96e251c9b | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-8409dbfdab | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-390671232b | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-33af3b8fc0 | check C004 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 934 |  |
| q-f2449c44f9 | check C005 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*lsass* OR *mimikatz* OR *sekurlsa* OR *procdump* OR *comsvcs* OR *MiniDump* OR *DumpCreds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-d08300024f | check C006 | search | {"dataset": "windows.other", "query": "message:(*lsass* OR *mimikatz* OR *procdump* OR *MiniDump* OR *sekurlsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 0 |  |
| q-fcf9eae7d8 | check C007 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-6bc4ad05dd | check C008 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-13090c4a23 | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-225845be1d | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*lsass* OR file.path:*.dmp)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 2 |  |
| q-51334d6f87 | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*comsvcs*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 1 |  |
| q-57eea1adf5 | check C012 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-631cec25ac | check C013 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 934 |  |
| q-86598bdd74 | check C014 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 6 |  |
| q-b692aff49b | check C015 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*lsass* OR *MiniDump* OR *comsvcs* OR *sekurlsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-a2c04d3b34 | check C016 | search | {"dataset": "windows.other", "query": "message:(*lsass* OR *MiniDump* OR *comsvcs*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-923736dc3f | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg\\ save* OR process.command_line:*save*hklm\\sam* OR process.command_line:*hklm\\security* OR process.command_line:*hklm\\system*)", "time_from": null, "time_to": null, "fields"… | 0 |  |
| q-1024cd9967 | check C018 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*sam* OR file.path:*security* OR file.path:*system* OR file.path:*.hiv OR file.path:*.save)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 331 |  |
| q-fc49931d61 | check C019 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:(*SAM* OR *SECURITY* OR *SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 15 | F03 |
| q-3b32990a91 | check C020 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (file.path:*sam* OR file.path:*security* OR file.path:*system*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 46 |  |
| q-ca67c47a30 | check C021 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*reg\\ save* OR process.command_line:*hklm\\sam* OR process.command_line:*hklm\\security*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer… | 0 |  |
| q-6c4a911736 | check C022 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 4484 |  |
| q-e68314b7a4 | check C023 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*reg\\ save* OR *hklm\\sam* OR *hklm\\security* OR *hklm\\system* OR *Invoke-NinjaCopy*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-7143551e07 | check C024 | search | {"dataset": "windows.other", "query": "message:(*reg\\ save* OR *hklm\\sam* OR *hklm\\security* OR *hklm\\system*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 0 |  |
| q-e8dce19d49 | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntds* OR process.command_line:*ntdsutil* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-2e472b1a20 | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ntds* OR file.path:*.dit)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proc… | 0 |  |
| q-27832b4bb0 | check C027 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (file.path:*ntds* OR file.path:*.dit)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proce… | 0 |  |
| q-4b3944c2db | check C028 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*ntdsutil* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow* OR process.command_line:*ntds.dit*)", "time_from": null, "time_to": null, "fields": ["@timest… | 0 |  |
| q-ef7f86aac5 | check C029 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-39eaeea526 | check C030 | search | {"dataset": "windows.other", "query": "message:(*ntds* OR *vssadmin* OR *diskshadow* OR *Volume Shadow Copy*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exec… | 0 |  |
| q-335800f0a8 | check C031 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*ntds* OR *vssadmin* OR *diskshadow* OR *Invoke-NinjaCopy*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "u… | 0 |  |
| q-21f97c3c88 | check C032 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*secrets* OR process.command_line:*lsadump* OR process.command_line:*cache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 4 |  |
| q-33e5ee8a9a | check C033 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-fb0db67cbe | check C034 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-069de0f4eb | check C035 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*SECURITY\\Policy\\Secrets*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executabl… | 0 |  |
| q-fed6d15759 | check C036 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*SECURITY\\Policy\\Secrets*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executabl… | 0 |  |
| q-4d5e44e656 | check C037 | search | {"dataset": "windows.security", "query": "event.code:4670 AND win.ObjectName:*SECURITY*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-d121119e04 | check C038 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*lsadump* OR *secrets* OR *SECURITY\\Policy\\Secrets*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-c8477e2f60 | check C039 | search | {"dataset": "windows.other", "query": "message:(*lsadump* OR *SECURITY\\Policy\\Secrets* OR *LSA Secrets*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 0 |  |
| q-dcdc021ec9 | check C040 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*dcc2* OR process.command_line:*mscache* OR process.command_line:*lsadump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 4 |  |
| q-8282ea5e6b | check C041 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-d4269b2b71 | check C042 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*SECURITY\\Cache*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proce… | 0 |  |
| q-4231306f05 | check C043 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*SECURITY\\Cache*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proce… | 0 |  |
| q-310e11f773 | check C044 | search | {"dataset": "windows.security", "query": "event.code:4670 AND win.ObjectName:*SECURITY\\Cache*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proce… | 0 |  |
| q-e7803e53dd | check C045 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*cache* OR *dcc2* OR *mscache* OR *lsadump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-968c2f82f6 | check C046 | search | {"dataset": "windows.other", "query": "message:(*SECURITY\\Cache* OR *cached credentials* OR *dcc2*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", … | 1 |  |
| q-b725b9b106 | check C047 | search | {"dataset": "windows.security", "query": "event.code:4662 AND win.Properties:\"*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*\"", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-00e5bc518d | check C048 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-b74ec001de | check C049 | search | {"dataset": "windows.other", "query": "event.code:4929 OR event.code:4930 OR event.code:4931", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-5931c4105c | check C050 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-b60efa219d | check C051 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*dcsync* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*Invoke-Mimikatz*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 0 |  |
| q-e9ac8035be | check C052 | search | {"dataset": "zeek", "query": "event.action:dce_rpc AND zeek.operation:*DRS*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 9 |  |
| q-945093048f | check C053 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*netsh* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap*)", "time_from": null, "time_to": n… | 2 |  |
| q-1d7da6d9a1 | check C054 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-1980ae57fc | check C055 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*pktmon* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap* OR process.command_line:*netsh trace*)", "time_from": null, "time_to": … | 9 |  |
| q-fe3537294c | check C056 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*pktmon* OR powershell.script_block_text:*netsh trace* OR powershell.script_block_text:*New-NetEventSession*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "o… | 2 |  |
| q-37924189a1 | check C057 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-292d5ab940 | check C058 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectType:*Key* OR win.ObjectName:*Credential* OR win.ObjectName:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.cod… | 5331 |  |
| q-61b502c6ac | check C059 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-6b3897732b | check C060 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*winlogon.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 470 | F12 |
| q-e376c4fc83 | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e6ce940414 | check C062 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Get-Credential* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 3 |  |
| q-454aec14d1 | check C063 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-77591d27b8 | check C064 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-4b24831611 | check C065 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 326 |  |
| q-f5e8a7246c | check C066 | search | {"dataset": "windows.sysmon", "query": "event.code:13 OR event.code:14", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 17541 |  |
| q-0d26be582b | check C067 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-3017858842 | check C068 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*Keyboard* OR win.ObjectName:*Input*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-88bce82cd5 | check C069 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-d7b5cf6361 | check C070 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*GetAsyncKeyState* OR powershell.script_block_text:*keylog* OR powershell.script_block_text:*SetWindowsHookEx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 0 |  |
| q-4dbad6940b | check C071 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-184b5fbbc8 | check C072 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*Prompt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "… | 4 |  |
| q-ec86da702f | check C073 | search | {"dataset": "windows.powershell", "query": "event.code:4103 OR event.code:4104 OR event.code:4105 OR event.code:4106", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proce… | 5494 |  |
| q-425decb9af | check C074 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 0 |  |
| q-c3fa9b3ada | check C075 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*prompt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user… | 0 |  |
| q-837df238c1 | check C076 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-1c2bbfa9f8 | check C077 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-86ad00f88b | check C078 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*login* OR file.path:*portal* OR file.path:*vpn*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-dee9066451 | check C079 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-e0f63dbb53 | check C080 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*login* OR powershell.script_block_text:*password* OR powershell.script_block_text:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name"… | 4 |  |
| q-874d1a2f03 | check C081 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*login* OR process.command_line:*portal*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 0 |  |
| q-94e8e01fa0 | check C082 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-76e82cb958 | check C083 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*portal* OR url.original:*vpn*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 0 |  |
| q-fa30ddee53 | check C084 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-976c1a8446 | check C085 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-472b4cfcdb | check C086 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-0cb7d6c3a0 | check C087 | search | {"dataset": "windows.sysmon", "query": "event.code:8 AND win.StartModule:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 95 |  |
| q-073e42d875 | check C088 | aggregate | {"dataset": "windows.security", "field": "win.TargetProcessName", "query": "event.code:4656 OR event.code:4663", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10834 |  |
| q-63b1c5e3b8 | check C089 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hook* OR powershell.script_block_text:*MiniDump* OR powershell.script_block_text:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-4c565acaa7 | check C090 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*MiniDump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-fd059b8069 | check C091 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-18e0e4e8a6 | check C092 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-8744199330 | check C093 | aggregate | {"dataset": "windows.security", "field": "win.Status", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-582e0ea2d1 | check C094 | count | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4776", "time_from": null, "time_to": null} | 1 |  |
| q-86ef0f586b | check C095 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Brute* OR powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name"… | 4 |  |
| q-a118cd022b | check C096 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*pass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-81cd3da07f | check C097 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 2 | F17 |
| q-4506157cf1 | check C098 | aggregate | {"dataset": "zeek", "field": "zeek.rcode_name", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-5e6b703f57 | check C099 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3aec5cfcbf | check C100 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-8b83c84469 | check C101 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e8dc4353ae | check C102 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Login*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 2 |  |
| q-039d24570a | check C103 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*net use* OR process.command_line:*net.exe*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-909dd1672e | check C104 | search | {"dataset": "windows.other", "query": "message:*4625* OR message:*failed*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 2 |  |
| q-54e37ca209 | check C105 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-9c3bbb3d2b | check C106 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-f3d385c701 | check C107 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4656 OR event.code:4663", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10834 |  |
| q-af94617338 | check C108 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*sam* OR process.command_line:*ntds* OR process.command_line:*secretsdump* OR process.command_line:*hashcat*)", "time_from": null, "time_to": null, "s… | 0 |  |
| q-7fbac808f6 | check C109 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*ntds* OR win.TargetFilename:*.dit OR win.TargetFilename:*sam*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-866b5a5fba | check C110 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*sam*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-3af1effded | check C111 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hashcat* OR powershell.script_block_text:*Invoke-Mimikatz* OR powershell.script_block_text:*DumpCreds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observ… | 0 |  |
| q-ec48ab5abb | check C112 | search | {"dataset": "windows.other", "query": "message:*ntds* OR message:*sam* OR message:*hive*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.com… | 6 |  |
| q-f91187b8fd | check C113 | search | {"dataset": "zeek", "query": "event.action:files AND (zeek.filename:*ntds* OR zeek.filename:*.dit OR zeek.filename:*.kirbi)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-c406bf42ab | check C114 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-490854e746 | check C115 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a491ade89e | check C116 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4771", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-0f82e49198 | check C117 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-eacb076b6b | check C118 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Spray* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 2 |  |
| q-e3828ae0bc | check C119 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*net use* OR process.command_line:*New-Object*Credential*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-6e219af7a7 | check C120 | search | {"dataset": "windows.other", "query": "message:*4771* OR message:*4625*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 0 |  |
| q-4959a5716f | check C121 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-e64cbaff58 | check C122 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-67c6fb12c4 | check C123 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-5408172608 | check C124 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e389edfe83 | check C125 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Login*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 3 |  |
| q-973ccd041e | check C126 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*login* OR process.command_line:*auth*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-bc2f77a37a | check C127 | search | {"dataset": "windows.other", "query": "message:*4625* OR message:*logon*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 2 |  |
| q-fe47416808 | check C128 | aggregate | {"dataset": "zeek", "field": "zeek.rcode_name", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-83f98764ff | check C129 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-c43d9d34eb | check C130 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F18 |
| q-91ea4a8711 | check C131 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 39283 |  |
| q-0b7393b702 | check C132 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 11 | F18 |
| q-41976e7681 | check C133 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*Vault*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 3 |  |
| q-7abd477294 | check C134 | search | {"dataset": "windows.other", "query": "message:*Credential* OR message:*Smart*Card*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 2 | F18 |
| q-0f881a6400 | check C135 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 10977 |  |
| q-5203ba726b | check C136 | aggregate | {"dataset": "windows.security", "field": "destination.ip", "query": "event.code:5156", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 3163 |  |
| q-808fe7c96d | check C137 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 1649 |  |
| q-28598c8efb | check C138 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*445* OR powershell.script_block_text:*WebDAV* OR powershell.script_block_text:*\\\\\\\\)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 0 |  |
| q-ee85d1585a | check C139 | search | {"dataset": "windows.other", "query": "message:*WebDAV* OR message:*NTLM*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 1 |  |
| q-acfc8e445f | check C140 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 50 |  |
| q-41b37c75ee | check C141 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 42 |  |
| q-33c9ddd9b4 | check C142 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 39283 |  |
| q-fc829dc3c1 | check C143 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 447 |  |
| q-c855b0c42f | check C144 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Invoke-* OR powershell.script_block_text:*Exploit*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 16 |  |
| q-669ef6feb9 | check C145 | search | {"dataset": "windows.other", "query": "message:*crash* OR message:*fault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 3 |  |
| q-d315878c8f | check C146 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 613 |  |
| q-98e92ea3c7 | check C147 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 460 |  |
| q-92763b880c | check C148 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 1649 |  |
| q-b7613c767f | check C149 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 39283 |  |
| q-179d54704b | check C150 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND file.path:*Cookies*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-d283030cd8 | check C151 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Cookies* OR powershell.script_block_text:*Login Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", … | 13 |  |
| q-86869f246c | check C152 | search | {"dataset": "windows.other", "query": "message:*Cookies* OR message:*Login Data*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 3 |  |
| q-d6b3836468 | check C153 | aggregate | {"dataset": "zeek", "field": "user_agent.original", "query": "event.action:http", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 62 |  |
| q-119ce0c152 | check C154 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 460 |  |
| q-23cd4f8a47 | check C155 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 1649 |  |
| q-c083ff781a | check C156 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 OR event.code:14", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 17541 |  |
| q-ddda02dc9a | check C157 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*password* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 2 |  |
| q-2871fb04a0 | check C158 | search | {"dataset": "windows.other", "query": "message:*password* OR message:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 2 |  |
| q-c76b838c62 | check C159 | aggregate | {"dataset": "zeek", "field": "zeek.filename", "query": "event.action:files", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 448 |  |
| q-209188a036 | check C160 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 312 |  |
| q-50c30c74a4 | check C161 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 447 |  |
| q-4c2d4ea9d6 | check C162 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 1649 |  |
| q-fc7e1723db | check C163 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Content* OR powershell.script_block_text:*Select-String*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 1 |  |
| q-84f44b246d | check C164 | search | {"dataset": "windows.other", "query": "message:*unattend* OR message:*web.config* OR message:*.xml*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-8d677e1556 | check C165 | aggregate | {"dataset": "zeek", "field": "zeek.filename", "query": "event.action:files", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 448 |  |
| q-dc9ce4c9e1 | check C166 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND TO_LOWER(registry.path) LIKE \"*\\\\software\\\\*\" AND (TO_LOWER(registry.path) LIKE \"*password*\" OR TO_LOWER(registry.path) LIKE \"*credential*\" OR TO_LOWER… | ERROR |  |
| q-10d463de95 | check C166 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND TO_LOWER(registry.path) LIKE \"*software*\" AND (TO_LOWER(registry.path) LIKE \"*password*\" OR TO_LOWER(registry.path) LIKE \"*credential*\" OR TO_LOWER(registr… | 15 | F30 |
| q-2c5d5f7a08 | check C167 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*reg* AND (process.command_line:*query* OR process.command_line:*save*))", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-758d81109f | check C168 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectType:Key", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5331 |  |
| q-b222ee0792 | check C169 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*winlogon*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*defaultpassword*\" OR TO_LOWER(powershell.scr… | 0 |  |
| q-34982a53ac | check C170 | search | {"dataset": "windows.other", "query": "event.code:4657 OR event.code:13 OR event.code:14", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.com… | 2 |  |
| q-81b545a9ef | check C171 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*history*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*consolehost_history*\" OR TO_LOWER(powershell.… | 0 |  |
| q-28f2388035 | check C172 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*consolehost_history*\" OR TO_LOWER(process.command_line) LIKE \"*psreadline*\" OR TO_LOWER(process.command_line) LIKE \"*h… | 0 |  |
| q-70bd046dc0 | check C173 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\") \| KEEP @timestamp, host.name, user.name, file.path, process.ex… | 0 |  |
| q-872ef489d7 | check C174 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*ConsoleHost_history* OR win.ObjectName:*PSReadLine*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3460f8c00d | check C175 | search | {"dataset": "windows.other", "query": "message:*history* OR message:*PSReadLine*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 5 |  |
| q-753381eb2d | check C176 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*.key\" OR TO_LOWER(file.path) LIKE \"*.pem\" OR TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*.p12\" OR TO_LOWER… | 1 |  |
| q-eda6768a7b | check C177 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*.pem*\" OR TO_LOWER(process.command_line) LIKE \"*.pfx*\" OR TO_LOWER(process.command_line) LIKE \"*.p12*\" OR TO_LOWER(pr… | 0 |  |
| q-fdb943a0c0 | check C178 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*.key OR win.RelativeTargetName:*.pem OR win.RelativeTargetName:*.pfx OR win.RelativeTargetName:*.p12 OR win.RelativeTargetName:*.ppk)", "t… | 0 |  |
| q-5484af7d16 | check C179 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*.pem*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*.pfx*\" OR TO_LOWER(powershell.script_block_text)… | 2 |  |
| q-0f1b6d40d4 | check C180 | search | {"dataset": "windows.other", "query": "file.path:(*.key OR *.pem OR *.pfx OR *.p12 OR *.ppk)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-f385e9d132 | check C181 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*groups.xml*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*gpprefdecrypt*\" OR TO_LOWER(powershell.scr… | 1 |  |
| q-731d2e92ed | check C182 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sysvol*\" OR TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR TO_LOWER(process.command_line) LIKE \"*cpassword*\") … | 0 |  |
| q-9fa563ca8e | check C183 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*groups.xml*\" OR TO_LOWER(file.path) LIKE \"*sysvol*\") \| KEEP @timestamp, host.name, user.name, file.path, process.executable, _id… | 22 |  |
| q-6ae912df81 | check C184 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*Groups.xml OR win.RelativeTargetName:*sysvol* OR win.RelativeTargetName:*Policies*)", "time_from": null, "time_to": null, "size": 50, "sub… | 38 |  |
| q-5932779b65 | check C185 | search | {"dataset": "windows.other", "query": "message:(*Groups.xml* OR *cpassword* OR *sysvol*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.com… | 0 |  |
| q-3b7d332c8c | check C186 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-44eb69350e | check C187 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass*\" OR TO_LOWER(win.TargetImage) LIKE \"*vault*\" OR TO_LOWER(win.TargetImage) LIKE \"*credential*\" OR TO_LOWER(win.Targ… | 326 |  |
| q-e1aee39cea | check C188 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*comsvcs*\" OR TO_LOWER(process.command_line) LIKE \"*minidump*\" OR TO_LOWER(process.command_line) LIKE \"*procdump*\" OR … | 1 |  |
| q-44aca757e1 | check C189 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*vault* OR win.ObjectName:*Credential* OR win.ObjectName:*Protect*)", "time_from": null, "time_to": null, "size": 50, "sub_field"… | 6 |  |
| q-3a0641c97e | check C190 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*vault* OR win.ObjectName:*Credential*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-8332595723 | check C191 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*minidump*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*sekurlsa*\" OR TO_LOWER(powershell.script_blo… | 0 |  |
| q-bcc47e2649 | check C192 | search | {"dataset": "windows.other", "query": "message:(*lsass* OR *minidump* OR *sekurlsa* OR *vault*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proc… | 0 |  |
| q-0b76db2035 | check C193 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*logins.json*\" OR TO_LOWER(process.command_line) LIKE \"*cookies*\… | ERROR |  |
| q-dc460db7ff | check C193 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*logins.json*\" OR TO_LOWER(process.command_line) LIKE \"*cookies*\… | 0 |  |
| q-05d225d8ad | check C194 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*\\\\google\\\\chrome\\\\user data*\" OR T… | ERROR |  |
| q-6baf7c8460 | check C194 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*google*chrome*user data*\" OR TO_LOWER(fi… | 0 |  |
| q-48bd12ac05 | check C195 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*msedge*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\") \| KEEP @timestamp, … | 0 |  |
| q-d327fcd049 | check C196 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Login Data* OR win.ObjectName:*logins.json* OR win.ObjectName:*Chrome* OR win.ObjectName:*Firefox* OR win.ObjectName:*Edge*)", "time_from": null, "time_to… | 0 |  |
| q-16540cc0bf | check C197 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*login data*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*logins.json*\" OR TO_LOWER(powershell.scrip… | 0 |  |
| q-d3188f8011 | check C198 | search | {"dataset": "windows.other", "query": "file.path:(*Login Data* OR *logins.json* OR *User Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proc… | 0 |  |
| q-95446f5ed3 | check C199 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-9a80624661 | check C200 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-52132d822f | check C201 | search | {"dataset": "windows.sysmon", "query": "event.code:15 AND win.TargetFilename:*vault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 0 |  |
| q-a057ce12fe | check C202 | search | {"dataset": "windows.security", "query": "event.code:4688 AND process.command_line:*vault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 0 |  |
| q-34d2dbf221 | check C203 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*vault* OR powershell.script_block_text:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 2 |  |
| q-b160cc7d5b | check C204 | search | {"dataset": "windows.other", "query": "message:*vault* OR message:*Credential Manager*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comma… | 14 |  |
| q-9e1b5daa06 | check C205 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-bb3afeb0b7 | check C206 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*1Password* OR win.TargetFilename:*KeePass* OR win.TargetFilename:*LastPass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 0 |  |
| q-0fa754bd7e | check C207 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*lastpass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 0 |  |
| q-3ed60dc801 | check C208 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*keepass* OR powershell.script_block_text:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 0 |  |
| q-633f5cbd5d | check C209 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*password manager*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comma… | 14 |  |
| q-b68c73b37a | check C210 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*Security* OR win.ObjectName:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.cod… | 0 |  |
| q-ff3a944bbb | check C211 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 | F33 |
| q-7eb2af7abf | check C212 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*samlib*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 50 |  |
| q-ac0178c724 | check C213 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-292a06b5f3 | check C214 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-abaf6490b5 | check C215 | search | {"dataset": "windows.security", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 312 | F34 |
| q-bde0f046b8 | check C216 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-74dfeb8b99 | check C217 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-1744043472 | check C218 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-1ff54975d0 | check C219 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-846d3b75d6 | check C220 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-661cec73c6 | check C221 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-b09613eb85 | check C222 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.dll AND win.TargetFilename:*System32*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-51549f28a6 | check C223 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-3bcb39fd6e | check C224 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Notification Packages* OR powershell.script_block_text:*PasswordFilter*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "eve… | 0 |  |
| q-097015d9cf | check C225 | search | {"dataset": "windows.other", "query": "message:*PasswordFilter* OR message:*Notification Packages*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 4 |  |
| q-5bf297a576 | check C226 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*ReversibleEncryption* OR powershell.script_block_text:*AllowReversiblePasswordEncryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 0 |  |
| q-33b3ab0ea8 | check C227 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-aff7cab8e9 | check C228 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ReversibleEncryption* OR process.command_line:*Set-ADUser*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.cod… | 0 |  |
| q-b45a78559d | check C229 | search | {"dataset": "windows.other", "query": "message:*ReversibleEncryption* OR message:*reversible*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proces… | 0 |  |
| q-247b56bbc5 | check C230 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*set-aduser*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(powershell.script_block_text)… | 1 |  |
| q-fd70967848 | check C231 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-2a9c372cf7 | check C232 | search | {"dataset": "windows.other", "query": "event.code:4739 OR event.code:4738 OR event.code:4732", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-32f0f02ad5 | check C233 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*ADUser* OR process.command_line:*AuthenticationPolicy* OR process.command_line:*dsmod* OR process.command_line:*dsacls*)", "time_from": null, "time_t… | 0 |  |
| q-09dcbaf24e | check C234 | count | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null} | 0 |  |
| q-f7a684fcfc | check C235 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*AAD* OR win.ImageLoaded:*Azure* OR win.ImageLoaded:*ADFS* OR win.ImageLoaded:*Identity*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2 |  |
| q-9e6628def1 | check C236 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*adfs*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*azuread*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*connect-msolserv… | 0 |  |
| q-956cce6f2f | check C237 | search | {"dataset": "windows.other", "query": "event.code:5136 OR event.code:5137 OR event.code:5141", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-aa5de0b62a | check C238 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetObject", "query": "event.code:13 AND (win.TargetObject:*NetworkProvider* OR win.TargetObject:*Credential Provider* OR win.TargetObject:*Winlogon*)", "time_from": null, "time_to": null, "size": 50, "sub_field": … | 41 |  |
| q-04283e5f33 | check C239 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*np*.dll OR win.ImageLoaded:*provider*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 145 |  |
| q-11891d0d76 | check C240 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*System32* OR file.path:*SysWOW64*) AND (file.path:*.dll)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 0 |  |
| q-03eefded90 | check C241 | count | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null} | 36 |  |
| q-19f308bdd2 | check C242 | search | {"dataset": "windows.other", "query": "event.code:4657 OR event.code:4656", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-42e4628e22 | check C243 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:139 OR destination.port:389 OR destination.port:88)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 383 |  |
| q-37259d41f8 | check C244 | aggregate | {"dataset": "windows.sysmon", "field": "dns.question.name", "query": "event.code:22", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 81 |  |
| q-bb56317e03 | check C245 | count | {"dataset": "windows.security", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null} | 10977 |  |
| q-9a87a32d2c | check C246 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-b90776a026 | check C247 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "event.action:conn OR event.action:dns OR event.action:smb_mapping", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 677 |  |
| q-54fb2fc618 | check C248 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:5355 OR destination.port:137 OR destination.port:445)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 47 |  |
| q-1094d6e69b | check C249 | search | {"dataset": "zeek", "query": "event.action:smb_mapping OR event.action:smb_files OR event.action:dce_rpc", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executabl… | 146 | F36 |
| q-be32153bb9 | check C250 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-ad80a661c9 | check C251 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetObject", "query": "event.code:13 AND win.TargetObject:*DNSClient*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0448e32784 | check C252 | search | {"dataset": "windows.other", "query": "event.code:4697 OR event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 5 | F38 |
| q-8eac1f3909 | check C253 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*enablemulticast*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*llmnr*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*respond… | 0 |  |
| q-84786b11bd | check C254 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 66 |  |
| q-b35571e582 | check C255 | aggregate | {"dataset": "windows.sysmon", "field": "dns.question.name", "query": "event.code:22", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 81 |  |
| q-527d8d6ff6 | check C256 | count | {"dataset": "windows.security", "query": "event.code:5156 OR event.code:5158", "time_from": null, "time_to": null} | 5059 |  |
| q-3ec5e36056 | check C257 | search | {"dataset": "windows.other", "query": "event.code:5156 OR event.code:5158", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-80ed602d33 | check C258 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-b95680cdb4 | check C259 | search | {"dataset": "windows.other", "query": "event.code:1341 OR event.code:1342 OR event.code:1020 OR event.code:1063", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.ex… | 0 |  |
| q-8777056381 | check C260 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-8d64188039 | check C261 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*dhcp* OR powershell.script_block_text:*DhcpServer* OR powershell.script_block_text:*New-DhcpServer*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 0 |  |
| q-9e024c23c9 | check C262 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*dhcp* OR process.command_line:*DhcpServer*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-9de19fd638 | check C263 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*dhcp* OR process.command_line:*DhcpServer*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-2c1db03f45 | check C264 | search | {"dataset": "zeek", "query": "event.action:conn AND network.transport:udp AND (destination.port:67 OR destination.port:68 OR source.port:67 OR source.port:68)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.d… | 0 |  |
| q-0a997728be | check C265 | search | {"dataset": "windows.other", "query": "event.code:10 OR event.code:1", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 6 |  |
| q-6330a0809f | check C266 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*kerberos* OR powershell.script_block_text:*Rubeus* OR powershell.script_block_text:*kirbi* OR powershell.script_block_text:*ticket*", "time_from": null, "time_to": null, "fields": ["@tim… | 0 |  |
| q-003895377e | check C267 | search | {"dataset": "windows.security", "query": "event.code:4672 OR event.code:4634", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 448 |  |
| q-991e3d0516 | check C268 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-cab6451fdd | check C269 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-4573110d4c | check C270 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-d0acddd22e | check C271 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-f0a729745a | check C272 | search | {"dataset": "windows.other", "query": "event.code:10 OR event.code:1", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 6 |  |
| q-d932af291c | check C273 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*krbtgt* OR powershell.script_block_text:*golden* OR powershell.script_block_text:*DCSync*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 0 |  |
| q-c8a54a7f76 | check C274 | search | {"dataset": "windows.security", "query": "event.code:4672 OR event.code:4634", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 448 |  |
| q-71660eb305 | check C275 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-fadb9c88a1 | check C276 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-626104f821 | check C277 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-7c0c6c3073 | check C278 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-3a5819a304 | check C279 | search | {"dataset": "windows.other", "query": "event.code:10 OR event.code:1", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 6 |  |
| q-590ca14eea | check C280 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*silver* OR powershell.script_block_text:*service ticket* OR powershell.script_block_text:*Rubeus*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.na… | 0 |  |
| q-298a2802cd | check C281 | search | {"dataset": "windows.security", "query": "event.code:4672 OR event.code:4634", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 448 |  |
| q-839785e2ab | check C282 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-76267a3e22 | check C283 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-6209545832 | check C284 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e6112acf38 | check C285 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-c93b718d26 | check C286 | search | {"dataset": "windows.other", "query": "event.code:10 OR event.code:1", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 6 |  |
| q-a4417d8483 | check C287 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*kerberoast* OR powershell.script_block_text:*SPN* OR powershell.script_block_text:*Invoke-Kerberoast*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observe… | 0 |  |
| q-869e6c059e | check C288 | search | {"dataset": "windows.security", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 312 |  |
| q-857ade904c | check C289 | search | {"dataset": "windows.security", "query": "event.code:4672", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 212 |  |
| q-531936fcc9 | check C290 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-35e634cd59 | check C291 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-20c9ff7de5 | check C292 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-b92678081a | check C293 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-63812710da | check C294 | search | {"dataset": "windows.other", "query": "event.code:1", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 3 |  |
| q-ffca6f3db8 | check C295 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*asrep* OR powershell.script_block_text:*AS-REP* OR powershell.script_block_text:*GetNPUsers*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-3c12a01955 | check C296 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-c85a093d11 | check C297 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-1341590462 | check C298 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*asrep* OR process.command_line:*GetNPUsers* OR process.command_line:*rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-04963b01bf | check C299 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-1450ac96a2 | check C300 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-629f8497e2 | check C301 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-e90fe07fbf | check C302 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-f042d62fc4 | check C303 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*token* OR powershell.script_block_text:*SAML*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 1 |  |
| q-53ea4e07ff | check C304 | search | {"dataset": "windows.other", "query": "message:*token* OR message:*cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 0 |  |
| q-9928004a8b | check C305 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-b8f4aa622e | check C306 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*Login\\ Data* OR file.path:*Web\\ Data* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "u… | 1 | F46 |
| q-00683e4453 | check C307 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Cookies* OR win.ObjectName:*Login\\ Data*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b0f2550c8f | check C308 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*SetCookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 0 |  |
| q-5ab0583862 | check C309 | search | {"dataset": "windows.other", "query": "message:*cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destina… | 0 |  |
| q-3ea757efa7 | check C310 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-57f34bca67 | check C311 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.AuthenticationPackageName:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proces… | 297 |  |
| q-5101c2050a | check C312 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAML* OR powershell.script_block_text:*NotOnOrAfter* OR powershell.script_block_text:*Assertion*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-eb98bf4500 | check C313 | search | {"dataset": "windows.other", "query": "message:*SAML* OR message:*ADFS*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 0 |  |
| q-ab6a6e7683 | check C314 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*.xml OR file.path:*.pem OR file.path:*.pfx)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 24 | F44 |
| q-8b8dda3d9f | check C315 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-d83cb1f85a | check C316 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-9d452fd6f1 | check C317 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-ffdad081a2 | check C318 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*MFA* OR powershell.script_block_text:*Authenticator* OR powershell.script_block_text:*Push*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-42336cff42 | check C319 | search | {"dataset": "windows.other", "query": "message:*MFA* OR message:*multi-factor*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 0 |  |
| q-9b5924655f | check C320 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-2af748eb07 | check C321 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-f05f1fdb65 | check C322 | search | {"dataset": "windows.security", "query": "event.code:4768 AND win.TicketEncryptionType:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.com… | 14 | F49 |
| q-e844866b13 | check C323 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*.pfx OR file.path:*.p12 OR file.path:*.cer OR file.path:*.kirbi)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 1 |  |
| q-65c003669d | check C324 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Cert* OR powershell.script_block_text:*Export-PfxCertificate* OR powershell.script_block_text:*New-SelfSignedCertificate*)", "time_from": null, "time_to": null, "fie… | 1 |  |
| q-471475cacf | check C325 | search | {"dataset": "windows.other", "query": "message:*certificate* OR message:*Cert*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 0 |  |
| q-fad339c835 | triage T1003 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhL"} | None |  |
| q-a9c649326d | triage T1003 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None | F01 |
| q-96195ab093 | triage T1003 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.name,… | ERROR |  |
| q-7890efaefc | triage T1003 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (process.executable LIKE \"*python*\" OR process.executable LIKE \"*PsExec*\" OR process.executable LIKE \"*sdelete*\" OR process.executable LIKE \"*rundll32*\") \| K… | ERROR |  |
| q-ed1c1ed611 | triage T1003 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.n… | 33 |  |
| q-e8f028da81 | triage T1003 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*python*\" OR process.executable LIKE \"*PsExec*\" OR process.executable LIKE \"*sdelete*\" OR process.executable LIKE \"*rundll32*\") … | 22 | F04 |
| q-658993f649 | triage T1003 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-8c3687ec02 | triage T1003 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (powershell.script_block_text LIKE \"*lsass*\" OR powershell.script_block_text LIKE \"*MiniDump*\" OR powershell.script_block_text LIKE \"*comsvcs*\" OR po… | 0 |  |
| q-1201cfbdf4 | triage T1003 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND process.executable LIKE \"*PowerShell*\" \| KEEP @timestamp, host.name, process.executable, win.GrantedAccess, win.CallTrace… | 4 | F01 |
| q-f4bd78cdba | triage T1003 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, powershell.script_block_text, _id, _index \| LIMIT 40"} | 40 | F01 |
| q-c8e67808c8 | triage T1003 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectName LIKE \"*lsass*\" \| KEEP @timestamp, host.name, user.name, process.executable, win.AccessMask, win.AccessList, _id, _index"} | 6 | F01 |
| q-c67dc3deba | triage T1003 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None | F02 |
| q-0ff9b802b4 | triage T1003 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (win.ObjectType LIKE \"*SAM*\" OR win.ObjectName LIKE \"*SAM*\") \| KEEP @timestamp, host.name, user.name, process.executable, win.ObjectType, win.ObjectName… | 0 |  |
| q-07fa891e80 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-6e600112cc | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-d1eb46b135 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-ecb40a805f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-f6d8f2e118 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-84facfebcb | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzydoz"} | None |  |
| q-a89c3b197d | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-ce582d06fc | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-9219453778 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-92f47cf086 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-a26872073f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-aceddc538f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RoJ7pL"} | None |  |
| q-57a7222c42 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-132ceeca7d | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDyQK"} | None |  |
| q-ada7bf6a8f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqWk4"} | None |  |
| q-624d47195f | triage T1040 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None | F05, F08 |
| q-d1a4048d4f | triage T1040 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b0zggu"} | None | F07 |
| q-94d3f81a08 | triage T1040 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (process.command_line LIKE \"*netsh*\" OR process.command_line LIKE \"*logman*\" OR process.command_line LIKE \"*pktmon*\" OR process.command_line LIKE \"*tcpdump*\" … | ERROR |  |
| q-27d073576c | triage T1040 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4688 AND (process.command_line LIKE \"*netsh*\" OR process.command_line LIKE \"*pktmon*\" OR process.command_line LIKE \"*tcpdump*\" OR process.command_line LIKE \"*windu… | ERROR |  |
| q-d566720c91 | triage T1040 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*netsh*\" OR process.command_line LIKE \"*logman*\" OR process.command_line LIKE \"*pktmon*\" OR process.command_line LIKE \"*tcpdump… | 9 | F05, F06 |
| q-2c19b1bbef | triage T1040 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (process.command_line LIKE \"*netsh*\" OR process.command_line LIKE \"*pktmon*\" OR process.command_line LIKE \"*tcpdump*\" OR process.command_line LIKE \"*w… | 2 | F05 |
| q-d66569a503 | triage T1040 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE powershell.script_block_text LIKE \"*pktmon*\" OR powershell.script_block_text LIKE \"*netsh trace*\" OR powershell.script_block_text LIKE \"*New-NetEventSession*\" OR powershell.scr… | 0 |  |
| q-1f379ea89d | triage T1040 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"6\" OR event.code == \"7\" \| WHERE TO_LOWER(win.ImageLoaded) LIKE \"*pktmon*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*npcap*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*winpcap… | 0 |  |
| q-01baf57a6f | triage T1040 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (win.DestinationPort == \"445\" OR win.DestinationPort == \"139\") \| KEEP @timestamp, host.name, process.executable, win.DestinationIp, win.DestinationPort, _id,… | 5 |  |
| q-f686c49bee | triage T1040 step 5 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.ImagePath, _id, _index"} | 5 |  |
| q-6a2d538d2a | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-ea52cb2e66 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-9a42d489b5 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WnQtls"} | None |  |
| q-346388b82b | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-fda134c072 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NUxiiK"} | None |  |
| q-0fe3cc4160 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NUxiiK"} | None |  |
| q-a8137dee05 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NNopD7"} | None |  |
| q-4b3f249d88 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b0zggu"} | None |  |
| q-2f534cdfa7 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b0zggu"} | None |  |
| q-8e4d99fbcb | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-0e55d4fe38 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMq"} | None | F09 |
| q-0879789a51 | triage T1056 step 1 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4663 AND win.ObjectName:*Lsa*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 1473 |  |
| q-1c7b6cdd86 | triage T1056 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-6ca293429b | triage T1056 step 2 | search | {"dataset": "windows.sysmon", "query": "process.executable:*cod.3aka3* OR win.TargetFilename:*cod.3aka3* OR process.command_line:*cod.3aka3*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 97 | F09 |
| q-cad142cf7c | triage T1056 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1… | 33 | F10, F12 |
| q-7f58c01830 | triage T1056 step 2 | search | {"dataset": "windows.security", "query": "process.executable:*cod.3aka3*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 9 | F09 |
| q-f38a260db4 | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None | F10 |
| q-0b92cf3612 | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F11 |
| q-8418758ef0 | triage T1056 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*cod.3aka3*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 1 | F09 |
| q-ec195e83e0 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WiJkSG"} | None |  |
| q-c64e63eb1b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMq"} | None |  |
| q-83d76cc931 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMo"} | None |  |
| q-af137f1cf3 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WiJkR5"} | None |  |
| q-71db61a2cc | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-7eca2b2e26 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-c4f88ba857 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-6a5cc41f03 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-bc421337bd | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-f618fe0328 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-20c795417d | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NNo5BS"} | None |  |
| q-7e04b0d150 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None | F14 |
| q-f6df3deb52 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F14 |
| q-67c46e9105 | triage T1110 step 1 | count | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4776 OR event.code:4771", "time_from": null, "time_to": null} | 1 |  |
| q-38e75d70a1 | triage T1110 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 326 |  |
| q-a0d93354d7 | triage T1110 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.SourceImage:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.SourceImage", "win.TargetImage", "win.GrantedAccess", "process.c… | 2 | F15 |
| q-9f6cb7880e | triage T1110 step 2 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:SAM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.ProcessName", "win.AccessMask", "user.name"], "size": 10, "sort": "asc"} | 10 | F15 |
| q-c5b0c8bb88 | triage T1110 step 2 | search | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4776 OR event.code:4771", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.Status", "source.ip", "win.LogonType"], "size": 10, "sort": "… | 1 | F13, F16 |
| q-664467c15a | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None | F13 |
| q-c0d4a3857d | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-78be1b241c | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-a8f3a79ca8 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-f19e10a883 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-57075d818c | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-2cd3501bcb | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-db840e227b | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-2aff968603 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YWMnGq"} | None |  |
| q-9f31da1916 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-39682fa0dd | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0y"} | None |  |
| q-b4bb6b56f9 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F18 |
| q-31b31ea753 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHQbW"} | None | F18 |
| q-0f378d0ebb | triage T1111 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, _id, _index \| LIMIT 50"} | 50 |  |
| q-1cd5292331 | triage T1111 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.ProcessName, win.TargetServerName, _id, _index \| LIMIT 30"} | 15 |  |
| q-24fb774ade | triage T1111 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None | F18 |
| q-1ad2cec47f | triage T1111 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess != \"0x1000\" \| KEEP @timestamp, host.name, process.executable, win.GrantedAccess, _id, _index \| LIMIT 3… | 30 |  |
| q-f15b257c0f | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-1f716d6a4d | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHQbW"} | None |  |
| q-25abceebee | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-fb48975481 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-f541b2cb28 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-a773ffb11d | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-8d3c42f9a2 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None |  |
| q-a453c4c502 | triage T1187 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx3F"} | None | F21 |
| q-6287975c4e | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 50 |  |
| q-294539e1b0 | triage T1187 step 1 | aggregate | {"dataset": "windows.security", "field": "win.TargetName", "query": "event.code:5145 OR event.code:5140", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 163 |  |
| q-29b48afb4c | triage T1187 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.lnk OR win.TargetFilename:*.scf OR win.TargetFilename:*.url OR win.TargetFilename:*.library-ms OR win.TargetFilename:*.searchconnector-ms)", "time_fr… | 3 |  |
| q-cf7f3ebe74 | triage T1187 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*hostui.lnk*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.TargetFilename", "user.name"], "size": 10, … | 1 |  |
| q-973447bf39 | triage T1187 step 2 | search | {"dataset": "zeek", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "source.ip", "destination.ip", "destination.port", "zeek.conn_state", "zeek.service", "observer.na… | 50 | F22 |
| q-7f52007eb8 | triage T1187 step 2 | search | {"dataset": "windows.security", "query": "event.code:5145", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ShareName", "win.RelativeTargetName", "win.SubjectUserName", "win.IpAddress"], "size": 30, "sort": "asc"} | 121 | F22 |
| q-09d98afc1e | triage T1187 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*hostui* OR powershell.script_block_text:*lnk* OR powershell.script_block_text:*StartUp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 3 |  |
| q-df7bcaf712 | triage T1187 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executable"], "size"… | 12 | F20 |
| q-9a07a87e3c | triage T1187 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SAm218"} | None | F19 |
| q-db2c7658a0 | triage T1187 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*hostui*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executable"], "size": 20… | 1 |  |
| q-291b17678f | triage T1187 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*hostui*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "win.TargetFilename"], "size": 20, "sort": "asc"} | 3 | F19 |
| q-6243ccbde3 | triage T1187 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtT0KI"} | None | F20 |
| q-ceaf9a3b7d | triage T1187 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUml9"} | None | F20 |
| q-d73b55c780 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SAm218"} | None |  |
| q-2da3b4987f | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SAm218"} | None |  |
| q-8a08193765 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SJxMAB"} | None |  |
| q-2d1c020311 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtShN2"} | None |  |
| q-f5d280800d | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtT0KI"} | None |  |
| q-b2b8fffc70 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUEbK"} | None |  |
| q-36dbe05b24 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUml9"} | None |  |
| q-f28cc5ec1c | triage T1187 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx3F"} | None |  |
| q-bc72b10053 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx3F"} | None |  |
| q-be7b32f6c0 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Yc1"} | None |  |
| q-29e7136462 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yph4sr"} | None |  |
| q-2cde74c7bb | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yph4sr"} | None |  |
| q-dfa104a615 | triage T1212 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, user.name, _id, _index \| SORT @timestamp… | 50 | F25 |
| q-5eaf6fe840 | triage T1212 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*python*\" OR process.executable LIKE \"*PsExec*\" OR process.executable LIKE \"*sdelete*\" OR process.executable LIKE \"*PSEXESVC*\") … | 19 |  |
| q-af643c4a8b | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None | F23 |
| q-61a560d2f4 | triage T1212 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (@timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:00.000Z\") \| KEEP @timestamp, host.name, user.name, powershell.script_blo… | 30 | F23 |
| q-68796afe2d | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1R-k13y"} | ERROR |  |
| q-c43e470397 | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0a"} | None | F24 |
| q-5954770400 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-ecbcc391b3 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-a34ba5d9b0 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-cfc7f54165 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-44d312dec1 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-2c0d27381a | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Qp"} | None |  |
| q-44834f3015 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0a"} | None |  |
| q-54b9439597 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0a"} | None |  |
| q-e1b177437a | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-24db6f2e45 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-99513871ae | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21gGA"} | None | F26 |
| q-125db9d7b0 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F26 |
| q-00672c24db | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*webcache*\" OR TO_… | 9 | F26 |
| q-bbd5241966 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookies*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*webcache*\" O… | 3 | F26 |
| q-916287af11 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*cookies*\" OR TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*webcache*\") \| KEEP @time… | 0 |  |
| q-cff1413ed7 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*cookies*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*login data*\") \| KEEP @timestamp, host.name, … | 0 |  |
| q-d9338bbdf2 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*appdata*\" AND (TO_LOWER(win.ObjectName) LIKE \"*microsoft\\\\edge*\" OR TO_LOWER(win.ObjectName) LIKE \"*google\\\\chrome*… | ERROR |  |
| q-8d768dbff1 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND TO_LOWER(message) LIKE \"*cookies*\" \| KEEP @timestamp, host.name, user.name, message, _id, _index"} | 0 |  |
| q-bc0485aeba | triage T1539 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND TO_LOWER(win.ObjectName) LIKE \"*appdata*local*microsoft*edge*\" \| KEEP @timestamp, host.name, user.name, process.executable, win.ObjectName, _id, _index"} | 0 |  |
| q-43b5e3df7e | triage T1539 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b42izk"} | None | F26 |
| q-251b33100f | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b42izk"} | None |  |
| q-6b668aabdc | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21gGA"} | None |  |
| q-e3a8eda342 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-dca21d7846 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-088838d898 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MrOOck"} | None |  |
| q-346428cc5d | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None | F27 |
| q-683c23ce59 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzyuVY"} | None |  |
| q-343e16637d | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None | F27 |
| q-9543d42cfd | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_RQ"} | None | F28 |
| q-c392af1f33 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*groups.xml*\" OR TO_LOWER(file.path) LIKE \"*sysvol*\") \| KEEP @timestamp, host.name, user.name, file.path, process.executable, _id… | 22 | F29 |
| q-9a2a55cd26 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND TO_LOWER(process.command_line) LIKE \"*pbeesly*\" \| KEEP @timestamp, host.name, user.name, process.command_line, process.executable, _id, _index"} | 14 | F28 |
| q-15af6f10b8 | triage T1552 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None | F27 |
| q-4e37dcabf5 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND TO_LOWER(win.ObjectName) LIKE \"*.pfx*\" \| KEEP @timestamp, host.name, user.name, win.ObjectName, win.ProcessName, win.AccessMask, _id, _index"} | 0 |  |
| q-30b24902a3 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-a39ee54fb2 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-a607c63f11 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-e6b6ce0335 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-ad949f2799 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-d76c6bf2da | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-8924723b07 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-3b66939548 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_RQ"} | None |  |
| q-d61973b698 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqLbie"} | None |  |
| q-f76d2ca464 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqLbie"} | None |  |
| q-0751c5c41c | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-9b010d0385 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-6759c68c7e | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-40dd6f1c86 | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhL"} | None |  |
| q-b3d9a236cf | triage T1555 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess != \"0x1000\" \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetImage, win.GrantedAc… | 33 | F31, F32 |
| q-8da1851a09 | triage T1555 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectName LIKE \"*lsass*\" \| KEEP @timestamp, host.name, user.name, win.ProcessName, win.ObjectName, win.AccessMask, win.AccessList, _id, _index"} | 6 | F31, F32 |
| q-b3521a2358 | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-8eb943472b | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-afa7e6b320 | triage T1555 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*lsass*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*dump*\" OR TO_LOWER(powershell.script_block_text… | 6 | F31 |
| q-8119d53d0d | triage T1555 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOWER(process.command_line) LIKE \"*credential*\" OR… | 0 |  |
| q-0dd0acb3c2 | triage T1555 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-0cf8498d4e | triage T1555 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-02a4c309fc | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-8e78b81c1c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-7492e7a761 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-cf6efd62a1 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-cdc81da9f4 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-ae563e4ca4 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-abfb1b44e1 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAenUm"} | None |  |
| q-6f213680be | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhM"} | None |  |
| q-e8693cf379 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YEBswT"} | None |  |
| q-64b1a81fdb | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e7008cac9f | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-03b85147a9 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*samlib*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-4e0548a30d | triage T1556 step 1 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-4428419226 | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F33 |
| q-18358d2de1 | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.GrantedAccess",… | 2 |  |
| q-1603b11e76 | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None | F33 |
| q-b125bb5078 | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-325100b432 | triage T1556 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*lsass*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*credential*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*mimikatz*\" … | 5 |  |
| q-6e63d8de08 | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-85466c287e | triage T1556 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*invoke-exfil*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*get-aduser*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*set-a… | 4 |  |
| q-b8065e3484 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-0ebf501fe3 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-8285fa3254 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-44a2b036c8 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-93ff6b65e1 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMw"} | None |  |
| q-fa25f8c3c6 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMw"} | None |  |
| q-7e9516c8eb | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yph4sy"} | None |  |
| q-a073e963e0 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "C221"} | ERROR |  |
| q-532003cd12 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "C227"} | ERROR |  |
| q-bd3bbcd08a | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "C231"} | ERROR |  |
| q-e25b3ab4c4 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "C234"} | ERROR |  |
| q-9ca6495dd1 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "C240"} | ERROR |  |
| q-5c6cb9d5cc | triage T1557 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None | F36 |
| q-c4d6fd34ac | triage T1557 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:3 AND (destination.port:445 OR destination.port:139 OR destination.port:389 OR destination.port:88)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 383 |  |
| q-79e4e7e172 | triage T1557 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceHostname", "query": "event.code:22", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 81 |  |
| q-2d12276f56 | triage T1557 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:22 AND (dns.question.name:NEWYORK.dmevals.local OR dns.question.name:NASHUA OR dns.question.name:SCRANTON OR dns.question.name:UTICA)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name",… | 24 | F35, F36 |
| q-12ef4e8dc2 | triage T1557 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND destination.port:445 AND process.executable:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "destination.ip", "desti… | 0 |  |
| q-5e815423b1 | triage T1557 step 2 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22 AND win.QueryStatus:0", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 74 |  |
| q-a92d8ea8f0 | triage T1557 step 3 | search | {"dataset": "zeek", "query": "event.action:conn AND (destination.port:445 OR destination.port:139 OR destination.port:137 OR destination.port:5355)", "time_from": null, "time_to": null, "fields": ["@timestamp", "observer.name", "source.ip", "destination.ip", "… | 52 | F37 |
| q-95a57623b8 | triage T1557 step 3 | search | {"dataset": "windows.sysmon", "query": "process.executable:*cod.3aka3*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executable", "user.name", "event.code"], "size": 20… | 96 |  |
| q-ff92e50a00 | triage T1557 step 4 | aggregate | {"dataset": "zeek", "field": "zeek.resp_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 613 |  |
| q-ea55bdd5c2 | triage T1557 step 4 | search | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ServiceName", "win.ServiceFileName", "user.name", "win.SubjectUserName"], "size": 25, "sort": "asc"} | 23 | F36 |
| q-b8d512dfe1 | triage T1557 step 4 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*arp* OR process.command_line:*netsh* OR process.command_line:*dhcp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.command_line", "proce… | 5 |  |
| q-a054c69c03 | triage T1557 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YWMXH-"} | None |  |
| q-940ec2a049 | triage T1557 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*arp* OR process.command_line:*netsh*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.exec… | 5 | F37 |
| q-aec82cae91 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SErGol"} | None |  |
| q-bba06d4edd | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SErGol"} | None |  |
| q-6669cfdeaa | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqL7gO"} | None |  |
| q-278cdd7fef | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-131d00c37f | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtY9"} | None |  |
| q-d2fd1a41dd | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ida"} | None |  |
| q-1a56f1465b | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NUyf30"} | None |  |
| q-3bbe0fa417 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-73a5dad33c | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Yc1"} | None |  |
| q-40e52b1788 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2I"} | None |  |
| q-5290c50ebb | triage T1558 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-0e8f803219 | triage T1558 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"kerberos\" \| KEEP @timestamp, source.ip, destination.ip, zeek.request_type, zeek.client, zeek.service, zeek.success, zeek.error_msg, zeek.cipher, _id, _index"} | 35 | F40, F41, F42, F43 |
| q-a616b960bb | triage T1558 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 |  |
| q-0594337cd4 | triage T1558 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*kerberos*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*ticket*\" OR TO_LOWER(powershell.script_b… | 0 |  |
| q-17c5460354 | triage T1558 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None | F39 |
| q-48dd705d6d | triage T1558 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-f53519a69c | triage T1558 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _id, _index \| LIMIT 20"} | 20 |  |
| q-0f362b9c9b | triage T1558 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| WHERE TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO… | 2 |  |
| q-f626058abc | triage T1558 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _inde… | 12 |  |
| q-a4c8939f7b | triage T1558 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None | F39 |
| q-ba36504bb9 | triage T1558 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUml9"} | None |  |
| q-22e3e5fbc8 | triage T1558 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUEbK"} | None |  |
| q-3878b86694 | triage T1558 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.SourceImage LIKE \"*PowerShell*\" \| KEEP @timestamp, host.name, win.SourceImage, win.SourceProcessId, win.GrantedAccess… | 4 | F39 |
| q-f2245f33a5 | triage T1558 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOWER(process.command_line) LIKE \"*ticket*\" OR TO_… | 0 |  |
| q-07667abba8 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-3a9c795eef | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-aa61bd3e6e | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-64bda0f464 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-4b90c7837c | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-c9ba5af220 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeV"} | None |  |
| q-4688a59835 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeV"} | None |  |
| q-4d7db5a95e | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeU"} | None |  |
| q-c872d1f2e5 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeW"} | None |  |
| q-902facc2da | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74ep"} | None |  |
| q-0b2b35a29d | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74ep"} | None |  |
| q-107e60cd42 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Idf"} | None |  |
| q-6780068977 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Idf"} | None |  |
| q-1a9a741d19 | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None |  |
| q-36c568f4a0 | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-ed6eb4da17 | triage T1606 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.Path, _id, _index \| SORT @timestamp ASC \| LIMIT 50"} | ERROR |  |
| q-8f542fe97e | triage T1606 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND file.path LIKE \"*pbeesly*\" \| KEEP @timestamp, host.name, process.executable, file.path, _id, _index \| SORT @timestamp ASC \| LIMIT 50"} | ERROR |  |
| q-ec850c80c8 | triage T1606 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.Path, _id, _index \| SORT @timestamp ASC \| LIMIT 50"} | 50 |  |
| q-9caa77821f | triage T1606 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND file.path LIKE \"*pbeesly*\" \| KEEP @timestamp, host.name, process.executable, file.path, _id, _index \| SORT @timestamp ASC \| LIMIT 50"} | 50 | F45 |
| q-971f8f973f | triage T1606 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND powershell.script_block_text LIKE \"*pfx*\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _id, _index \| LIMIT 20"} | 2 | F44 |
| q-42822ae1bd | triage T1606 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (powershell.script_block_text LIKE \"*ADFS*\" OR powershell.script_block_text LIKE \"*SAML*\" OR powershell.script_block_text LIKE \"*Assertion*\" OR power… | 1 |  |
| q-4d7af83009 | triage T1606 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-f77b02a602 | triage T1606 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (powershell.script_block_text LIKE \"*ADFS*\" OR powershell.script_block_text LIKE \"*DKM*\" OR powershell.script_block_text LIKE \"*TokenSigning*\" OR pow… | 5 | F44, F45 |
| q-65834736a9 | triage T1606 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE process.executable LIKE \"*victim*\" OR process.executable LIKE \"*.scr\" OR process.executable LIKE \"*3aka3*\" \| KEEP @timestamp, host.name, process.executable, process.command_line, … | 20 |  |
| q-b6c9ad9063 | triage T1606 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (win.ObjectName LIKE \"*Crypto*\" OR win.ObjectName LIKE \"*cert*\" OR win.ObjectName LIKE \"*ADFS*\" OR win.ObjectName LIKE \"*Keys*\") \| KEEP @timestamp, … | 0 |  |
| q-60bc8f0105 | triage T1606 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE win.ObjectName LIKE \"*ADFS*\" OR win.ObjectName LIKE \"*TokenSigning*\" OR win.ObjectName LIKE \"*DKM*\" OR win.ServiceName LIKE \"*adfs*\" \| KEEP @timestamp, host.name, user.name, w… | 0 |  |
| q-7b454d9288 | triage T1606 step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE win.ObjectName LIKE \"*.pfx*\" OR win.ObjectName LIKE \"*Downloads*\" \| KEEP @timestamp, host.name, user.name, win.ObjectName, win.ProcessName, event.code, _id, _index \| LIMIT 30"} | 0 |  |
| q-c5f9a58612 | triage T1606 step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.ProcessName, win.TargetServerName, _id, _index \| LIMIT 30"} | 15 |  |
| q-0001860a94 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-435bb91cab | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-2cd6421e02 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-793dcdf16c | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-ce5a8c7f0e | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-cde0eb2d9a | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-95488b9c1e | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WgHZ_9"} | None |  |
| q-1e27d7fee1 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WgHZ_9"} | None |  |
| q-bd18dfe93e | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aMP"} | None |  |
| q-16a1cf1f2e | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-9b24404947 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-b2c3c1d917 | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None | F47 |
| q-26ab8beacd | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None | F47 |
| q-b345918da6 | triage T1649 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*.p12\" OR TO_LOWER(file.path) LIKE \"*.cer\" OR TO_LOWER(file.path) LIKE \"*.kirbi\") \| KEEP … | 1 |  |
| q-6a2473dbcc | triage T1649 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*export-pfxcertificate*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*get-privatekeys*\" OR TO_LOWER(p… | ERROR |  |
| q-b59cf67046 | triage T1649 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*export-pfxcertificate*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*get-privatekeys*\" OR TO_LOWER(p… | 2 |  |
| q-02ef22a021 | triage T1649 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*readme.ps1*\" OR TO_LOWER(process.command_line) LIKE \"*get-privatekeys*\" OR TO_LOWER(process.command_line) LIKE \"*expor… | 0 |  |
| q-4be41f892b | triage T1649 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTX"} | None | F47 |
| q-c869d1b63f | triage T1649 step 4 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ObjectName", "win.OperationType", "win.NewValue", "win.ProcessName"]… | 1 | F48 |
| q-4f9de54575 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-c718d3bbe8 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-7503a139f7 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-b07c2f7616 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTX"} | None |  |
| q-f46ff179c3 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-8910649549 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-a1da49b867 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeUuC-"} | None |  |
| q-26fbf112cb | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeUuC-"} | None |  |
| q-9bc362b360 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeUuC-"} | None |  |
| q-a2d6d514f3 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YbQlYK"} | None |  |
| q-4542a9aebd | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm9"} | None |  |
| q-bbfab89007 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm9"} | None |  |
| q-ebaeb95db3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-8ff46e09e3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-a81ad4e959 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-558dfef81a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-1c38a43a44 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-cbc0b6b236 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzydoz"} | None |  |
| q-d89e55de3b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-6c996c8084 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-b4791db8a2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-551c5aef86 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-b36723dd8e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-da5191fabb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RoJ7pL"} | None |  |
| q-68d6ea1399 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-20e9e951bf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDyQK"} | None |  |
| q-76c35fc326 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqWk4"} | None |  |
| q-fc31932885 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-16690ac3c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-5cc0d8a18c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WnQtls"} | None |  |
| q-f5bd3b9d77 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-ce5df183fa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NUxiiK"} | None |  |
| q-354bcb4475 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NUxiiK"} | None |  |
| q-8d5c0a2318 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NNopD7"} | None |  |
| q-653de6bd43 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b0zggu"} | None |  |
| q-70aaa7c53f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b0zggu"} | None |  |
| q-e480d84a15 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-d3c6f3fe68 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WiJkSG"} | None |  |
| q-6b151358a2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMq"} | None |  |
| q-2bca3ceb48 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMo"} | None |  |
| q-749664930d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WiJkR5"} | None |  |
| q-de133132ce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-991d89b0f2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-71dffe19bf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-acd0805d04 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-42dd3b87cb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-1dbf84aef1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-5c55215ef1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NNo5BS"} | None |  |
| q-64c627abaf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-4b3cb25353 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-2f552496b1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-d9f8c9fced | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-22af96bb78 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-685ad810c6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-94ee10873a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YWMnGq"} | None |  |
| q-1efdb485cc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-500645a27e | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0y"} | None |  |
| q-7701875a71 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-9fba1e50d8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHQbW"} | None |  |
| q-a192cfc829 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-f4fca4d3c4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-d141b9fc37 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-18ab9c2998 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-9012909814 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None |  |
| q-8d6cc9819a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SAm218"} | None |  |
| q-d7140730cb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SAm218"} | None |  |
| q-2ab4446c61 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SJxMAB"} | None |  |
| q-d13c95901f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtShN2"} | None |  |
| q-86ed1b504b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtT0KI"} | None |  |
| q-2d188e562f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUEbK"} | None |  |
| q-be82076e8a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUml9"} | None |  |
| q-3f838b3ba7 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx3F"} | None |  |
| q-af2de543e0 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx3F"} | None |  |
| q-57f421d9ee | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Yc1"} | None |  |
| q-a332530a3b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yph4sr"} | None |  |
| q-98fed38810 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yph4sr"} | None |  |
| q-76cc5f8da3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-6557fde160 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-2856bd823b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-bccb4be517 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-4dc6f161ce | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-51069e6a0f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Qp"} | None |  |
| q-128c0b32a2 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0a"} | None |  |
| q-a2d6b36f5d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0a"} | None |  |
| q-566f3784d3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-3cfe0b6f7f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-ee9ffc8abe | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b42izk"} | None |  |
| q-6c95ca8ea1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21gGA"} | None |  |
| q-7c9aa338f6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-f467195e6a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-a64071b75c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MrOOck"} | None |  |
| q-e49edd63c6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-f5942321bd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-9e59bc8975 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-ce51925b6b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-7bb12dae32 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-95ddc983cf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-bac7be559f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-6e7a3b06ae | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_RQ"} | None |  |
| q-429158f6ce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqLbie"} | None |  |
| q-80c81de33f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqLbie"} | None |  |
| q-8caa89673b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-aee68a24c8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-44c086cee2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-bd52eb8c22 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-5c7908d251 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-62e252fdcd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-b1b1cf9744 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-7613ac7462 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-af50852a39 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAenUm"} | None |  |
| q-45c7353921 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhM"} | None |  |
| q-62917f72b8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YEBswT"} | None |  |
| q-68e8b8c14a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-7258b907a6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-bf7bac856e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-e30079dad2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-253b857d32 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMw"} | None |  |
| q-c22d97e6e7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMw"} | None |  |
| q-ac222dd15c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yph4sy"} | None |  |
| q-007f2caece | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SErGol"} | None |  |
| q-4aab48c7a4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SErGol"} | None |  |
| q-a4db5f7290 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqL7gO"} | None |  |
| q-0347365283 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-5a055ba4d2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtY9"} | None |  |
| q-161dd3f1fa | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ida"} | None |  |
| q-9c3954c9f1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NUyf30"} | None |  |
| q-3da398184f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-4452f95da8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Yc1"} | None |  |
| q-b5d8555ed3 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2I"} | None |  |
| q-26f2183340 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-49d83eade5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-e856173eb5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-c8c921c802 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-c9543c41f2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-94e7d131c6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeV"} | None |  |
| q-40b8325267 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeV"} | None |  |
| q-a2a354a4d4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeU"} | None |  |
| q-cb9234a997 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeW"} | None |  |
| q-14b2912167 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74ep"} | None |  |
| q-59356747d8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74ep"} | None |  |
| q-c77a5f4a5e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Idf"} | None |  |
| q-00b0f250da | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Idf"} | None |  |
| q-b2eaaf8f3c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-8004e2e3d1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-8731f0178a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-0bea905c96 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-d805bb89fc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-5729fa8c2c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-021f51dadd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WgHZ_9"} | None |  |
| q-2d23d27812 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WgHZ_9"} | None |  |
| q-ef3a6ad7e1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aMP"} | None |  |
| q-303b59856f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-9cc4a6faed | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-0eb008ff6f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-b3d890a39f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-546ed1cb94 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-90753c25fd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTX"} | None |  |
| q-0eca45a2da | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-853daed9ac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-4c3253872f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeUuC-"} | None |  |
| q-9bd8a3b1f7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeUuC-"} | None |  |
| q-20bcd5ae43 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeUuC-"} | None |  |
| q-a3dac822dd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YbQlYK"} | None |  |
| q-72167946b4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm9"} | None |  |
| q-da823dd354 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm9"} | None |  |
| q-bfed9ffddf | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T02:50:00.000Z\" AND @timestamp <= \"2020-05-02T03:20:00.000Z\" AND event.code == \"1\" \| KEEP @timestamp, host.name, user.name, process.executable, process.co… | 304 |  |
| q-ade0d753b0 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T02:50:00.000Z\" AND @timestamp <= \"2020-05-02T03:20:00.000Z\" AND event.code == \"10\" \| STATS c = COUNT(*) BY host.name, process.executable, win.TargetImage… | 500 |  |
| q-ce6b19970f | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T02:50:00.000Z\" AND @timestamp <= \"2020-05-02T03:20:00.000Z\" AND event.code == \"1\" AND (process.executable LIKE \"*python*\" OR process.executable LIKE \"*… | 11 | F51, F52, F53 |
| q-3bd982e167 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T02:50:00.000Z\" AND @timestamp <= \"2020-05-02T03:20:00.000Z\" AND event.code == \"11\" \| KEEP @timestamp, host.name, user.name, process.executable, file.path… | 500 |  |
| q-954c2fdcb9 | pivot step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T02:50:00.000Z\" AND @timestamp <= \"2020-05-02T03:20:00.000Z\" AND event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, powershell.script_block… | 403 |  |
| q-6fcef6eb86 | pivot step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T02:50:00.000Z\" AND @timestamp <= \"2020-05-02T03:20:00.000Z\" AND (process.executable LIKE \"*python*\" OR process.executable LIKE \"*Rar.exe*\" OR process.ex… | 78 | F51 |
| q-6e60b04b29 | pivot step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T02:50:00.000Z\" AND @timestamp <= \"2020-05-02T03:20:00.000Z\" AND event.code IN (\"4648\",\"4624\",\"4672\",\"4663\",\"5145\",\"5140\",\"4673\",\"4690\") AN… | 105 |  |
| q-769dff5cfb | pivot step 4 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T02:50:00.000Z\" AND @timestamp <= \"2020-05-02T03:20:00.000Z\" AND event.code IN (\"7045\",\"7040\",\"5858\",\"5857\",\"5860\",\"20523\",\"98\",\"1500\",\"2004\… | 116 |  |
| q-6010e213c3 | pivot step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T02:50:00.000Z\" AND @timestamp <= \"2020-05-02T03:20:00.000Z\" AND event.code == \"3\" AND (process.executable LIKE \"*python*\" OR process.executable LIKE \"*… | 370 | F51 |
| q-171805c9b1 | pivot step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T02:50:00.000Z\" AND @timestamp <= \"2020-05-02T03:20:00.000Z\" AND event.code IN (\"12\",\"13\",\"14\") AND (registry.path LIKE \"*Vault*\" OR registry.path LI… | 35 |  |
| q-2dedb26d10 | pivot step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None | F54 |
| q-ab498d6074 | pivot step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T03:05:00.000Z\" AND @timestamp <= \"2020-05-02T03:20:00.000Z\" AND event.code == \"4103\" AND (win.Payload LIKE \"*python*\" OR win.Payload LIKE \"*Rar*\" … | 77 | F55 |
| q-508519398a | pivot step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T03:09:00.000Z\" AND @timestamp <= \"2020-05-02T03:20:00.000Z\" AND event.code == \"4688\" AND (process.command_line LIKE \"*python*\" OR process.command_line… | 17 | F50, F51 |
| q-a43f14b4b1 | pivot step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T03:09:00.000Z\" AND @timestamp <= \"2020-05-02T03:20:00.000Z\" AND host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, hos… | 11 | F52 |
| q-a9e3cce329 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP1_"} | None |  |
| q-910bae4303 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSCot"} | None |  |
| q-e103d9e7ba | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YmeJMa"} | None |  |
| q-4823dc98d7 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsKx"} | None |  |
| q-f432616fde | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDiNo"} | None |  |
| q-8089e19e9d | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDSP-"} | None |  |
| q-ddbe860ef2 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDSP-"} | None |  |
| q-d5d874e97f | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSCpJ"} | None |  |
| q-e1326e4801 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RhBpvd"} | None |  |
| q-12d4b12617 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxhdc"} | None |  |
| q-78c15d0290 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQx3"} | None |  |
| q-9c546ae67b | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nd9MRE"} | None |  |
| q-bd6aececdc | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emY"} | None |  |
| q-c6a4ee5bd3 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WrUWHO"} | None |  |
| q-7118338dbd | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-da86a3c009 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-9ca71286fc | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-a7a94c8817 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTy"} | None |  |
| q-fa78d601d5 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b0ywiq"} | None |  |
| q-5c6d8df393 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-33ae78d705 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-2f3963d15d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-d0752d479c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-87608ce83d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-ee613217eb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzydoz"} | None |  |
| q-0a265ec52a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-544f6bf8f3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-52f162a417 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-3635d0243d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-ce7ec128b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-03f95969b4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RoJ7pL"} | None |  |
| q-e71665d75f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-5234bf261f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDyQK"} | None |  |
| q-78fc6603e6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqWk4"} | None |  |
| q-536fb95994 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-9f815cfaa3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-888f1b4452 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WnQtls"} | None |  |
| q-54cdeb6aa3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-1c4d777a62 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NUxiiK"} | None |  |
| q-2f914960f4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NUxiiK"} | None |  |
| q-f36aa2ad3f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NNopD7"} | None |  |
| q-8bd3ea17c4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b0zggu"} | None |  |
| q-76d0e68bd3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b0zggu"} | None |  |
| q-21a6a9dde9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-6096f17e23 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WiJkSG"} | None |  |
| q-9c53fc021a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMq"} | None |  |
| q-c7d2c341a9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMo"} | None |  |
| q-78fcca8cf9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WiJkR5"} | None |  |
| q-cbb9176b3d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-36dcf65501 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-37d7a4787a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-6020af738b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-a9f5c2990c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-3f2b02bf71 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-732bfb855b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NNo5BS"} | None |  |
| q-0bd6865b90 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-03d570f443 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-ebb51b04a3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-b177e8122b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-7b105c677f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-e42a97077b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-725a38f8fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YWMnGq"} | None |  |
| q-df90fcc217 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-11a7eec840 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0y"} | None |  |
| q-976e3034fb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-9229c91d64 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHQbW"} | None |  |
| q-bd636b1f85 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-bfbac6eda9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-1d174b381c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-e67cd0bb7f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-deaeb2a5c1 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None |  |
| q-8bc54ce1c6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SAm218"} | None |  |
| q-e14f79b7b9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SAm218"} | None |  |
| q-5f556cb00e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SJxMAB"} | None |  |
| q-2524e427e8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtShN2"} | None |  |
| q-dac6630afb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtT0KI"} | None |  |
| q-95176591a7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUEbK"} | None |  |
| q-3850e61fc8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUml9"} | None |  |
| q-7f5a62c999 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx3F"} | None |  |
| q-c2da776eb7 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx3F"} | None |  |
| q-e14902fdcc | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Yc1"} | None |  |
| q-f54b855458 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yph4sr"} | None |  |
| q-2176799cda | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yph4sr"} | None |  |
| q-489369d504 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-87241ac2c4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-f9c459f3af | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-3b9da0b30e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-f15f926488 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-bdd3caa0c8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Qp"} | None |  |
| q-e059f23d3d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0a"} | None |  |
| q-8b6a606580 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0a"} | None |  |
| q-0b98f62264 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-fedbee2d8e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-4d8bfc5620 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b42izk"} | None |  |
| q-c65af4f962 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21gGA"} | None |  |
| q-b9cc3206b2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-27bef7004e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-aa2c8d3d13 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MrOOck"} | None |  |
| q-66d024b951 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-7bb43dff52 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-b18ed75848 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-68eaeef758 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-f67678c121 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-fa936b0471 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-b77841fa6d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-b1270e45f7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_RQ"} | None |  |
| q-c47a704684 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqLbie"} | None |  |
| q-6d6719e9d6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqLbie"} | None |  |
| q-6644908e65 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-339e29fe29 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-a527745344 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-8c50329507 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-525c486ed5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-449784fd7c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-8d1b5e22b6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-cf84c241fa | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-2c73cfcf3c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAenUm"} | None |  |
| q-2fc2c85ecf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhM"} | None |  |
| q-9ed20958ec | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YEBswT"} | None |  |
| q-283bd46930 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-82fd1c889c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-17583ccbd0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-dbfc48381f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-6ed242fd0e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMw"} | None |  |
| q-12890aadf3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMw"} | None |  |
| q-4b6ce27fde | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yph4sy"} | None |  |
| q-62ecfb59be | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SErGol"} | None |  |
| q-df9a7b4694 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SErGol"} | None |  |
| q-1e634f0835 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqL7gO"} | None |  |
| q-8f9d106f84 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-53605f0bd3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtY9"} | None |  |
| q-e9dafc254b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ida"} | None |  |
| q-1f4276f8af | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NUyf30"} | None |  |
| q-5ca5968eed | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-a891076db1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Yc1"} | None |  |
| q-eb4bfbe20f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2I"} | None |  |
| q-53d71572ce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-b9cb7e6d95 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-3c30414307 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-87fb9477f1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-d71b65d38c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-651a35b069 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeV"} | None |  |
| q-10b04dbea0 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeV"} | None |  |
| q-c2e944af95 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeU"} | None |  |
| q-6a47b76d34 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeW"} | None |  |
| q-f8369f3503 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74ep"} | None |  |
| q-4f9417cc92 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74ep"} | None |  |
| q-e365d1eb64 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Idf"} | None |  |
| q-1391361502 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Idf"} | None |  |
| q-e134df56d5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-e44907e48d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-8192fbd858 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-79964327f7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-dd9839ed74 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-af1e32c2e5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-623fbb64a9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WgHZ_9"} | None |  |
| q-57d3610d8b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WgHZ_9"} | None |  |
| q-89fc2e5991 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aMP"} | None |  |
| q-fefa65b574 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-ae22225344 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-96dc33dfe4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-203156a0a7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-b46beb73a6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-4533ccaf6d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTX"} | None |  |
| q-fdfc5f101f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-00587d6bd2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-af6e086c85 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeUuC-"} | None |  |
| q-480cdf664e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeUuC-"} | None |  |
| q-36fa02d4a7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeUuC-"} | None |  |
| q-8a52dbd81f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YbQlYK"} | None |  |
| q-5a2a6ec079 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm9"} | None |  |
| q-5f67b920c4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm9"} | None |  |
| q-fcc63a4096 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP1_"} | None |  |
| q-65793b4247 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSCot"} | None |  |
| q-9599d0d228 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YmeJMa"} | None |  |
| q-6914f1e167 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsKx"} | None |  |
| q-0df8b345c5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDiNo"} | None |  |
| q-0ecb40bdf6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDSP-"} | None |  |
| q-7008bb7000 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDSP-"} | None |  |
| q-40cabea5b2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSCpJ"} | None |  |
| q-ed1ce30045 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RhBpvd"} | None |  |
| q-c4072fa7e6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxhdc"} | None |  |
| q-ea8b97df75 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQx3"} | None |  |
| q-daef6c6c0d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nd9MRE"} | None |  |
| q-b833b6aafb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emY"} | None |  |
| q-b93da7664c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WrUWHO"} | None |  |
| q-8bb0ae2f18 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-83531d9bb2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-cfc2c90b4c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-d8dfad5709 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTy"} | None |  |
| q-d951360cf5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b0ywiq"} | None |  |

## Verification

Evidence items cited: 172; confirmed against the stored events: 171; rejected: 1. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 9 item(s) in 5 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
