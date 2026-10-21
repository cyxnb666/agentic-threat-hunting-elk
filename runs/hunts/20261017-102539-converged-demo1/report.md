# Threat hunt report — 20261017-102539-converged-demo1

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 6 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003.001 (F01, F09, F22, F41, F60), I02 T1003.001 (F56), I04 T1552 (F27), I05 T1552.001 (F26, F59), I06 T1552.001 (F57, F58, F51), I07 T1649 (F25, F55)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-17T02:25:40+00:00 / 2026-10-17T02:35:09+00:00 (569.4 s) |
| LLM calls / tokens | 148 / {'prompt': 4182634, 'completion': 125654} |
| MCP tool calls | 1224 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003.001 | yes | malicious/high | F01, F09, F22, F41, F60 | PowerShell full-access LSASS handle on scranton (credential dumping / in-memory theft) |
| I02 | T1003.001 | yes | malicious/high | F56 | wsmprovhost.exe full-access LSASS handle on nashua |
| I03 | T1003.001 | yes | suspicious/medium | F61 | sdclt.exe (UAC-bypass binary) launched from cmd.exe on scranton just before the credential-access tooling |
| I04 | T1552 | yes | malicious/high | F27 | Hardcoded plaintext credentials in attacker PowerShell tooling on scranton |
| I05 | T1552.001 | yes | malicious/high | F26, F59 | accesschk.exe wrote passwordsDB on scranton |
| I06 | T1552.001 | yes | malicious/high | F57, F58, F51 | PsExec64 with cleartext domain password from scranton to nashua |
| I07 | T1649 | yes | malicious/high | F25, F55 | Get-PrivateKeys exported machine certificate private keys to password-protected .pfx on scranton |
| I08 | out-of-scope:T1027 | no | suspicious/medium | F37 | DLLs written to user Temp are Add-Type compilations, not password filter DLLs |
| I09 | out-of-scope:T1105 | no | suspicious/medium | F52 | WebDAV cookie creation (DavSetCookie) on scranton |
| I10 | out-of-scope:T1547.001 | no | suspicious/medium | F20 | hostui.lnk dropped into all-users StartUp folder on scranton |

## Findings

### F07 · malicious / high · T1003 · Credential-access tooling staged and executed in pbeesly session on scranton (Sysinternals suite, keystroke capture, cert export)

Evidence status: **NOT verified (4/5 evidence items)** — excluded from the verdict

On scranton.dmevals.local the user pbeesly ran a hidden, encoded PowerShell payload (parent control.exe /name Microsoft.BackupAndRestoreCenter) that decoded a bitmap into a script, then executed Invoke-Discovery, Invoke-Persistence steps 1 and 2, accesschk.exe from C:\Program Files\SysinternalsSuite, Get-PrivateKeys (exporting every LocalMachine certificate to .pfx with password 'saribas'), Invoke-ScreenCapture, Get-Clipboard and Get-Keystrokes, and finally a second hidden base64 PowerShell (-nop -w hidden -e ...) launched from a registry value read via Get-ItemPropertyValue 'HKLM:\SOFTWARE\Javasoft'. This is a hands-on-keyboard credential-access campaign; the LSASS full-access handle from the same PowerShell process is the credential-dumping step.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:27.859Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkHK8X3 | q-5378709133 | ok |
| 2 | 2020-05-02 03:21:28.949Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewAkAGIAPQAkAGUAbg… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkHK8V2 | q-5378709133 | FAILED: claimed value differs from the stored value |
| 3 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwAjopf | q-4d78488146 | ok |
| 4 | 2020-05-02 03:04:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Persistence -PersistStep 2 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkCzT | q-4d78488146 | ok |
| 5 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCRb2o | q-4646895325 | ok |

### F01 · malicious / high · T1003.001 · PowerShell.exe opened LSASS with full access (0x1FFFFF / 0x1F3FFF) on scranton during attacker interactive session

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976, the hidden -noni -noexit -ep bypass PowerShell launched by control.exe that decoded a bitmap payload from C:\Users\pbeesly\Downloads\monkey.png) opened a handle to C:\windows\system32\lsass.exe (PID 736) at 2020-05-02T03:05:16 with GrantedAccess 0x1f3fff and then 0x1fffff, with a CallTrace ending in UNKNOWN(000001996D28200D) — code not backed by a loaded module, the classic LSASS-dump signature. This occurred inside the same pbeesly session that ran Invoke-Discovery, Invoke-Persistence, accesschk.exe, Get-PrivateKeys (Export-PfxCertificate of all LocalMachine certs) and Get-Keystrokes. Other LSASS handles in the dataset are benign (svchost/lsm.dll, wininit/csrss at boot, Windows Defender MsMpEng, Azure telemetry/antimalware perfmon).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-93fa94f74f | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-93fa94f74f | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-165730b9ff | ok |
| 4 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgwo_a | q-5378709133 | ok |
| 5 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-b5fef8d36e | ok |

### F56 · malicious / high · T1003.001 · wsmprovhost.exe (PowerShell Remoting) opened lsass.exe with 0x1f3fff on nashua.dmevals.local

Evidence status: **verified**

On nashua.dmevals.local at 2020-05-02T03:09:29Z the WinRM host process C:\windows\system32\wsmprovhost.exe running as pbeesly opened a handle to C:\windows\system32\lsass.exe with GrantedAccess 0x1f3fff (includes VM_READ); the same access was recorded in the Security log (4663, AccessMask 0x1f3fff) for the same host/user. The call trace shows the handle taken from managed code (System.ni.dll frames), i.e. a .NET/PowerShell in-memory read of LSASS. This is a new host compared with the scranton anchors and shows the LSASS credential-dump technique repeated over PowerShell Remoting.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-b7f6db329c | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-b7f6db329c | ok |
| 3 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFv53 | q-f6aa6cf1d7 | ok |
| 4 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFv53 | q-f6aa6cf1d7 | ok |

### F60 · malicious / medium · T1003.001 · PowerShell on scranton compiled attacker .NET assemblies with csc.exe from %TEMP% response files (Add-Type) before LSASS access

Evidence status: **verified**

On scranton.dmevals.local csc.exe was invoked twice by powershell.exe (pbeesly) at 02:58:45 and 03:08:03 with @response files in %TEMP% (qkbkqqbs, 0piklvia), producing qkbkqqbs.dll and 0piklvia.dll. The parent PowerShell was launched hidden with -ep bypass and decoded a payload steganographically from C:\Users\pbeesly\Downloads\monkey.png before IEX. This is runtime compilation of attacker .NET code (Add-Type) on the compromised host, the same mechanism behind the anchored LSASS handle and password-filter DLL findings.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.cmdline" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpfwJ_Y | q-738d154068 | ok |
| 2 | 2020-05-02 03:08:03.260Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\pbeesly\AppData\Local\Temp\0piklvia\0piklvia.cmdline" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchIto6IP6B | q-738d154068 | ok |
| 3 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpfwJ_Y | q-738d154068 | ok |

### F09 · malicious / high · T1056.004 · PowerShell on scranton opened lsass.exe with full access (0x1fffff / 0x1f3fff) — credential API hooking / in-memory credential theft

Evidence status: **verified**

On 2020-05-02 at 03:05:16 UTC, PowerShell.exe (PID 2976, user pbeesly, DMEVALS) on scranton.dmevals.local opened a handle to C:\windows\system32\lsass.exe (PID 736) twice within 31 ms, first with GrantedAccess 0x1f3fff and then 0x1fffff (PROCESS_ALL_ACCESS). The call trace ends in an UNKNOWN module (UNKNOWN(000001996D252982) / UNKNOWN(000001996D28200D)) rather than a signed system DLL, consistent with injected/reflective code reading lsass memory. Windows Security corroborates the same handle requests (4656, AccessMask 0x1f3fff and 0x1fffff, ProcessName powershell.exe) and an audited 4663 access to \Device\HarddiskVolume2\Windows\System32\lsass.exe by powershell.exe at the same second. This occurred inside a malicious PowerShell toolkit on scranton (script blocks Get-PrivateKeys exporting all LocalMachine certificates to .pfx with password 'saribas', and Invoke-Exfil staging Downloads into OfficeSupplies.7z and copying it to \\192.168.0.4\webdav), shortly after a hidden, encoded PowerShell launched from control.exe via a bitmap-steganography IEX one-liner. The other lsass handle opens in the window are benign system/agent activity (svchost.exe 0x1000/0x101001 via lsm.dll, wininit/csrss at boot, WindowsAzureTelemetryService.exe 0x1400 via CorperfmonExt.dll, CollectGuestLogs.exe and MsMpEng.exe with 0x10).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-e34329e5b9 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-e34329e5b9 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-c8a268cefa | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-c8a268cefa | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo57 | q-0989625fdd | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo4k | q-0989625fdd | ok |
| 7 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo54 | q-588eca24c0 | ok |
| 8 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-b631513dcd | ok |
| 9 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-b631513dcd | ok |
| 10 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgwo_a | q-dd923358c0 | ok |

### F22 · malicious / medium · T1212 · PowerShell opened a full-access handle to lsass.exe on scranton.dmevals.local during a hands-on-keyboard credential/collection session

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:05:16Z, PowerShell.exe (PID 2976 / 0xba0) running as DMEVALS\pbeesly requested a handle to \Device\HarddiskVolume2\Windows\System32\lsass.exe with GrantedAccess 0x1FFFFF (and a second handle with 0x1F3FFF), i.e. PROCESS_ALL_ACCESS including 'Read from process memory' and 'Duplicate handle into or out of process' — the access pattern used to read LSASS credential material. The call trace ends in UNKNOWN(000001996D28200D), i.e. code not backed by a loaded module, consistent with in-memory/reflective tooling rather than a signed dumper. This occurred inside an interactive pbeesly session that minutes earlier ran Invoke-Discovery, Invoke-Persistence -PersistStep 1/2, accesschk.exe, Get-PrivateKeys (Export-PfxCertificate of machine certs with hardcoded password 'saribas'), Invoke-ScreenCapture, Get-Clipboard and a keystroke/AV-check function, and that also staged user documents/password-named files into an archive — a credential-access and collection toolkit. No Mimikatz/Invoke-Mimikatz script block was logged (C137 zero hits), so the LSASS access is the primary T1212 evidence rather than a named dumping tool. Note the 4104 script-block log has a gap between 03:05:08 ('exit') and 03:05:25, so the exact command that opened the handle was not captured.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-234d901bff | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-234d901bff | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-234d901bff | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-1a4ccbce33 | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo57 | q-4b5991730a | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo57 | q-4b5991730a | ok |
| 7 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo57 | q-4b5991730a | ok |
| 8 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-807ee20131 | ok |
| 9 | 2020-05-02 03:04:57.000Z | scranton.dmevals.local | windows.powershell | win.Payload | CommandInvocation(Export-PfxCertificate): "Export-PfxCertificate"  ParameterBinding(Export-PfxCertificate): name="Cert"; value=""  ParameterBinding(Export-PfxCe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkCwQ | q-12c5da7ca8 | ok |
| 10 | 2020-05-02 03:04:57.000Z | scranton.dmevals.local | windows.powershell | win.Payload | CommandInvocation(ConvertTo-SecureString): "ConvertTo-SecureString"  ParameterBinding(ConvertTo-SecureString): name="String"; value="saribas"  ParameterBinding(… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkCwK | q-12c5da7ca8 | ok |

### F27 · malicious / high · T1552 · Hardcoded plaintext credentials embedded in attacker PowerShell tooling (Invoke-Exfil, Get-PrivateKeys)

Evidence status: **verified**

On scranton.dmevals.local the pbeesly session loaded attacker scripts from C:\Program Files\SysinternalsSuite\psversion.ps1 and readme.ps1 that embed plaintext credentials: Invoke-Exfil (2020-05-02T03:08:02Z) builds a PSCredential from user "cozy" and password "MyCozyPassw0rd!" to map \\192.168.0.4\webdav and copy a password-protected 7z archive of the Downloads folder there, and Get-PrivateKeys (03:04:56Z) uses the plaintext password "saribas" for the exported .pfx. These are unsecured credentials stored in files on the compromised host, used by the adversary for exfiltration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-c435dbdaac | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-c435dbdaac | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-72ee53dd02 | ok |

### F58 · malicious / high · T1552 · Hardcoded plaintext domain credential reused by PsExec64 from scranton to nashua

Evidence status: **verified**

The PsExec64 command line executed by PowerShell on scranton embeds the plaintext domain password for dmevals\pbeesly ('Fl0nk3rt0n!T0by'), which was then used to authenticate to nashua (4624 type 2, workstation NASHUA, Negotiate, at 03:11:40, 03:12:46, 03:13:49, 03:15:03). This extends the anchor finding of hardcoded credentials in attacker tooling to lateral movement onto nashua.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEeE | q-403dfd30db | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.LogonType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0fg | q-b326943382 | ok |
| 3 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.WorkstationName | NASHUA | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0fg | q-b326943382 | ok |

### F57 · malicious / high · T1552.001 · PsExec64 launched from scranton with cleartext password to run python.exe on nashua; python payload then harvested user files into a password-protected RAR

Evidence status: **verified**

On scranton.dmevals.local PowerShell (pbeesly) ran C:\Program Files\SysinternalsSuite\PsExec64.exe four times (03:11:18, 03:12:25, 03:13:28, 03:14:42) with the cleartext credential '-u dmevals\pbeesly -p Fl0nk3rt0n!T0by' to start C:\Windows\Temp\python.exe on \\NASHUA. On nashua the resulting python.exe (parent C:\Windows\PSEXESVC.exe, user pbeesly) ran five times, spawned powershell.exe and cmd.exe, connected to 192.168.0.4:8443, and at 03:15:59 a PowerShell block enumerated the user profile for *psw*, *pass*, *login*, *admin*, *sifr*, *sifer*, *vpn*, *.pst, *.ost and archive files and compressed them into %APPDATA%\working.zip. At 03:16:19 C:\Windows\Temp\Rar.exe was run with '-hpfGzq5yKw' to build a password-protected C:\Users\pbeesly\Desktop\working.zip, then sdelete64.exe wiped Rar.exe and both zips. Credential-file harvesting plus anti-forensics on a host not covered by the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2r93 | q-738d154068 | ok |
| 2 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2b9g | q-6afae450ea | ok |
| 3 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | powershell.script_block.text | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCk1OJ | q-4f3fdaf9d0 | ok |
| 4 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkmtdI9 | q-6afae450ea | ok |
| 5 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItknvJ-S | q-92294adeec | ok |
| 6 | 2020-05-02 03:16:52.456Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkjomHY | q-6afae450ea | ok |

### F59 · malicious / high · T1552.001 · accesschk.exe run by PowerShell on scranton wrote passwordsDB

Evidence status: **verified**

On scranton.dmevals.local at 03:04:34 accesschk.exe was started by powershell.exe (pbeesly) and at 03:04:35 wrote C:\Program Files\SysinternalsSuite\passwordsDB — attacker tooling enumerating access to credential stores, consistent with the anchored T1552.001 finding and confirming the tool ran from the SysinternalsSuite masquerade directory.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCRb2o | q-738d154068 | ok |
| 2 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCRb2e | q-eb79334cad | ok |

### F25 · malicious / high · T1552.004 · Get-PrivateKeys PowerShell function exported every LocalMachine certificate to a password-protected .pfx in the user's Downloads folder

Evidence status: **verified**

On scranton.dmevals.local, in the context of user pbeesly (SID ...-1107), a PowerShell script block named Get-PrivateKeys was logged at 2020-05-02T03:04:56Z (script block 9d153741-75c3-4062-afe3-aeca0aee611b, path C:\Program Files\SysinternalsSuite\readme.ps1). It enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint, writing to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded plaintext password "saribas". One second later, at 2020-05-02T03:04:57.460Z, Sysmon event 11 confirms the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx was created by powershell.exe (PID 3876). This is private-key/certificate material being harvested for later use or exfiltration, part of a broader hands-on-keyboard intrusion on scranton (the same session ran Invoke-Discovery, sdclt/control UAC bypass, csc.exe compilation, accesschk, sdelete64 cleanup, and an Invoke-Exfil routine).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-72ee53dd02 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-72ee53dd02 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-72ee53dd02 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-ada00e3527 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-ada00e3527 | ok |

### F51 · malicious / high · T1606 · Credential-access and WebDAV exfil tooling executed by pbeesly on SCRANTON (SysinternalsSuite masquerade scripts, lsass handle, cleartext PsExec creds)

Evidence status: **verified**

On scranton.dmevals.local between 2020-05-02T02:56Z and 03:21Z, user pbeesly ran a chain of attacker tooling from C:\Program Files\SysinternalsSuite: PowerShell read lsass.exe with full-access masks (0x1f3fff and 0x1fffff at 03:05:16), a script block from readme.ps1 enumerated token/group attributes (Get-AttributesMask), accesschk.exe was launched, and psversion.ps1 defined an Invoke-Exfil function that 7-Zips the user's Downloads with password 'lolol' and copies it to a WebDAV share at \\192.168.0.4\webdav using hardcoded credentials (cozy / MyCozyPassw0rd!). sdelete64.exe was used to wipe files (C:\programdata\victim\???cod.3aka3.scr, Draft.Zip, SysinternalsSuite.zip). PsExec64.exe was then run four times with cleartext credentials (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by) against \\NASHUA to launch C:\Windows\Temp\python.exe, producing 4648 explicit-credential logons on SCRANTON targeting NASHUA and PSEXESVC.exe-driven 4648s on nashua.dmevals.local. This is credential theft plus staging/exfiltration, not normal administration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-88f771d738 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-bd2f093576 | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-b488b306d5 | ok |
| 4 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-b488b306d5 | ok |
| 5 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-AttributesMask($AttributesMask) {     &lt;#         SE_GROUP_MANDATORY          0x00000001  The group is mandatory.         SE_GROUP_ENABLED_BY_DEF… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkCwA | q-3edf1d8cb4 | ok |
| 6 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2r93 | q-32250c5e66 | ok |
| 7 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpHV4S3 | q-32250c5e66 | ok |
| 8 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEcw | q-56f43f21f1 | ok |
| 9 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0ff | q-56f43f21f1 | ok |

### F55 · malicious / high · T1649 · Get-PrivateKeys PowerShell function exported machine certificate private keys to password-protected .pfx files on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local, in the session of user DMEVALS\pbeesly, a PowerShell script block named Get-PrivateKeys (ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b, logged with Path C:\Program Files\SysinternalsSuite\readme.ps1) enumerated every certificate in cert:\LocalMachine recursively and called Export-PfxCertificate for each certificate with a thumbprint, writing the private-key-bearing .pfx to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded password "saribas". The function was invoked at 2020-05-02T03:04:56Z (script block 'Get-PrivateKeys', PID 3876) and at 03:04:57.460Z Sysmon recorded the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by powershell.exe (PID 3876). This is direct theft of authentication certificate private keys from the local machine store, matching T1649. The activity sits inside a broader intrusion chain on the same host: at 02:58:44Z a hidden, execution-policy-bypassing PowerShell (parent control.exe /name Microsoft.BackupAndRestoreCenter) decoded a payload from C:\Users\pbeesly\Downloads\monkey.png via System.Drawing pixel extraction and IEX'd it; at 03:08:51Z a second PowerShell (PID 3852) ran an Invoke-BeachCleanup function (Path C:\Program Files\SysinternalsSuite\psversion.ps1) that deleted Downloads\*.pfx, *.bmp, *.png and %APPDATA%\OfficeSupplies.7z, and Sysmon event 23 confirms coyn5igj.3io.pfx was deleted at 03:08:51.489Z by DMEVALS\pbeesly. The export-then-wipe pattern indicates deliberate exfiltration staging and anti-forensics. No certificate-based (PKINIT) authentication was observed: all 14 Kerberos 4768 TGT requests in windows.security show PreAuthType 2 (password pre-auth) with Status 0x0, and the single SystemCertificates registry modification (4657 on nashua.dmevals.local, ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656, by NASHUA$) is not linked to this activity. Zeek x509/kerberos data (2020-04-30) does not overlap the Windows window and shows only AS/TGS requests w…

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-24b953fae4 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-24b953fae4 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-24b953fae4 | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSxb | q-7fe22e16a2 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-ea50096a4c | ok |
| 6 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-ea50096a4c | ok |
| 7 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCk1N1 | q-3361786b70 | ok |
| 8 | 2020-05-02 03:08:51.489Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkx5I18 | q-0d456ccb4c | ok |
| 9 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgwo_a | q-a8e5891ce9 | ok |
| 10 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEcb | q-9f9c651449 | ok |

### F61 · suspicious / medium · T1003.001 · sdclt.exe (UAC-bypass binary) launched from cmd.exe on scranton just before the credential-access tooling

Evidence status: **verified**

On scranton.dmevals.local, immediately after the attacker payload C:\ProgramData\victim\â€®cod.3aka3.scr was started by explorer.exe with /S at 02:55:56, cmd.exe launched sdclt.exe three times at 02:58:42-43, right before the csc.exe Add-Type compilation. sdclt is a known UAC-bypass binary; the sequence is consistent with the attacker elevating to reach LSASS and the certificate store, though the sdclt command lines carry no arguments.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\sdclt.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgxY85 | q-738d154068 | ok |
| 2 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\cmd.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgxY85 | q-738d154068 | ok |
| 3 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpk1QgV | q-738d154068 | ok |

### F20 · suspicious / medium · T1187 · PowerShell on scranton.dmevals.local drops hostui.lnk into the all-users StartUp folder (persistence, not forced authentication)

Evidence status: **verified**

On scranton.dmevals.local, the PowerShell process (PID 3876, ProcessGuid {47ab858c-e23d-5eac-c603-000000000400}) first wrote C:\Users\pbeesly\Downloads\SysinternalsSuite\hostui.txt at 03:00:27Z and then created C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk at 03:04:23Z. Later, at 03:21:19Z, pbeesly ran 'powershell.exe -c "Start-Process C:\Windows\System32\hostui.exe -verb runas"' (parent cmd.exe), and the matching 4104 script block was logged. This is a shortcut dropped into a startup location plus an elevated launch of hostui.exe — behaviour consistent with persistence/execution, but no evidence of forced authentication: the .lnk was not shown to point at a UNC/WebDAV path, and no outbound SMB/WebDAV authentication to an attacker-controlled host was observed. The two other .lnk files (Backup and Restore (Windows 7).lnk, System and Security.lnk) were created by Explorer.EXE in pbeesly's Recent folder and are normal shell artefacts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpESdr2 | q-10a4a50142 | ok |
| 2 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpESdr2 | q-0a24b94711 | ok |
| 3 | 2020-05-02 03:00:27.205Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\SysinternalsSuite\hostui.txt | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpMctGb | q-4c383ebcd5 | ok |
| 4 | 2020-05-02 03:21:19.323Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHoX1uOFchItj59cFt | q-e281e700a5 | ok |
| 5 | 2020-05-02 03:21:26.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Start-Process C:\Windows\System32\hostui.exe -verb runas | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwIqjTX | q-c3c5434275 | ok |

### F26 · suspicious / medium · T1552.001 · accesschk.exe wrote a file named passwordsDB on scranton during the intrusion

Evidence status: **verified**

At 2020-05-02T03:04:35.069Z on scranton.dmevals.local, Sysmon event 11 shows C:\Program Files\SysinternalsSuite\accesschk.exe (PID 9204) creating the file C:\Program Files\SysinternalsSuite\passwordsDB. This occurred inside the same pbeesly intrusion session that also ran Get-PrivateKeys and Invoke-Exfil, and the file name indicates credential material being written to disk. No command line for this accesschk invocation was captured, so the exact purpose is inferred from the file name and surrounding activity rather than observed directly.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCRb2e | q-a0f1c59987 | ok |
| 2 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\accesschk.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCRb2e | q-a0f1c59987 | ok |
| 3 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | @timestamp | 2020-05-02T03:04:35.069Z | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCRb2e | q-a0f1c59987 | ok |

### F37 · suspicious / medium · T1556.002 · Password filter DLL: DLLs written to user Temp are PowerShell Add-Type compilations, not LSA notification packages

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (user pbeesly) created C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.dll at 2020-05-02T02:58:45Z and C:\Users\pbeesly\AppData\Local\Temp\0piklvia\0piklvia.dll at 03:08:03Z, with csc.exe compiling the first one. The 02:58:45 script block (4104) shows Add-Type with kernel32 VirtualAlloc/CreateThread DllImport declarations followed by a large shellcode byte array — in-memory code execution, not a password filter. No 4657 change to 'Notification Packages', no 4663 access to LSA DLLs, and no 4104 referencing Notification/PasswordFilter/lsa were found, so no password filter was registered. The DLL writes are attacker tooling but do not implement T1556.002.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:45.621Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpfwJ-Y | q-785d1037f9 | ok |
| 2 | 2020-05-02 03:08:03.253Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Temp\0piklvia\0piklvia.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchIto6IP6U | q-785d1037f9 | ok |
| 3 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $cFIrwwpZzGzU = @"  [DllImport("kernel32.dll")]  public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwHppbR | q-a2cb9016b9 | ok |

### F41 · suspicious / medium · T1556.008 · Network Provider DLL: no NetworkProvider registry or file activity; LSASS access is memory-read credential theft

Evidence status: **verified**

No Sysmon event 13 registry set under *NetworkProvider* and no event 11 file creation under *NetworkProvider* were found, so no network provider DLL was registered. However, on scranton.dmevals.local PowerShell.exe opened lsass.exe with GrantedAccess 0x1f3fff (2020-05-02T03:05:16.623Z) and 0x1fffff (03:05:16.654Z), and wsmprovhost.exe on nashua.dmevals.local opened lsass.exe with 0x1f3fff at 03:09:29.430Z — full-access handles consistent with LSASS memory credential dumping rather than network-provider persistence. The same pbeesly session also ran accesschk.exe (03:04:34Z) and wrote C:\Program Files\SysinternalsSuite\passwordsDB, and executed Invoke-Command against NASHUA to enumerate processes with usernames (23:09:23 local).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-084c66d179 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-084c66d179 | ok |
| 3 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCRb2o | q-b47222b0c5 | ok |
| 4 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwBj58r | q-b99304f8f5 | ok |

### F52 · suspicious / medium · T1606.001 · WebDAV cookie creation (DavSetCookie) and INetCookies artifact on SCRANTON — WebDAV used as exfil channel, not forged web session

Evidence status: **verified**

On scranton.dmevals.local, rundll32.exe was launched five times between 03:08:50Z and 03:10:23Z by the WebClient svchost service with the command line 'rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav', and svchost.exe created C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies at 03:21:05Z. This is the WebDAV client storing an authentication cookie for the 192.168.0.4 webdav endpoint that the Invoke-Exfil script block targets. The cookie is a legitimate WebClient artifact generated by the attacker's own WebDAV mapping, not a forged/stolen browser cookie replayed to impersonate a user, so it is suspicious context rather than confirmed T1606.001 forgery. No browser cookie stores were touched and no PowerShell referenced cookie theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:50.846Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkx5Y1- | q-32250c5e66 | ok |
| 2 | 2020-05-02 03:08:50.846Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | C:\windows\system32\svchost.exe -k LocalService -p -s WebClient | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkx5Y1- | q-32250c5e66 | ok |
| 3 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkKNZkz | q-7be33e1697 | ok |
| 4 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-b488b306d5 | ok |

### F02 · benign / medium · T1003.002 · SAM database handle opened by lsass.exe on scranton (0xf003f / 0xf07df) — no evidence of attacker SAM dumping

Evidence status: **verified**

The only SAM-related object-access events are 4656 handles on SAM_SERVER 'SAM' (AccessMask 0xf003f) and SAM_DOMAIN 'SCRANTON' (0xf07df) on scranton.dmevals.local at 2020-05-02T03:20:46, where the requesting process is C:\Windows\System32\lsass.exe itself under the machine account SCRANTON$ — normal local SAM access by the LSA, not an external dumper. No 4663 SAM object access, no reg save / SAM hive file writes (C019, C021, C022 all zero hits), and no attacker process touched the SAM hive.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.ObjectType | SAM_SERVER | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO1YtA | q-a65cf99978 | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO1YtA | q-a65cf99978 | ok |
| 3 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.ObjectType | SAM_DOMAIN | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO1YtH | q-a65cf99978 | ok |

### F03 · benign / high · T1003.003 · No NTDS.dit / ntdsutil / vssadmin / diskshadow activity observed

Evidence status: **verified**

All NTDS checks returned zero hits: no process creation with ntdsutil/ntds/vssadmin/diskshadow command lines (C024, C027), no file creation of ntds.dit (C025), no file-change events on ntds (C026), and no PowerShell script blocks referencing ntds/vssadmin/diskshadow (C029). No domain-controller credential extraction was observed in the 2020-05-02 window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JAs | q-43ecfe49ca | ok |

### F04 · benign / medium · T1003.004 · LSA Secrets: only routine LOCAL SERVICE $MACHINE.ACC queries; no attacker SECURITY hive access

Evidence status: **verified**

The 4662 events on Object Server LSA / SecretObject 'Policy\Secrets\$MACHINE.ACC' (Query secret value, AccessMask 0x2) come from NT AUTHORITY\LOCAL SERVICE (S-1-5-19) on nashua, scranton and utica — routine machine-account secret reads by the local service. No 4663/4656/4670 events on SECURITY hive or Policy\Secrets objects (C033, C034, C035 zero hits), no reg save / SECURITY command lines (C031 zero hits) and no PowerShell referencing SECURITY/Secrets (C036 zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:02:59.000Z | nashua.dmevals.local | windows.security | win.ObjectName | Policy\Secrets\$MACHINE.ACC | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwrPVRX | q-021185c9fd | ok |
| 2 | 2020-05-02 03:02:59.000Z | nashua.dmevals.local | windows.security | user.name | LOCAL SERVICE | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwrPVRX | q-021185c9fd | ok |

### F05 · benign / high · T1003.005 · No cached domain credential access observed

Evidence status: **verified**

All cached-credential checks returned zero hits: no 4663/4656/4670 object access on SECURITY or Cache objects (C040, C041, C042) and no PowerShell script blocks referencing cache/lsass/secretsdump (C043). Nothing indicates extraction of cached domain credentials in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.ObjectName | SAM | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO1YtA | q-a65cf99978 | ok |

### F06 · benign / medium · T1003.006 · DCSync: single DS replication-right GUID access by NEWYORK$ machine account, no attacker DCSync

Evidence status: **verified**

One 4662 Directory Service Access event on newyork.dmevals.local at 2020-05-01T23:16:15 (local) shows Subject NEWYORK$ (S-1-5-18, logon 0x167EDA) accessing object %{19195a5b-6da0-11d0-afd3-00c04fd930c9} with Properties containing {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} (DS-Replication-Get-Changes). The subject is the machine account of the DC itself, not a user or attacker process, and there is no accompanying DRSUAPI/lsadump/dcsync command line (C048) or PowerShell DCSync/Invoke-Mimikatz/lsadump script block (C049). Treated as benign DC-internal replication activity rather than a DCSync attack.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.Properties | %%7688  		{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  	{19195a5b-6da0-11d0-afd3-00c04fd930c9}   | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhC87m | q-75f1bc1b13 | ok |
| 2 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhC87m | q-75f1bc1b13 | ok |

### F08 · benign / high · T1040 · netsh trace packet capture on scranton.dmevals.local is Azure Network Watcher agent telemetry, not adversary sniffing

Evidence status: **verified**

The only packet-capture activity in the Windows telemetry is a single netsh trace session on scranton.dmevals.local at 2020-05-02T03:19:17Z: 'netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl"' followed ~7 seconds later by 'netsh.exe trace stop'. Both Security 4688 and Sysmon event 1 show the creator/parent process as C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe (command line "...NetworkWatcherAgent.exe" /service), running as NT AUTHORITY\SYSTEM with LogonId 0x3e7. This is the documented Azure Network Watcher packet-capture extension behaviour (short-lived ETL capture in the agent's TEMP GUID folder), not interactive attacker use. No other capture tooling was found: no pktmon/dumpcap/windump/tcpdump/RawCap/Npcap/WinPcap command lines in Sysmon or Security 4688, no pcap/npf/Packet driver image loads (Sysmon event 6), no capture-driver service installs (7045), and no promiscuous/monitor/sniff command lines. The 7045 service installs in the window are unrelated (Java(TM) Virtual Machine Support Service via javamtsup.exe on scranton, and repeated PSEXESVC installs on nashua by user pbeesly), none of which are packet-capture drivers. In the non-overlapping zeek window (2020-04-30) the only notices are SSL::Invalid_Server_Cert self-signed certificate validation failures from 10.0.1.4 to 192.168.0.5:443 and 10.0.1.6 to 192.168.0.4:8443, with no sniffing-related notice or weird entries indicating a sniffer on the wire.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsU5KNV | q-32552377d1 | ok |
| 2 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | win.ParentProcessName | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsU5KNV | q-8fc26d30b0 | ok |
| 3 | 2020-05-02 03:19:24.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsS3MUJ | q-32552377d1 | ok |
| 4 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | win.ParentCommandLine | "C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe" /service | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkYcTxy | q-22c6d8fdba | ok |
| 5 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | user.name | SYSTEM | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkYcTxy | q-06ed42cdc8 | ok |
| 6 | 2020-04-30 00:15:18.392Z | simplerockbuild.simplerock.lan | zeek | zeek.note | SSL::Invalid_Server_Cert | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylrovu | q-bb977c26ea | ok |
| 7 | 2020-04-30 00:40:44.740Z | bobs.bigwheel.local | zeek | zeek.note | SSL::Invalid_Server_Cert | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz7ud8y | q-bd5972a02d | ok |

### F10 · benign / medium · T1056 · Benign lsass handle activity by system services and Azure agents (no input-capture tooling found)

Evidence status: **verified**

The bulk of the 326 lsass handle opens in the window are routine: svchost.exe (289 events, GrantedAccess 0x1000/0x101001 with call traces through lsm.dll), WindowsAzureTelemetryService.exe (13 events, 0x1400 via CorperfmonExt.dll performance counters), AntimalwareConfig.exe (15), wininit.exe/csrss.exe at boot (0x1fffff/0x1000000), CollectGuestLogs.exe and MsMpEng.exe (0x10 read-attributes). No keylogger driver, no input-capture service, and no GUI/web-portal capture artifacts were observed; the only anomalous lsass access is the PowerShell full-access pair reported under T1056.004. The 7045 service installs (javamtsup.exe on scranton, PSEXESVC on nashua) are not input-capture tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x101001 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkady05 | q-e34329e5b9 | ok |
| 2 | 2020-05-02 03:19:42.009Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkbfEQ2 | q-e34329e5b9 | ok |
| 3 | 2020-05-02 03:20:15.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Program Files\Windows Defender\MsMpEng.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsQ2P9A | q-588eca24c0 | ok |
| 4 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | process.executable | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWXW | q-373d8238a2 | ok |

### F11 · benign / medium · T1056.001 · No keylogging observed

Evidence status: **verified**

No keylogger indicators were found: no process command lines containing keylog/GetAsyncKeyState/SetWindowsHookEx, no PowerShell script blocks with keyboard-hook APIs, and no keyboard-filter driver service installs. Registry writes under CurrentControlSet\Services are dominated by W32Time, BAM, PSEXESVC and DFSR keys; the only 'Keyboard' paths are benign CTF KeyboardLayout / Keyboard Layout Preload values written by LogonUI.exe and winlogon.exe. The credential theft on scranton was memory-based (lsass), not keystroke capture.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.756Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\.DEFAULT\Software\Microsoft\CTF\SortOrder\AssemblyItem\0x00000409\{34745C63-B2F0-4784-8B67-5E12C8701A31}\00000000\KeyboardLayout | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkADeNe | q-8a631583d1 | ok |
| 2 | 2020-05-02 03:20:46.756Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\LogonUI.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkADeNe | q-8a631583d1 | ok |

### F12 · benign / medium · T1056.002 · No GUI input capture; consent.exe and PSCredential usage are legitimate

Evidence status: **verified**

The only processes matching credential/prompt/consent command lines are three legitimate C:\Windows\System32\consent.exe UAC consent processes. PowerShell 4103 hits are DSC/AD module cmdlets on newyork.dmevals.local (DomainAdministratorCredential, SafemodeAdministratorPassword as PSCredential objects) and pbeesly's own New-Object PSCredential / New-PSDrive WebDavShare calls on scranton, which are part of the exfiltration script rather than a fake credential prompt. No credential-prompt lookalike or GUI input capture was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:37.000Z | newyork.dmevals.local | windows.powershell | message | CommandInvocation(Test-TargetResource): "Test-TargetResource"  ParameterBinding(Test-TargetResource): name="DomainName"; value="dmevals.local"  ParameterBinding… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwDlU_o | q-9c705c9579 | ok |
| 2 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | message | CommandInvocation(New-PSDrive): "New-PSDrive"  ParameterBinding(New-PSDrive): name="Name"; value="WebDavShare"  ParameterBinding(New-PSDrive): name="PSProvider"… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwDlShi | q-9c705c9579 | ok |

### F13 · benign / medium · T1056.003 · No web portal capture observed

Evidence status: **verified**

No IIS/w3wp/appcmd process activity and no file access to wwwroot or inetpub were observed in the Windows telemetry. The zeek dataset (2020-04-30) does not overlap the Windows window, so network-side web-portal capture could not be correlated; nothing in the Windows data indicates web credential capture.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-c8a268cefa | ok |

### F14 · benign / high · T1110 · No brute-force authentication activity; credential theft on scranton was lsass memory access, not password guessing

Evidence status: **verified**

Across windows.security (2020-05-02 02:55-03:28Z) there are zero 4625 failed-logon events, zero 4771 and only one 4776 (a success, Status 0x0, for pbeesly on newyork at 23:20:40 local). All 297 4624 logons are successful and dominated by machine accounts (NEWYORK$ 123, SCRANTON$ 37, NASHUA$ 25) plus pbeesly (30). No repeated authentication attempts, no failure bursts, no password-guessing tooling. The credential access that did occur on scranton.dmevals.local was PowerShell.exe opening lsass.exe with GrantedAccess 0x1FFFFF / 0x1F3FFF at 03:05:16Z (a memory-dump access mask, T1003.001 territory), which is outside the T1110 family. The single 'net user/password' command-line hit (C097) and the 'net use/runas' hit (C119) resolve to a benign Start-Process hostui.exe -verb runas and svchost/netsh noise, not scripted authentication.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO14sT | q-94d3fb1398 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-dbb0c51341 | ok |
| 3 | 2020-05-02 03:21:19.323Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHoX1uOFchItj59cFt | q-ad942745e9 | ok |

### F15 · benign / high · T1110.001 · No password guessing: zero 4625 failures and no brute-force script blocks

Evidence status: **verified**

Checks C099-C104 returned no 4625 events in windows.security or windows.other, and no PowerShell script block referencing 4625/Failed Logon/Brute. The only 4104 blocks matching password/credential keywords are unrelated: a Get-PrivateKeys certificate-export function with a hardcoded string on scranton (pbeesly, 23:04:56), an Invoke-Exfil 7-Zip archive password on scranton (23:08:02), and AD-cmdlet help text on newyork. None of these generate repeated logon attempts. The 4648 explicit-credential logons for pbeesly (9) are psexec-driven remote execution, not guessing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-26f6b191ad | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-8fd84f54bb | ok |
| 3 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0ff | q-94d3fb1398 | ok |

### F16 · benign / medium · T1110.002 · lsass handle access by PowerShell is memory dumping, not offline password cracking

Evidence status: **verified**

C106/C107/C110/C112 hits are explained by legitimate or non-cracking behaviour: the 10 handle requests to SAM/SECURITY/NTDS objects come solely from C:\Windows\System32\lsass.exe itself, 4670 permission changes are services.exe/svchost.exe/SearchIndexer.exe housekeeping, and the single SAM-related windows.other event is the informational 16962 'Remote calls to the SAM database are being restricted' message on scranton. No hashcat/secretsdump/Invoke-Mimikatz/NTDS script blocks (C111) and no SAM/NTDS/.dit/.hiv file writes (C109). The high-privilege lsass opens (0x1FFFFF by PowerShell.exe pid 2976 on scranton at 03:05:16Z, 0x1F3FFF by wsmprovhost.exe on nashua at 03:09:29Z) indicate in-memory credential theft (T1003.001), not password cracking, so no T1110.002 activity is present.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-b559d3066c | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-b559d3066c | ok |
| 3 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.other | event.code | 16962 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWX2 | q-770cd8e1c1 | ok |

### F17 · benign / high · T1110.003 · No password spraying: no failure spikes, 4648 logons are psexec remote execution

Evidence status: **verified**

C113-C117 found no 4625/4771 events at all, so there is no spray pattern (no many-users-one-password failure burst). The 4648 explicit-credential events for pbeesly alternate between scranton (IpAddress 10.0.1.6) and nashua (ProcessName C:\Windows\PSEXESVC.exe, SubjectUserName NASHUA$) every ~20-60s between 23:11 and 23:15 local, matching four PSEXESVC service installs on nashua (7045, 23:11:39-23:15:03) — i.e. repeated psexec remote execution with known credentials, not spraying. Remaining 4648s are DWM-*/UMFD-*/SCRANTON$ logon-session noise from winlogon/wininit/taskhostw.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWV3 | q-74a49e2c5d | ok |
| 2 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.IpAddress | 10.0.1.6 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEcw | q-94d3fb1398 | ok |
| 3 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | DWM-1 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsc9wOe | q-94d3fb1398 | ok |

### F18 · benign / high · T1110.004 · No credential stuffing: no failed logons and no credential-replay tooling

Evidence status: **verified**

C302-C307 returned no 4625/4771/4776 failure events. The C305 'net/runas/psexec' command-line stack is 28 svchost.exe and 2 netsh.exe events plus one benign runas of hostui.exe, none of which replay stolen credential lists. The 4104 credential-keyword blocks (C306) are the certificate-export and 7-Zip exfil functions on scranton, which use a single hardcoded string rather than a credential list. The only successful 4776 (pbeesly, newyork, 23:20:40) is a single NTLM validation, not stuffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO14sT | q-94d3fb1398 | ok |
| 2 | 2020-05-02 03:21:27.859Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkHK8X3 | q-ad942745e9 | ok |

### F19 · benign / medium · T1111 · No MFA/credential-provider interception artifacts; lsass handle opens traced to Sysinternals accesschk token enumeration and PowerShell remoting

Evidence status: **verified**

Hunting for T1111 (MFA interception) on 2020-05-02 02:55-03:28Z across scranton/nashua/newyork/utica found no MFA-provider or credential-interception artifacts: no registry writes to SecurityProviders (C123 zero hits), no new service resembling a fake credential/MFA provider (the only 7045 installs are javamtsup.exe on scranton and repeated PSEXESVC on nashua, both installed by pbeesly), and no script block referencing MFA/token theft. The high-access lsass handle opens that could look like credential/MFA-secret reads are explainable: on scranton, PowerShell.exe (pid 2976) opened lsass with 0x1f3fff and 0x1fffff at 03:05:16, immediately after pbeesly ran C:\Program Files\SysinternalsSuite\accessChk.exe (03:04:34) and the Sysinternals readme.ps1 script block that enumerates access-token group attributes (SE_GROUP_LOGON_ID etc.) - i.e. token/privilege enumeration, not MFA interception. On nashua, wsmprovhost.exe opened lsass with 0x1f3fff at 03:09:29 with a call trace through Microsoft.PowerShell.Commands.Management.ni.dll, consistent with a PowerShell remoting session (the same pbeesly PSEXESVC/4648 activity at 03:11-03:15). The remaining lsass opens are OS components (wininit.exe, csrss.exe, svchost.exe via lsm.dll/sysmain.dll, AntimalwareConfig.exe and WindowsAzureTelemetryService.exe with 0x1400). The 4648 explicit-credential events are pbeesly re-using its own credentials to NASHUA over SMB (10.0.1.6:445) and PSEXESVC localhost logons, plus routine DWM/UMFD/winlogon and taskhostw machine-account logons - no alternate-credential or token theft. Note: the environment does show other malicious activity (an Invoke-Exfil script block on scranton using a hardcoded PSCredential for a WebDAV share at \\192.168.0.4\webdav), but that is credential use/exfiltration, not MFA interception.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-6f4d99bdeb | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-6f4d99bdeb | ok |
| 3 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCRb2o | q-604f2e4aeb | ok |
| 4 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkCwA | q-a1d8f694c6 | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-6f4d99bdeb | ok |
| 6 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-6f4d99bdeb | ok |
| 7 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEcw | q-d2c366972a | ok |
| 8 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0ff | q-d2c366972a | ok |
| 9 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | process.executable | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWXW | q-09e336aac3 | ok |
| 10 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-9e62b37784 | ok |

### F21 · benign / high · T1187 · SMB traffic in the Windows window is normal domain administration (ADMIN$/IPC$/SYSVOL) between known internal hosts

Evidence status: **verified**

All 66 Sysmon network events to ports 445/139 are System-process SMB connections between known internal addresses: newyork.dmevals.local to 10.0.0.4 and to link-local fe80::e40c:95b6:b0a7:6429, nashua/scranton to 10.0.1.6 and 10.0.0.4, utica to 10.0.0.4. The 42 Security 5140 share-access events are only \\*\IPC$, \\*\SYSVOL and \\*\ADMIN$ from machine accounts (SCRANTON$, NASHUA$, UTICA$, WEC$) and user pbeesly from 10.0.1.4/10.0.1.5/10.0.1.6/10.0.1.10 — standard domain logon-script/SYSVOL and admin-share access, with no attacker-controlled share or external SMB endpoint. The Zeek window (2020-04-30) does not overlap the Windows window; its SMB connections are 10.0.1.4 -> 10.0.1.6:445 (30), 10.0.1.4/10.0.1.6 -> 10.0.0.4:445 (10) and 10.0.1.4 -> 192.168.0.4:445 (10), all internal, with no WebDAV (80/443 to a UNC-style host) coercion observed. No 4104 script block referencing WebDAV or NTLM was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.0.4 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpIWWNw | q-6220cf1884 | ok |
| 2 | 2020-05-02 02:56:48.006Z | newyork.dmevals.local | windows.sysmon | destination.ip | fe80:0:0:0:e40c:95b6:b0a7:6429 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpizV0q | q-7014079a92 | ok |
| 3 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\SYSVOL | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwsQxHC | q-edd1344e8d | ok |
| 4 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.ShareName | \\*\ADMIN$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFUeT | q-edd1344e8d | ok |
| 5 | 2020-05-02 03:05:19.000Z | newyork.dmevals.local | windows.security | win.IpAddress | 10.0.1.10 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo6a | q-edd1344e8d | ok |

### F23 · benign / high · T1212 · wsmprovhost.exe LSASS handle on nashua.dmevals.local explained by Get-Process -IncludeUserName

Evidence status: **verified**

On nashua.dmevals.local at 2020-05-02T03:09:29Z, wsmprovhost.exe (PID 7720) opened lsass.exe with GrantedAccess 0x1F3FFF, which at first looks like credential dumping. The call trace is entirely managed code (System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll), and the PowerShell 4104 script block logged one second earlier in the same pbeesly session is 'Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" }'. Get-Process -IncludeUserName resolves each process owner via LSASS, which produces exactly this handle. No memory-read tooling, no dump file, and no further LSASS access followed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-553424fcaf | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-553424fcaf | ok |
| 3 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz-ho2U | q-d4f7867a16 | ok |

### F24 · benign / high · T1212 · Remaining LSASS handle access (svchost, wininit, csrss, Azure telemetry/antimalware) is OS and platform baseline

Evidence status: **verified**

The bulk of the 326 lsass handle events are baseline: svchost.exe (289 events, mostly 0x1000 and 0x101001 with lsm.dll call traces), wininit.exe/csrss.exe at 03:19:09 with 0x1fffff during session-manager startup, and the Azure guest agents WindowsAzureTelemetryService.exe (0x1400, CorperfmonExt.dll call trace) and AntimalwareConfig.exe (0x1400) performing performance-counter reads. All have call traces inside known signed modules and none show the UNKNOWN-module trace seen for the PowerShell access. Kerberos activity (4768/4769) is limited to normal pbeesly and machine-account TGT/TGS requests with no RC4/kerberoasting pattern, and no 4769 for a service account was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9def4\|c:\windows\system32\lsm.dll+1aa6e\|c:\windows\system32\lsm.dll+1a9c3\|c:\windows\system32\lsm.dll+65e1\|c:\windows\system32… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkady05 | q-1a4ccbce33 | ok |
| 2 | 2020-05-02 03:19:42.009Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkbfEQ2 | q-1a4ccbce33 | ok |
| 3 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\csrss.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JAu | q-1a4ccbce33 | ok |

### F28 · benign / high · T1552.002 · Registry writes touching Password/Credential keys are all OS-internal; no credential harvesting from registry observed

Evidence status: **verified**

All 17 Sysmon event 13 writes to registry paths containing Password/Credential/Secret were made by legitimate Windows components: svchost.exe writing HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength/ProviderPasswordCharacterGroups on nashua and scranton, lsass.exe writing the DeviceGuard CredentialGuard\Enabled value, services.exe creating the CredentialEnrollmentManagerUserSvc_13619b service keys and MuiCache entries, and winlogon.exe writing the PasswordExpiryNotification values for SID ...-1107. No reg query/reg save or SAM/SECURITY hive access was found (checks C156 and C158 returned zero hits). The one registry-read-and-execute script block (Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression) is a code-execution/staging trick, not credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JA2 | q-b4378a9093 | ok |
| 2 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JA2 | q-b4378a9093 | ok |
| 3 | 2020-05-02 03:20:48.264Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc_13619b\ImagePath | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkEHr1e | q-b4378a9093 | ok |
| 4 | 2020-05-02 03:21:20.841Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\S-1-5-21-1830255721-3727074217-2423397540-1107\Software\Microsoft\Windows\Winlogon\PasswordExpiryNotification\NotShownReason | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkILZ_7 | q-b4378a9093 | ok |

### F29 · benign / high · T1552.003 · No shell-history credential access observed

Evidence status: **verified**

Checks for ConsoleHost_history / PSReadLine / Get-History in PowerShell script blocks (C159), process command lines (C160) and file creation (C161) all returned zero hits, and no ConsoleHost_history file creation appeared in the sysmon file-create review. Nothing indicates the adversary read shell history for credentials.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:03.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Discovery {     $DiscoveryInfo =@()     $CurrentDir = Get-Location      $DiscoveryInfo += [PSCustomObject]@{                 CurrentDirectory = … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSwG | q-bc90677b2c | ok |

### F30 · benign / high · T1552.006 · No Group Policy Preferences / SYSVOL credential access observed

Evidence status: **verified**

Checks for Groups.xml, cpassword, gpprefdecrypt, SYSVOL in PowerShell script blocks (C166), process command lines (C167), SMB file access 5145 (C168) and file creation (C169) all returned zero hits. The only SYSVOL-related file activity was the local GroupPolicy DataStore gpt.ini write, which is normal policy processing, not GPP credential extraction.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-ada00e3527 | ok |

### F31 · benign / high · T1555 · LSASS handle access on scranton/nashua traced to process enumeration, not credential dumping

Evidence status: **verified**

On 2020-05-02 the only non-service processes opening handles to lsass.exe were PowerShell instances. On scranton.dmevals.local, PowerShell.exe (PID 2976, SYSTEM) opened lsass (PID 736) with GrantedAccess 0x1f3fff at 03:05:16.623Z; the corresponding script-block log at 03:01:03 shows the user pbeesly running 'get-process', and the 4663 object-access event at 03:05:16 records AccessMask 0x10 (%%4484) for powershell.exe against \Device\HarddiskVolume2\Windows\System32\lsass.exe. On nashua.dmevals.local, wsmprovhost.exe opened lsass (PID 728) with 0x1f3fff at 03:09:29.430Z, and the script blocks at 03:09:28-29 are 'Get-Process -IncludeUserName \| Select-Object UserName,SessionId ...' — a username/session query, not a memory dump. No procdump/comsvcs/MiniDump/sekurlsa command line exists in sysmon or security 4688 (0 hits), and no 4663 access to SAM/SECURITY/NTDS was found. The remaining lsass handles are routine (svchost 0x1000, WindowsAzureTelemetryService/AntimalwareConfig 0x1400, wininit/csrss at boot).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-465c51e42b | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-ff9874672d | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-6e2cf9f0da | ok |
| 4 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz-ho2U | q-95c6db0a9f | ok |
| 5 | 2020-05-02 03:01:03.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | get-process | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwEmW7D | q-ee0fd8520c | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x10 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo54 | q-e9bbe41279 | ok |

### F32 · benign / high · T1555.003 · No browser credential-store access (Login Data / Local State / logins.json / key4.db)

Evidence status: **verified**

Across windows.sysmon, windows.security and windows.powershell there is no creation, copy, command-line reference or script-block reference to Chrome/Edge 'Login Data' or 'Local State', Firefox 'logins.json'/'key4.db'/'signons.sqlite', or Cookies. The only file-creation hit in the browser-store pattern was C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies, a Windows service-profile cookie file, not a browser credential store. No process was observed opening chrome.exe/firefox.exe/msedge.exe memory. The scranton intrusion (user pbeesly) did perform other collection — Get-Clipboard, Invoke-ScreenCapture, Get-Keystrokes, Get-PrivateKeys exporting certs to .pfx — but none of it touched browser password stores.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | host.name | scranton.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-ff9874672d | ok |
| 2 | 2020-05-02 03:06:42.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Clipboard | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwAjopc | q-f64ce1965d | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-f64ce1965d | ok |

### F33 · benign / high · T1555.004 · No Windows Credential Manager / Vault harvesting; vaultsvc references are OS service registration

Evidence status: **verified**

No process creation, script block or registry write indicates use of cmdkey, vaultcmd, CredRead/CredEnumerate or DPAPI vault extraction. The only 'vault'/'Credential' strings in the data are OS housekeeping on scranton.dmevals.local: services.exe writing MuiCache entries for '@%SystemRoot%\system32\vaultsvc.dll,-1003' = 'Credential Manager' and for CredentialEnrollmentManager.exe, plus creation of the CredentialEnrollmentManagerUserSvc_13619b service keys at 03:20:48 — standard Windows service registration, not credential theft. The 4663 lsass object-access events carry AccessMask 0x10 (%%4484) from CollectGuestLogs.exe, MsMpEng.exe and powershell.exe, i.e. read-attribute style access, not the memory-read masks used for dumping. Credential Guard was reported disabled (LsaCfgFlagsDefault 0x0) but nothing exploited it.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:49.485Z | scranton.dmevals.local | windows.sysmon | registry.data.strings | Credential Manager | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkTWMJg | q-5533971025 | ok |
| 2 | 2020-05-02 03:20:48.264Z | scranton.dmevals.local | windows.sysmon | registry.data.strings | C:\windows\system32\CredentialEnrollmentManager.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkEHr1e | q-5533971025 | ok |
| 3 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | registry.data.strings | DWORD (0x00000000) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JAz | q-5533971025 | ok |
| 4 | 2020-05-02 03:20:15.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Program Files\Windows Defender\MsMpEng.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsQ2P9A | q-e9bbe41279 | ok |

### F34 · benign / high · T1555.005 · No password-manager (KeePass/1Password/LastPass) artifacts or access

Evidence status: **verified**

No .kdbx file creation, no keepass/1password/lastpass process creation, no script-block or message reference to a password manager anywhere in windows.sysmon, windows.security, windows.powershell or windows.other. The only password-like content found was the attacker's own hardcoded credential in the scranton exfiltration script ('$Password = "MyCozyPassw0rd!"' used to map \\192.168.0.4\webdav) and the 7-Zip archive password 'lolol' — attacker tooling, not a password store being read.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-cab12a1bfc | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-cab12a1bfc | ok |

### F35 · benign / medium · T1556 · No evidence of authentication-process modification; LSASS handle opens are routine (svchost/AV/telemetry) plus attacker-side credential access on scranton

Evidence status: **verified**

Of 326 Sysmon event 10 handle-opens against C:\windows\system32\lsass.exe, 289 come from C:\windows\system32\svchost.exe (mostly GrantedAccess 0x1000), 15 from C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\AntimalwareConfig.exe and 13 from C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe — normal security/telemetry consumers. The only high-privilege opens are from PowerShell.exe on scranton.dmevals.local at 2020-05-02T03:05:16Z (0x1f3fff and 0x1fffff) and wsmprovhost.exe on nashua.dmevals.local at 03:09:29Z (0x1f3fff), which are credential-access behaviour (LSASS memory read) rather than modification of the authentication process. No 4657 registry change to LSA/SAM/Security keys, no 4688/4104 referencing lsass/mimikatz/procdump, and no lsass/cryptdll strings in windows.other were found. Image loads into lsass-related modules are stock system DLLs (cryptdll.dll 32, samcli.dll 21, samlib.dll 17, ntdsapi.dll 14).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-084c66d179 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-084c66d179 | ok |
| 3 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JAt | q-084c66d179 | ok |

### F36 · benign / medium · T1556.001 · Domain controller authentication: only standard Kerberos/Advapi/NtLmSsp logon packages observed

Evidence status: **verified**

Across 297 event 4624 logons the LogonProcessName values are Kerberos (217), Advapi (76), User32 (2), NtLmSsp (1) and '-' (1) — all standard Windows authentication packages, with no custom or injected package. Network logons (4624 type 3) target machine accounts NEWYORK$, SCRANTON$, NASHUA$, UTICA$, WEC$ and user pbeesly, consistent with normal domain traffic. No 4104 script block or windows.other message referenced lsass/cryptdll/mimikatz. No DC authentication tampering observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:02:59.000Z | nashua.dmevals.local | windows.security | win.SubjectUserName | LOCAL SERVICE | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwrPVRX | q-321df99c74 | ok |

### F38 · benign / high · T1556.005 · Reversible encryption: no account-control or policy changes; 4657 hits are WMI Autologger registry noise

Evidence status: **verified**

No 4739 policy-change events exist, and no 4104/4688/other-channel content referenced Reversible, AllowReversiblePasswordEncryption, Set-ADAccountControl or dsmod. The 36 event 4657 registry modifications are dominated by \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\WMI\Autologger\EventLog-Application\{GUID} keys plus a SystemCertificates entry and WSMAN SafeClientList — routine system configuration, not account encryption settings.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:02:59.000Z | nashua.dmevals.local | windows.security | win.ObjectName | Policy\Secrets\$MACHINE.ACC | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwrPVRX | q-321df99c74 | ok |

### F39 · benign / medium · T1556.006 · MFA modification: no authentication-policy object changes; 4662 SecretObject reads are LOCAL SERVICE machine-account access

Evidence status: **verified**

Only 7 events matched 4662/5136. Six are 4662 reads of Policy\Secrets\$MACHINE.ACC (ObjectType SecretObject, AccessMask 0x2) by LOCAL SERVICE on nashua, scranton and utica — normal machine-account secret access. The seventh is a 4662 by NEWYORK$ on newyork.dmevals.local at 2020-05-01T23:16:15Z against object %{11487126-e2dc-4f51-acb1-1b0df0573bb5} with AccessMask 0x100 and properties listing {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} and {19195a5b-6da0-11d0-afd3-00c04fd930c9} (directory-service replication/DS-Replication-Get-Changes control access). No 4739 and no 5136 directory modifications were recorded, so no MFA/authentication policy was altered.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhC87m | q-321df99c74 | ok |
| 2 | 2020-05-02 03:03:00.000Z | scranton.dmevals.local | windows.security | win.ObjectName | Policy\Secrets\$MACHINE.ACC | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwrPVRa | q-321df99c74 | ok |

### F40 · benign / medium · T1556.007 · Hybrid identity: no federation/token-signing or directory changes; logon packages all standard

Evidence status: **verified**

No 5136 directory-service modifications were recorded at all, and the 4624 LogonProcessName distribution (Kerberos 217, Advapi 76, User32 2, NtLmSsp 1, '-' 1) shows no non-standard authentication package that would indicate a hybrid-identity/PTA or token-signing bypass. The 20,259 image-load events are overwhelmingly stock System32 DLLs (ntdll.dll, KernelBase.dll, kernel32.dll, rpcrt4.dll, sechost.dll ...); no unusual identity-provider DLL was identified.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.ObjectType | %{19195a5b-6da0-11d0-afd3-00c04fd930c9} | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhC87m | q-321df99c74 | ok |

### F42 · benign / medium · T1557 · No adversary-in-the-middle positioning observed; SMB/DNS traffic is normal domain traffic

Evidence status: **verified**

Across the 2020-05-02 Windows window (02:55-03:28Z) and the 2020-04-30 Zeek window (00:06-00:45Z) there is no evidence of a host positioned between peers. All Sysmon 3 SMB (445) connections are made by the System process to the domain controller 10.0.0.4 and to nashua 10.0.1.6, i.e. ordinary domain/SMB traffic, not relay to an attacker host. Zeek conn records show only three source MACs (00:0d:3a:13:e3:69, 00:0d:3a:4d:42:f2, fc:bd:67:e1:a9:c1) and the destination MAC 12:34:56:78:9a:bc is a synthetic placeholder value, not a duplicated real MAC spanning many IPs. The only non-internal network logon source, 172.18.39.2, is the WEC collector (win.host wec.internal.cloudapp.net) authenticating pbeesly with NTLM V2, which is expected log forwarding. Note: the malicious javamtsup.exe service on scranton is execution/persistence activity, not AiTM.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:57.321Z | nashua.dmevals.local | windows.sysmon | destination.ip | 10.0.0.4 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkJMpSF | q-aaf2396053 | ok |
| 2 | 2020-05-02 03:14:42.609Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.1.6 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkovmKh | q-aaf2396053 | ok |
| 3 | 2020-04-30 00:06:38.899Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4ut | q-118b0420e2 | ok |
| 4 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.IpAddress | 172.18.39.2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO1ovv | q-90f71fed0c | ok |

### F43 · benign / medium · T1557.001 · Name resolution and SMB authentication show no poisoning or relay; wpad query failed with no answer

Evidence status: **verified**

Sysmon 22 DNS queries on the Windows hosts are routine: DC/service discovery (_ldap._tcp..., NEWYORK/SCRANTON/NASHUA), Microsoft telemetry and update endpoints, and reverse lookups. The single 'wpad' query on scranton came from svchost.exe (SYSTEM) and returned QueryStatus 9003 with no results, so no rogue WPAD/proxy answer was delivered. The '..localmachine' queries from spoolsv.exe resolved to the legitimate host address 10.0.1.4. Zeek DNS shows only NOERROR (25) and NXDOMAIN (12) responses with no anomalous answer redirection, and SMB (445) destinations are limited to 10.0.1.6, 10.0.0.4 and 192.168.0.4. The odd DNS-querying binary C:\ProgramData\victim\â€®cod.3aka3.scr on scranton only resolved its own host name and its own IPv6 PTR, which is not name-resolution poisoning.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:31.333Z | scranton.dmevals.local | windows.sysmon | win.QueryStatus | 9003 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchIttzHCIM | q-9cc528409b | ok |
| 2 | 2020-05-02 03:19:48.135Z | scranton.dmevals.local | windows.sysmon | win.QueryResults | 10.0.1.4; | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItps_TYH | q-159de1299f | ok |
| 3 | 2020-05-02 02:56:00.762Z | scranton.dmevals.local | windows.sysmon | win.QueryName | SCRANTON | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpk1AhU | q-ea079a2631 | ok |
| 4 | 2020-04-30 00:06:38.903Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 10.0.0.4 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4ud | q-76a5671ee3 | ok |

### F44 · benign / medium · T1557.002 · No ARP cache poisoning indicators; MAC-to-IP mapping is consistent

Evidence status: **verified**

Zeek conn records in the 2020-04-30 window contain only three distinct source MAC addresses and no single MAC appearing across many unrelated IPs, which is the hallmark of ARP cache poisoning. The dominant destination MAC 12:34:56:78:9a:bc is a synthetic placeholder value present on 559 records, not a real attacker NIC claiming multiple IPs. Host-to-host flows stay on their expected paths (10.0.1.4 and 10.0.1.6 to the DC 10.0.0.4, plus broadcast to 10.0.1.255), with no evidence of traffic being redirected through an unexpected peer.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:06:38.899Z | simplerockbuild.simplerock.lan | zeek | zeek.orig_l2_addr | 00:0d:3a:4d:42:f2 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4ut | q-118b0420e2 | ok |
| 2 | 2020-04-30 00:06:38.899Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4ut | q-118b0420e2 | ok |
| 3 | 2020-04-30 00:08:43.385Z | bobs.bigwheel.local | zeek | destination.ip | 10.0.1.255 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8vYpc | q-296d32a07b | ok |

### F46 · benign / medium · T1558 · No Kerberos ticket theft or forgery observed; all Kerberos traffic is normal AES/preauth traffic

Evidence status: **verified**

Across windows.security (2020-05-02 02:55-03:28Z) the only Kerberos events are 14x 4768 and 28x 4769, all on newyork.dmevals.local, all with TicketEncryptionType 0x12 (AES256), Status 0x0 and PreAuthType 2. Service tickets are requested only for machine accounts (NEWYORK$, NASHUA$, SCRANTON$, WEC$) and krbtgt by pbeesly/SCRANTON$ from 10.0.1.4/10.0.1.6 - ordinary workstation-to-DC ticket acquisition, no RC4 downgrade, no anomalous SPN sweep. The only lsass access with broad rights came from PowerShell.exe (0x1fffff/0x1f3fff) on scranton and wsmprovhost.exe (0x1f3fff) on nashua, but no ticket/hash artifacts followed: no .kirbi/.ccache files, no sekurlsa/klist/rubeus/kerberos command lines, and the only dumps written were WerFault crash dumps. The PowerShell 800 event that matched 'lsass' was merely a Get-Process listing. Zeek (2020-04-30, non-overlapping window) shows 14 AS and 11 TGS requests with no roasting burst.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqO44i | q-270d24dc1e | ok |
| 2 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEcb | q-6b045061ce | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-e584340b7f | ok |
| 4 | 2020-05-02 03:05:27.395Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\WER\Temp\WER51F5.tmp.dmp | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpBPBlG | q-74a3c2956b | ok |

### F47 · benign / medium · T1558.001 · No golden ticket indicators: krbtgt tickets are legitimate AES TGT-service requests

Evidence status: **verified**

The 3 krbtgt service-ticket requests (4769) on newyork.dmevals.local at 2020-05-01T23:04:04, 23:19:13 and 23:19:15 local time are for pbeesly@DMEVALS.LOCAL and SCRANTON$@DMEVALS.LOCAL, all AES (0x12), Status 0x0, TicketOptions 0x60810010, and each is preceded by a matching 4768 TGT request with PreAuthType 2 from the same client (10.0.1.4) - i.e. normal TGT renewal/service use, not forged tickets. No krbtgt/golden/mimikatz strings in PowerShell or other Windows channels, and no lsass dump artifacts. The PowerShell 800 hit was a benign Get-Process output listing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItse-36P | q-270d24dc1e | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TicketOptions | 0x60810010 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItse-36P | q-270d24dc1e | ok |
| 3 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItse-35u | q-6b045061ce | ok |
| 4 | 2020-05-02 03:01:04.000Z | scranton.dmevals.local | windows.powershell | win.Category | Pipeline Execution Details | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwEmm4J | q-61f696747b | ok |

### F48 · benign / medium · T1558.002 · No silver ticket indicators: service tickets are AES for machine accounts only

Evidence status: **verified**

All 28 TGS requests on newyork.dmevals.local target machine accounts (NEWYORK$ 11, NASHUA$ 10, SCRANTON$ 3, WEC$ 1) plus krbtgt 3, all encrypted with 0x12 (AES) and Status 0x0, requested by pbeesly@DMEVALS.LOCAL or SCRANTON$@DMEVALS.LOCAL from 10.0.1.4/10.0.1.6. No RC4 (0x17) service tickets, no unusual service accounts, and no silver/ticket/kirbi strings in PowerShell. The wsmprovhost.exe lsass access on nashua (0x1f3fff) has a call trace through System.ni.dll / Microsoft.PowerShell.Commands.Management.ni.dll, consistent with PowerShell remoting activity rather than a service-account hash dump, and no ticket files were written.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NASHUA$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjF_4Y | q-0f9ca2bcd9 | ok |
| 2 | 2020-05-02 03:19:14.000Z | newyork.dmevals.local | windows.security | win.ServiceName | WEC$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItse-34r | q-9c6b34e605 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-794b4fe642 | ok |

### F49 · benign / medium · T1558.003 · No Kerberoasting: no RC4 service tickets and no SPN enumeration

Evidence status: **verified**

Kerberoasting requires RC4-encrypted TGS replies for user/service accounts. All 28 4769 events carry TicketEncryptionType 0x12 (AES256) and Status 0x0, and the requested services are only machine accounts and krbtgt - no user SPNs were requested. No kerberoast/Invoke-Kerberoast/SPN/Rubeus strings appear in PowerShell or other Windows channels, and no kerberos/ticket/klist command lines exist in Sysmon process creation. Zeek kerberos logs (2020-04-30, separate window) show 14 AS and 11 TGS requests, no roasting burst.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo73 | q-0f9ca2bcd9 | ok |
| 2 | 2020-05-02 03:20:45.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO1osp | q-9c6b34e605 | ok |

### F50 · benign / medium · T1558.004 · No AS-REP roasting: all TGT requests used preauthentication and succeeded

Evidence status: **verified**

All 14 4768 events on newyork.dmevals.local have PreAuthType 2 (preauthentication required) and Status 0x0, for pbeesly (9) and SCRANTON$ (5) from 10.0.1.4/10.0.1.6. There are no failed TGT requests (no 0x18/0x25 statuses) and no asreproast/GetNPUsers/DontReqPreAuth strings in Sysmon command lines, PowerShell or other Windows channels, so no account without preauthentication was targeted.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0e9 | q-6b045061ce | ok |
| 2 | 2020-05-02 03:11:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0e9 | q-6b045061ce | ok |

### F53 · benign / medium · T1606.002 · No SAML/token-signing forgery observed; Kerberos and logon activity is ordinary domain authentication

Evidence status: **verified**

No evidence of forged SAML tokens or token-signing certificate abuse. Searches for SAML/ADFS/NotOnOrAfter/token-signing strings in PowerShell script blocks and windows.other messages returned zero hits, and no HTTP traffic to an ADFS endpoint exists in the zeek window. The 297 successful 4624 logons are dominated by Kerberos (217) and Advapi (76) with only 2 User32 and 1 NtLmSsp, and the zeek Kerberos records are only AS (14) and TGS (11) requests between 10.0.1.4/10.0.1.6 and the DC 10.0.0.4 — normal domain authentication. The 4648 explicit-credential events are explained by the attacker's PsExec usage (pbeesly to NASHUA, PSEXESVC.exe on nashua) and by routine DWM/UMFD/winlogon localhost logons, not by forged federated tokens. Note the zeek window (2020-04-30) does not overlap the Windows telemetry (2020-05-02), so network-side SAML use cannot be fully excluded.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:04.000Z | newyork.dmevals.local | windows.security | win.LogonProcessName | Kerberos | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjGP6n | q-b473b28c35 | ok |
| 2 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\winlogon.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsc9wOe | q-56f43f21f1 | ok |

### F54 · benign / high · T1621 · No MFA request generation observed; zeek hits are internal WebDAV and internal TLS traffic

Evidence status: **verified**

The two zeek hits flagged for T1621 are not MFA-related. The 443 connections are internal host-to-host TLS flows from 10.0.1.4 to 192.168.0.5 (zeek service 'ssl', conn_state SF, 437 bytes out / 204450 bytes in) observed by simplerockbuild.simplerock.lan on 2020-04-30T00:15:18Z. The 62 HTTP records all go to a single internal destination 192.168.0.4 on port 80; the sampled event is a WebDAV client (user_agent 'DavClnt') OPTIONS / request answered 403 Forbidden. No external identity/MFA provider (e.g. Okta, Azure AD, Duo) appears in DNS or TLS server names, and no MFA/2FA/authenticator/one-time-code strings exist in windows.other messages or windows.powershell 4104 script blocks. Windows security shows no 4625 failed logons at all and no authentication-service processes or objects matching auth/mfa. The genuine malicious activity in this window (pbeesly on scranton.dmevals.local running Invoke-SeaDukeStage, Invoke-Exfil, Invoke-Persistence, Invoke-ScreenCapture) is credential-access-adjacent tradecraft but contains no MFA prompt generation, so T1621 is not observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:15:18.365Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 192.168.0.5 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4uo | q-bdfa5a4508 | ok |
| 2 | 2020-04-30 00:15:18.365Z | simplerockbuild.simplerock.lan | zeek | zeek.service | ssl | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4uo | q-bdfa5a4508 | ok |
| 3 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | zeek.user_agent | DavClnt | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4uv | q-9d8ae4b695 | ok |
| 4 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | zeek.status_code | 403 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4uv | q-9d8ae4b695 | ok |
| 5 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwBjiC8 | q-ef7ebf1be0 | ok |

### F45 · not_observed / medium · T1557.003 · No DHCP spoofing activity; no DHCP traffic or DHCP-related events present

Evidence status: **verified**

No DHCP spoofing indicators exist in any dataset. A Sysmon 3 search for UDP ports 67/68 returned zero rows, so no host contacted or impersonated a DHCP server. The windows.other System channel contains no DHCP-server/client event codes (1341/1342/1020/1063 returned zero hits), windows.powershell has no DHCP-related content, and Zeek UDP log types are limited to conn and dns with no DHCP log. The only UDP service ports observed are 53, 138, 123, 137, 389 and 1900, all normal.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:57.321Z | nashua.dmevals.local | windows.sysmon | destination.port | 445 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkJMpSF | q-aaf2396053 | ok |
| 2 | 2020-04-30 00:06:38.899Z | simplerockbuild.simplerock.lan | zeek | network.transport | udp | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4ut | q-118b0420e2 | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Signed Store app self-restarting; only produced WerFault crash reports, no credential access. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | PyInstaller-packed payload in C:\Windows\Temp started four times by C:\Windows\PSEXESVC.exe as pbeesly (PsExec from scranton with cleartext creds); spawned powe… |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Dropped by the python payload into C:\Windows\Temp and run by powershell.exe with '-hpfGzq5yKw' to create a password-protected archive of harvested user files; … |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Dropped by the python payload and run from cmd.exe to securely delete Rar.exe and both working.zip archives — anti-forensics of the credential-collection output… |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure guest agent diagnostic collector; its lsass handle (0x1410) is the standard guest-log read and appears on all four hosts. |
| newyork.dmevals.local | C:\Windows\System32\conhost.exe | 3 | C:\WindowsAzure\Packages\CollectGuestLogs.exe, C:\Windows\System32\cmd.exe, C:\W… | benign | Console host spawned by normal cmd/dsregcmd/CollectGuestLogs activity on newyork. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher extension binary started by services.exe/cmd.exe; runs netsh diagnostics, no credential access. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure IaaS antimalware extension configuration helper started by WindowsAzureGuestAgent. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure VM custom script extension handler; standard platform component. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure AD domain-join extension handler; standard platform component. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler, signed updater component. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler (64-bit), signed updater component. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Google Update service/updater started by services.exe/svchost; routine software update activity. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Run by powershell.exe on scranton at 03:04:34 and wrote C:\Program Files\SysinternalsSuite\passwordsDB — attacker tooling enumerating access to credential store… |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Launched four times by powershell.exe with cleartext domain credentials to run C:\Windows\Temp\python.exe on \\NASHUA — lateral movement carrying the credential… |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Run by powershell.exe to wipe the dropped .scr, Draft.Zip and SysinternalsSuite.zip on scranton — anti-forensics of the intrusion. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Windows Defender service; its lsass handle (0x1fffff) is normal AV scanning behaviour. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Windows Defender network inspection service started by services.exe. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Suspiciously named screen-saver binary in C:\ProgramData\victim started by explorer.exe with /S; it spawned cmd.exe and conhost.exe and was later wiped with sde… |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Invoked twice by powershell.exe with @response files in %TEMP% (qkbkqqbs, 0piklvia) producing qkbkqqbs.dll and 0piklvia.dll — runtime compilation of attacker .N… |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Started by powershell.exe via 'Start-Process C:\Windows\System32\hostui.exe -verb runas' — elevation/UAC-abuse step tied to the hostui.lnk persistence anchor. |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | Three sdclt.exe starts from cmd.exe at 02:58:42-43 immediately before the csc.exe Add-Type compilation; sdclt is a known UAC-bypass binary, consistent with the … |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent firewall helper started by WindowsAzureGuestAgent. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent volume discovery utility. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure Windows guest agent service, standard platform component. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | 1 | C:\Windows\System32\services.exe | benign | Azure telemetry service, standard platform component. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\WaAppAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure agent host process, standard platform component. |
| scranton.dmevals.local | C:\WindowsAzure\SecAgent\WaSecAgentProv.exe | 2 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure security agent provider, standard platform component. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\Plugins\VFPl… | 1 | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | benign | Azure network agent plugin, standard platform component. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | 1 | C:\Windows\System32\services.exe | benign | Azure network agent service, standard platform component. |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | Hands-on-keyboard credential-access campaign by pbeesly on scranton: hidden encoded PowerShell, Sysinternals accesschk, private-key/cert export, keystroke capture, clipboard theft, plus LSASS full-access handle. |
| T1003.001 LSASS Memory | malicious | wsmprovhost.exe as pbeesly opened lsass.exe with 0x1f3fff on nashua.dmevals.local (Sysmon 10 and Security 4663), a new host beyond the scranton anchors; csc.exe Add-Type compilation preceded it on scranton. |
| T1003.002 Security Account Manager | benign | Only lsass.exe itself (SCRANTON$) opened SAM_SERVER/SAM_DOMAIN handles; no reg save, no SAM hive file access, no attacker process touching SAM. |
| T1003.003 NTDS | not_observed | No ntdsutil/vssadmin/diskshadow process, no ntds.dit file creation or modification, no PowerShell referencing ntds. |
| T1003.004 LSA Secrets | benign | Only routine LOCAL SERVICE queries of Policy\Secrets\$MACHINE.ACC; no SECURITY hive or Policy\Secrets object access by any other principal. |
| T1003.005 Cached Domain Credentials | not_observed | No object access on SECURITY/Cache objects and no PowerShell referencing cache/secretsdump. |
| T1003.006 DCSync | benign | Single DS-Replication-Get-Changes GUID access on newyork by the DC's own machine account NEWYORK$; no DRSUAPI/lsadump/dcsync tooling or script blocks. |
| T1040 Network Sniffing | benign | Only capture activity is a short netsh trace start/stop on scranton.dmevals.local spawned by the Azure Network Watcher agent (NetworkWatcherAgent.exe /service) as SYSTEM, writing an ETL to the agent's TEMP GUID folder — … |
| T1056 Input Capture | malicious | Input/credential capture tooling present on scranton: PowerShell toolkit (Get-PrivateKeys certificate export, Invoke-Exfil) plus full-access lsass handle; other lsass access is benign system/agent activity. |
| T1056.001 Keylogging | not_observed | No keylogger processes, keyboard-hook script blocks, or keyboard filter driver installs; registry 'Keyboard' hits are benign CTF KeyboardLayout values written by LogonUI/winlogon. |
| T1056.002 GUI Input Capture | not_observed | Only legitimate consent.exe UAC processes and DSC/AD PSCredential parameter bindings; no fake credential prompt or GUI capture. |
| T1056.003 Web Portal Capture | not_observed | No IIS/w3wp/appcmd activity or wwwroot/inetpub access in Windows telemetry; zeek window does not overlap. |
| T1056.004 Credential API Hooking | malicious | PowerShell.exe (PID 2976, pbeesly) on scranton opened lsass with 0x1f3fff and 0x1fffff with an UNKNOWN-module call trace, corroborated by 4656/4663 lsass access events. |
| T1110 Brute Force | not_observed | Zero 4625/4771 failures in windows.security and windows.other; all 297 4624 logons successful. Credential access on scranton was lsass memory access (0x1FFFFF by PowerShell.exe), not brute force. |
| T1110.001 Password Guessing | not_observed | No failed logons and no brute-force/4625-referencing script blocks; password-keyword 4104 hits are certificate export and 7-Zip archive passwords. |
| T1110.002 Password Cracking | not_observed | No hashcat/secretsdump/Mimikatz/NTDS tooling or hive file writes; SAM/NTDS handle requests come only from lsass.exe itself and the 16962 event is an informational SAM restriction notice. |
| T1110.003 Password Spraying | not_observed | No failure spikes; repeated 4648 logons for pbeesly correlate with four PSEXESVC service installs on nashua, i.e. psexec remote execution, not spraying. |
| T1110.004 Credential Stuffing | not_observed | No failed authentications and no credential-list replay tooling; net/runas command lines are svchost/netsh noise and one benign hostui.exe runas. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA/credential-provider interception evidence: zero registry writes to SecurityProviders, no fake credential/MFA provider service (only javamtsup.exe and PSEXESVC installs by pbeesly), no MFA/token-harvesting script b… |
| T1187 Forced Authentication | not_observed | No forced-authentication activity: SMB (445/139) traffic is only System-process connections between known internal hosts (10.0.0.4, 10.0.1.4/5/6/10, link-local fe80::e40c:95b6:b0a7:6429) and share access is limited to IP… |
| T1212 Exploitation for Credential Access | suspicious | On scranton.dmevals.local, PowerShell.exe running as DMEVALS\pbeesly opened lsass.exe with GrantedAccess 0x1FFFFF/0x1F3FFF (read-from-process-memory, duplicate-handle) at 03:05:16Z, with an UNKNOWN-module call trace, ins… |
| T1539 Steal Web Session Cookie | not_observed | no status submitted |
| T1552 Unsecured Credentials | malicious | Cleartext domain password 'Fl0nk3rt0n!T0by' embedded in PsExec64 command lines used from scranton to authenticate to nashua. |
| T1552.001 Credentials In Files | malicious | python.exe payload on nashua enumerated the user profile for *pass*/*psw*/*login*/*sifr*/*vpn*/*.pst files and archived them into a password-protected RAR; accesschk.exe wrote passwordsDB on scranton. |
| T1552.002 Credentials in Registry | benign | All Password/Credential registry writes came from svchost, lsass, services and winlogon; no reg query/save or SAM/SECURITY access. |
| T1552.003 Shell History | not_observed | No ConsoleHost_history, PSReadLine or Get-History activity in script blocks, command lines or file creation. |
| T1552.004 Private Keys | malicious | Get-PrivateKeys exported all LocalMachine certificates to C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx via Export-PfxCertificate on scranton. |
| T1552.006 Group Policy Preferences | not_observed | No Groups.xml, cpassword, gpprefdecrypt or SYSVOL access in PowerShell, process, SMB 5145 or file-create telemetry. |
| T1555 Credentials from Password Stores | benign | All lsass handle events are routine service access (svchost 0x1000, telemetry/AV 0x1400, boot-time wininit/csrss) or PowerShell process enumeration (get-process / Get-Process -IncludeUserName); no dumping tooling or dump… |
| T1555.003 Credentials from Web Browsers | not_observed | No access, copy or reference to browser credential stores (Login Data, Local State, logins.json, key4.db, Cookies) in sysmon, security or PowerShell logs. |
| T1555.004 Windows Credential Manager | not_observed | No cmdkey/vaultcmd/CredRead activity; vaultsvc and CredentialEnrollmentManager strings are OS MuiCache/service-registration writes by services.exe. |
| T1555.005 Password Managers | not_observed | No .kdbx files, no KeePass/1Password/LastPass processes or script references; only attacker-embedded credentials in the exfil script. |
| T1556 Modify Authentication Process | not_observed | LSASS handle opens are dominated by svchost.exe (289), Azure antimalware (15) and Azure telemetry (13); no registry/file modification of the authentication process was found. |
| T1556.001 Domain Controller Authentication | not_observed | Only standard logon packages (Kerberos, Advapi, User32, NtLmSsp) in 4624 events; no DC authentication tampering. |
| T1556.002 Password Filter DLL | not_observed | Temp DLLs on scranton are PowerShell Add-Type/csc compilations for shellcode execution; no Notification Packages registry change or LSA DLL access. |
| T1556.005 Reversible Encryption | not_observed | No 4739 events and no reversible-encryption related commands; 4657 hits are WMI Autologger registry noise. |
| T1556.006 Multi-Factor Authentication | not_observed | Only routine 4662 $MACHINE.ACC reads by LOCAL SERVICE and one NEWYORK$ replication-control access; no 5136/4739 policy changes. |
| T1556.007 Hybrid Identity | not_observed | No 5136 directory modifications and no non-standard authentication packages indicating hybrid-identity bypass. |
| T1556.008 Network Provider DLL | not_observed | No NetworkProvider registry (event 13) or file (event 11) activity; the LSASS full-access handles from PowerShell/wsmprovhost are credential dumping, not network provider registration. |
| T1557 Adversary-in-the-Middle | benign | SMB (445) connections are only System-process traffic to the DC 10.0.0.4 and nashua 10.0.1.6; the sole external logon source 172.18.39.2 is the WEC collector. No host is positioned between peers. |
| T1557.001 Name Resolution Poisoning and SMB Relay | benign | DNS queries are routine DC/telemetry lookups; the one wpad query from svchost returned QueryStatus 9003 with no answer, and Zeek DNS shows only NOERROR/NXDOMAIN with no redirected answers. SMB destinations are internal o… |
| T1557.002 ARP Cache Poisoning | benign | Only three source MACs in Zeek conn data and no MAC spanning many IPs; the 12:34:56:78:9a:bc destination MAC is a synthetic placeholder, not a real poisoning indicator. |
| T1557.003 DHCP Spoofing | not_observed | Zero Sysmon connections to UDP 67/68, no DHCP event codes in windows.other, no DHCP content in PowerShell logs, and no DHCP log type in Zeek. |
| T1558 Steal or Forge Kerberos Tickets | not_observed | Only 14x4768 and 28x4769 Kerberos events, all AES (0x12), Status 0x0, PreAuthType 2, for machine accounts/krbtgt; no ticket files, no ticket-dumping tooling, no RC4 downgrade. Broad lsass access by PowerShell/wsmprovhost… |
| T1558.001 Golden Ticket | not_observed | krbtgt 4769 requests are legitimate AES tickets preceded by matching preauthenticated 4768 requests from the same client; no krbtgt/golden/mimikatz strings and no lsass dump artifacts. |
| T1558.002 Silver Ticket | not_observed | Service tickets are AES for machine accounts (NEWYORK$, NASHUA$, SCRANTON$, WEC$) only; no RC4, no unusual service accounts, no silver/kirbi strings. |
| T1558.003 Kerberoasting | not_observed | No RC4 service tickets, no user SPNs requested, no kerberoast/SPN/Rubeus strings, no kerberos/klist command lines; Zeek shows no TGS burst. |
| T1558.004 AS-REP Roasting | not_observed | All 4768 requests used PreAuthType 2 with Status 0x0; no failed TGT requests and no asreproast/GetNPUsers/DontReqPreAuth activity. |
| T1606 Forge Web Credentials | malicious | On scranton.dmevals.local, pbeesly ran attacker tooling from C:\Program Files\SysinternalsSuite: PowerShell opened lsass.exe with 0x1f3fff/0x1fffff access, token-attribute enumeration (Get-AttributesMask), accesschk.exe,… |
| T1606.001 Web Cookies | suspicious | rundll32 davclnt.dll,DavSetCookie for http://192.168.0.4/webdav and an INetCookies file created by svchost on SCRANTON show WebDAV credential-cookie handling tied to the attacker's exfil share, but this is a WebClient ar… |
| T1606.002 SAML Tokens | not_observed | Zero hits for SAML/ADFS/NotOnOrAfter/token-signing in PowerShell and windows.other, no ADFS HTTP in zeek; 4624 logons are Kerberos/Advapi dominated and zeek Kerberos shows only AS/TGS requests to the DC. 4648 events are … |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | No MFA/2FA/authenticator/one-time-code strings in windows.other messages or windows.powershell 4104 script blocks; no 4625 failed logons in windows.security; no auth/MFA service or process names. The flagged zeek hits ar… |
| T1649 Steal or Forge Authentication Certificates | malicious | On scranton.dmevals.local, user pbeesly's PowerShell session ran a Get-PrivateKeys function (Path C:\Program Files\SysinternalsSuite\readme.ps1) that recursively enumerated cert:\LocalMachine and exported every certifica… |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 5 hits | 0 hits | 10984 hits | 1099 hits | n/a |
| T1003.001 LSASS Memory | 5 hits | 0 hits | 103 hits | 330 hits | n/a |
| T1003.002 Security Account Manager | 5 hits | 0 hits | 6 hits | 11 hits | n/a |
| T1003.003 NTDS | 5 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.004 LSA Secrets | 5 hits | 0 hits | 0 hits | 327 hits | n/a |
| T1003.005 Cached Domain Credentials | 5 hits | 0 hits | 0 hits | 331 hits | n/a |
| T1003.006 DCSync | 5 hits | 0 hits | 14 hits | 0 hits | 123 hits |
| T1040 Network Sniffing | 5 hits | 0 hits | 2 hits | 1 hits | 613 hits |
| T1056 Input Capture | 5 hits | 0 hits | 29 hits | 652 hits | 53 hits |
| T1056.001 Keylogging | 5 hits | 0 hits | 29 hits | 1683 hits | 53 hits |
| T1056.002 GUI Input Capture | 5 hits | 13 hits | 3 hits | 3 hits | 53 hits |
| T1056.003 Web Portal Capture | 5 hits | 2 hits | 0 hits | 8 hits | 62 hits |
| T1056.004 Credential API Hooking | 0 hits | 0 hits | 13 hits | 857 hits | n/a |
| T1110 Brute Force | 0 hits | 4 hits | 0 hits | 1 hits | n/a |
| T1110.001 Password Guessing | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1110.002 Password Cracking | 1 hits | 0 hits | 153 hits | 326 hits | n/a |
| T1110.003 Password Spraying | 0 hits | 4 hits | 15 hits | 1 hits | n/a |
| T1110.004 Credential Stuffing | 0 hits | 4 hits | 0 hits | 31 hits | n/a |
| T1111 Multi-Factor Authentication Interception | 5 hits | 3 hits | 312 hits | 326 hits | n/a |
| T1187 Forced Authentication | 4 hits | 0 hits | 163 hits | 69 hits | 50 hits |
| T1212 Exploitation for Credential Access | 6 hits | 0 hits | 42 hits | 652 hits | n/a |
| T1539 Steal Web Session Cookie | 0 hits | 13 hits | 460 hits | 162 hits | n/a |
| T1552 Unsecured Credentials | 4 hits | 2 hits | 0 hits | 61 hits | n/a |
| T1552.001 Credentials In Files | 4 hits | 1 hits | 312 hits | 27 hits | n/a |
| T1552.002 Credentials in Registry | n/a | 5 hits | 0 hits | 17 hits | n/a |
| T1552.003 Shell History | n/a | 0 hits | n/a | 0 hits | n/a |
| T1552.004 Private Keys | n/a | 1 hits | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | n/a | 0 hits | 0 hits | 0 hits | n/a |
| T1555 Credentials from Password Stores | n/a | 3 hits | 6 hits | 653 hits | n/a |
| T1555.003 Credentials from Web Browsers | n/a | 0 hits | 0 hits | 1 hits | n/a |
| T1555.004 Windows Credential Manager | 2 hits | 3 hits | 0 hits | 326 hits | n/a |
| T1555.005 Password Managers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556 Modify Authentication Process | 0 hits | 0 hits | 0 hits | 401 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | 0 hits | 530 hits | 359 hits | n/a |
| T1556.002 Password Filter DLL | 10 hits | 0 hits | 6 hits | 76 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 5494 hits | 36 hits | 0 hits | n/a |
| T1556.006 Multi-Factor Authentication | n/a | 0 hits | 7 hits | n/a | n/a |
| T1556.007 Hybrid Identity | n/a | n/a | 297 hits | 20259 hits | n/a |
| T1556.008 Network Provider DLL | n/a | n/a | 36 hits | 326 hits | n/a |
| T1557 Adversary-in-the-Middle | n/a | n/a | 10977 hits | 1310 hits | 2815 hits |
| T1557.001 Name Resolution Poisoning and SMB Relay | n/a | n/a | 241 hits | 147 hits | 297 hits |
| T1557.002 ARP Cache Poisoning | n/a | n/a | n/a | 1310 hits | 1288 hits |
| T1557.003 DHCP Spoofing | 216 hits | 0 hits | 0 hits | 308 hits | 115 hits |
| T1558 Steal or Forge Kerberos Tickets | 1 hits | 0 hits | 518 hits | 652 hits | 35 hits |
| T1558.001 Golden Ticket | 0 hits | 1 hits | 268 hits | 326 hits | 35 hits |
| T1558.002 Silver Ticket | 1 hits | 0 hits | 84 hits | 326 hits | 35 hits |
| T1558.003 Kerberoasting | 0 hits | 0 hits | 396 hits | 326 hits | 35 hits |
| T1558.004 AS-REP Roasting | 0 hits | 0 hits | 42 hits | 0 hits | 35 hits |
| T1606 Forge Web Credentials | 0 hits | 1 hits | 312 hits | 326 hits | n/a |
| T1606.001 Web Cookies | 0 hits | 0 hits | 312 hits | 1 hits | 502 hits |
| T1606.002 SAML Tokens | 0 hits | 0 hits | 312 hits | 326 hits | 70 hits |
| T1621 Multi-Factor Authentication Request Generatio… | 0 hits | 0 hits | 0 hits | n/a | 66 hits |
| T1649 Steal or Forge Authentication Certificates | 0 hits | 1 hits | 64 hits | 1 hits | 826 hits |

Cells: 265, gaps: 0.

## Queries

Every MCP tool call of this run (1224), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-3a0f68ac11 | scope | list_data_sources | {} | None |  |
| q-81989b2588 | scope | get_registry | {} | None |  |
| q-ff4e6d016d | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-10f5f2fbec | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-4b8097bf50 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-9a243a7921 | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-f1b2022236 | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-18c3ac095c | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 200, "sub_field": null} | 447 |  |
| q-6844b5f721 | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-38eb169790 | check C003 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-616283f3b7 | check C004 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-021185c9fd | check C005 | search | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 7 | F04 |
| q-a0d46f0fd6 | check C006 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*procdump* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*ntds*)", "time_from": null, "time_to": nu… | 0 |  |
| q-723cf45262 | check C007 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-18b371166e | check C008 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-43ecfe49ca | check C009 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*comsvcs* OR process.command_line:*procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 1 | F03 |
| q-b83f7cb7e6 | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*lsass* OR win.TargetFilename:*.dmp)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 2 |  |
| q-69bd648a47 | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-cafb306698 | check C012 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line… | 0 |  |
| q-085b16d436 | check C013 | search | {"dataset": "windows.security", "query": "event.code:4673 AND (win.ProcessName:*lsass* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 103 |  |
| q-388b451b46 | check C014 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*comsvcs*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-ec3e897aba | check C015 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-57e0d059a9 | check C016 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg\\ save* OR process.command_line:*SAM* OR process.command_line:*SECURITY* OR process.command_line:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 1 |  |
| q-bfc5eef052 | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SECURITY* OR win.TargetFilename:*.hiv OR win.TargetFilename:*.save)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer… | 3 |  |
| q-6fadba0782 | check C018 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*SAM* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execut… | 7 |  |
| q-5056f3305c | check C019 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proce… | 0 |  |
| q-9b35df51ff | check C020 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*SAM* OR process.command_line:*ntdsutil*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 6 |  |
| q-74df71e442 | check C021 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 0 |  |
| q-7bb61aaa1e | check C022 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*reg\\ save* OR win.ScriptBlockText:*SAM* OR win.ScriptBlockText:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-4b85d4d6b3 | check C023 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-030c8219b2 | check C024 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntdsutil* OR process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-cb79530133 | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*ntds* OR win.TargetFilename:*.dit)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 0 |  |
| q-dedccb0e86 | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND win.TargetFilename:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 0 |  |
| q-8305c74362 | check C027 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*ntdsutil* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name",… | 0 |  |
| q-afa1f0902c | check C028 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-0e98f4a4d7 | check C029 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ntds* OR win.ScriptBlockText:*vssadmin* OR win.ScriptBlockText:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-37356aa7e3 | check C030 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-693fc1d280 | check C031 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*SECURITY* OR process.command_line:*Policy*Secrets* OR process.command_line:*reg\\ save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name"… | 0 |  |
| q-48679ca7dd | check C032 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-a8a0f7909d | check C033 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*Policy*Secrets*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 0 |  |
| q-9766643af9 | check C034 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*Secrets*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-f28fc6b95a | check C035 | search | {"dataset": "windows.security", "query": "event.code:4670 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*Secrets*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-31cfa852c8 | check C036 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SECURITY* OR win.ScriptBlockText:*Secrets* OR win.ScriptBlockText:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-1a12c8ec07 | check C037 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-acc2729ea4 | check C038 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-f9f5fd3469 | check C039 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*lsass* OR process.command_line:*mimikatz* OR process.command_line:*secretsdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 5 |  |
| q-9c409a236f | check C040 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*Cache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-b9b73a8b10 | check C041 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*Cache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-0a0fba1bad | check C042 | search | {"dataset": "windows.security", "query": "event.code:4670 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*Cache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-a324cb2743 | check C043 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cache* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*secretsdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-0203f07b2a | check C044 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-793f7b6742 | check C045 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-02548216f0 | check C046 | search | {"dataset": "windows.security", "query": "event.code:4662 AND win.Properties:*1131f6aa* OR event.code:4662 AND win.Properties:*1131f6ad*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 0 |  |
| q-11f9c302f2 | check C047 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-27b565f41d | check C048 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-8a3923221e | check C049 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*DCSync* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*lsadump* OR win.ScriptBlockText:*DRSUAPI*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-5b1ad54df4 | check C050 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-5b46d304f3 | check C051 | aggregate | {"dataset": "zeek", "field": "zeek.operation", "query": "event.action:dce_rpc", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 123 |  |
| q-32552377d1 | check C052 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*netsh* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*RawCap*)", "time_from": null, "time_to": n… | 2 | F08 |
| q-63325c05cc | check C053 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*pktmon* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*RawCap* OR process.command_line:*netsh*cap*)", "… | 1 |  |
| q-2862e5ef12 | check C054 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:*promisc*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-922bfecfbd | check C055 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-ac3a6fb895 | check C056 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*pktmon* OR win.ScriptBlockText:*WinPcap* OR win.ScriptBlockText:*promiscuous* OR win.ScriptBlockText:*Get-NetAdapter*)", "time_from": null, "time_to": null, "fields": ["@time… | 0 |  |
| q-cb2f56bdae | check C057 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-58b1335e78 | check C058 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-fe5c84040f | check C059 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-77fab452bb | check C060 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-8fda39a686 | check C061 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 23 |  |
| q-03a5161b6f | check C062 | search | {"dataset": "windows.security", "query": "event.code:4670 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exe… | 0 |  |
| q-52bd6770fe | check C063 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*SetWindowsHookEx* OR win.ScriptBlockText:*GetKeyboardState*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 0 |  |
| q-373d8238a2 | check C064 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F10 |
| q-5bcc4a63fa | check C065 | aggregate | {"dataset": "zeek", "field": "zeek.name", "query": "event.action:dns", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 53 |  |
| q-65477fd31e | check C066 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*CurrentControlSet\\\\Services*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1357 |  |
| q-6737259951 | check C067 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*keylog* OR process.command_line:*GetAsyncKeyState* OR process.command_line:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "size": 50, "sub… | 0 |  |
| q-1aff38c3c8 | check C068 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-649d54d21c | check C069 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-473fe0de27 | check C070 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exe… | 23 |  |
| q-9c205690a2 | check C071 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-11ec15fd04 | check C072 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*keylog* OR win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obse… | 0 |  |
| q-19a3319317 | check C073 | aggregate | {"dataset": "zeek", "field": "zeek.name", "query": "event.action:dns", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 53 |  |
| q-9bc687ab2f | check C074 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3 |  |
| q-dee18493a9 | check C075 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*CredentialUIBroker* OR win.ScriptBlockText:*Windows.Security.Credentials* OR win.ScriptBlockText:*ShowDialog* OR win.ScriptBlockText:*Get-Credential*)", "time_from": null, "t… | 0 |  |
| q-9c705c9579 | check C076 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (win.Payload:*Credential* OR win.Payload:*prompt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 13 | F12 |
| q-0c896fb878 | check C077 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3 |  |
| q-0d49a85346 | check C078 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-9e25d18e8c | check C079 | aggregate | {"dataset": "zeek", "field": "zeek.name", "query": "event.action:dns", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 53 |  |
| q-4f5c33ef00 | check C080 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*login* OR win.TargetFilename:*logon* OR win.TargetFilename:*portal* OR win.TargetFilename:*.aspx OR win.TargetFilename:*.php)", "time_from": null, "ti… | 8 |  |
| q-c31d5e0c5e | check C081 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*w3wp* OR process.command_line:*iis* OR process.command_line:*appcmd*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-19042c803f | check C082 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*wwwroot* OR win.ObjectName:*inetpub*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0ae849b6e1 | check C083 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*inetpub* OR win.ScriptBlockText:*wwwroot* OR win.ScriptBlockText:*login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 2 |  |
| q-06998ada4c | check C084 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-7c3972f403 | check C085 | aggregate | {"dataset": "zeek", "field": "url.original", "query": "event.action:http", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 62 |  |
| q-f9ee7b8d9f | check C086 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a8f734178b | check C087 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-ae5af4079f | check C088 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*samlib* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*vaultcli* OR win.ImageLoaded:*dpapi*)", "time_from": null, "time_to": nu… | 203 |  |
| q-98bf433536 | check C089 | search | {"dataset": "windows.sysmon", "query": "event.code:8 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 2 |  |
| q-5d9d3a9faf | check C090 | aggregate | {"dataset": "windows.security", "field": "win.CallerProcessName", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 13 |  |
| q-09ded38d4c | check C091 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*Get-Process*lsass*)", "time_from": null, "time_to": null, "fields": ["@times… | 0 |  |
| q-76aeb5de90 | check C092 | search | {"dataset": "windows.other", "query": "message:*lsass* OR process.executable:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 0 |  |
| q-019722bdaa | check C093 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-4c07e98b52 | check C094 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-7cc22c79b9 | check C095 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-f7324b9074 | check C096 | search | {"dataset": "windows.other", "query": "event.code:4625 OR event.code:4776 OR message:*logon*fail*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 0 |  |
| q-c41d831264 | check C097 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net*user* OR process.command_line:*password* OR process.command_line:*pass*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1 |  |
| q-26f6b191ad | check C098 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Logon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 4 | F15 |
| q-77eda1750c | check C099 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-ee78557464 | check C100 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-7a70677156 | check C101 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-8a841782c8 | check C102 | search | {"dataset": "windows.other", "query": "event.code:4625", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-299d922985 | check C103 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*4625* OR win.ScriptBlockText:*Failed*Logon* OR win.ScriptBlockText:*Brute*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-bf96097b0b | check C104 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*net*use* OR process.command_line:*net*user*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-55db555f03 | check C105 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-e2176126c1 | check C106 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4656 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10 |  |
| q-8e6e15864d | check C107 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4670", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 143 |  |
| q-3192a6de65 | check C108 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*sam* OR process.command_line:*ntds* OR process.command_line:*secretsdump* OR process.command_line:*hashcat* OR process.command_line:*john*)", "time_f… | 0 |  |
| q-b65db371d1 | check C109 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*NTDS* OR win.TargetFilename:*.dit* OR win.TargetFilename:*.hive*)", "time_from": null, "time_to": null, "size": 100, "sub_… | 0 |  |
| q-a609076117 | check C110 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*sam* OR win.TargetImage:*lsa* )", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-f69789c094 | check C111 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*hashcat* OR win.ScriptBlockText:*secretsdump* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*NTDS*)", "time_from": null, "time_to": null, "fields": ["@times… | 0 |  |
| q-770cd8e1c1 | check C112 | search | {"dataset": "windows.other", "query": "message:*NTDS* OR message:*SAM* OR message:*hashcat*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 1 | F16 |
| q-8ea543dbef | check C113 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 200, "sub_field": null} | 0 |  |
| q-06f7359517 | check C114 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-8eb22d0098 | check C115 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 15 |  |
| q-cf7962bcfb | check C116 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-dab9dce1af | check C117 | search | {"dataset": "windows.other", "query": "event.code:4625 OR event.code:4771", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-40d96013f7 | check C118 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Spray* OR win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 4 |  |
| q-1195538684 | check C119 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*net*use* OR process.command_line:*runas*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1 |  |
| q-2f304df774 | check C120 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-4a51b74c4a | check C121 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-3251b02ddc | check C122 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 326 |  |
| q-e71ced3ce0 | check C123 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*SecurityProviders*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-365ddc3b87 | check C124 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 3 |  |
| q-09e336aac3 | check C125 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F19 |
| q-d26ca960bf | check C126 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:5145", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 121 |  |
| q-8c98e8c146 | check C127 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 42 |  |
| q-bb9f51d8cb | check C128 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*\\\\*.lnk OR win.TargetFilename:*\\\\*.url OR win.TargetFilename:*\\\\*.scf)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 3 |  |
| q-d86784a1ea | check C129 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 66 |  |
| q-8a66334e87 | check C130 | search | {"dataset": "windows.other", "query": "event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 4 |  |
| q-a2f31deeb3 | check C131 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*WebDAV* OR win.ScriptBlockText:*NTLM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 0 |  |
| q-8ca77e4c85 | check C132 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 50 |  |
| q-efd70f0c1e | check C133 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-7459569a9a | check C134 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 326 |  |
| q-1f46b881be | check C135 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 28 |  |
| q-cc647a2d80 | check C136 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-ede31d8185 | check C137 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 0 |  |
| q-4213c69ed0 | check C138 | search | {"dataset": "windows.other", "query": "event.code:1 OR event.code:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 6 |  |
| q-4d2cbe44d9 | check C139 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 162 |  |
| q-35e7df977d | check C140 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND (win.TargetImage:*chrome* OR win.TargetImage:*firefox* OR win.TargetImage:*msedge*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 0 |  |
| q-df531e610a | check C141 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 460 |  |
| q-96d8e438c6 | check C142 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*Login Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "use… | 13 |  |
| q-8e06c6ed05 | check C143 | search | {"dataset": "windows.other", "query": "event.code:2", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 0 |  |
| q-2eceb50459 | check C144 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*\\\\*.txt OR win.TargetFilename:*\\\\*.config OR win.TargetFilename:*\\\\*.xml OR win.TargetFilename:*unattend*)", "time_from": null, "time_to": null,… | 44 |  |
| q-32c58091d2 | check C145 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 17 |  |
| q-da3b28b148 | check C146 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*findstr* OR process.command_line:*password* OR process.command_line:*credential*)", "time_from": null, "time_to": null, "size": 30, "sub_field… | 0 |  |
| q-84dba92680 | check C147 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*password* OR win.ScriptBlockText:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 2 |  |
| q-cb78325b68 | check C148 | search | {"dataset": "windows.other", "query": "event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 4 |  |
| q-00b946f7a5 | check C149 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*type* OR process.command_line:*findstr* OR process.command_line:*Get-Content*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 1 |  |
| q-c5cf4b3d32 | check C150 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*\\\\*.txt OR win.TargetFilename:*\\\\*.ini OR win.TargetFilename:*\\\\*.config)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 26 |  |
| q-30e7573d3c | check C151 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 15 |  |
| q-7b131c3276 | check C152 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-2977f30cfb | check C153 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Get-Content* OR win.ScriptBlockText:*Select-String*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 1 |  |
| q-c1e6039ed6 | check C154 | search | {"dataset": "windows.other", "query": "event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 4 |  |
| q-66d28f3245 | check C155 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential* OR registry.path:*Secret* OR registry.path:*DefaultPassword*)", "time_from": null, "time_to": null, "size": 50, "sub_fie… | 17 |  |
| q-fde7eda0c5 | check C156 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg\\ query* OR process.command_line:*reg\\ save* OR process.command_line:*Password* OR process.command_line:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timest… | 0 |  |
| q-1c5d0fb770 | check C157 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*reg\\ query* OR win.ScriptBlockText:*Get-ItemProperty*)", "time_from": null, "time_to": null, "fields": … | 5 |  |
| q-961b6bfbe4 | check C158 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*Password*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f6390403a5 | check C159 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ConsoleHost_history* OR win.ScriptBlockText:*history* OR win.ScriptBlockText:*Get-History* OR win.ScriptBlockText:*PSReadLine*)", "time_from": null, "time_to": null, "fields"… | 0 |  |
| q-a281575ed8 | check C160 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ConsoleHost_history* OR process.command_line:*Get-History* OR process.command_line:*PSReadLine*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observ… | 0 |  |
| q-4f66b03a42 | check C161 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ConsoleHost_history* OR file.path:*PSReadLine*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-c433c51b6c | check C162 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*.key OR file.path:*.pem OR file.path:*.pfx OR file.path:*.p12 OR file.path:*.ppk OR file.path:*.pgp OR file.path:*.gpg OR file.path:*.cer OR file.path:*.p7b OR file.pat… | 1 |  |
| q-5ae7f92820 | check C163 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*.pfx OR process.command_line:*.pem OR process.command_line:*.key OR process.command_line:*certutil* OR process.command_line:*Export-PfxCertificate*)", "time_from": null, "time_to":… | 0 |  |
| q-6909d15bd5 | check C164 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:5145 AND (win.ObjectName:*.key OR win.ObjectName:*.pem OR win.ObjectName:*.pfx OR win.ObjectName:*.p12 OR win.ObjectName:*.ppk)", "time_from": null, "time_to": null, "size": 50, "s… | 0 |  |
| q-3b07648fe1 | check C165 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*.pfx OR win.ScriptBlockText:*.pem OR win.ScriptBlockText:*.key OR win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*Get-ChildItem*)", "time_from": null, "ti… | 1 |  |
| q-8d2f861f56 | check C166 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Groups.xml OR win.ScriptBlockText:*cpassword OR win.ScriptBlockText:*gpprefdecrypt* OR win.ScriptBlockText:*AES* OR win.ScriptBlockText:*SYSVOL*)", "time_from": null, "time_t… | 0 |  |
| q-a7e7166753 | check C167 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Groups.xml OR process.command_line:*cpassword OR process.command_line:*SYSVOL* OR process.command_line:*gpprefdecrypt*)", "time_from": null, "time_to": null, "fields": ["@timestamp… | 0 |  |
| q-ba149269df | check C168 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:5145 AND (win.ObjectName:*Groups.xml OR win.ObjectName:*SYSVOL* OR win.ObjectName:*.xml)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-fa818b8123 | check C169 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*Groups.xml OR file.path:*SYSVOL*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 0 |  |
| q-dd1c1d25fc | check C170 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-b33a75eae5 | check C171 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-132022b9cf | check C172 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*sekurlsa* OR process.command_line:*lsass*)", "time_from": null, "time_to": n… | 1 |  |
| q-3a81dd974e | check C173 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-1bc26244b8 | check C174 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*ntdsutil* OR process.command_line:*vssad… | 0 |  |
| q-5f89abb17a | check C175 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*Credential*)", "time_from": null, … | 3 |  |
| q-eda45c650d | check C176 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Login\\ Data* OR file.path:*Local\\ State* OR file.path:*logins.json* OR file.path:*key4.db* OR file.path:*signons.sqlite* OR file.path:*Cookies*)", "time_from": null, … | 1 |  |
| q-ec7bafb8cc | check C177 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*chrome.exe OR win.TargetImage:*firefox.exe OR win.TargetImage:*msedge.exe OR win.TargetImage:*iexplore.exe)", "time_from": null, "time_to": null, "size":… | 0 |  |
| q-aedacf59c6 | check C178 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Login\\ Data* OR process.command_line:*Local\\ State* OR process.command_line:*logins.json* OR process.command_line:*key4.db* OR process.command_line:*sqlite*)", "time_from": null,… | 0 |  |
| q-9dd023f038 | check C179 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Login\\ Data* OR win.ObjectName:*Local\\ State* OR win.ObjectName:*logins.json* OR win.ObjectName:*key4.db*)", "time_from": null, "time_to": null, "size":… | 0 |  |
| q-7195a554be | check C180 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Login\\ Data* OR win.ScriptBlockText:*Local\\ State* OR win.ScriptBlockText:*logins.json* OR win.ScriptBlockText:*key4.db* OR win.ScriptBlockText:*sqlite*)", "time_from": nul… | 0 |  |
| q-8e1d866a0f | check C181 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*vault* OR process.command_line:*credman* OR process.command_line:*Credential* OR process.command_line:*cmdkey*)", "time_from": null, "time_to": null,… | 0 |  |
| q-bfd7c201e0 | check C182 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-d2527fbea0 | check C183 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetObject", "query": "event.code:15 AND (win.TargetObject:*Vault* OR win.TargetObject:*Credentials*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e9e42ab0ec | check C184 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*cmdkey* OR process.command_line:*Credential*)", "time_from": null, "time_to": null, "size": 50, "sub_field": nul… | 0 |  |
| q-7f63917628 | check C185 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Vault* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 3 |  |
| q-88636e747f | check C186 | search | {"dataset": "windows.other", "query": "message:*Vault* OR message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 |  |
| q-2139a58433 | check C187 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*lastpass* OR process.command_line:*bitwarden* OR process.command_line:*password… | 0 |  |
| q-b2c6475eab | check C188 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.kdbx OR win.TargetFilename:*1password* OR win.TargetFilename:*keepass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c48b5d866a | check C189 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*lastpass* OR process.command_line:*bitwarden*)", "time_from": null, "time_… | 0 |  |
| q-157c3d52a2 | check C190 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*kdbx* OR win.ScriptBlockText:*keepass* OR win.ScriptBlockText:*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-9290d95ada | check C191 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 0 |  |
| q-c3947c922a | check C192 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-7f72f31cb1 | check C193 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*wdigest*)", "time_from": null, "time_to": null, "size": 50, "sub_field": nu… | 75 |  |
| q-3011514985 | check C194 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*Security*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e31e80b689 | check C195 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*mimikatz* OR process.command_line:*procdump* OR process.command_line:*comsvcs*)", "time_from": null, "time_to": … | 0 |  |
| q-1eda5b42f4 | check C196 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-5819f1415b | check C197 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-65a6a62086 | check C198 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-d13b155fcb | check C199 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 218 |  |
| q-26b16729e6 | check C200 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-d2fc83f617 | check C201 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 33 |  |
| q-10bbbf1e08 | check C202 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*cryptdll* OR win.ScriptBlockText:*mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-cc5e83ffc1 | check C203 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-a5cebba2b4 | check C204 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*lsa* OR win.TargetFilename:*password* OR win.TargetFilename:*.dll)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 29 |  |
| q-f1c847b03f | check C205 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*ntds*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 47 |  |
| q-b4d5bdcd6c | check C206 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657 AND (win.ObjectName:*Notification Packages* OR win.ObjectName:*lsa* OR win.ObjectName:*Password*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-da58cefad5 | check C207 | aggregate | {"dataset": "windows.security", "field": "win.TargetFilename", "query": "event.code:4663 AND (win.ObjectName:*.dll OR win.ObjectName:*lsa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-ee6d9b3494 | check C208 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Notification* OR win.ScriptBlockText:*PasswordFilter* OR win.ScriptBlockText:*lsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name… | 0 |  |
| q-0aa7f9b4ad | check C209 | search | {"dataset": "windows.other", "query": "message:*Notification* OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 10 |  |
| q-87e7af910d | check C210 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Reversible* OR win.ScriptBlockText:*AllowReversiblePasswordEncryption* OR win.ScriptBlockText:*Set-ADAccountControl*)", "time_from": null, "time_to": null, "fields": ["@times… | 0 |  |
| q-feaa046084 | check C211 | search | {"dataset": "windows.powershell", "query": "event.code:4103 OR event.code:4104", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 5494 |  |
| q-300c948b0e | check C212 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4739 OR event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-208c86880c | check C213 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADAccountControl* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "size": 50, "sub_fi… | 0 |  |
| q-238d73d31b | check C214 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*encryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-739b021f51 | check C215 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*str… | ERROR |  |
| q-0b838e8cd2 | check C215 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*str… | ERROR |  |
| q-6a883e6797 | check C216 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-cfdaceae2d | check C217 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4662 OR event.code:5136", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-7d642f49d5 | check C218 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-1996ad8e84 | check C219 | count | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null} | 0 |  |
| q-2d2715b95f | check C220 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-d37922cfe8 | check C221 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetObject", "query": "event.code:13 AND registry.path:*NetworkProvider*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-5a14a02f71 | check C222 | aggregate | {"dataset": "windows.sysmon", "field": "win.Image", "query": "event.code:11 AND file.path:*NetworkProvider*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-7a0b69b964 | check C223 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-3322e02bd7 | check C224 | count | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null} | 36 |  |
| q-e7a35ef72c | check C225 | aggregate | {"dataset": "windows.sysmon", "field": "win.Image", "query": "event.code:22", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 81 |  |
| q-2ac1eaaa20 | check C226 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-9682ef9f9a | check C227 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-e59c52316a | check C228 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-a321c39064 | check C229 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 66 |  |
| q-03f5b1346a | check C230 | aggregate | {"dataset": "windows.security", "field": "win.IpAddress", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 218 |  |
| q-0ae6b3a5bc | check C231 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-277216a7d9 | check C232 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-d9ffc8b6a3 | check C233 | aggregate | {"dataset": "windows.sysmon", "field": "win.Image", "query": "event.code:22", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 81 |  |
| q-66e972f5b9 | check C234 | search | {"dataset": "windows.other", "query": "event.code:1341 OR event.code:1342 OR event.code:1020 OR event.code:1063", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.ex… | 0 |  |
| q-9fa7199c66 | check C235 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 216 |  |
| q-282eaab972 | check C236 | search | {"dataset": "windows.security", "query": "event.code:5156 AND network.transport:udp", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-330c672918 | check C237 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3 AND network.transport:udp", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 308 |  |
| q-69ea72a6d1 | check C238 | search | {"dataset": "windows.powershell", "query": "*dhcp*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.… | 0 |  |
| q-01794f2252 | check C239 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "network.transport:udp", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 115 |  |
| q-db3c156755 | check C240 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4768 OR event.code:4769 OR event.code:4770 OR event.code:4771 OR event.code:4672 OR event.code:4634", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 490 |  |
| q-89b99617ef | check C241 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-915b7b0de2 | check C242 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-0f2f3bece4 | check C243 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-a99b2bb2bd | check C244 | search | {"dataset": "windows.powershell", "query": "*kerberos* OR *ticket* OR *kirbi* OR *Rubeus*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.co… | 0 |  |
| q-1fd100f3e8 | check C245 | search | {"dataset": "windows.other", "query": "*kerberos* OR *ticket*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "d… | 1 |  |
| q-261eef464a | check C246 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-1279458899 | check C247 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-8e23ba7753 | check C248 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 28 |  |
| q-29421c4ff4 | check C249 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-1cf435e27d | check C250 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-484e8f3726 | check C251 | search | {"dataset": "windows.powershell", "query": "*krbtgt* OR *golden* OR *mimikatz* OR *lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.co… | 1 |  |
| q-1983579d0d | check C252 | search | {"dataset": "windows.other", "query": "*krbtgt* OR *golden*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "des… | 0 |  |
| q-968d0ac597 | check C253 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-770768db12 | check C254 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 28 |  |
| q-6aec22305c | check C255 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-86874bd0e5 | check C256 | aggregate | {"dataset": "windows.security", "field": "win.IpAddress", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 28 |  |
| q-33ef888262 | check C257 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-aad50ec3db | check C258 | search | {"dataset": "windows.powershell", "query": "*silver* OR *ticket* OR *kirbi*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 0 |  |
| q-79057cb771 | check C259 | search | {"dataset": "windows.other", "query": "*ticket* OR *Kerberos*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "d… | 1 |  |
| q-f7a81ad02c | check C260 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-a9237bf7ff | check C261 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-ff6cc9f2df | check C262 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 28 |  |
| q-35cde21c11 | check C263 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 28 |  |
| q-f0f85ab0f1 | check C264 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-0225d54ea3 | check C265 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-a3622ee433 | check C266 | search | {"dataset": "windows.powershell", "query": "*kerberoast* OR *Invoke-Kerberoast* OR *SPN* OR *Rubeus*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", … | 0 |  |
| q-95176252eb | check C267 | search | {"dataset": "windows.other", "query": "*kerberoast* OR *SPN*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "de… | 0 |  |
| q-c411472a45 | check C268 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-2181ae2b29 | check C269 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-e336fc6ee7 | check C270 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 14 |  |
| q-e04468ebe4 | check C271 | aggregate | {"dataset": "windows.security", "field": "win.Status", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-587f279443 | check C272 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*asreproast* OR process.command_line:*GetNPUsers* OR process.command_line:*rubeus*)", "time_from": null, "time_to": null, "size": 50, "sub_field": n… | 0 |  |
| q-617406e70e | check C273 | search | {"dataset": "windows.powershell", "query": "*asreproast* OR *GetNPUsers* OR *DontReqPreAuth*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-e4f81f8a03 | check C274 | search | {"dataset": "windows.other", "query": "*asrep* OR *preauth*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "des… | 0 |  |
| q-f99bdf127b | check C275 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-8acafad5b5 | check C276 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-6352a6e7f8 | check C277 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-2e00952149 | check C278 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-d851d26ad0 | check C279 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cookie* OR win.ScriptBlockText:*token* OR win.ScriptBlockText:*SAML* OR win.ScriptBlockText:*forge*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 1 |  |
| q-7c0f01fc8f | check C280 | search | {"dataset": "windows.other", "query": "message:*token* OR message:*cookie* OR message:*SAML*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-7fe9ccfc8f | check C281 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-25cd4ea924 | check C282 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-e124c291a8 | check C283 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-0ecbd9e7f6 | check C284 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cookie* OR win.ScriptBlockText:*Cookies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.na… | 0 |  |
| q-a14e0a57cc | check C285 | search | {"dataset": "windows.other", "query": "message:*cookie* OR message:*Cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 0 |  |
| q-df703032ba | check C286 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-3678c6c352 | check C287 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-d3c26b918f | check C288 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SAML* OR win.ScriptBlockText:*NotOnOrAfter* OR win.ScriptBlockText:*token-signing*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name… | 0 |  |
| q-a4f65823a8 | check C289 | search | {"dataset": "windows.other", "query": "message:*SAML* OR message:*ADFS* OR message:*Token*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 0 |  |
| q-4dff3a9ffc | check C290 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-fd29dd383f | check C291 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-9d53854037 | check C292 | aggregate | {"dataset": "windows.security", "field": "win.Status", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-9b7f394bc3 | check C293 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b5a4071325 | check C294 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MFA* OR win.ScriptBlockText:*2FA* OR win.ScriptBlockText:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-5af3e8d7ff | check C295 | search | {"dataset": "windows.other", "query": "message:*MFA* OR message:*multi-factor* OR message:*2FA*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proc… | 0 |  |
| q-79ad960b9e | check C296 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-8d55338ac9 | check C297 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-744826daf9 | check C298 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-9b4bab4d25 | check C299 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.pfx OR win.TargetFilename:*.p12 OR win.TargetFilename:*.cer OR win.TargetFilename:*.crt)", "time_from": null, "time_to": null, "size": 50, "sub_field… | 1 |  |
| q-f3bb17b645 | check C300 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*certutil* OR win.ScriptBlockText:*Certificate*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 1 |  |
| q-f510a313ea | check C301 | search | {"dataset": "windows.other", "query": "message:*certificate* OR message:*Certificate*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 0 |  |
| q-160ee637b5 | check C302 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-4f7cb040a8 | check C303 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ae5b592f4b | check C304 | count | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null} | 0 |  |
| q-2df94f83cf | check C305 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*runas* OR process.command_line:*psexec*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 31 |  |
| q-8fd84f54bb | check C306 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Password* OR win.ScriptBlockText:*PSCredential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.nam… | 4 | F15 |
| q-48d82df2c7 | check C307 | search | {"dataset": "windows.other", "query": "event.code:4625 OR event.code:4771 OR event.code:4776", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-b9cd5d2ccb | check C308 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-296d32a07b | check C309 | search | {"dataset": "zeek", "query": "event.action:conn AND network.transport:udp", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 62 | F44 |
| q-1e59d7131c | check C310 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-bcfcc730fd | check C311 | search | {"dataset": "zeek", "query": "event.action:dns", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.ip",… | 53 |  |
| q-59ba734dad | check C312 | aggregate | {"dataset": "zeek", "field": "dns.response_code", "query": "event.action:dns", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 53 |  |
| q-9e1d962197 | check C313 | search | {"dataset": "zeek", "query": "event.action:smb_mapping OR event.action:smb_files OR event.action:dce_rpc", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executabl… | 146 |  |
| q-1065805e25 | check C314 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn AND destination.port:445", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 45 |  |
| q-d38a2c3396 | check C315 | search | {"dataset": "zeek", "query": "event.action:conn AND network.transport:udp", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 62 |  |
| q-76077570da | check C316 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-732b42437c | check C317 | aggregate | {"dataset": "zeek", "field": "zeek.resp_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-2cd783cf50 | check C318 | search | {"dataset": "zeek", "query": "event.action:http", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.ip"… | 62 |  |
| q-c9bdbc7005 | check C319 | aggregate | {"dataset": "zeek", "field": "user_agent.original", "query": "event.action:http", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 62 |  |
| q-ccd8e26ace | check C320 | search | {"dataset": "zeek", "query": "event.action:ssl", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.ip",… | 378 |  |
| q-979e253a6d | check C321 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-691dd1c843 | check C322 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-731f33af7d | check C323 | search | {"dataset": "zeek", "query": "event.action:http AND url.original:*adfs*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 0 |  |
| q-608f4fd5b5 | check C324 | search | {"dataset": "zeek", "query": "event.action:conn AND destination.port:443", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 2 |  |
| q-b42c535fec | check C325 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn AND destination.port:443", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2 |  |
| q-addf0ac50c | check C326 | search | {"dataset": "zeek", "query": "event.action:http", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.ip"… | 62 |  |
| q-fdee50829e | check C327 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 35 |  |
| q-ed5aa31424 | check C328 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 35 |  |
| q-290c181f17 | check C329 | search | {"dataset": "zeek", "query": "event.action:x509", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.ip"… | 378 |  |
| q-43e9ea0b81 | check C330 | aggregate | {"dataset": "zeek", "field": "tls.server.issuer", "query": "event.action:ssl", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 378 |  |
| q-165730b9ff | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F01 |
| q-7635228391 | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.SourceImage:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.SourceImage", "win.GrantedAccess", "win.Ca… | 4 |  |
| q-93fa94f74f | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None | F01 |
| q-e62aa4cd54 | triage T1003 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.Scri… | ERROR |  |
| q-1322e4cd8a | triage T1003 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.… | 50 |  |
| q-5378709133 | triage T1003 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND (process.executable:*PowerShell* OR process.executable:*powershell*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable",… | 11 | F01, F07 |
| q-4d78488146 | triage T1003 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:30.000Z\" \| KEEP @timestamp, u… | 38 | F07 |
| q-8ca35bcfa1 | triage T1003 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItkHK8V2"} | ERROR |  |
| q-b5fef8d36e | triage T1003 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None | F01 |
| q-4646895325 | triage T1003 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:06:00.000Z\" \| KEEP @timestamp, process.… | 15 | F07 |
| q-a65cf99978 | triage T1003 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\") AND win.ObjectType IN (\"SAM_DOMAIN\",\"SAM_SERVER\",\"SAM_ALIAS\",\"Process\",\"File\") \| KEEP @timestamp, host.name, event.code, user.name… | 60 | F02, F05 |
| q-75f1bc1b13 | triage T1003 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None | F06 |
| q-0c8f0e50c7 | triage T1003 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectType IN (\"SAM_DOMAIN\",\"SAM_SERVER\",\"SAM_ALIAS\") \| KEEP @timestamp, host.name, user.name, win.ObjectType, win.ObjectName, win.ProcessName, wi… | 0 |  |
| q-3e0a3e1c81 | triage T1003 step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectType LIKE \"SAM*\" \| KEEP @timestamp, host.name, user.name, win.ObjectType, win.ObjectName, win.ProcessName, win.AccessMask, _id, _index \| LIMIT … | 0 |  |
| q-e4ae800ca1 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-d0448e1774 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-2c168493fd | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-b4bdd62c13 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-de96d045e9 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-084fdf670e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtA"} | None |  |
| q-cbe09cb3cd | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtA"} | None |  |
| q-aa80f9349c | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtH"} | None |  |
| q-aaedb1c444 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAs"} | None |  |
| q-9157e5cf20 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRX"} | None |  |
| q-0dfc83c96f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRX"} | None |  |
| q-a1c713f0c3 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtA"} | None |  |
| q-5e00aafe25 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-2825bb2e25 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-ecb70ebe31 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkHK8X3"} | None |  |
| q-cba33aeba8 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkHK8V2"} | None |  |
| q-2657d51658 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopf"} | None |  |
| q-e84816915b | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCzT"} | None |  |
| q-933ca72c23 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2o"} | None |  |
| q-8fc26d30b0 | triage T1040 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5KNV"} | None | F08 |
| q-9850446c73 | triage T1040 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS3MUJ"} | None |  |
| q-06ed42cdc8 | triage T1040 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:*netsh*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 2 | F08 |
| q-436a3b1d46 | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*trace* OR process.command_line:*.etl*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 4 |  |
| q-22c6d8fdba | triage T1040 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None | F08 |
| q-a13667604c | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*pktmon* OR process.command_line:*dumpcap* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*RawCap* OR process.command_line:*Npcap* OR pr… | 0 |  |
| q-2f205d41b4 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:6 AND (win.ImageLoaded:*pcap* OR win.ImageLoaded:*npf* OR win.ImageLoaded:*Packet*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 0 |  |
| q-681722810a | triage T1040 step 2 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (message:*pcap* OR message:*npf* OR message:*Packet* OR message:*WinPcap* OR message:*Npcap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset… | 0 |  |
| q-a713278397 | triage T1040 step 3 | search | {"dataset": "zeek", "query": "event.action:notice OR event.action:weird", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 14 |  |
| q-2b2ed316d3 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*promiscuous* OR process.command_line:*monitor* OR process.command_line:*sniff*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-bb977c26ea | triage T1040 step 4 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovu"} | None | F08 |
| q-bd5972a02d | triage T1040 step 4 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz7ud8y"} | None | F08 |
| q-0465f2ea82 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5KNV"} | None |  |
| q-098cab5fe9 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5KNV"} | None |  |
| q-fc6fddd3d5 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS3MUJ"} | None |  |
| q-e1da6319d0 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-5a17f19f29 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-e2172c407f | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovu"} | None |  |
| q-13baa8ab12 | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz7ud8y"} | None |  |
| q-e34329e5b9 | triage T1056 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1… | 33 | F09, F10 |
| q-8c7f6fa04c | triage T1056 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win… | 4 |  |
| q-c8a268cefa | triage T1056 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None | F09, F13 |
| q-f0139f422c | triage T1056 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-b631513dcd | triage T1056 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*comsvcs*\" OR… | 6 | F09 |
| q-e725be4e56 | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-ca1b5f1f89 | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-92204f724a | triage T1056 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*minidump*\" OR TO_LOWER(pro… | 1 |  |
| q-dd923358c0 | triage T1056 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND TO_LOWER(process.executable) LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.executable, proce… | 11 | F09 |
| q-0989625fdd | triage T1056 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4656\" AND win.ObjectName LIKE \"*lsass*\" AND process.executable LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.executable, win.ObjectName, wi… | 2 | F09 |
| q-588eca24c0 | triage T1056 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectName LIKE \"*lsass*\" \| KEEP @timestamp, host.name, user.name, process.executable, win.ObjectName, win.AccessMask, win.ProcessName, _id, _index \|… | 6 | F09, F10 |
| q-230c12610e | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-e95b5181e4 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-6a02774280 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-97e4fd9a75 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-8a4abb48db | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-8632916227 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo4k"} | None |  |
| q-9d2f3087bd | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-a4ad8c4068 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-e92479938a | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-85b8be8a75 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-5966e45507 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkady05"} | None |  |
| q-92908c9a86 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkbfEQ2"} | None |  |
| q-85ec122ab4 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsQ2P9A"} | None |  |
| q-f8c3f44e10 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWXW"} | None |  |
| q-70425814c1 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkady05"} | None |  |
| q-702da63e42 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlU_o"} | None |  |
| q-9d265c9ec4 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlShi"} | None |  |
| q-9dc66f70a8 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-8a631583d1 | triage T1056 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND registry.path LIKE \"*Keyboard*\" \| KEEP @timestamp, host.name, registry.path, process.executable, _id, _index \| LIMIT 5"} | 5 | F11 |
| q-89135e53d6 | triage T1110 step 1 | count | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776 OR event.code:4648", "time_from": null, "time_to": null} | 16 |  |
| q-b559d3066c | triage T1110 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*sam* OR win.TargetImage:*lsa*) AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR … | 9 | F16 |
| q-dbb0c51341 | triage T1110 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None | F14 |
| q-330002dbe6 | triage T1110 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Dump* OR win.ScriptBlockText:*Get-Process*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 3 |  |
| q-ffac55c2bf | triage T1110 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND process.executable:*PowerShell.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.… | 0 |  |
| q-94d3fb1398 | triage T1110 step 3 | search | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776 OR event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "win.LogonType", "win.IpAddress",… | 16 | F14, F15, F17, F18 |
| q-735ef6df53 | triage T1110 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND TO_LOWER(process.executable) LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id,… | ERROR |  |
| q-3686977b5a | triage T1110 step 4 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.LogonType"} | 297 |  |
| q-ad942745e9 | triage T1110 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND TO_LOWER(process.executable) LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, … | 12 | F14, F18 |
| q-74a49e2c5d | triage T1110 step 5 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ServiceName", "win.ImagePath", "win.ServiceAccount", "message"], "size": 10, "sort": "asc"} | 5 | F17 |
| q-b7b8334849 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-9d5a2e7689 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-57ba5fbcc9 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItj59cFt"} | None |  |
| q-14444ed1fb | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-c938b69a66 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-81dbb95a52 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-223265f82a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-9999c1e919 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-a9480c08fb | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX2"} | None |  |
| q-3833513c6d | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWV3"} | None |  |
| q-ff85074bca | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-019d216297 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsc9wOe"} | None |  |
| q-f78130656e | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-68e7f2c285 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkHK8X3"} | None |  |
| q-9fe3529ddf | triage T1111 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3… | 33 |  |
| q-9e62b37784 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None | F19 |
| q-6f4d99bdeb | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1000000)", "time_from": null, "time… | 9 | F19 |
| q-579af8917e | triage T1111 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4648 \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetServerName, win.TargetUserName, win.IpAddress, win.IpPort, _id, _index \| SORT @timestamp"} | ERROR |  |
| q-d2c366972a | triage T1111 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetServerName, win.TargetUserName, win.IpAddress, win.IpPort, _id, _index \| SORT @timestamp… | 15 | F19 |
| q-fcb6427fa8 | triage T1111 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-ce207cff34 | triage T1111 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE process.pid == 2976 OR win.ProcessId == \"2976\" OR win.ParentProcessId == \"2976\" \| KEEP @timestamp, host.name, event.code, process.executable, process.command_line, win.TargetFilenam… | 40 |  |
| q-a1d8f694c6 | triage T1111 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" O… | 1 | F19 |
| q-dbc4903e83 | triage T1111 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None |  |
| q-599ff503fc | triage T1111 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*minidump*\" OR TO… | 2 |  |
| q-076bdba971 | triage T1111 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-604f2e4aeb | triage T1111 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:06:30.000Z\" \| KEEP @timestamp, user.nam… | 17 | F19 |
| q-6c5682e655 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-0d8c3e9297 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-7c82fff6f8 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2o"} | None |  |
| q-d9c5749c14 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None |  |
| q-bbc017bca9 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-a8b13c9900 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-5d3bc396b5 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-1e994ea6d5 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-61aab4c591 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWXW"} | None |  |
| q-c50a04db89 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-15a41cad72 | triage T1187 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "host.name", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 30, "sub_field": "destination.ip"} | 66 |  |
| q-e626a0acce | triage T1187 step 1 | aggregate | {"dataset": "windows.security", "field": "win.IpAddress", "query": "event.code:5140", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.ShareName"} | 42 |  |
| q-46ae8d7006 | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 30, "sub_field": "source.ip"} | 50 |  |
| q-6220cf1884 | triage T1187 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "destination.ip", "de… | 66 | F21 |
| q-10a4a50142 | triage T1187 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*\\\\*.lnk OR win.TargetFilename:*\\\\*.url OR win.TargetFilename:*\\\\*.scf)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.execut… | 3 | F20 |
| q-0a24b94711 | triage T1187 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpESdr2"} | None | F20 |
| q-edd1344e8d | triage T1187 step 3 | search | {"dataset": "windows.security", "query": "event.code:5140 AND win.IpAddress:(\"10.0.1.4\" OR \"10.0.1.6\" OR \"10.0.1.10\" OR \"10.0.1.5\")", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ShareName", "win.IpAddress… | 29 | F21 |
| q-f6abb28062 | triage T1187 step 4 | search | {"dataset": "windows.sysmon", "query": "process.entity_id:\"{47ab858c-e23d-5eac-c603-000000000400}\"", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executab… | 1968 |  |
| q-7014079a92 | triage T1187 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND destination.port:445 AND win.Initiated:true AND NOT destination.ip:(\"10.0.0.4\" OR \"10.0.1.6\" OR \"10.0.1.4\" OR \"10.0.1.5\" OR \"10.0.1.10\")", "time_from": null, "time_to": null, "fields": ["@times… | 12 | F21 |
| q-e281e700a5 | triage T1187 step 5 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND process.executable:*powershell.exe AND (win.TargetFilename:*hostui* OR process.command_line:*hostui* OR win.TargetFilename:*StartUp*)", "time_from": null, "time_to": null, "fields": [… | 4 | F20 |
| q-c3c5434275 | triage T1187 step 5 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND (win.ScriptBlockText:*hostui* OR win.ScriptBlockText:*StartUp* OR win.ScriptBlockText:*lnk*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name… | 2 | F20 |
| q-4c383ebcd5 | triage T1187 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpMctGb"} | None | F20 |
| q-00c3a15aab | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpESdr2"} | None |  |
| q-7728eae5bf | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpESdr2"} | None |  |
| q-06b688b074 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpMctGb"} | None |  |
| q-21fd8c06e7 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItj59cFt"} | None |  |
| q-1878f7a512 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqjTX"} | None |  |
| q-b902753ede | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpIWWNw"} | None |  |
| q-f83b487385 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpizV0q"} | None |  |
| q-0eda8246f7 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwsQxHC"} | None |  |
| q-0a9618cc7f | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFUeT"} | None |  |
| q-bb6c2256e0 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo6a"} | None |  |
| q-1a4ccbce33 | triage T1212 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F22, F24 |
| q-862eec1766 | triage T1212 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.GrantedAccess:0x1400", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 24 |  |
| q-234d901bff | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None | F22 |
| q-d6e6ebb9c7 | triage T1212 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code IN (\"4104\", \"4103\", \"800\", \"400\") \| KEEP @timestamp, host.name, event.code, user.name, win.ScriptBlockText, win.Payloa… | 60 |  |
| q-807ee20131 | triage T1212 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:00.000Z\" \| KEEP @timestamp, h… | 30 | F22 |
| q-553424fcaf | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None | F23 |
| q-d4f7867a16 | triage T1212 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:08:00.000Z\" AND @timestamp <= \"2020-05-02T03:11:00.000Z\" \| KEEP @timestamp, hos… | 2 | F23 |
| q-fcc3787284 | triage T1212 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4624\", \"4672\", \"4648\") AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:15:00.000Z\" \| STATS c = COUNT(*) BY host.name, win.Logon… | 23 |  |
| q-d81a5c9861 | triage T1212 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:05:00.000Z\" AND @timestamp <= \"2020-05-02T03:05:25.000Z\" \| KEEP @timestamp, u… | 2 |  |
| q-9d7e43cc98 | triage T1212 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| STATS c = COUNT(*) BY process.executable, host.name \| SORT c ASC \| LIMIT 60"} | 60 |  |
| q-f0ce15e043 | triage T1212 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\", \"4656\", \"4673\") AND (TO_LOWER(win.ObjectName) LIKE \"*lsass*\" OR TO_LOWER(win.ProcessName) LIKE \"*lsass*\" OR TO_LOWER(win.TargetProcessName) LIKE \"*lsa… | 30 |  |
| q-24091122cd | triage T1212 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4673\" \| STATS c = COUNT(*) BY win.PrivilegeList, win.ProcessName, host.name \| SORT c DESC \| LIMIT 30"} | 30 |  |
| q-4b5991730a | triage T1212 step 7 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None | F22 |
| q-12c5da7ca8 | triage T1212 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:50.000Z\" AND @timestamp <= \"2020-05-02T03:05:20.000Z\" \| KEEP @timestamp, event.code, user.name, win.S… | 40 | F22 |
| q-6acb028a49 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-f8d78c6917 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-13d6381411 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-46b9e9b667 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-436d6208cb | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-111454bc2c | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-10ebe4770d | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-b7f9fd63c9 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-ab567b71d9 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwQ"} | None |  |
| q-6a39211e5b | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwK"} | None |  |
| q-4a3bd182cc | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-2e1a65eeda | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-3701b72d6f | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz-ho2U"} | None |  |
| q-006816c490 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkady05"} | None |  |
| q-5c837bb8a7 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkbfEQ2"} | None |  |
| q-eaae316176 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAu"} | None |  |
| q-53f81f9872 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-c87b4f1b93 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYrx"} | None |  |
| q-1fb9682d72 | triage T1539 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*Web Data* OR win.TargetFilename:*Local State*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 6 |  |
| q-7092bdab52 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*\\\\user data\\\\*\" OR TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" O… | ERROR |  |
| q-f722e9c36e | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*cookies*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*user data*\" OR T… | ERROR |  |
| q-0e479e6355 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*user data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO… | 5 |  |
| q-ec58656f3f | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookies*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*user data*\" … | 1 |  |
| q-e0ec714671 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code IN (\"10\",\"23\",\"9\",\"2\") AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE … | ERROR |  |
| q-4b337676d2 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, win.Path, win.ScriptBlockId, _id, _index \| SORT @timestamp ASC"} | 157 |  |
| q-f5499d45d0 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code IN (\"10\",\"23\",\"9\",\"2\") AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE … | 2 |  |
| q-481f9f2414 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.security METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*cookies*\" OR TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*user data*\" OR TO_LOWER(win.Objec… | ERROR |  |
| q-b0bd2490ee | triage T1539 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*cookies*\" OR TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*user data*\" OR TO_LOWER(w… | 0 |  |
| q-625ab9bf71 | triage T1539 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \| SORT @t… | 359 |  |
| q-f92638968b | triage T1539 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-52623ee567 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNpkH"} | None |  |
| q-0f85877fe0 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-01df61b326 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkfkUhu"} | None |  |
| q-8934dc85c4 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNpkf"} | None |  |
| q-ffffa15a3f | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYrx"} | None |  |
| q-dc46697ef3 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-72ee53dd02 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None | F25, F27 |
| q-936b5987e2 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqjKK"} | None |  |
| q-bc90677b2c | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSwG"} | None | F29 |
| q-1598580578 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDl0_c"} | None |  |
| q-0b43dfb49b | triage T1552 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*coyn5igj*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "file.path", "process.executable", "process.command_line", "win.TargetFilename"], "size": 20… | 1 |  |
| q-d45436133e | triage T1552 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, win.Path, win.ScriptBlockId, _id, _index \| SORT @timestamp ASC"} | ERROR |  |
| q-886b0c5361 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \| SORT @timestamp… | ERROR |  |
| q-c47dc7e164 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, win.Path, win.ScriptBlockId, _id, _index \| SORT @timestamp ASC"} | 157 |  |
| q-bd22f3c267 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \| SORT @times… | 141 |  |
| q-ada00e3527 | triage T1552 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None | F25, F30 |
| q-e34a428d55 | triage T1552 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz5hds0"} | ERROR |  |
| q-b4378a9093 | triage T1552 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (registry.path LIKE \"*Password*\" OR registry.path LIKE \"*Credential*\" OR registry.path LIKE \"*Secret*\") \| KEEP @timestamp, host.name, user.name, process.e… | 17 | F28 |
| q-3207f691a5 | triage T1552 step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:*Invoke-Exfil*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ScriptBlockText", "win.Path"], "size": 20, "sort": "asc"} | 2 |  |
| q-25168b19d7 | triage T1552 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*unattend*\" OR file.path LIKE \"*Groups.xml*\" OR file.path LIKE \"*SYSVOL*\" OR file.path LIKE \"*ConsoleHost_history*\" OR file.path LIKE \"… | 1 |  |
| q-d88b0b9f9f | triage T1552 step 5 | esql | {"query": "FROM logs-windows.security METADATA _id, _index \| WHERE event.code == \"5145\" AND (win.ObjectName LIKE \"*SYSVOL*\" OR win.ObjectName LIKE \"*Groups.xml*\" OR win.ObjectName LIKE \"*Policies*\") \| KEEP @timestamp, host.name, user.name, win.Object… | ERROR |  |
| q-a0f1c59987 | triage T1552 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None | F26 |
| q-c435dbdaac | triage T1552 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None | F27 |
| q-aea2b5e70b | triage T1552 step 6 | search | {"dataset": "windows.security", "query": "event.code:5145 AND (win.ObjectName:*SYSVOL* OR win.ObjectName:*Groups.xml* OR win.ObjectName:*Policies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ObjectName", "win.… | 0 |  |
| q-03cb3b443b | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-95a78fc5d9 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-154e13fa0b | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-a7ed1158af | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-163829aadd | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-e0e1489344 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-c968437f50 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-760eaab758 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-36b1242b30 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-de32104846 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-c2d372923f | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-a31e56ec1e | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JA2"} | None |  |
| q-6fdeceac67 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JA2"} | None |  |
| q-951288e33e | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkEHr1e"} | None |  |
| q-90770443ad | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkILZ_7"} | None |  |
| q-0ab5d4d6f5 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSwG"} | None |  |
| q-7b148a12e0 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-465c51e42b | triage T1555 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1… | 33 | F31 |
| q-cab12a1bfc | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None | F34 |
| q-ff9874672d | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None | F31, F32 |
| q-6e2cf9f0da | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None | F31 |
| q-cd5aa3fee6 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:15:00.000Z\" \| KEEP @timestamp, host.name, user.name, process.executable, process.comman… | ERROR |  |
| q-20693991ff | triage T1555 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:15:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.Path, win.ScriptBlockTe… | ERROR |  |
| q-a019ef7074 | triage T1555 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:15:00.000Z\" \| KEEP @timestamp, host.name, user.name, process.executable, process.co… | 97 |  |
| q-ee0fd8520c | triage T1555 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:15:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.Path, win.ScriptBlo… | 232 | F31 |
| q-e9bbe41279 | triage T1555 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*lsass*\" OR TO_LOWER(win.ObjectName) LIKE \"*sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*security*\" OR TO_LOWER(win.ObjectN… | 6 | F31, F33 |
| q-344811e3a8 | triage T1555 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOWER(process.command_line) LIKE \"*credential*\" OR… | 0 |  |
| q-f64ce1965d | triage T1555 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" AND host.name IN (\"scranton.dmevals.local\", \"nashua.dmevals.lo… | 80 | F32 |
| q-6915f2a742 | triage T1555 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*local state*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIK… | 0 |  |
| q-5533971025 | triage T1555 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*vault*\" OR TO_LOWER(registry.path) LIKE \"*credential*\" OR TO_LOWER(registry.path) LIKE \"*protect*\" OR TO_LOWER(registry.pat… | 43 | F33 |
| q-95c6db0a9f | triage T1555 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" AND @timestamp >= \"2020-05-02T03:08:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, hos… | 2 | F31 |
| q-43a4f182fc | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-18abf4844c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-d57a316744 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-b65d967313 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz-ho2U"} | None |  |
| q-394222bbff | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwEmW7D"} | None |  |
| q-143d052804 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-17fba9e217 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-78a20f94e5 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopc"} | None |  |
| q-3586de1d9c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-9ab29e5320 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkTWMJg"} | None |  |
| q-af50ff19b7 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkEHr1e"} | None |  |
| q-c5fc7ffc33 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAz"} | None |  |
| q-3a4e170852 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsQ2P9A"} | None |  |
| q-c161e36393 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-453512dfb2 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-1e864539af | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-870d5820e1 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:11 AND (win.TargetFilename:*0piklvia* OR win.TargetFilename:*qkbkqqbs* OR win.TargetFilename:*passwordsDB*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 19 |  |
| q-321df99c74 | triage T1556 step 1 | search | {"dataset": "windows.security", "query": "event.code:4662 OR event.code:5136", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ObjectName", "win.ObjectType", "win.SubjectUserName", "win.AccessMask", "win.Properties"… | 7 | F36, F38, F39, F40 |
| q-084c66d179 | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (process.executable:*PowerShell* OR process.executable:*wsmprovhost* OR process.executable:*wininit* OR process.executable:*csrss*)", "time_from": null, "time_to": null, "fie… | 8 | F35, F41 |
| q-785d1037f9 | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*0piklvia* OR win.TargetFilename:*qkbkqqbs* OR win.TargetFilename:*passwordsDB*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.ex… | 19 | F37 |
| q-f1e7bd3169 | triage T1556 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Add-Type* OR win.ScriptBlockText:*DllImport* OR win.ScriptBlockText:*OpenProcess* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*Cre… | 8 |  |
| q-b47222b0c5 | triage T1556 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*accesschk* OR process.command_line:*passwordsDB* OR process.command_line:*procdump* OR process.command_line:*dump*)", "time_from": null, "time_to": … | 2 | F41 |
| q-a2cb9016b9 | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHppbR"} | None | F37 |
| q-b2833e9c31 | triage T1556 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\"", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "wi… | 0 |  |
| q-dba89794da | triage T1556 step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:21:00.000Z\"", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "wi… | 0 |  |
| q-b5eac3b004 | triage T1556 step 6 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND @timestamp >= \"2020-05-01T23:00:00.000-04:00\" AND @timestamp <= \"2020-05-01T23:21:00.000-04:00\"", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.… | 0 |  |
| q-b99304f8f5 | triage T1556 step 7 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:*0piklvia* OR event.code:4104 AND win.ScriptBlockText:*Get-Process*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "win.… | 3 | F41 |
| q-fb9f37016f | triage T1556 step 7 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:*Invoke-Mimikatz* OR event.code:4104 AND win.ScriptBlockText:*sekurlsa* OR event.code:4104 AND win.ScriptBlockText:*DumpCreds* OR event.code:4104 AND win.ScriptBlockText:*Get-K… | 0 |  |
| q-e64370a0c0 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-11ba07346e | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-3e24550542 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAt"} | None |  |
| q-5aaf7487e3 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRX"} | None |  |
| q-38bcd24a25 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpfwJ-Y"} | None |  |
| q-dcf82dae4e | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchIto6IP6U"} | None |  |
| q-daf724778c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHppbR"} | None |  |
| q-b727efdca7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRX"} | None |  |
| q-8664611b85 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-7d79480cb6 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRa"} | None |  |
| q-71fa7fb701 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-032793e9e7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-3fb8a3051e | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-c3b3b50372 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2o"} | None |  |
| q-81424370ab | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwBj58r"} | None |  |
| q-ea079a2631 | triage T1557 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:22 AND win.Image:*cod.3aka3.scr*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 2 | F43 |
| q-8e1c434849 | triage T1557 step 1 | search | {"dataset": "zeek", "query": "event.action:conn AND zeek.resp_l2_addr:\"12:34:56:78:9a:bc\"", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 559 |  |
| q-118b0420e2 | triage T1557 step 2 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ut"} | None | F42, F44, F45 |
| q-76a5671ee3 | triage T1557 step 2 | search | {"dataset": "zeek", "query": "event.action:conn AND destination.port:445", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 45 | F43 |
| q-2ebd434bf6 | triage T1557 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 22 AND win.Image LIKE \"*PsExec64*\" \| KEEP @timestamp, host.name, win.Image, win.QueryName, win.QueryResults, _id, _index"} | ERROR |  |
| q-92679f9b4c | triage T1557 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 3 AND destination.port == 445 \| KEEP @timestamp, host.name, process.executable, destination.ip, user.name, _id, _index \| LIMIT 30"} | ERROR |  |
| q-2c1463b81a | triage T1557 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"22\" AND win.Image LIKE \"*PsExec64*\" \| KEEP @timestamp, host.name, win.Image, win.QueryName, win.QueryResults, _id, _index"} | 4 |  |
| q-aaf2396053 | triage T1557 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND destination.port == 445 \| KEEP @timestamp, host.name, process.executable, destination.ip, user.name, _id, _index \| LIMIT 30"} | 30 | F42, F45 |
| q-04b006eb77 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4697\" \| KEEP @timestamp, host.name, win.ServiceName, win.ServiceFileName, win.ServiceAccount, user.name, _id, _index \| LIMIT 30"} | 23 |  |
| q-b887da0d31 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" AND win.IpAddress == \"172.18.39.2\" \| KEEP @timestamp, host.name, win.TargetUserName, win.IpAddress, win.LogonProcessName, win.Authe… | 1 |  |
| q-10f26f62de | triage T1557 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo6u"} | None |  |
| q-90f71fed0c | triage T1557 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1ovv"} | None | F42 |
| q-159de1299f | triage T1557 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"22\" AND (win.QueryName == \"wpad\" OR win.QueryName == \"..localmachine\" OR win.QueryName == \"prisoner.iana.org\") \| KEEP @timestamp, host.name, win.Image, win.QueryN… | 4 | F43 |
| q-8fa335bc2a | triage T1557 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE process.executable LIKE \"*javamtsup*\" OR win.TargetFilename LIKE \"*javamtsup*\" OR process.command_line LIKE \"*javamtsup*\" \| KEEP @timestamp, host.name, event.code, process.executa… | 14 |  |
| q-9cc528409b | triage T1557 step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchIttzHCIM"} | None | F43 |
| q-b6905cf0ef | triage T1557 step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 67 OR destination.port == 68 OR source.port == 67 OR source.port == 68) \| KEEP @timestamp, host.name, process.executable, source.ip, destina… | 0 |  |
| q-39a1381e92 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkJMpSF"} | None |  |
| q-f4f22d9a87 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkovmKh"} | None |  |
| q-e2e0fd63da | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ut"} | None |  |
| q-bd6ca97ad4 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1ovv"} | None |  |
| q-715e1002eb | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchIttzHCIM"} | None |  |
| q-4ea8cfff13 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItps_TYH"} | None |  |
| q-0f73d88186 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1AhU"} | None |  |
| q-f1db1f09f6 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ud"} | None |  |
| q-77f1795a9b | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ut"} | None |  |
| q-1bcea11450 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ut"} | None |  |
| q-4d9b9e0945 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8vYpc"} | None |  |
| q-43b7f78ed2 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkJMpSF"} | None |  |
| q-81cd62a517 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ut"} | None |  |
| q-0bef8c481f | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (process.executable:*PowerShell* OR process.executable:*wsmprovhost* OR process.executable:*wininit* OR process.executable:*csrss* OR process.executable:*services*)", "time_f… | 9 |  |
| q-270d24dc1e | triage T1558 step 1 | search | {"dataset": "windows.security", "query": "event.code:4769 AND win.ServiceName:krbtgt", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ServiceName", "win.TargetUserName", "win.IpAddress", "win.TicketEncryptionType", "win.TicketOp… | 3 | F46, F47 |
| q-e584340b7f | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None | F46 |
| q-794b4fe642 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None | F48 |
| q-61f696747b | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwEmm4J"} | None | F47 |
| q-d51b3dbf38 | triage T1558 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*powershell* OR process.executable:*wsmprovhost* OR process.executable:*cmd.exe*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "pr… | 30 |  |
| q-0f9ca2bcd9 | triage T1558 step 3 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ServiceName", "win.TargetUserName", "win.IpAddress", "win.TicketEncryptionType", "win.TicketOptions", "win.Status", "win.… | 28 | F48, F49 |
| q-9c6b34e605 | triage T1558 step 4 | search | {"dataset": "windows.security", "query": "event.code:4769 AND (win.ServiceName:WEC$ OR win.ServiceName:SCRANTON$)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ServiceName", "win.TargetUserName", "win.IpAddress", "win.TicketE… | 4 | F48, F49 |
| q-6b045061ce | triage T1558 step 4 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.IpAddress", "win.PreAuthType", "win.Status", "win.TicketEncryptionType", "win.TicketOptions"], "siz… | 14 | F46, F47, F50 |
| q-a6d142e65b | triage T1558 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-edf46409e2 | triage T1558 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*sekurlsa* OR process.command_line:*kerberos* OR process.command_line:*ticket* OR process.command_line:*kirbi* OR process.command_line:*ptt* OR process.command_line:*klist*)", "time… | 0 |  |
| q-221f37c865 | triage T1558 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*python* OR process.executable:*\\\\Temp\\\\*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.TargetFil… | 9 |  |
| q-74a3c2956b | triage T1558 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.kirbi OR win.TargetFilename:*.ccache OR win.TargetFilename:*.ticket OR win.TargetFilename:*lsass* OR win.TargetFilename:*.dmp)", "time_from": null, "time_to": null, "fields": ["@ti… | 2 | F46 |
| q-95f1ed29b4 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqO44i"} | None |  |
| q-694da0f6c6 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcb"} | None |  |
| q-c08f2cf326 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-c99fd9d047 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpBPBlG"} | None |  |
| q-87b67b2f2f | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-36P"} | None |  |
| q-f9897214ef | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-36P"} | None |  |
| q-efa4d37fb7 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-35u"} | None |  |
| q-e016cc9ff6 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwEmm4J"} | None |  |
| q-39359437a0 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjF_4Y"} | None |  |
| q-038e20f214 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-34r"} | None |  |
| q-933b5b81ae | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-f5ed7bca98 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo73"} | None |  |
| q-f7543ded81 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1osp"} | None |  |
| q-eeedd2891e | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0e9"} | None |  |
| q-9b0680e2ee | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0e9"} | None |  |
| q-bd2f093576 | triage T1606 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F51 |
| q-3edf1d8cb4 | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None | F51 |
| q-e7a58e937d | triage T1606 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 \| KEEP @timestamp, host.name, user.name, win.Path, win.ScriptBlockId, _id, _index \| SORT @timestamp ASC \| LIMIT 60"} | ERROR |  |
| q-32250c5e66 | triage T1606 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*readme.ps1* OR process.command_line:*Sysinternals* OR process.command_line:*lsass* OR process.command_line:*token* OR process.command_line:*Cookie*)", "time_from": null, "time_to":… | 14 | F51, F52 |
| q-7a23270bac | triage T1606 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.Path, win.ScriptBlockId, _id, _index \| SORT @timestamp ASC \| LIMIT 80"} | 80 |  |
| q-7be33e1697 | triage T1606 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*INetCookies* OR win.TargetFilename:*Cookies* OR win.TargetFilename:*webdav* OR win.TargetFilename:*WebClient*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 1 | F52 |
| q-9c4e7a626d | triage T1606 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*webdav*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credential*\" … | 10 |  |
| q-b473b28c35 | triage T1606 step 4 | search | {"dataset": "windows.security", "query": "event.code:4624 AND (win.LogonType:3 OR win.LogonType:9 OR win.LogonType:10) AND win.TargetUserName:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "win.Ta… | 22 | F53 |
| q-b488b306d5 | triage T1606 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None | F51, F52 |
| q-56f43f21f1 | triage T1606 step 5 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "win.TargetUserName", "win.TargetServerName", "win.ProcessName", "win.SubjectUserName", "win.IpAddr… | 15 | F51, F53 |
| q-b0b9d4581c | triage T1606 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*WebClient* OR registry.path:*WebDav* OR registry.path:*AuthForwardServerList* OR registry.path:*BasicAuthLevel*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 0 |  |
| q-88f771d738 | triage T1606 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.SourceImage:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.executable", "process.command_lin… | 4 | F51 |
| q-9bebab40ee | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-f1805e30c4 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-3cb14c8708 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-d0b6ccea23 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-c090e85166 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None |  |
| q-aae1ee80e1 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-f607ed6da9 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpHV4S3"} | None |  |
| q-c648c86c23 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-b15b2f83ee | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-25d823022e | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y1-"} | None |  |
| q-24b4db10db | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y1-"} | None |  |
| q-ff15e0b970 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-b4552561a0 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-7bf2990627 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjGP6n"} | None |  |
| q-580a1e1ed2 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsc9wOe"} | None |  |
| q-bdfa5a4508 | triage T1621 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uo"} | None | F54 |
| q-9d8ae4b695 | triage T1621 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uv"} | None | F54 |
| q-203cd3bb7b | triage T1621 step 1 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:http", "time_from": null, "time_to": null, "size": 20, "sub_field": "url.domain"} | 62 |  |
| q-e3aded362d | triage T1621 step 1 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*mfa*\" OR TO_LOWER(message) LIKE \"*multi-factor*\" OR TO_LOWER(message) LIKE \"*authenticator*\" OR TO_LOWER(message) LIKE \"*2fa*\" OR TO_LOWER(message) LIKE \… | 0 |  |
| q-ef7ebf1be0 | triage T1621 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*mfa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*authenticator*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*2fa*\"… | 16 | F54 |
| q-c5758df78e | triage T1621 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" \| STATS c = COUNT(*) BY win.LogonType, win.AuthenticationPackageName, host.name \| SORT c DESC"} | 11 |  |
| q-ce75dac7a9 | triage T1621 step 2 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 613 |  |
| q-4bf04e2daf | triage T1621 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"ssl\" \| STATS c = COUNT(*) BY destination.ip, destination.port, tls.server.subject \| SORT c DESC \| LIMIT 15"} | 2 |  |
| q-8347592c42 | triage T1621 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" OR event.code == \"4648\" OR event.code == \"4625\" \| STATS c = COUNT(*) BY event.code, win.TargetUserName, host.name \| SORT c DESC \| LIMIT 20"} | 11 |  |
| q-1d175160d8 | triage T1621 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE TO_LOWER(win.ProcessName) LIKE \"*auth*\" OR TO_LOWER(win.ProcessName) LIKE \"*mfa*\" OR TO_LOWER(win.ServiceName) LIKE \"*auth*\" OR TO_LOWER(win.ServiceName) LIKE \"*mfa*\" OR TO_LOW… | 0 |  |
| q-1f3249d43e | triage T1621 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"dns\" OR event.action == \"notice\" \| STATS c = COUNT(*) BY event.action, dns.question.name, zeek.note \| SORT c DESC \| LIMIT 25"} | 23 |  |
| q-71f80033ba | triage T1621 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uo"} | None |  |
| q-c36d68989f | triage T1621 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uo"} | None |  |
| q-c2a05daf4f | triage T1621 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uv"} | None |  |
| q-988400ad2e | triage T1621 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uv"} | None |  |
| q-48e80d2cad | triage T1621 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwBjiC8"} | None |  |
| q-24b953fae4 | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None | F55 |
| q-6c2c1d9abf | triage T1649 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*pfx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetFilename", "process.executable", "process.command_line", "user.name", "win.Image"], "size"… | 1 |  |
| q-ea50096a4c | triage T1649 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None | F55 |
| q-90601e4d83 | triage T1649 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*certutil* OR process.command_line:*Export-Pfx* OR process.command_line:*readme.ps1* OR process.command_line:*Get-PrivateKeys*)", "time_from": null, "time_to": null, "fields": ["@ti… | 0 |  |
| q-9f9c651449 | triage T1649 step 2 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.PreAuthType", "win.IpAddress", "win.Status", "win.TicketEncryptionType"], "size": 20, "sort": "asc"… | 14 | F55 |
| q-7c3e59e37b | triage T1649 step 3 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.OperationType", "win.ProcessName", "win.SubjectUserName", "win.… | 1 |  |
| q-296587dc29 | triage T1649 step 3 | search | {"dataset": "windows.sysmon", "query": "process.command_line:*readme.ps1* OR process.command_line:*Get-PrivateKeys* OR win.TargetFilename:*coyn5igj*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.comm… | 2 |  |
| q-0d456ccb4c | triage T1649 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5I18"} | None | F55 |
| q-37666eaf6d | triage T1649 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*pfx* OR win.ScriptBlockText:*PrivateKeys* OR win.ScriptBlockText:*Certificates* OR win.ScriptBlockText:*cert:\\\\*)", "time_from": null, "time_to": null, "fields": ["@timesta… | ERROR |  |
| q-add22a34c9 | triage T1649 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (win.ScriptBlockText LIKE \"*pfx*\" OR win.ScriptBlockText LIKE \"*PrivateKeys*\" OR win.ScriptBlockText LIKE \"*Certificate*\") \| KEEP @timestamp, host.name,… | ERROR |  |
| q-944be5eb77 | triage T1649 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*powershell.exe AND (process.command_line:*Downloads* OR process.command_line:*.ps1*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", … | 1 |  |
| q-a8e5891ce9 | triage T1649 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None | F55 |
| q-d1328390ea | triage T1649 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*pfx*\" OR win.ScriptBlockText LIKE \"*PrivateKeys*\" OR win.ScriptBlockText LIKE \"*Certificate*\") \| KEEP @timestamp, host.n… | 3 |  |
| q-7fe22e16a2 | triage T1649 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSxb"} | None | F55 |
| q-3361786b70 | triage T1649 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1N1"} | None | F55 |
| q-eac33f2964 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-cc234e62ed | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-571ebceffb | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-6b84a5dfc4 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSxb"} | None |  |
| q-bbbb95a12e | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-cecc46b6c6 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-296fc46e62 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1N1"} | None |  |
| q-2e27c944ad | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5I18"} | None |  |
| q-a87d3846bc | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-f7a97175d1 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcb"} | None |  |
| q-b3954976dd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-25ab009e3a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-8aba7ad651 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-8eb306e1d9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-75d5cf9d5c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-8011fc2b53 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtA"} | None |  |
| q-f1a4836daa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtA"} | None |  |
| q-4b53356e55 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtH"} | None |  |
| q-5cb811a116 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAs"} | None |  |
| q-b4209aff99 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRX"} | None |  |
| q-ec29e0e3b0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRX"} | None |  |
| q-6ea60116a5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtA"} | None |  |
| q-21dc3cdb72 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-d4f1c0c8b8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-b74daacdc1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkHK8X3"} | None |  |
| q-944c34237a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkHK8V2"} | None |  |
| q-a1515d402a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopf"} | None |  |
| q-4a82de9f8c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCzT"} | None |  |
| q-021bea84d4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2o"} | None |  |
| q-b75ccca564 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5KNV"} | None |  |
| q-bc09468c29 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5KNV"} | None |  |
| q-cf0c867ea2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS3MUJ"} | None |  |
| q-15d27e4dac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-2149dd1694 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-55f5adc63c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovu"} | None |  |
| q-bacbd39282 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz7ud8y"} | None |  |
| q-11b2bd36b0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-1ebb5e8ade | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-e28a0dfc47 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-b8b6796b55 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-e66352eb52 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-3f07fc413e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo4k"} | None |  |
| q-f18374fb8a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-c7e9011ae5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-ec7c7e7357 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-aeb5a033c1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-d7ecea6424 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkady05"} | None |  |
| q-16c55062ce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkbfEQ2"} | None |  |
| q-e23ab44578 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsQ2P9A"} | None |  |
| q-87e077a13f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWXW"} | None |  |
| q-9edc3e1b41 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkADeNe"} | None |  |
| q-7341433704 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkADeNe"} | None |  |
| q-7967bc1b9f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlU_o"} | None |  |
| q-bda57b6531 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlShi"} | None |  |
| q-7c5cb0da58 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-48f30eb492 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-94ea15d489 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-f78fa57a9c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItj59cFt"} | None |  |
| q-e193d7e322 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-4e321de65c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-c2fb4ee906 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-efe40e0456 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-47ee4a2812 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-12503bd791 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX2"} | None |  |
| q-8d79fa0406 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWV3"} | None |  |
| q-67cf94df7f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-9bfa092e49 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsc9wOe"} | None |  |
| q-07ec268d78 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-0ec7c77d9d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkHK8X3"} | None |  |
| q-d3bd759b48 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-faf7ed6c1b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-6de8add88b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2o"} | None |  |
| q-29212179a2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None |  |
| q-b9352cf15b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-1f02b0123e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-f80970f18d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-9567e224bf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-72673e3776 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWXW"} | None |  |
| q-e40281e8a0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-de4bd76d5e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpESdr2"} | None |  |
| q-9b4a50432e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpESdr2"} | None |  |
| q-8db5c14e33 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpMctGb"} | None |  |
| q-4b3f8a8036 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItj59cFt"} | None |  |
| q-b49ef40ecc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqjTX"} | None |  |
| q-bf46c8b17b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpIWWNw"} | None |  |
| q-7fc58a9544 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpizV0q"} | None |  |
| q-8149e22bf4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwsQxHC"} | None |  |
| q-3123e93020 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFUeT"} | None |  |
| q-1b32d69dcb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo6a"} | None |  |
| q-67f3dd3cf2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-d314e214b1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-e44b66faac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-eb9c3e2004 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-240e72a790 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-bc634f400e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-52c26e110a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-128a02fbc5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-dfdef7c69a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwQ"} | None |  |
| q-8e407b6719 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwK"} | None |  |
| q-7b92419873 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-b503cfd2e7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-5412383bb7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz-ho2U"} | None |  |
| q-239e06e010 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkady05"} | None |  |
| q-3957b159ae | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkbfEQ2"} | None |  |
| q-830e330c43 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAu"} | None |  |
| q-01625daf0c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-e57c437dcb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-690fc63d6b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-bb84cfdb86 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-212729af82 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-9c758bec95 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-18a89e4c09 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-1c1a55d6d2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-8d4d109660 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-8d9f8eac3c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-ed4200eabb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-bb9afd34eb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JA2"} | None |  |
| q-ed9a7bdf1b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JA2"} | None |  |
| q-871a09f71c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkEHr1e"} | None |  |
| q-47ac74ca71 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkILZ_7"} | None |  |
| q-67907b577b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSwG"} | None |  |
| q-e9ebce4152 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-f26bf8ab25 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-a06b4e2ded | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-113c29515a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-9d4276ad55 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz-ho2U"} | None |  |
| q-ac108ac370 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwEmW7D"} | None |  |
| q-0052cbadfb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-7f52149511 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-3fa32c168c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopc"} | None |  |
| q-55c58b4457 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-217a7fe793 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkTWMJg"} | None |  |
| q-578dc29af6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkEHr1e"} | None |  |
| q-88acaf6d71 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAz"} | None |  |
| q-db76863d35 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsQ2P9A"} | None |  |
| q-b6199304f9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-2c8e812670 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-8e45d78f31 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-e04762086e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-e085d737ce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAt"} | None |  |
| q-27e2f62638 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRX"} | None |  |
| q-9ef153f259 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpfwJ-Y"} | None |  |
| q-5f8d0658b7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchIto6IP6U"} | None |  |
| q-08569dd026 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHppbR"} | None |  |
| q-755e56bfb3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRX"} | None |  |
| q-b5aa8d5509 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-de64b34d37 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRa"} | None |  |
| q-ae908f3372 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-72038fb73b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-0985aac822 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-7a5ea1fece | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2o"} | None |  |
| q-f817f15ff4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwBj58r"} | None |  |
| q-9c35a36410 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkJMpSF"} | None |  |
| q-594bc8ba7a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkovmKh"} | None |  |
| q-8ce0694b1e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ut"} | None |  |
| q-e2c63a0851 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1ovv"} | None |  |
| q-589ac9b62f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchIttzHCIM"} | None |  |
| q-de9f281004 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItps_TYH"} | None |  |
| q-a90bd09248 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1AhU"} | None |  |
| q-3e144dc974 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ud"} | None |  |
| q-0a32e1ee31 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ut"} | None |  |
| q-428fdb83f6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ut"} | None |  |
| q-b109837a2d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8vYpc"} | None |  |
| q-6f132b85cd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkJMpSF"} | None |  |
| q-dac3a8f8aa | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ut"} | None |  |
| q-5eeb275150 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqO44i"} | None |  |
| q-f104e396d3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcb"} | None |  |
| q-23a8e02103 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-2ebb39adb5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpBPBlG"} | None |  |
| q-e78ea1065e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-36P"} | None |  |
| q-acff20da80 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-36P"} | None |  |
| q-b7cd75171f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-35u"} | None |  |
| q-11ff619b41 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwEmm4J"} | None |  |
| q-f8034b84e8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjF_4Y"} | None |  |
| q-1d324541f9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-34r"} | None |  |
| q-e82338151e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-cba1b81c14 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo73"} | None |  |
| q-893d87053d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1osp"} | None |  |
| q-f2f1bb92c5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0e9"} | None |  |
| q-b1d2356e23 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0e9"} | None |  |
| q-8644f141f2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-2f4b66c9a5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-8bbefd5e5a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-008a0d5cbb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-ec05dcef3a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None |  |
| q-739a0c21bb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-9048e037d3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpHV4S3"} | None |  |
| q-50c8abf4b5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-df52c763dd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-072f5d4be2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y1-"} | None |  |
| q-a77671eee3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y1-"} | None |  |
| q-94a8673a13 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-190f397bdc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-4c8cb7b957 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjGP6n"} | None |  |
| q-21cf6d44ee | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsc9wOe"} | None |  |
| q-82ab194abc | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uo"} | None |  |
| q-ccf872ab42 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uo"} | None |  |
| q-695752a21b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uv"} | None |  |
| q-246c53e257 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uv"} | None |  |
| q-c021b57cb0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwBjiC8"} | None |  |
| q-2c828c9023 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-11cb4420ec | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-322ba493e9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-ff943946f3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSxb"} | None |  |
| q-952baafced | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-1a4398db82 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-734b4f4850 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1N1"} | None |  |
| q-19277eca34 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5I18"} | None |  |
| q-c89fea2280 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-4c3d9b41fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcb"} | None |  |
| q-5f7f541687 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29.430000+00:00", "time_to": "2020-05-02T03:26:40+00:00", "size": 100, "sub_field": "process.parent.exec… | 61 |  |
| q-29cb70491b | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29.430000+00:00", "time_to": "2020-05-02T03:26:40+00:00", "size": 100, "sub_field": "process.executable"} | 248 |  |
| q-0325ac6358 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29.430000+00:00", "time_to": "2020-05-02T03:26:40+00:00", "size": 100, "sub_field": "process.parent… | 63 |  |
| q-5aa2243993 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29.430000+00:00", "time_to": "2020-05-02T03:26:40+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-a35c3401f5 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:56:18+00:00", "time_to": "2020-05-02T03:26:18+00:00", "size": 100, "sub_field": "process.parent.executable… | 18 |  |
| q-9684607b61 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:56:18+00:00", "time_to": "2020-05-02T03:26:18+00:00", "size": 100, "sub_field": "process.executable"} | 76 |  |
| q-6cb078bced | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:56:18+00:00", "time_to": "2020-05-02T03:26:18+00:00", "size": 100, "sub_field": "process.parent.execu… | 18 |  |
| q-dbaf20be4d | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:56:18+00:00", "time_to": "2020-05-02T03:26:18+00:00", "size": 100, "sub_field": null} | 2185 |  |
| q-6f0379dfd7 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:36:26+00:00", "size": 100, "sub_field": "process.parent.ex… | 359 |  |
| q-b4e7cc795f | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:36:26+00:00", "size": 100, "sub_field": "process.executable"} | 1276 |  |
| q-8349efdac5 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:36:26+00:00", "size": 100, "sub_field": "process.pare… | 370 |  |
| q-ca56c26f34 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:36:26+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-cfc5a8b28a | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == 1 AND (process.executable LIKE \"*python.exe\" OR process.executable LIKE \"*Rar.exe\" OR process.executable LIKE \"*sdelete64.exe… | ERROR |  |
| q-2943be254a | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == 1 AND (process.executable LIKE \"*accessChk.exe\" OR process.executable LIKE \"*PsExec64.exe\" OR process.executable LIKE \"*sde… | ERROR |  |
| q-6afae450ea | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"1\" AND (process.executable LIKE \"*python.exe\" OR process.executable LIKE \"*Rar.exe\" OR process.executable LIKE \"*sdelete64… | 10 | F57 |
| q-738d154068 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"1\" AND (process.executable LIKE \"*accessChk.exe\" OR process.executable LIKE \"*PsExec64.exe\" OR process.executable LIKE \"… | 15 | F57, F59, F60, F61 |
| q-92294adeec | pivot step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"11\",\"3\",\"22\",\"23\",\"2\") AND (process.executable LIKE \"*python.exe\" OR process.executable LIKE \"*powershell.exe\" OR … | 399 | F57 |
| q-6a0ad8c0bc | pivot step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, user.name, powershell.script_block_text, _id, _index \| SORT @timestamp"} | ERROR |  |
| q-e04430654a | pivot step 4 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-6b2f55f39a | pivot step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"11\" AND process.executable LIKE \"*python.exe\" AND file.path NOT LIKE \"*_MEI29522*\" \| KEEP @timestamp, process.executable, … | 2 |  |
| q-82fd871960 | pivot step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp"} | 11 |  |
| q-4f3fdaf9d0 | pivot step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1OJ"} | None | F57 |
| q-ca7ffedbfc | pivot step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"10\" AND (target.process.executable LIKE \"*lsass*\" OR target.process.executable LIKE \"*winlogon*\" OR target.process.executab… | ERROR |  |
| q-90dc0cd977 | pivot step 7 | get_fields | {"dataset": "windows.sysmon", "prefix": "win"} | None |  |
| q-df1061710b | pivot step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"10\" \| KEEP @timestamp, user.name, process.executable, win.GrantedAccess, _id, _index \| SORT @timestamp"} | 500 |  |
| q-4d270bfae0 | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"10\" \| STATS c = COUNT(*) BY process.executable, win.TargetImage, win.GrantedAccess \| SORT c DESC"} | 298 |  |
| q-a45388357d | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*\\\\sam\" OR TO_LOWER(file.path) LIKE \"*\\\\security\" OR TO_LOWER(file.path) LIKE \"*\\\\system32\\\\config*\" OR TO_LOWER(file.pa… | ERROR |  |
| q-eb79334cad | pivot step 9 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*config\\\\\\\\sam\" OR TO_LOWER(file.path) LIKE \"*config\\\\\\\\security\" OR TO_LOWER(file.path) LIKE \"*config\\\\\\\\system\" OR… | 4 | F59 |
| q-b7f6db329c | pivot step 9 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| KEEP @timestamp, user.name, process.executable, win.TargetImage, win.GrantedAccess,… | 29 | F56 |
| q-23839530eb | pivot step 10 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4103\" AND (TO_LOWER(win.Message) LIKE \"*lsass*\" OR TO_LOWER(win.Message) LIKE \"*credential*\" OR TO_LOWER(win.Message) L… | 4 |  |
| q-243c522418 | pivot step 10 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:09:00.000Z\" AND @timestamp <= \"2020-05-02T03:11:00.000Z\" \| KEEP @timestamp, use… | 2 |  |
| q-f6aa6cf1d7 | pivot step 11 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\") AND (TO_LOWER(win.ObjectName) LIKE \"*config\\\\\\\\sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*config\\\\\\\\security*\" OR TO_LOWER(win.ObjectName) L… | 19 | F56 |
| q-0b9c77c643 | pivot step 11 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4688\" AND (process.executable LIKE \"*python*\" OR process.executable LIKE \"*Rar*\" OR process.executable LIKE \"*sdelete*\"… | 13 |  |
| q-b326943382 | pivot step 12 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4624\" \| KEEP @timestamp, user.name, win.LogonType, win.IpAddress, win.WorkstationName, win.AuthenticationPackageName, _id, _… | 25 | F58 |
| q-403dfd30db | pivot step 12 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4688\" AND (process.executable LIKE \"*accesschk*\" OR process.executable LIKE \"*PsExec*\" OR process.executable LIKE \"*ho… | 11 | F58 |
| q-f55fdcaf85 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-2fcd892613 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-cfb17cbe7f | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-5cfa9244ae | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-7e892a4679 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-c55ce0c305 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-1fb261e352 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1OJ"} | None |  |
| q-c73f484e7e | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdI9"} | None |  |
| q-fe23eea289 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ-S"} | None |  |
| q-6f2c63fe1d | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkjomHY"} | None |  |
| q-ef8ad9c2d6 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEeE"} | None |  |
| q-9753df93cb | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0fg"} | None |  |
| q-9d3d3b97f9 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0fg"} | None |  |
| q-8be4cf2d80 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-843ff9a102 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-dcb49d4675 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-039820ae02 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-ce439642b7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-454b14ab67 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtA"} | None |  |
| q-2527b625e3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtA"} | None |  |
| q-0bbc60c413 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtH"} | None |  |
| q-d418a2b2cb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAs"} | None |  |
| q-82c9ef7edd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRX"} | None |  |
| q-e7d7cd9cc2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRX"} | None |  |
| q-f19bfbe897 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YtA"} | None |  |
| q-210fb8c5fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-f6918cb59e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-94a3f62b37 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkHK8X3"} | None |  |
| q-c11f6e8c9b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkHK8V2"} | None |  |
| q-c9e115d6a5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopf"} | None |  |
| q-015de2247b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCzT"} | None |  |
| q-cc9367d928 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2o"} | None |  |
| q-281985ba02 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5KNV"} | None |  |
| q-7cfad2f603 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5KNV"} | None |  |
| q-ff22236c1f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS3MUJ"} | None |  |
| q-e11fc18900 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-cb8def4009 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-70e5037043 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovu"} | None |  |
| q-820dd25d82 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz7ud8y"} | None |  |
| q-0a0c3c5580 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-e1b80f9d5d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-92786ef0bd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-f48aa23016 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-2bb83c4ed7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-8a919f4ab9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo4k"} | None |  |
| q-cc05ab466a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-95da08e753 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-c622aeaccd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-ca2444b4d0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-2c46b6d57c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkady05"} | None |  |
| q-d4fa940edd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkbfEQ2"} | None |  |
| q-362048ab22 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsQ2P9A"} | None |  |
| q-7fdf2bca0a | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWXW"} | None |  |
| q-334f1c9e47 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkADeNe"} | None |  |
| q-5a6ae00338 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkADeNe"} | None |  |
| q-040140adfb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlU_o"} | None |  |
| q-5942f79ad7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlShi"} | None |  |
| q-652754cea1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-55b9040970 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-b58c8e0387 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-b0f2a49ebe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItj59cFt"} | None |  |
| q-6ecc5ecb73 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-cd65b52b48 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-a6129bf1e0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-60fec7033c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-fb1488477d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-fae46a9126 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX2"} | None |  |
| q-7e100b45f9 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWV3"} | None |  |
| q-aa89b0c0da | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-82ba7ffd4d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsc9wOe"} | None |  |
| q-b8eceac5b1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-727d023b1a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkHK8X3"} | None |  |
| q-0b7d04d6bd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-fcf05924e2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-3d377d75dd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2o"} | None |  |
| q-ffcaed6a48 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None |  |
| q-bf76bd58ba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-66c1f33f22 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-7748088f77 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-93f1bfefce | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-995d3e7f70 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWXW"} | None |  |
| q-f881ab294f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-f5196440ff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpESdr2"} | None |  |
| q-1e52901d7e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpESdr2"} | None |  |
| q-52c6ab3c86 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpMctGb"} | None |  |
| q-fd137000b3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItj59cFt"} | None |  |
| q-411872702d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqjTX"} | None |  |
| q-a8a7805fe9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpIWWNw"} | None |  |
| q-b1d07f9c0e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpizV0q"} | None |  |
| q-2d1ad5e602 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwsQxHC"} | None |  |
| q-42e4ecfe43 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFUeT"} | None |  |
| q-0afa40850a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo6a"} | None |  |
| q-f066e03f4c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-ef2e573981 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-6c7c3ce724 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-31cc164f95 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-6b08f10621 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-fb04441028 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-71459e8bf9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-f6c45ddd1c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-e1fe41c470 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwQ"} | None |  |
| q-776da63c16 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwK"} | None |  |
| q-b38b5230cb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-5d3aee80fb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-63b05d09f4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz-ho2U"} | None |  |
| q-629796716d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkady05"} | None |  |
| q-d8addfc007 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkbfEQ2"} | None |  |
| q-25388c64de | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAu"} | None |  |
| q-26a40015ca | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-fbd67d77f9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-9a19049b7f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-1785af1a43 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-01728271f7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-d5fca13194 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-d1787e3118 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-d97f51da30 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-5fcc4f88b0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-b0c82df8c1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-024473f072 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-ac6135a4e0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JA2"} | None |  |
| q-bfb70ccc04 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JA2"} | None |  |
| q-1c5f44067b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkEHr1e"} | None |  |
| q-f1c698db33 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkILZ_7"} | None |  |
| q-c9d7faaa66 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSwG"} | None |  |
| q-f67b014114 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-86236d6e31 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-69a4a71cb9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-8f30801543 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-4fbc9f73c2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz-ho2U"} | None |  |
| q-26ae466dc9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwEmW7D"} | None |  |
| q-28d514218e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-27a3b2f7b7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-a68c28a5d6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopc"} | None |  |
| q-ae9f829ec9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-06d09976ed | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkTWMJg"} | None |  |
| q-ad1c5b75b6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkEHr1e"} | None |  |
| q-7505c8b86d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAz"} | None |  |
| q-769c84add9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsQ2P9A"} | None |  |
| q-a15d0a5881 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-def801c6b8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-91e9719074 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-0b8d95ea76 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-818ef99ca2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAt"} | None |  |
| q-668e15aee5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRX"} | None |  |
| q-2f334d1ac8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpfwJ-Y"} | None |  |
| q-89de7f7a08 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchIto6IP6U"} | None |  |
| q-4fcf589cd1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHppbR"} | None |  |
| q-8507a673f1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRX"} | None |  |
| q-8be99a7fe0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-8e622bce9a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRa"} | None |  |
| q-e3431b4911 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-fad69c776e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-fcaed4a38d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-48d1ac9ad9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2o"} | None |  |
| q-cd53bffe0f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwBj58r"} | None |  |
| q-e98238bed9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkJMpSF"} | None |  |
| q-8054ae0cf2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkovmKh"} | None |  |
| q-795e9ba6ed | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ut"} | None |  |
| q-36bd4d2320 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1ovv"} | None |  |
| q-4a350af95e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchIttzHCIM"} | None |  |
| q-87da584534 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItps_TYH"} | None |  |
| q-4edec3d1f2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1AhU"} | None |  |
| q-51f706e5b1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ud"} | None |  |
| q-f76e79a02e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ut"} | None |  |
| q-168dad6fff | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ut"} | None |  |
| q-8ad7a0525d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8vYpc"} | None |  |
| q-efc460f1f9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkJMpSF"} | None |  |
| q-5a1e8d3df2 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ut"} | None |  |
| q-0b134da51a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqO44i"} | None |  |
| q-c4bb4a3e22 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcb"} | None |  |
| q-8ca8b70ee7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-db0973dec9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpBPBlG"} | None |  |
| q-b000d2c20d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-36P"} | None |  |
| q-a332cfa4c3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-36P"} | None |  |
| q-437e4a6edc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-35u"} | None |  |
| q-cb5e320c95 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwEmm4J"} | None |  |
| q-1ed168d8c5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjF_4Y"} | None |  |
| q-9100b4c8b5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-34r"} | None |  |
| q-f345be2746 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-7069683c96 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo73"} | None |  |
| q-ce4acbb7a5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1osp"} | None |  |
| q-7367a1d93f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0e9"} | None |  |
| q-323450a6d3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0e9"} | None |  |
| q-97a4e7714d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-0f16f0833e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-94e4f3056b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-91dc53182f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-ec99888f9e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None |  |
| q-bef3571f18 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-1745fcab54 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpHV4S3"} | None |  |
| q-77f6136f78 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-219aa71010 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-30c84b08c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y1-"} | None |  |
| q-df1d43b732 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y1-"} | None |  |
| q-d9598c9275 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-0343d10a29 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-c9e712ffbb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjGP6n"} | None |  |
| q-74354c7fd3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsc9wOe"} | None |  |
| q-f810f98e14 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uo"} | None |  |
| q-b238e7ce1e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uo"} | None |  |
| q-4500b88a95 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uv"} | None |  |
| q-964754660e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uv"} | None |  |
| q-75b9d3229e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwBjiC8"} | None |  |
| q-409e1ac5f0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-870c74a238 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-385211daee | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-b235be2a1a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSxb"} | None |  |
| q-e427d5b973 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-343eecbc0f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-da2198e42d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1N1"} | None |  |
| q-51b6833fc8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5I18"} | None |  |
| q-146675a216 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-c5d7a0f1bb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcb"} | None |  |
| q-791e8b002e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-4571ef83f7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-5d4ef4746c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-0de214dd66 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-bd70ea9e5a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-a8885f3f80 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-8d53098805 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1OJ"} | None |  |
| q-a96da235de | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdI9"} | None |  |
| q-938ab85a01 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ-S"} | None |  |
| q-e9b66cf16b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkjomHY"} | None |  |
| q-9487be404e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEeE"} | None |  |
| q-a89c5a9091 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0fg"} | None |  |
| q-d69aa6d951 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0fg"} | None |  |
| q-99e5061bf1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2o"} | None |  |
| q-68172d733d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-fe889483ba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpfwJ_Y"} | None |  |
| q-fd10aa4c9c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchIto6IP6B"} | None |  |
| q-369a95e03f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpfwJ_Y"} | None |  |
| q-6fb2817fd6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgxY85"} | None |  |
| q-9eb3f4e117 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgxY85"} | None |  |
| q-1b2edb4ad8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |

## Verification

Evidence items cited: 221; confirmed against the stored events: 220; rejected: 1. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 6 item(s) in 3 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
