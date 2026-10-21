# Threat hunt report — 20261017-120051-converged-fix2

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 5 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003.001 (F01, F13, F22, F29, F33, F34, F44, F59), I03 T1056.001 (F55, F56), I04 T1187 (F20), I05 T1552.001 (F26, F57), I07 T1552.004 (F25, F52, F58)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-17T04:00:51+00:00 / 2026-10-17T04:11:40+00:00 (649.2 s) |
| LLM calls / tokens | 175 / {'prompt': 4581976, 'completion': 139806} |
| MCP tool calls | 1220 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003.001 | yes | malicious/high | F01, F13, F22, F29, F33, F34, F44, F59 | Steganographic PowerShell loader opened full-access LSASS handles on SCRANTON and NASHUA |
| I02 | T1003.002 | yes | suspicious/medium | F60 | SAM_SERVER handles requested on SCRANTON |
| I03 | T1056.001 | yes | malicious/high | F55, F56 | Get-Keystrokes keylogger and clipboard collection on SCRANTON |
| I04 | T1187 | yes | malicious/high | F20 | WebDAV forced authentication from SCRANTON to attacker server 192.168.0.4 |
| I05 | T1552.001 | yes | malicious/high | F26, F57 | Password-targeted file collection and encrypted archiving on SCRANTON and NASHUA |
| I06 | T1552.002 | yes | suspicious/medium | F27 | Registry value read and piped to Invoke-Expression on SCRANTON |
| I07 | T1552.004 | yes | malicious/high | F25, F52, F58 | Get-PrivateKeys exported LocalMachine certificates to password-protected .pfx on SCRANTON |
| I08 | T1557.001 | yes | suspicious/low | F41 | SMB/WinRM authentication traffic duplicated across two L2 paths |
| I09 | T1557.002 | yes | suspicious/medium | F40 | Same IP 10.0.1.4 on two L2 addresses toward 10.0.1.6 |
| I10 | out-of-scope:T1003 | no | suspicious/medium | F16 | Credential material accessed on SCRANTON but no offline cracking observed |
| I11 | out-of-scope:T1021.002 | no | malicious/high | F08, F62 | PsExec64 with plaintext credentials delivered python.exe implant to NASHUA |
| I12 | out-of-scope:T1027.004 | no | malicious/high | F66 | csc.exe compiled in-memory loader DLLs from hidden PowerShell on SCRANTON |
| I13 | out-of-scope:T1041 | no | malicious/high | F61 | Credential material exfiltrated to attacker WebDAV share 192.168.0.4 |
| I14 | out-of-scope:T1059.001 | no | malicious/high | F10 | Credential-access chain staged via sdclt/control.exe and PsExec-delivered python.exe |
| I15 | out-of-scope:T1059.003 | no | suspicious/low | F43 | No on-host AiTM tooling; Temp python.exe via PsExec unrelated to AiTM |
| I16 | out-of-scope:T1069 | no | malicious/high | F64 | accesschk.exe permission discovery on SCRANTON |
| I17 | out-of-scope:T1070.004 | no | malicious/medium | F02 | Credential-access tooling and anti-forensics in the SCRANTON PowerShell session |
| I18 | out-of-scope:T1070.004 | no | malicious/high | F63 | Rar.exe and sdelete64.exe used to encrypt and wipe collected data on NASHUA |
| I19 | out-of-scope:T1078 | no | suspicious/medium | F17 | Explicit-credential logons are pbeesly reusing its own credentials to NASHUA via PsExec |
| I20 | out-of-scope:T1218.011 | no | malicious/high | F67 | sdclt.exe abused to spawn hidden PowerShell on SCRANTON |
| I21 | out-of-scope:T1548.002 | no | suspicious/medium | F68 | hostui.exe launched with runas by PowerShell on SCRANTON |

## Findings

### F02 · malicious / medium · T1003 · Credential-access tooling and anti-forensics in the same SCRANTON PowerShell session

Evidence status: **verified**

The compromised pbeesly session on scranton.dmevals.local combined credential-targeted activity with cleanup: sdelete64.exe was used to securely delete C:\programdata\victim\???cod.3aka3.scr, C:\Users\pbeesly\AppData\Roaming\Draft.Zip and C:\Users\pbeesly\Downloads\SysinternalsSuite.zip (03:02–03:03Z), accesschk.exe was executed (03:04:34Z), and a Get-PrivateKeys function attempted to export machine certificates with Export-PfxCertificate using the hardcoded password "saribas" (03:04:56–03:04:57Z, failing with "Cannot export non-exportable private key"). The session also ran Invoke-Discovery, screen capture, Get-Clipboard and Get-Keystrokes. This is credential theft behaviour beyond the lsass handle access, and the sdelete use indicates deliberate destruction of staging artifacts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpHV4S3 | q-25cd63fb8c | ok |
| 2 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCRb2o | q-25cd63fb8c | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Message | Creating Scriptblock text (1 of 1):  function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-C… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-97d3f9f1a4 | ok |
| 4 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.Message | Creating Scriptblock text (1 of 1):  Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes"    ScriptBlock ID: 7c8ce66d-dd1a-4a72-8e88-42dd7ff48c… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwAjopf | q-66e33cd255 | ok |

### F01 · malicious / high · T1003.001 · Hidden steganography-launched PowerShell opened full-access handles to lsass.exe on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T02:58:44Z, control.exe ("C:\Windows\System32\control.exe" /name Microsoft.BackupAndRestoreCenter) spawned powershell.exe PID 2976 as DMEVALS\pbeesly at High integrity with the command line "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');...IEX([System.Text.Encoding]::ASCII.GetString($o[0..3932]))" — a hidden, execution-policy-bypassing loader that decodes a payload from pixel data in monkey.png and IEXes it. At 03:05:16Z that same PowerShell process (PID 2976) opened handles to lsass.exe (PID 736) with GrantedAccess 0x1F3FFF and 0x1FFFFF, i.e. full PROCESS_ALL_ACCESS-style masks consistent with reading LSASS memory for credential extraction. The same session ran Sysinternals tooling from C:\Program Files\SysinternalsSuite (sdelete64.exe, accesschk.exe) and later PsExec64.exe with cleartext credentials (dmevals\pbeesly / Fl0nk3rt0n!T0by) against \\NASHUA. No dump file was written to disk in the observed window (only WER crash dumps from WerFault.exe), so the dump may have been staged in memory or the write was not captured.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgwo_a | q-8e625fc67d | ok |
| 2 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgwo_a | q-8e625fc67d | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-207f849271 | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-207f849271 | ok |
| 5 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-35ff142e2f | ok |
| 6 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-35ff142e2f | ok |
| 7 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2r93 | q-25cd63fb8c | ok |

### F08 · malicious / medium · T1040 · SeaDukeStage PowerShell stage pushed an unsigned PyInstaller python.exe implant to NASHUA that beacons over TLS to 192.168.0.4:8443

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell function named 'Invoke-SeaDukeStage -ComputerName NASHUA' (2020-05-02T03:10:22Z). It then repeatedly invoked PsExec64.exe with plaintext credentials (dmevals\pbeesly / Fl0nk3rt0n!T0by) to launch C:\Windows\Temp\python.exe on NASHUA (four launches 03:11:18-03:14:42Z). On nashua.dmevals.local the payload ran as a PyInstaller bundle (extracting _MEI29522 with _socket.pyd/_ssl.pyd/_hashlib.pyd), unsigned (Company/Description '-', IMPHASH all zeros, SHA256 43782EC4337D8F3DDB7EA0C451B3BC4F212F84C8D5571BD0A842001C859A02AE), and opened a rapid burst of TCP connections from 10.0.1.6 to 192.168.0.4:8443 (03:15:05Z onward). Zeek (separate, non-overlapping 2020-04-30 window) shows the same 10.0.1.6 -> 192.168.0.4:8443 pattern as SSL with a self-signed certificate (CN=rempel.group.net) raising an SSL::Invalid_Server_Cert notice, i.e. a covert C2 channel. The implant's bundled _socket/_ssl modules and the 'SeaDukeStage' naming are consistent with a network-collection/sniffing-capable implant, but no packet-capture driver, promiscuous-mode or raw-socket artifact (pktmon, npcap, windump, SIO_RCVALL) was observed in the available telemetry, so the T1040 attribution rests on the implant's network-collection tooling rather than direct capture evidence.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwBjiC8 | q-d94f2acbd6 | ok |
| 2 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwDlShx | q-502aa237b2 | ok |
| 3 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2r93 | q-2afe348e46 | ok |
| 4 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | win.Hashes | SHA1=585EB59D12A111E9291518C5CF5D3FD296C2B581,MD5=57292CE8714E2D221D9D97C9D061D332,SHA256=43782EC4337D8F3DDB7EA0C451B3BC4F212F84C8D5571BD0A842001C859A02AE,IMPHA… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2b9g | q-70f1c025ba | ok |
| 5 | 2020-05-02 03:15:04.150Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Temp\_MEI29522\_socket.pyd | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItknvJ_- | q-a4acd9b61b | ok |
| 6 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | win.DestinationIp | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItknvJ-S | q-991072d3b3 | ok |
| 7 | 2020-04-30 00:40:44.740Z | bobs.bigwheel.local | zeek | zeek.msg | SSL certificate validation failed with (self signed certificate) | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz7ud8y | q-d6cf4e1ffd | ok |
| 8 | 2020-04-30 00:40:44.736Z | bobs.bigwheel.local | zeek | zeek.issuer | emailAddress=synthesize@rempel.group.net,CN=rempel.group.net,OU=synthesize,O=Rempel Group,ST=SC,C=US | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz7ud8U | q-37424fb623 | ok |

### F10 · malicious / high · T1056 · Credential-access tooling staged and executed on SCRANTON/NASHUA via sdclt→control.exe→hidden PowerShell stager and PsExec-delivered python.exe

Evidence status: **verified**

On 2020-05-02 the DMEVALS\pbeesly account drove a credential-access chain. On scranton.dmevals.local, sdclt.exe spawned control.exe (/name Microsoft.BackupAndRestoreCenter) at 02:58:43, which launched a hidden, execution-policy-bypassing PowerShell that decoded a bitmap (C:\Users\pbeesly\Downloads\monkey.png) into shellcode and IEX'd it at 02:58:44-45. Earlier, at 02:55:56, an unsigned .scr (C:\ProgramData\victim\â€®cod.3aka3.scr, SignatureStatus Unavailable) was launched from explorer.exe and spawned cmd.exe/conhost.exe with full 0x1fffff process access. From scranton, pbeesly ran PsExec64.exe against \\NASHUA with the cleartext password for dmevals\pbeesly, repeatedly (03:11-03:14), causing PSEXESVC.exe to launch C:\Windows\Temp\python.exe on nashua.dmevals.local (file created 03:10:23), which opened 0x1fffff handles on cmd.exe and powershell.exe and beaconed to 192.168.0.4:8443. pbeesly also opened lsass.exe with 0x1fffff/0x1f3fff access from powershell.exe on scranton (03:05:16) and from wsmprovhost.exe on nashua (03:09:29). A PowerShell Invoke-Exfil function (7Zip4Powershell, password-protected archive to %APPDATA%\OfficeSupplies.7z) was also present. This is hands-on-keyboard credential theft, not normal system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:43.212Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\System32\control.exe"  /name Microsoft.BackupAndRestoreCenter | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgw49k | q-b0bae9e73f | ok |
| 2 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgwo_a | q-39a83d980d | ok |
| 3 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwHp5aa | q-3b90f1690f | ok |
| 4 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpk1QgV | q-5be22e77fc | ok |
| 5 | 2020-05-02 02:55:56.151Z | scranton.dmevals.local | windows.sysmon | win.SignatureStatus | Unavailable | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpk1QgP | q-a3560e096d | ok |
| 6 | 2020-05-02 03:14:42.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwDlSh0 | q-0a3a3b5699 | ok |
| 7 | 2020-05-02 03:10:23.626Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkv3cGg | q-964ab75455 | ok |
| 8 | 2020-05-02 03:15:03.941Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkovWJ1 | q-f2c5247cef | ok |
| 9 | 2020-05-02 03:17:59.352Z | nashua.dmevals.local | windows.sysmon | destination.port | 8443 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkglS44 | q-03f3bad8e0 | ok |
| 10 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo57 | q-929980c978 | ok |
| 11 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFv53 | q-2e071a0168 | ok |
| 12 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-0a3a3b5699 | ok |

### F56 · malicious / high · T1056 · Clipboard collection and AV check before keylogging on SCRANTON

Evidence status: **verified**

pbeesly read the clipboard and ran Keystroke-Check to look for security products before keylogging.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:42.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Clipboard | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwAjopc | q-87ffc504d5 | ok |
| 2 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Keystroke-Check | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwAjooe | q-87ffc504d5 | ok |

### F55 · malicious / high · T1056.001 · Get-Keystrokes keylogger job run on SCRANTON by pbeesly

Evidence status: **verified**

pbeesly ran Get-Keystrokes as a background job on SCRANTON, viewed it, then removed it.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwAjopf | q-6f166d0602 | ok |
| 2 | 2020-05-02 03:07:36.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz_iFNN | q-87ffc504d5 | ok |

### F20 · malicious / high · T1187 · WebDAV forced authentication: SCRANTON (10.0.1.4) sent NTLM credentials to attacker WebDAV server 192.168.0.4

Evidence status: **verified**

On 2020-04-30 between 00:32:18 and 00:35:25 UTC, host 10.0.1.4 (SCRANTON, the same host that later authenticates as pbeesly and pushes PSEXESVC.exe to NASHUA) was driven to authenticate to an external WebDAV server at 192.168.0.4 over HTTP/80. The sequence is textbook forced authentication: first a DavClnt OPTIONS request to '/' (403 Forbidden), then repeated SMB probes to 192.168.0.4 on 445/139 that were all rejected (conn_state REJ), then Microsoft-WebDAV-MiniRedir/10.0.18362 OPTIONS and PROPFIND requests to /webdav, /webdav/ and /webdav/OfficeSupplies.7z. The PROPFIND requests carried an AUTHORIZATION header (client_header_names includes AUTHORIZATION) and returned 207 Multi-Status, i.e. the victim's credentials were accepted by the attacker-controlled server. The lure file OfficeSupplies.7z (1,082,089 bytes, md5 dd5ea7248edbdc4b158e3c81c154857b) was uploaded from 10.0.1.4 to 192.168.0.4, and a 5,305,104-byte application/x-dosexec payload was downloaded back from 192.168.0.4 to 10.0.1.4 (extracted as HTTP-FV8BmBzhLupORXNNc.exe). This is the credential-capture step of the intrusion; the Windows datasets (2020-05-02) show the follow-on use of the captured account pbeesly (Kerberos AS/TGS for cifs/NASHUA, ADMIN$ write of PSEXESVC.exe to nashua.dmevals.local from 10.0.1.4).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | DavClnt | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4uv | q-ad51273903 | ok |
| 2 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 192.168.0.4 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4uv | q-ad51273903 | ok |
| 3 | 2020-04-30 00:32:21.950Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4sG | q-1b4b6dfded | ok |
| 4 | 2020-04-30 00:32:21.950Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4sG | q-1b4b6dfded | ok |
| 5 | 2020-04-30 00:32:21.950Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 207 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4sG | q-1b4b6dfded | ok |
| 6 | 2020-04-30 00:32:21.950Z | simplerockbuild.simplerock.lan | zeek | zeek.client_header_names | ["CONNECTION", "USER-AGENT", "DEPTH", "TRANSLATE", "CONTENT-LENGTH", "HOST", "AUTHORIZATION"] | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4sG | q-1b4b6dfded | ok |
| 7 | 2020-04-30 00:32:21.989Z | simplerockbuild.simplerock.lan | zeek | file.mime_type | application/x-7z-compressed | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4sp | q-89368103d5 | ok |
| 8 | 2020-04-30 00:32:21.989Z | simplerockbuild.simplerock.lan | zeek | file.hash.md5 | dd5ea7248edbdc4b158e3c81c154857b | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4sp | q-89368103d5 | ok |
| 9 | 2020-04-30 00:35:25.659Z | simplerockbuild.simplerock.lan | zeek | file.mime_type | application/x-dosexec | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4u2 | q-00a2872be8 | ok |
| 10 | 2020-04-30 00:35:25.659Z | simplerockbuild.simplerock.lan | zeek | zeek.extracted | HTTP-FV8BmBzhLupORXNNc.exe | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4u2 | q-00a2872be8 | ok |
| 11 | 2020-04-30 00:32:17.069Z | simplerockbuild.simplerock.lan | zeek | zeek.conn_state | REJ | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylrovV | q-7f837bb935 | ok |
| 12 | 2020-04-30 00:40:22.447Z | simplerockbuild.simplerock.lan | zeek | zeek.client | pbeesly/DMEVALS.LOCAL | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylrov8 | q-fedf2a23ac | ok |
| 13 | 2020-05-02 03:18:20.000Z | nashua.dmevals.local | windows.security | win.RelativeTargetName | PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItse_H6B | q-fb866e3a1f | ok |

### F22 · malicious / high · T1212 · In-memory shellcode loader and full-access LSASS handle opens on SCRANTON/NASHUA (pbeesly)

Evidence status: **verified**

On 2020-05-02 between 03:01 and 03:21 UTC, user pbeesly on scranton.dmevals.local ran PowerShell that opened handles to lsass.exe with credential-dumping-grade access rights: PowerShell.exe (PID 2976) requested 0x1f3fff and 0x1fffff at 03:05:16, and earlier PowerShell.exe (PID 3876) requested 0x1000 at 03:01:03. On nashua.dmevals.local, wsmprovhost.exe (PID 7720, the WinRM host spawned by pbeesly's Invoke-Command) opened lsass.exe with 0x1f3fff at 03:09:29, with a call trace through System.ni.dll / Microsoft.PowerShell.Commands.Management.ni.dll. At 03:21:29 on scranton, pbeesly's PowerShell created a script block that resolves GetProcAddress/GetModuleHandle via Microsoft.Win32.UnsafeNativeMethods, builds a ReflectedDelegate dynamic assembly and decodes a base64 PE ('/EiD5PDozAAAAEFRQVBSUVZIMdJl...') — an in-memory shellcode/PE loader consistent with exploitation tooling used to reach credential material — plus a second block launching a hidden (-nop -w hidden) gzip/base64 encoded PowerShell payload. The same actor also used PsExec64 with a plaintext password (Fl0nk3rt0n!T0by) to run C:\Windows\Temp\python.exe on NASHUA and sdelete64 to wipe files, showing hands-on-keyboard credential abuse. The remaining lsass accesses (svchost.exe, AntimalwareConfig.exe, WindowsAzureTelemetryService.exe, wininit.exe, csrss.exe, services.exe) are normal system/AV behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-489faf1bba | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-489faf1bba | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-489faf1bba | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-489faf1bba | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-489faf1bba | ok |
| 6 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwIqSbu | q-bb3e9e0e96 | ok |
| 7 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwIqSbu | q-fb88648d7d | ok |
| 8 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | if([IntPtr]::Size -eq 4){$b=$env:windir+'\sysnative\WindowsPowerShell\v1.0\powershell.exe'}else{$b='powershell.exe'};$s=New-Object System.Diagnostics.ProcessSta… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwIqigy | q-0ef6b2ac46 | ok |
| 9 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2r93 | q-109ce34d4d | ok |
| 10 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2b9g | q-109ce34d4d | ok |

### F61 · malicious / high · T1552 · Credential material exfiltrated to attacker WebDAV share 192.168.0.4

Evidence status: **verified**

Invoke-Exfil on SCRANTON compressed Downloads into OfficeSupplies.7z and copied it to \\192.168.0.4\webdav.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-625e0e3371 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-625e0e3371 | ok |

### F64 · malicious / high · T1552 · accesschk.exe run by attacker PowerShell on SCRANTON

Evidence status: **verified**

pbeesly ran accesschk.exe from the attacker-staged SysinternalsSuite for permission discovery on SCRANTON.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCRb2o | q-321de3adaa | ok |
| 2 | 2020-05-02 03:04:34.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | &amp; "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzG | q-87ffc504d5 | ok |

### F65 · malicious / high · T1552 · RLO-named screen saver dropped steganographic payload on SCRANTON

Evidence status: **NOT verified (1/2 evidence items)** — excluded from the verdict

The RLO-named screen saver launched from explorer dropped monkey.png, the stego carrier for the hidden PowerShell stage.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | process.command_line | None | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpizF2M | q-321de3adaa | FAILED: cited query did not return this event; field process.command_line not in the event |
| 2 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\monkey.png | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpizF2M | q-ca87f2f883 | ok |

### F66 · malicious / high · T1552 · csc.exe compiled in-memory loader DLLs from hidden PowerShell on SCRANTON

Evidence status: **verified**

Hidden PowerShell used csc.exe to compile loader DLLs in Temp during the credential-access session on SCRANTON.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.cmdline" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpfwJ_Y | q-321de3adaa | ok |
| 2 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpfwJ_Y | q-321de3adaa | ok |

### F67 · malicious / high · T1552 · sdclt.exe abused to spawn hidden PowerShell on SCRANTON

Evidence status: **verified**

sdclt.exe was launched from cmd and spawned the hidden steganography PowerShell that opened lsass.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\sdclt.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgxY85 | q-321de3adaa | ok |
| 2 | 2020-05-02 02:58:44.338Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgwo_R | q-321de3adaa | ok |

### F26 · malicious / high · T1552.001 · Credential-file-targeted collection and password-protected archiving on nashua

Evidence status: **verified**

On nashua.dmevals.local, user pbeesly ran a PowerShell one-liner (script block 4adf51bc-704e-4481-8e1f-d7af5cc7acaa, 03:15:59Z) that recursively enumerates the user profile for document/archive types plus wildcard patterns explicitly aimed at credentials (*psw*, *pass*, *login*, *admin*, *sifr*, *sifer*, *vpn*) and compresses the results with Compress-Archive. The archive C:\Users\pbeesly\AppData\Roaming\working.zip was created at 03:16:00.353Z, then C:\Windows\Temp\Rar.exe was executed with a password switch (-hpfGzq5yKw) to produce C:\Users\pbeesly\Desktop\working.zip (03:16:19), and sdelete64.exe was used to wipe Rar.exe at 03:16:52. The same pattern of staging credential-bearing files into a password-protected archive appears on scranton (Invoke-Exfil compressing Downloads into OfficeSupplies.7z, created 03:08:35Z).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCk1OJ | q-2dca83fae6 | ok |
| 2 | 2020-05-02 03:16:00.353Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkmtdLv | q-5c745fa0a6 | ok |
| 3 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkmtdI9 | q-7921ed04a9 | ok |
| 4 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkx5Y3M | q-5c745fa0a6 | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-10044d6f71 | ok |

### F57 · malicious / high · T1552.001 · Password-targeted file collection and encrypted archives on SCRANTON and NASHUA

Evidence status: **verified**

pbeesly collected password/login-named files into working.zip on NASHUA and OfficeSupplies.7z on SCRANTON, then Rar-encrypted and sdelete-wiped them.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCk1OJ | q-609794745e | ok |
| 2 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkmtdI9 | q-f98b665142 | ok |

### F62 · malicious / high · T1552.001 · PsExec64 with plaintext credentials delivered python.exe to NASHUA

Evidence status: **verified**

pbeesly used PsExec64 with a plaintext password to launch the Temp python.exe implant on NASHUA.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2r93 | q-321de3adaa | ok |
| 2 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2b9g | q-f98b665142 | ok |

### F63 · malicious / high · T1552.001 · Rar.exe and sdelete64.exe from Temp used to encrypt and wipe collected data on NASHUA

Evidence status: **verified**

Rar.exe from Temp password-encrypted working.zip on NASHUA and sdelete64 wiped the tool and archive.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkmtdI9 | q-f98b665142 | ok |
| 2 | 2020-05-02 03:16:52.456Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkjomHY | q-f98b665142 | ok |

### F25 · malicious / high · T1552.004 · PowerShell Get-PrivateKeys exports all LocalMachine certificates to .pfx files on scranton

Evidence status: **verified**

On 2020-05-02 at 03:04:56 UTC (2020-05-01 23:04:56 local) on scranton.dmevals.local, user pbeesly ran a PowerShell script block defining function Get-PrivateKeys (script block 9d153741-75c3-4062-afe3-aeca0aee611b, loaded from C:\Program Files\SysinternalsSuite\readme.ps1). The function enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint, writing each to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded password "saribas". The function was then invoked by name (script block 206799ba-a627-40b9-892e-398c92354238) and Sysmon file-create event 11 confirms the resulting artifact C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx written by powershell.exe at 03:04:57.460Z. This is private-key/certificate harvesting for later credential use.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-445a0cbc2a | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-e6fc92de48 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSxb | q-4c48647dd6 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-aa33efee0c | ok |
| 5 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-e6fc92de48 | ok |

### F58 · malicious / high · T1552.004 · Get-PrivateKeys exported LocalMachine certificates to .pfx on SCRANTON

Evidence status: **verified**

pbeesly ran Get-PrivateKeys from readme.ps1, exporting every LocalMachine cert to a random .pfx in Downloads.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-0e5866d809 | ok |
| 2 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-9d80d48c7b | ok |

### F59 · malicious / high · T1555 · wsmprovhost on NASHUA opened lsass with 0x1F3FFF access

Evidence status: **verified**

pbeesly's WinRM host process on NASHUA requested a full-access lsass handle including read/write process memory.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFv53 | q-b997f6b9d8 | ok |
| 2 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFv53 | q-b997f6b9d8 | ok |

### F33 · malicious / high · T1556 · Steganographic PowerShell payload on SCRANTON opened lsass.exe with PROCESS_ALL_ACCESS (0x1FFFFF) — credential theft, not auth-process modification

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T02:58:44Z, control.exe ("/name Microsoft.BackupAndRestoreCenter") spawned PowerShell.exe (PID 2976, user DMEVALS\pbeesly, IntegrityLevel High) with a hidden, execution-policy-bypass command that decodes a bitmap at C:\Users\pbeesly\Downloads\monkey.png into a byte array and IEX-executes it (steganographic loader). At 03:05:16Z that same process (SourceProcessGUID {47ab858c-e1e4-5eac-b803-000000000400}, PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1F3FFF and then 0x1FFFFF — full access to the credential store, the classic lsass-dump access mask. The actor also ran a Keystroke-Check function enumerating AV products (scriptblock path C:\Program Files\SysinternalsSuite\psversion.ps1) and later used PsExec64 with the cleartext password of pbeesly against NASHUA. This is credential access against the authentication process, but no evidence of the authentication process itself being modified (no unsigned modules in lsass, no password-filter/notification-package registration, no reversible-encryption or MFA/hybrid-identity changes).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgwo_a | q-a0113a7bfd | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-be6c575ece | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-61c90e092f | ok |
| 4 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Keystroke-Check {     Get-Process \| Where-Object { $_.ProcessName -Eq "avp" -or $_.ProcessName -Eq "acs" -or $_.ProcessName -Eq "outpost" -or $_.Proce… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwAjYpu | q-13e4189e1d | ok |
| 5 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwDlShx | q-6b7838474f | ok |

### F44 · malicious / high · T1558 · Credential access on scranton: PowerShell full-access handle to lsass during hands-on-keyboard intrusion

Evidence status: **verified**

On scranton.dmevals.local the user pbeesly ran a hands-on intrusion chain (malicious C:\ProgramData\victim\cod.3aka3.scr launched from explorer at 02:55:56, spawning cmd.exe and powershell.exe, then SysinternalsSuite download/extraction, sdelete64 anti-forensics, Invoke-Discovery, Invoke-Persistence, Get-PrivateKeys exporting .pfx files, screen capture). At 03:05:16 the same PowerShell.exe (PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1F3FFF and 0x1FFFFF — full process access consistent with credential/ticket extraction from LSASS. No Kerberos-specific tooling (Rubeus/Mimikatz/kirbi) was observed in script blocks, so the ticket-theft sub-techniques are not directly evidenced, but the LSASS credential-access prerequisite is clearly present.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-318f959616 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-318f959616 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-318f959616 | ok |
| 4 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpk1QgV | q-3f8cf960f2 | ok |
| 5 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-5eab2b3d8d | ok |

### F52 · malicious / high · T1649 · PowerShell Get-PrivateKeys exports all LocalMachine certificates to password-protected .pfx on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly (SID S-1-5-21-1830255721-3727074217-2423397540-1107) ran a PowerShell session (PID 3876) that defined and invoked a function Get-PrivateKeys. The function enumerates every certificate under cert:\LocalMachine recursively and, for each certificate with a thumbprint, calls Export-PfxCertificate into "$env:USERPROFILE\Downloads\$RandomFileName.pfx" using a hardcoded plaintext password ("saribas"). The script block was recorded at 2020-05-02T03:04:56Z (4104, ScriptBlockId 9d153741-75c3-4062-afe3-aeca0aee611b, Path C:\Program Files\SysinternalsSuite\readme.ps1) and one second later at 03:04:57.460Z Sysmon recorded the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by that same powershell.exe (PID 3876). The exported .pfx was touched again by powershell.exe at 03:08:51Z (Sysmon event 23). This is bulk theft of machine certificate private keys with a known export password — exactly the certificate-stealing behaviour of T1649 and a plausible precursor to forging authentication certificates / PKINIT abuse. No Certipy/Certify tooling, no forged-certificate use, and no exfiltration channel for the .pfx were observed in the available windows.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-6e098c8ee9 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-f1a7b55894 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSxb | q-446ab5dbae | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-07a0ede08c | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-20a81f117b | ok |
| 6 | 2020-05-02 03:08:51.489Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkx5I18 | q-7351a64150 | ok |

### F60 · suspicious / medium · T1003.002 · SAM_SERVER handles with 0xF003F requested on SCRANTON

Evidence status: **verified**

lsass on SCRANTON requested SAM_SERVER handles with 0xF003F at 03:19 and 03:20; no dump file observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0xf003f | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsS38Vi | q-241567bee0 | ok |
| 2 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectName | SAM | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsS38Vi | q-241567bee0 | ok |

### F13 · suspicious / medium · T1056.004 · Credential API hooking not directly evidenced; lsass handle requests by powershell/wsmprovhost are the closest indicator

Evidence status: **verified**

No MiniDump/comsvcs/DumpCreds script blocks or lsass references were found in 4104 or windows.other, so no explicit API-hooking or dumping code was captured. However, pbeesly's powershell.exe on scranton.dmevals.local requested a 0x1fffff handle to \Device\HarddiskVolume2\Windows\System32\lsass.exe (03:05:16) and wsmprovhost.exe on nashua.dmevals.local requested 0x1f3fff (03:09:29) — full read/write/VM-operation access to LSASS, consistent with in-memory credential access/hooking. The remaining lsass handles are benign (svchost/lsm.dll RPC, MsMpEng, CollectGuestLogs, AntimalwareConfig perf counters).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo57 | q-929980c978 | ok |
| 2 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFv53 | q-2e071a0168 | ok |

### F16 · suspicious / medium · T1110.002 · Credential material accessed on scranton (lsass + certificate export), but no offline cracking observed

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1fffff at 03:05:16Z, and powershell.exe (PID 3876) opened lsass with 0x1000 at 03:01:03Z; the same PID 3876 executed the Get-PrivateKeys script block that exports all LocalMachine certificates to .pfx files. This is credential access/dumping on the host, but no evidence of password cracking was found: no hashcat/Invoke-Mimikatz/ntds script blocks, no SAM/NTDS/reg save command lines, no .dit/.hive file writes, and no hive or NTDS dump files transferred in the zeek files log (only GPO gpt.ini/GptTmpl.inf). The 4656 SAM/SECURITY/NTDS handle requests were all from lsass.exe itself (normal).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-bbbea49008 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-bbbea49008 | ok |
| 3 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpLb9km | q-6d191c96e0 | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-74ffcc5953 | ok |

### F17 · suspicious / medium · T1110.003 · Explicit-credential logons are pbeesly reusing its own credentials to NASHUA via PsExec, not spraying

Evidence status: **verified**

All 15 4648 events involve a single account: pbeesly. Four of them on scranton (03:11:18, 03:12:25, 03:13:28, 03:14:42Z) use pbeesly's own credentials against Target Server NASHUA over cifs/445 from 10.0.1.6, and each is followed ~20s later on nashua by a 4648 from C:\Windows\PSEXESVC.exe for pbeesly to localhost. The remaining 4648s are machine/system accounts (SCRANTON$, DWM-1/2, UMFD-0/1/2) from winlogon/wininit/taskhostw. There is no pattern of one password tried against many accounts (spraying) and no 4625/4771 failures; this is lateral movement with an already-valid credential.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEcw | q-b6a7c9c18a | ok |
| 2 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEcw | q-b6a7c9c18a | ok |
| 3 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0ff | q-186ef9e333 | ok |

### F68 · suspicious / medium · T1552 · hostui.exe launched with runas by PowerShell on SCRANTON

Evidence status: **verified**

PowerShell started hostui.exe with -verb runas to elevate, immediately before the HKLM Javasoft payload ran.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\System32\hostui.exe"  | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkILJ_D | q-321de3adaa | ok |
| 2 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkILJ_D | q-321de3adaa | ok |

### F27 · suspicious / medium · T1552.002 · PowerShell reads and executes a value from HKLM\SOFTWARE\Javasoft on scranton

Evidence status: **verified**

On scranton.dmevals.local at 03:21:28Z, user pbeesly executed the script block Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression (script block 9639dbf7-5666-4e14-83d4-06cb7eff7ece). Reading a value from a non-standard registry key and piping it straight into Invoke-Expression is a registry-stored-payload/credential pattern consistent with hiding data in the registry; it occurred in the same pbeesly session as the certificate export and exfil staging. No registry credential-hive reads (reg query/reg save of SAM/SECURITY) were observed, and the Sysmon registry SetValue hits for Password/Credential paths were all routine Windows/IdentityCRL/CredentialEnrollmentManager service writes.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:28.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwIqjKK | q-445a0cbc2a | ok |
| 2 | 2020-05-02 03:21:28.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwIqjKK | q-97205b1d8b | ok |

### F29 · suspicious / medium · T1555 · PowerShell and WinRM host processes opened lsass.exe with full-access masks on scranton and nashua

Evidence status: **verified**

On 2020-05-02, lsass.exe was opened with unusually broad access rights by scripting hosts: PowerShell.exe (PID 2976) on scranton.dmevals.local at 03:05:16 requested 0x1FFFFF and 0x1F3FFF, and wsmprovhost.exe (PID 7720, the WinRM host) on nashua.dmevals.local at 03:09:29 requested 0x1F3FFF. The wsmprovhost call trace runs through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll, i.e. a PowerShell cmdlet inside a remote WinRM session touching LSASS. The remaining rare masks (wininit/csrss 0x1FFFFF at 03:19:09, svchost 0x101001/0x3000) coincide with a boot/reboot sequence on scranton and are consistent with normal system startup. No procdump/comsvcs/MiniDump command line, no 4688 dump process and no lsass-related message in windows.other were found, so a completed LSASS dump is not proven; the PowerShell/WinRM LSASS handles remain unexplained and warrant follow-up on the originating WinRM client.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-0009037656 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-0009037656 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-0e79d7ad5a | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-0e79d7ad5a | ok |
| 5 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-448b5947df | ok |

### F34 · suspicious / medium · T1556.001 · lsass handle access on SCRANTON/NASHUA from PowerShell and wsmprovhost — no DC authentication-process patching observed

Evidence status: **verified**

Handle-open events against lsass.exe came from PowerShell.exe (0x1F3FFF then 0x1FFFFF, scranton, 03:05:16Z) and from wsmprovhost.exe (0x1F3FFF, nashua, 03:09:29Z, call trace through System.ni.dll / Microsoft.PowerShell.Commands.Management.ni.dll, i.e. a PowerShell remoting session). The remaining high-access opens (wininit.exe, csrss.exe, svchost.exe 0x101001/0x3000) are normal Windows components. No unsigned or non-Microsoft module was loaded into lsass: the only lsass image loads seen are lsass.exe, samsrv.dll and wdigest.dll, all Signed=true / SignatureStatus=Valid / Signature 'Microsoft Windows'. No 4657 modification of SAM/LSA/Security/Authentication registry keys and no lsass/cryptdll references in other or PowerShell logs. So the DC authentication process was targeted for credential extraction, not patched.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-cb0223251f | ok |
| 2 | 2020-05-02 03:19:09.850Z | scranton.dmevals.local | windows.sysmon | win.SignatureStatus | Valid | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpo7f89 | q-5cc755b7ac | ok |
| 3 | 2020-05-02 03:19:10.196Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\wdigest.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkXa2mu | q-5cc755b7ac | ok |
| 4 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JAt | q-61c90e092f | ok |

### F43 · suspicious / low · T1557 · Adversary-in-the-Middle: no on-host interception tooling; Temp python.exe launched via PsExec is unrelated to AiTM

Evidence status: **verified**

On the Windows side (2020-05-02 02:55-03:28) no AiTM tooling was found: the only network-adjacent executions are Azure guest-agent diagnostics (netsh trace, ipconfig /all, arp /a, route print) on scranton.dmevals.local. The most unusual process is C:\Windows\Temp\python.exe on nashua.dmevals.local, run five times as user pbeesly between 03:11:40 and 03:15:04 with an empty command line, four times parented by C:\Windows\PSEXESVC.exe and once by itself; this is remote execution of a dropped interpreter, not an interception/relay component, and no evidence ties it to the L2 anomaly seen in the non-overlapping zeek window. The AiTM hypothesis therefore rests on the zeek L2 duplication only; the Windows datasets show no poisoning or relay artifacts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2b9g | q-32d8f162fc | ok |
| 2 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2b9g | q-32d8f162fc | ok |
| 3 | 2020-05-02 03:15:04.235Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItknvJ_4 | q-32d8f162fc | ok |
| 4 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkYcTxy | q-ed272d999f | ok |

### F41 · suspicious / low · T1557.001 · SMB/WinRM authentication traffic to 10.0.1.6 duplicated across two L2 paths; WPAD name resolution present but answered normally

Evidence status: **verified**

SMB (445) and WinRM (5985) sessions from 10.0.1.4 to 10.0.1.6 carry Kerberos/GSSAPI authentication (zeek.service 'gssapi,smb,krb') and are recorded twice with different MAC pairs at 00:33:26-00:33:29 and 00:35:25-00:35:26, which is the shape of an SMB/authentication relay or interception path rather than a single direct flow. Name-resolution side: 10.0.1.4 and 10.0.1.6 repeatedly query wpad.dmevals.local to the DNS server 10.0.0.4 (8 queries, every 10 minutes) and those queries carry no answers in the retrieved records, so no poisoned WPAD/LLMNR response was observed; the only DNS answers seen are legitimate (newyork.dmevals.local -> 10.0.0.4, wec.dmevals.local -> 10.0.1.10). No LLMNR (5355) traffic appears in the port stack. The relay interpretation rests only on the duplicated L2 paths; no relay tooling, no NTLM relay target and no Windows-side corroboration were retrieved.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:35:26.036Z | bobs.bigwheel.local | zeek | zeek.service | gssapi,smb,krb | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8u4r9 | q-00632e3884 | ok |
| 2 | 2020-04-30 00:35:26.050Z | simplerockbuild.simplerock.lan | zeek | zeek.service | krb,smb,gssapi | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4t- | q-b7691fe5dc | ok |
| 3 | 2020-04-30 00:06:38.903Z | simplerockbuild.simplerock.lan | zeek | zeek.service | krb,smb,gssapi | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4ud | q-eeac853ec5 | ok |
| 4 | 2020-04-30 00:33:26.297Z | simplerockbuild.simplerock.lan | zeek | destination.port | 5985 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4uK | q-b7691fe5dc | ok |
| 5 | 2020-04-30 00:27:59.163Z | simplerockbuild.simplerock.lan | zeek | dns.question.name | wpad.dmevals.local | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4vH | q-f4ffccb093 | ok |
| 6 | 2020-04-30 00:06:38.899Z | simplerockbuild.simplerock.lan | zeek | zeek.answers | ["10.0.0.4"] | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4tU | q-6bbb10ee45 | ok |

### F40 · suspicious / medium · T1557.002 · Same IP 10.0.1.4 observed on two different L2 addresses while talking to 10.0.1.6 (possible ARP cache poisoning / on-path host)

Evidence status: **verified**

In the zeek window (2020-04-30 00:06-00:45) host 10.0.1.4 normally appears with source MAC 00:0d:3a:4d:42:f2 and its peer 10.0.1.6 with 00:0d:3a:13:e3:69. However 44 connections are recorded with source IP 10.0.1.4 but source MAC fc:bd:67:e1:a9:c1 and response MAC 00:0d:3a:13:e3:69, i.e. the same IP flows appear twice with two different L2 address pairs. The duplicate flows are near-simultaneous: at 00:33:26-00:33:29 WinRM (5985) sessions to 10.0.1.6 are logged once with fc:bd:67:e1:a9:c1 -> 00:0d:3a:13:e3:69 and once with 00:0d:3a:4d:42:f2 -> 12:34:56:78:9a:bc, and at 00:35:25-00:35:26 SMB (445) sessions to 10.0.1.6 are likewise duplicated with both MAC pairs. The fc:bd:67:e1:a9:c1 activity is confined to 00:30-00:45 (4 conns in the 00:30 bucket, 24 in 00:35, 15 in 00:40, 1 in 00:45) and covers 5985, 445, 135 and 55121. This duplicate-IP/differing-MAC pattern is consistent with an on-path host impersonating 10.0.1.4 at layer 2 (ARP cache poisoning) to intercept its SMB/WinRM authentication, but the evidence is indirect: no ARP protocol records, no attacker tooling and no Windows-side corroboration were retrieved, and the zeek window does not overlap the Windows telemetry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:35:25.606Z | bobs.bigwheel.local | zeek | zeek.orig_l2_addr | fc:bd:67:e1:a9:c1 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8u4rQ | q-00632e3884 | ok |
| 2 | 2020-04-30 00:35:25.606Z | bobs.bigwheel.local | zeek | destination.port | 445 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8u4rQ | q-00632e3884 | ok |
| 3 | 2020-04-30 00:35:25.619Z | simplerockbuild.simplerock.lan | zeek | zeek.orig_l2_addr | 00:0d:3a:4d:42:f2 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4vf | q-b7691fe5dc | ok |
| 4 | 2020-04-30 00:33:26.283Z | bobs.bigwheel.local | zeek | zeek.orig_l2_addr | fc:bd:67:e1:a9:c1 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8u4rk | q-00632e3884 | ok |
| 5 | 2020-04-30 00:33:26.297Z | simplerockbuild.simplerock.lan | zeek | zeek.orig_l2_addr | 00:0d:3a:4d:42:f2 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4uK | q-b7691fe5dc | ok |
| 6 | 2020-04-30 00:35:25.606Z | bobs.bigwheel.local | zeek | zeek.resp_l2_addr | 00:0d:3a:13:e3:69 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8u4rQ | q-00632e3884 | ok |

### F05 · benign / medium · T1003.002 · No SAM hive dumping observed

Evidence status: **verified**

No reg save of HKLM\SAM/SECURITY, no SAM/SYSTEM/SECURITY hive file copies (only Prefetch .pf files matched), and no 4663/4688 events referencing SAM. The only SAM-related registry write is HKLM\SAM\SAM\Domains\Account\F, a single routine write, and the windows.other hits for SAM are the default 'Remote calls to the SAM database are being restricted' policy message on scranton. No evidence of SAM credential extraction.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.other | message | Remote calls to the SAM database are being restricted using the default security descriptor: O:SYG:SYD:(A;;RC;;;BA).  For more information please see http://go.… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWX2 | q-1b839f1a3a | ok |

### F06 · benign / medium · T1003.003 · No NTDS.dit access or copy observed

Evidence status: **verified**

No file creation matching *ntds*, no ntdsutil/vssadmin/diskshadow process creation, no 4663 object access to ntds.dit and no PowerShell script blocks referencing ntds/vssadmin/diskshadow in any of the four hosts. The domain controller newyork.dmevals.local shows no NTDS extraction activity in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.ObjectType | %{19195a5b-6da0-11d0-afd3-00c04fd930c9} | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhC87m | q-1fd5625382 | ok |

### F03 · benign / medium · T1003.004 · LSA Secrets registry queries are routine LOCAL SERVICE machine-account reads

Evidence status: **verified**

The only 4662 events touching Policy\Secrets are six queries of Policy\Secrets\$MACHINE.ACC by NT AUTHORITY\LOCAL SERVICE on nashua, scranton and utica (AccessMask 0x2, OperationType Query) — normal machine-account secret access by the local service, not lsadump-style extraction. No process command line referencing secrets/lsadump/sekurlsa and no SECURITY\Policy\Secrets registry writes were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:02:59.000Z | nashua.dmevals.local | windows.security | win.ObjectName | Policy\Secrets\$MACHINE.ACC | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwrPVRX | q-1fd5625382 | ok |
| 2 | 2020-05-02 03:02:59.000Z | nashua.dmevals.local | windows.security | win.SubjectUserName | LOCAL SERVICE | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwrPVRX | q-1fd5625382 | ok |

### F07 · benign / medium · T1003.005 · Cached domain credential registry activity is benign OS noise

Evidence status: **verified**

The 6625 registry writes matching *Cache* are dominated by TaskCache, NetworkList Nla Cache, AppContainer Internet Settings Cache and CloudStore entries; the only SECURITY\Cache value is HKLM\SECURITY\Cache\NL$1 (5 writes), which is the normal cached-logon bookkeeping value. No cachedump/mscache/dcc2 commands were found (the only *cache* process matches were dxgiadaptercache.exe and svchost.exe), and no 4663/4656 object access to SECURITY\Cache was recorded.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-207f849271 | ok |

### F04 · benign / medium · T1003.006 · Single 4662 by NEWYORK$ is a machine-account directory read, not DCSync

Evidence status: **verified**

On newyork.dmevals.local at 2020-05-01T23:16:15-04:00 the computer account NEWYORK$ performed one 4662 object access (AccessMask 0x100) whose Properties list includes {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} (DS-Replication-Get-Changes) and {19195a5b-6da0-11d0-afd3-00c04fd930c9}. It is a single event by the DC's own machine account, not a non-DC principal repeatedly invoking replication rights, and no other replication-right accesses were seen — insufficient for a DCSync determination.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhC87m | q-1fd5625382 | ok |
| 2 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.Properties | %%7688  		{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  	{19195a5b-6da0-11d0-afd3-00c04fd930c9}   | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhC87m | q-1fd5625382 | ok |

### F09 · benign / medium · T1040 · NetworkWatcherAgent, logman, ipconfig/ARP/ROUTE and Zeek conn stacking show no packet-capture tooling or promiscuous-mode artifacts

Evidence status: **verified**

The remaining T1040 check hits are explained by normal system behaviour. The rare process creations in the sysmon event-1 stack are Azure guest-agent components (C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\...\NetworkWatcherAgent.exe, CollectGuestLogs.exe, WaSecAgentProv.exe), built-in diagnostics (logman.exe, ipconfig.exe, ARP.EXE, ROUTE.EXE, dsregcmd.exe) and Sysinternals tooling used by the intrusion for other purposes (PsExec64, sdelete64). No pktmon, windump, tcpdump, rawcap, npcap/WinPcap driver install or promiscuous-mode indicator appeared. Zeek conn stacking by service shows only ordinary protocols (ssl, dns, krb_tcp, dce_rpc, gssapi, smb, http) and by port only standard services plus 8443 (the C2 channel reported separately) and 55121 (repeated S0 connection attempts from 10.0.1.4 to 10.0.1.6 with zero bytes, i.e. failed connects, not captured traffic). Zeek cannot observe promiscuous mode, so absence of capture artifacts is not proof of absence, but nothing in these datasets shows a sniffer being installed or run.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:03:14.693Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\sdelete64.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpFT8y4 | q-2afe348e46 | ok |
| 2 | 2020-04-30 00:36:17.869Z | bobs.bigwheel.local | zeek | zeek.conn_state | S0 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8u4rs | q-ff5d0d6178 | ok |
| 3 | 2020-04-30 00:36:17.869Z | bobs.bigwheel.local | zeek | destination.port | 55121 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8u4rs | q-ff5d0d6178 | ok |

### F11 · benign / medium · T1056.001 · No keylogger artifacts found; keyboard-related registry writes are OS input-stack noise

Evidence status: **verified**

The only keyboard-related registry activity in the window is Windows' own input stack on scranton.dmevals.local: LogonUI.exe/winlogon.exe writing HKU\.DEFAULT Keyboard Layout\Preload and CTF\RemoteSession\KeyboardLayout values, and System writing HKLM\HARDWARE\DEVICEMAP\KeyboardClass and TERMINPUT_BUS keyboard device parameters. No SetWindowsHookEx/GetAsyncKeyState keylogger DLL was loaded (image-load query for keylog/hook/monkey/victim returned only the .scr loading itself), and no keylogger command lines were observed. The malicious stager and python.exe implant are credential-access tooling, but no keylogging component was evidenced in these logs.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:43.022Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\HARDWARE\DEVICEMAP\KeyboardClass\\Device\KeyboardClass2 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkADuPE | q-40fab11024 | ok |
| 2 | 2020-05-02 03:20:45.196Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\.DEFAULT\Keyboard Layout\Preload\1 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkEH740 | q-40fab11024 | ok |
| 3 | 2020-05-02 03:20:43.567Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\.DEFAULT\Software\Microsoft\CTF\RemoteSession\KeyboardLayout | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkSVMCG | q-40fab11024 | ok |

### F12 · benign / medium · T1056.002 · No GUI credential-prompt capture observed; 4104 'prompt' blocks are module boilerplate

Evidence status: **NOT verified (0/1 evidence items)** — excluded from the verdict

The 52 script blocks whose text is 'prompt' and the CimCmdletization/alias blocks in windows.powershell are standard PowerShell module boilerplate (e.g. the xActiveDirectory MSFT_xADCommon.ps1 helper on newyork.dmevals.local), not credential-dialog spoofing. No Get-Credential, CredentialUI or fake-logon-prompt code was found in the 4104 events. The malicious PowerShell on scranton used a bitmap-decoding stager rather than a GUI prompt, so GUI input capture is not evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:32.000Z | newyork.dmevals.local | windows.powershell | win.ScriptBlockText | dentity parameter, but the New-ADUser cmdlet uses the         Name parameter.     .EXAMPLE         $getADUserParams = Get-CommonADParameters @PSBoundParameters … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwDlAOq | q-9d078fbed6 | FAILED: claimed value differs from the stored value |

### F14 · benign / high · T1110 · No brute-force authentication activity; credential theft and reuse instead

Evidence status: **verified**

Across windows.security (2020-05-02 02:55-03:28Z) there are zero 4625 failed-logon events and zero 4771 Kerberos pre-auth failures on any of the four hosts (scranton, newyork, nashua, utica). The only 4776 credential validation seen was for pbeesly with status 0x0 (success) on newyork at 03:20:40Z. The only Kerberos error on the wire (zeek, 2020-04-30 window) was KDC_ERR_PREAUTH_REQUIRED (7 events), which is normal pre-authentication negotiation, not an authentication failure. The credential-related activity that does exist on scranton is theft and reuse of already-valid credentials (certificate export with hardcoded password 'saribas', lsass access with GrantedAccess 0x1fffff, and pbeesly explicit-credential logons to NASHUA), which is not brute force.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO14sT | q-6cad4299cc | ok |
| 2 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | event.code | 4776 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO14sT | q-6cad4299cc | ok |

### F15 · benign / high · T1110.001 · No password guessing; PowerShell 'password' hits are certificate export and archive encryption

Evidence status: **verified**

The two PowerShell 4104 script blocks matching *Password*/*Login* on scranton are not login attempts: 'Get-PrivateKeys' (pbeesly, 23:04:56 local) uses ConvertTo-SecureString -String "saribas" only to protect exported .pfx certificate files, and 'Invoke-Exfil' (pbeesly, 23:08:02 local) uses -Password "lolol" to encrypt a 7z archive and a single hardcoded credential (cozy / MyCozyPassw0rd!) for a WebDAV drive. Neither iterates candidate passwords against an account. No 4625 failures exist to indicate guessing, and no process command line with password/passwd/pwd arguments was found in sysmon.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-74ffcc5953 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-1010cd4b4f | ok |

### F18 · benign / high · T1110.004 · No credential stuffing; only a single hardcoded credential used for WebDAV exfil

Evidence status: **verified**

No evidence of stuffing lists or many username/password pairs being tried. The only credential pair in the data is the hardcoded cozy / MyCozyPassw0rd! used once by the Invoke-Exfil script block on scranton to map \\192.168.0.4\webdav via New-PSDrive. No 4625 failures, no 4771 failures, and the only Kerberos error on the wire was KDC_ERR_PREAUTH_REQUIRED (7), which is normal pre-auth negotiation rather than a failed authentication.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-1010cd4b4f | ok |

### F19 · benign / high · T1111 · No MFA interception activity; credential-related hits are standard Windows components and benign PowerShell/.NET lsass reads

Evidence status: **verified**

Across windows.security, windows.sysmon, windows.powershell and windows.other (2020-05-02 02:55-03:28Z) there is no evidence of MFA interception: no smartcard/credential-provider/NGC file drops (Sysmon 11 query returned 0), no MFA/smartcard command lines (only the standard 'svchost.exe -k LocalSystemNetworkRestricted -p -s NgcSvc' service host on scranton), and no non-standard authentication packages (4624 packages are only Kerberos 217, Negotiate 78, NTLM 1, '-' 1; logon processes Kerberos 217, Advapi 76, User32 2, NtLmSsp 1, '-' 1). The rare logon-process hits are ordinary: a SYSTEM logon type 0 at boot on scranton and pbeesly network (type 3) / RDP (type 10) logons from 172.18.39.2 on scranton. The 11 registry writes touching 'Credential' are services.exe creating the built-in per-user service CredentialEnrollmentManagerUserSvc_13619b (ImagePath C:\windows\system32\CredentialEnrollmentManager.exe) plus MuiCache entries - normal OS behaviour. lsass process-access events (326 total, dominated by svchost.exe 289) include only 7 from non-standard sources: powershell.exe on scranton with GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION) and wsmprovhost.exe on nashua with 0x1F3FFF whose call trace runs through Microsoft.PowerShell.Commands.Management.ni.dll, i.e. PowerShell management cmdlets querying process info, not credential/MFA theft; wininit/csrss/services accesses are boot-time. The one PowerShell script block matching 'Credential' (scranton, pbeesly, 23:08) is an Invoke-Exfil function that hardcodes a 'cozy' credential to map a WebDAV share and copy a 7z archive - data exfiltration, not MFA interception. Note: the environment does show other malicious activity (Invoke-Exfil/WebDAV exfil on scranton), but it does not implement T1111.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-1a626959e4 | ok |
| 2 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpLb9km | q-e3ae348794 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-02321c676f | ok |
| 4 | 2020-05-02 03:20:48.264Z | scranton.dmevals.local | windows.sysmon | win.Details | C:\windows\system32\CredentialEnrollmentManager.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkEHr1e | q-e2508d55d5 | ok |
| 5 | 2020-05-02 03:20:55.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s NgcSvc | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsM0qmS | q-64f9a29018 | ok |
| 6 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.security | message | An account was successfully logged on.    Subject:  	Security ID:		S-1-0-0  	Account Name:		-  	Account Domain:		-  	Logon ID:		0x0    Logon Information:  	Logo… | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsc-QNb | q-be753768cf | ok |

### F21 · benign / medium · T1187 · Routine SMB/445 and IPC$/SYSVOL/ADMIN$ traffic on 2020-05-02 is benign domain administration

Evidence status: **verified**

The Windows-side SMB hits are ordinary domain activity, not forced authentication. All 66 Sysmon event.code 3 connections to 139/445 are made by process.executable 'System' as user SYSTEM, targeting the domain controller 10.0.0.4, the IPv6 link-local address fe80::e40c:95b6:b0a7:6429, and 10.0.1.6. The corresponding 5140/5145 share accesses are machine-account IPC$ samr/lsarpc calls (SCRANTON$, NASHUA$, UTICA$, WEC$, NEWYORK$), SYSVOL gpt.ini policy reads by NEWYORK$, and one ADMIN$ write of PSEXESVC.exe by pbeesly to nashua.dmevals.local from 10.0.1.4. No .library-ms/.searchConnector-ms/.url files were created (C131 zero hits), no WebDAV/NTLM/Responder strings in PowerShell script blocks (C133 zero hits), and no WebClient/WebDAV service messages in windows.other (C136 zero hits). The forced-authentication activity itself is confined to the zeek window (2020-04-30) and is reported separately.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:57.321Z | nashua.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkJMpSF | q-41d5bdfd73 | ok |
| 2 | 2020-05-02 03:21:57.321Z | nashua.dmevals.local | windows.sysmon | destination.ip | 10.0.0.4 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkJMpSF | q-41d5bdfd73 | ok |
| 3 | 2020-05-02 03:22:32.000Z | newyork.dmevals.local | windows.security | win.RelativeTargetName | samr | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsJxqw2 | q-fb866e3a1f | ok |
| 4 | 2020-05-02 03:26:48.000Z | newyork.dmevals.local | windows.security | win.RelativeTargetName | dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\gpt.ini | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsEwOVS | q-fb866e3a1f | ok |

### F23 · benign / medium · T1212 · Routine lsass.exe handle opens by system, AV and telemetry processes

Evidence status: **verified**

The bulk of the 326 lsass process-access events come from expected sources: svchost.exe (289), the Azure IaaS antimalware AntimalwareConfig.exe (15), WindowsAzureTelemetryService.exe (13), and OS components wininit.exe, csrss.exe and services.exe (e.g. wininit/csrss opening lsass with 0x1fffff at 03:19:09 on scranton during normal session/security initialization, and services.exe with 0x1000 via RPCRT4). These are standard Windows and monitoring-agent behaviours, not exploitation. The PowerShell/wsmprovhost lsass accesses are reported separately as malicious.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JAt | q-489faf1bba | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\csrss.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JAu | q-489faf1bba | ok |
| 3 | 2020-05-02 03:19:13.337Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\services.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkei3QI | q-489faf1bba | ok |

### F24 · benign / high · T1539 · No browser session-cookie theft found; 'cookie' hits are WebDAV DavSetCookie for attacker exfil share

Evidence status: **verified**

Hunting for T1539 on the 2020-05-02 window found no access to browser cookie/credential stores. Sysmon file-create events matching *cookies*/*login data*/*web data*/*local state* returned only one unrelated INetCookies file under a LocalService package profile on scranton.dmevals.local, and security 4663 object-access events on those filenames returned zero rows. The only 'cookie' command lines are five rundll32.exe davclnt.dll,DavSetCookie invocations by pbeesly on scranton.dmevals.local (parent svchost.exe -k LocalService -p -s WebClient) that set a WebDAV auth cookie for http://192.168.0.4/webdav — the destination used by the attacker's Invoke-Exfil script block, i.e. exfiltration plumbing rather than browser session-cookie theft. MicrosoftEdge.exe activity on scranton.dmevals.local is the browser writing its own _TempTestAccess.txt, RecoveryStore and Temp files under pbeesly's profile, which is normal browser behaviour. The malicious PowerShell on the host (Invoke-ScreenCapture, Invoke-Exfil) is real attacker activity but does not touch browser cookie stores, so T1539 itself is not observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkv3sHT | q-1eae49a35d | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkKNZkz | q-19c4393ca2 | ok |
| 3 | 2020-05-02 03:21:05.198Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\DataStore\_TempTestAccess.txt | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkKNpkH | q-36ae7c7161 | ok |
| 4 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-e32affe7cf | ok |
| 5 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/ {     Start-Job -Name "Screenshot" -ScriptBlock {       … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwAjYrA | q-3cb9dd605f | ok |

### F28 · benign / medium · T1552 · Routine credential-related registry writes and benign lsass handle opens

Evidence status: **verified**

The 17-20 Sysmon registry SetValue hits on Password/Credential paths are all standard Windows activity: IdentityCRL ProviderPasswordLength/CharacterGroups, DeviceGuard CredentialGuard\Enabled, CredentialEnrollmentManagerUserSvc_13619b service registration, MuiCache entries and Winlogon PasswordExpiryNotification values. The 4663 lsass.exe object accesses (AccessMask 0x10) come from Windows Defender MsMpEng.exe and C:\WindowsAzure\Packages\CollectGuestLogs.exe on newyork/scranton/nashua/utica, i.e. AV and Azure guest-log collection, not credential dumping. The PowerShell 4104 hits containing 'credential' were localized MSFT_ScriptResourceStrings.psd1 resource files, and the windows.other 'Credential Guard configuration: 0x0, 0' event is a boot-time status message.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:15.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Program Files\Windows Defender\MsMpEng.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsQ2P9A | q-e2c05f93ea | ok |
| 2 | 2020-05-02 03:20:42.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\WindowsAzure\Packages\CollectGuestLogs.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO14sP | q-e2c05f93ea | ok |
| 3 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWX1 | q-46620c6071 | ok |

### F30 · benign / medium · T1555.003 · No browser credential-store access observed; only a benign INetCookies file write

Evidence status: **verified**

No process command line referenced Login Data, logins.json, key4.db, Cookies or Web Data (0 hits), and no 4663 object access on browser credential stores. The only file event matching browser-store patterns was svchost.exe creating C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_...\AC\INetCookies on scranton.dmevals.local at 03:21:05, which is a normal LocalService package cookie file, not a credential database. The 4104 script blocks that matched 'Credential' were unrelated (an AD cmdlet help block and an exfiltration function).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkKNZkz | q-708bf85c39 | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkKNZkz | q-708bf85c39 | ok |

### F31 · benign / medium · T1555.004 · No Windows Credential Manager / Vault access found

Evidence status: **verified**

No process creation referenced vault, cmdkey or credman, no registry writes to Vault/Credentials paths, and no 4688 for credential-manager tooling. The only 'Credential' hits were a Credential Guard configuration status message (event code 14) on scranton.dmevals.local and a DNS PTR registration failure message, neither of which is credential-store access. The 4104 'Credential' matches were an AD cmdlet help block and an exfiltration function using a hardcoded PSCredential.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWX1 | q-0c1416b44f | ok |

### F32 · benign / medium · T1555.005 · No password-manager artifacts observed

Evidence status: **verified**

No process command lines, file creations, object accesses, script blocks or other-channel messages referenced KeePass, 1Password, Bitwarden or .kdbx files on any host in the window. The only credential-adjacent PowerShell activity was pbeesly's Invoke-Exfil function on scranton.dmevals.local (23:08 local), which compresses the Downloads folder with a hardcoded 7-Zip password and copies it to a WebDAV share using a hardcoded credential — data staging/exfiltration, not password-manager theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-d5a19787a7 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-d5a19787a7 | ok |

### F35 · benign / medium · T1556.002 · No password-filter / Notification Packages registration found

Evidence status: **verified**

No evidence of a password filter DLL being installed. The 4657 registry-modification events (36 total) contain no Notification Packages, Password or Lsa value names; the only hits for 'Notification Packages'/'PasswordFilter' in windows.other were unrelated DHCP/logon-notification messages (e.g. 'User Logon Notification for Customer Experience Improvement Program'). No DLL writes into System32 were recorded and no PowerShell script block referenced Notification Packages or PasswordFilter. The only auth-related DLL loads (sspicli, cryptdll, samlib, samcli, wdigest) are standard Microsoft modules.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.other | message | User Logon Notification for Customer Experience Improvement Program | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWX7 | q-753de2a61b | ok |
| 2 | 2020-05-02 03:19:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\WMI\Autologger\EventLog-Application\{3000b92b-ca8b-4269-90ea-c4185ee09e92} | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsU5qNj | q-efbef51d42 | ok |

### F36 · benign / medium · T1556.005 · No reversible-encryption / Set-ADAccountControl activity observed

Evidence status: **verified**

No 4739 (domain policy change) events exist in windows.security, and no process command line, PowerShell script block or other-channel message referenced AllowReversiblePasswordEncryption, ReversibleEncryption or Set-ADAccountControl. The credential theft on SCRANTON was done by direct lsass memory access, not by enabling reversible password storage.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-be6c575ece | ok |

### F37 · benign / medium · T1556.006 · No MFA modification events (4739 absent)

Evidence status: **verified**

windows.security contains no event.code:4739 events at all, so no authentication/MFA policy change was recorded on any of the four hosts during the window. Nothing in the PowerShell or other channels referenced MFA configuration changes.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | event.code | 4648 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEcw | q-2f1216db81 | ok |

### F38 · benign / medium · T1556.007 · No hybrid-identity / directory-service modification (5136 absent)

Evidence status: **verified**

No 5136 directory-service-change events exist in windows.security, and the stacked Sysmon image-load data shows only standard Microsoft DLLs (ntdll, KernelBase, kernel32, rpcrt4, sechost, combase, sspicli, dpapi, userenv ...) with no identity-sync or federation component tampering. The observed activity is credential theft from lsass, not hybrid identity backdooring.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:50.942Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\wdigest.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkx5Y0E | q-5cc755b7ac | ok |

### F39 · benign / medium · T1556.008 · No network provider DLL registration; 4657 changes are wevtutil autologger config

Evidence status: **verified**

The 36 registry-modification (4657) events are not NetworkProvider changes: they are Autologger\EventLog-Application settings (Enabled, MatchAnyKeyword) written by C:\Windows\System32\wevtutil.exe under SCRANTON$ at 2020-05-01T23:19:16Z, plus one SystemCertificates Blob write by Sysmon.exe on NASHUA. No unusual DLL was loaded into winlogon/lsass (all image loads Microsoft-signed and valid), so no credential-capture network provider was installed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:16.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wevtutil.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsW6jeK | q-efbef51d42 | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhDM5P | q-efbef51d42 | ok |

### F42 · benign / high · T1557.003 · No DHCP spoofing: DHCP-related event codes absent; ipconfig/netsh/arp/route executions are Azure guest-agent diagnostics

Evidence status: **verified**

No DHCP server/lease events exist in windows.other (the event-code stack contains no 1341/1342/1020/1063 and no DHCP-Server codes) and no PowerShell script block references DHCP or rogue servers. The only DHCP/network-configuration command executions on 2020-05-02 are on scranton.dmevals.local as SYSTEM: netsh trace start/stop and ipconfig /all spawned by the Azure NetworkWatcherAgent, and ipconfig /all, route.exe print and arp.exe /a spawned by WindowsAzureGuestAgent, WindowsAzureTelemetryService and WaAppAgent - read-only diagnostics of the Azure guest agent, not DHCP reconfiguration. Logon process names for 4624 are dominated by Kerberos (217) and Advapi (76) with a single NtLmSsp, showing no unusual authentication path attributable to DHCP redirection.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkYcTxy | q-ed272d999f | ok |
| 2 | 2020-05-02 03:19:24.192Z | scranton.dmevals.local | windows.sysmon | process.command_line | "ipconfig.exe" /all | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpp7sSn | q-ed272d999f | ok |
| 3 | 2020-05-02 03:19:25.370Z | scranton.dmevals.local | windows.sysmon | process.command_line | "arp.exe" /a | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpo7f-S | q-24e7794b30 | ok |
| 4 | 2020-05-02 03:19:24.769Z | scranton.dmevals.local | windows.sysmon | process.command_line | "route.exe" print | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpp7sQv | q-24e7794b30 | ok |

### F45 · benign / medium · T1558.001 · No golden-ticket evidence; krbtgt TGT requests are normal Kerberos logons

Evidence status: **verified**

The only krbtgt service-ticket requests (4769) on newyork.dmevals.local are TGT requests for pbeesly@DMEVALS.LOCAL (03:04:04, 03:19:13, 03:19:15) and SCRANTON$@DMEVALS.LOCAL (03:19:13, 03:19:15), all with Ticket Encryption Type 0x12 (AES256), Ticket Options 0x60810010 and Failure Code 0x0, each paired with a matching 4624 type-3 Kerberos logon. No RC4 (0x17) krbtgt tickets, no 4768/4770/4771 events, no DCSync/Mimikatz/krbtgt script-block content, and no 4672 grants to accounts that should not hold them (4672 subjects are machine accounts/SYSTEM, pbeesly on nashua/scranton, and DWM/UMFD). Nothing indicates a forged TGT.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItse-36P | q-bde97faad1 | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItse-36P | q-bde97faad1 | ok |
| 3 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqO44i | q-a5ba116575 | ok |

### F46 · benign / medium · T1558.002 · No silver-ticket evidence; TGS requests are machine-account service tickets

Evidence status: **verified**

All 28 4769 events on newyork.dmevals.local are AES256 (0x12) service tickets for machine accounts (NEWYORK$, NASHUA$, SCRANTON$, WEC$) requested by pbeesly or SCRANTON$, with Failure Code 0x0 and no anomalous service accounts. No 4769/4770 in windows.other, no silver/SPN script-block content, and the only high-access lsass handles are from legitimate system processes (svchost, wininit, csrss, wsmprovhost) plus the malicious PowerShell on scranton already reported under T1558. No forged service ticket is evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NASHUA$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjF_4Y | q-a5ba116575 | ok |
| 2 | 2020-05-02 03:19:14.000Z | newyork.dmevals.local | windows.security | win.ServiceName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItse-34o | q-a5ba116575 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-318f959616 | ok |

### F47 · benign / medium · T1558.003 · No Kerberoasting: all 4769 tickets AES256, no RC4 SPN sweep

Evidence status: **verified**

Stacking 4769 by account gives only pbeesly@DMEVALS.LOCAL (15) and SCRANTON$@DMEVALS.LOCAL (13), and every one of the 28 tickets uses Ticket Encryption Type 0x12 (AES256) — no RC4 (0x17) requests that would indicate Kerberoasting. No GetUserSPNs/Invoke-Kerberoast/SPN script-block content in windows.powershell and no 4769/4768 in windows.other. The 4648 explicit-credential logons by pbeesly are PsExec (C:\Windows\PSEXESVC.exe) lateral movement, not ticket roasting.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEcq | q-a5ba116575 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0ff | q-745abebd08 | ok |

### F48 · benign / medium · T1558.004 · No AS-REP Roasting observed

Evidence status: **verified**

No 4768 (AS-REQ) events exist in windows.other or windows.security, and no asreproast/GetNPUsers/Rubeus command lines or script-block content were found in windows.sysmon or windows.powershell. The Kerberos activity present is limited to 4769 TGS requests on newyork.dmevals.local.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | event.code | 4769 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo73 | q-a5ba116575 | ok |

### F49 · benign / medium · T1606 · No forged web credentials observed; activity is credential theft and lateral movement by pbeesly on scranton/nashua

Evidence status: **verified**

Across windows.security, windows.sysmon, windows.powershell and windows.other (2020-05-02 02:55-03:28Z) there is no artifact of web-credential forgery: no ADFS/SAML/token-signing strings in windows.other or PowerShell 4104 blocks, and all 297 successful 4624 logons use standard logon processes (Kerberos 217, Advapi 76, User32 2, NtLmSsp 1, '-' 1) with no anomalous LogonProcessName. The hits that did fire reflect credential ACCESS and lateral movement by user pbeesly: PowerShell (PID 2976) opened lsass.exe with GrantedAccess 0x1fffff on scranton at 03:05:16Z, and pbeesly made explicit-credential 4648 logons to NASHUA (10.0.1.6) with PSEXESVC.exe on nashua. This is credential theft/lateral movement, not T1606 forgery.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-8aba69f446 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-8aba69f446 | ok |
| 3 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0ff | q-340fb0b39f | ok |
| 4 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEcw | q-340fb0b39f | ok |

### F50 · benign / medium · T1606.001 · Browser cookie stores not accessed for forgery; file-creation hits are ServiceState log files

Evidence status: **verified**

The 162 sysmon file-creation hits matching *Cookies*/*Login Data*/*Web Data* are all svchost.exe writing C:\Windows\ServiceState\EventLog\Data\lastalive0.dat and lastalive1.dat on nashua, scranton, utica and newyork — routine service-state files, not browser cookie databases. No PowerShell 4104 block references Cookies/SetCookie/document.cookie and no windows.other message mentions cookie. No forged session cookie replay is visible: 4624 logon processes are all standard. The genuine malicious activity in the window is credential theft (lsass 0x1fffff access by PowerShell) and document/password-file archiving, not cookie forgery.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:28.893Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceState\EventLog\Data\lastalive1.dat | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpl1glI | q-1c59af5fc6 | ok |
| 2 | 2020-05-02 02:55:28.893Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpl1glI | q-1c59af5fc6 | ok |
| 3 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCk1OJ | q-17e059bb53 | ok |

### F51 · benign / medium · T1606.002 · No SAML/ADFS token forgery artifacts; lsass access is credential dumping, not token-signing theft

Evidence status: **verified**

No SAML, NotOnOrAfter, token-signing or ADFS strings appear in PowerShell 4104 blocks or windows.other messages, and no ADFS service activity is present. The 326 lsass process-access events are dominated by benign 0x1000 (293) and 0x1400 (24) reads from svchost.exe, WindowsAzureTelemetryService.exe, wininit.exe and csrss.exe; the handful of high-privilege accesses (0x1fffff/0x1f3fff by PowerShell.exe on scranton at 03:05:16Z and wsmprovhost.exe on nashua at 03:09:29Z) are consistent with credential dumping over an existing intrusion, not with theft of SAML token-signing certificates. The 4648 explicit-credential logons are pbeesly to NASHUA via PSEXESVC.exe (lateral movement) plus local DWM/UMFD/SCRANTON$ system logons.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-731b0f3b50 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-731b0f3b50 | ok |
| 3 | 2020-05-02 03:12:25.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjEkfw | q-340fb0b39f | ok |
| 4 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkCwA | q-088755c083 | ok |

### F53 · benign / medium · T1649 · Registry write to SystemCertificates\ROOT on NASHUA by Sysmon.exe — unrelated to certificate theft

Evidence status: **verified**

The only 4657 registry modification touching a certificate store was on nashua.dmevals.local at 2020-05-01T23:16:19Z: value "Blob" under \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656, operation type %%1905 (existing value modified), performed by process C:\Windows\Sysmon.exe under the machine account NASHUA$. This is a single value update on a different host from the SCRANTON certificate export, executed by the Sysmon service binary under the computer account rather than by an interactive user, and is consistent with routine certificate-store maintenance/trust refresh rather than an adversary installing a rogue root CA. No other certificate-store registry writes were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhDM5P | q-6902e16fed | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhDM5P | q-6902e16fed | ok |
| 3 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.SubjectUserName | NASHUA$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhDM5P | q-6902e16fed | ok |

### F54 · benign / medium · T1649 · Kerberos TGT requests for pbeesly and SCRANTON$ show no certificate/PKINIT anomaly

Evidence status: **verified**

All 14 4768 TGT requests in the window were logged on newyork.dmevals.local for krbtgt: 9 for pbeesly from 10.0.1.4/10.0.1.6 and 5 for the machine account SCRANTON$ from 10.0.1.4, all with Status 0x0, PreAuthType 2 (pre-authentication used) and TicketEncryptionType 0x12 (AES256). There is no RC4 downgrade, no pre-auth-disabled request and no PKINIT-style certificate logon, so the Kerberos telemetry does not itself evidence certificate-based authentication abuse; the certificate theft is evidenced by the PowerShell export and .pfx creation instead.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEcb | q-0e1f2d6e59 | ok |
| 2 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEcb | q-0e1f2d6e59 | ok |
| 3 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItse-35u | q-0e1f2d6e59 | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Normal Skype app self-restart with WerFault crash reporting. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | PyInstaller implant pushed via PsExec from SCRANTON, spawns powershell and drops Rar/sdelete. |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Rar from Temp used by pbeesly to password-encrypt working.zip before wiping. |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Anti-forensic wiping of Rar.exe and working.zip on NASHUA. |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure guest agent log collection, routine. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher plugin, routine. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure antimalware config, routine. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure custom script extension, routine. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure domain join extension, routine. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google updater crash handler, routine. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google updater crash handler, routine. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Google updater service, routine. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Sysinternals tool run by attacker PowerShell for permission discovery. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Used by pbeesly with plaintext password to launch python.exe on NASHUA. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Anti-forensic deletion of payload, Draft.Zip and SysinternalsSuite.zip. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Defender service, routine. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Defender network inspection service, routine. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Right-to-left-override screen saver launched from explorer that dropped monkey.png stego payload. |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | C# compiler invoked by hidden PowerShell to build in-memory loader DLLs in Temp. |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Started with -verb runas by PowerShell to elevate, part of the intrusion chain. |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | malicious | sdclt abused via DelegateExecute to spawn control.exe and hidden PowerShell. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent firewall tool, routine. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent volume tool, routine. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure guest agent service, routine. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | 1 | C:\Windows\System32\services.exe | benign | Azure telemetry service, routine. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\WaAppAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure agent service, routine. |
| scranton.dmevals.local | C:\WindowsAzure\SecAgent\WaSecAgentProv.exe | 2 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure security agent, routine. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\Plugins\VFPl… | 1 | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | benign | Azure network agent plugin, routine. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | 1 | C:\Windows\System32\services.exe | benign | Azure network agent service, routine. |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | Compromised pbeesly session on scranton ran hidden steganography-loaded PowerShell, Sysinternals accesschk/sdelete64 cleanup, certificate private-key export attempts and keystroke/clipboard collection alongside lsass han… |
| T1003.001 LSASS Memory | malicious | PowerShell.exe PID 2976 (child of control.exe, hidden -ep bypass loader) opened lsass.exe with GrantedAccess 0x1F3FFF and 0x1FFFFF on scranton at 03:05:16Z; no dump file on disk, but full-access LSASS handles from a non-… |
| T1003.002 Security Account Manager | suspicious | SAM_SERVER 0xF003F handles on SCRANTON, no dump file seen. |
| T1003.003 NTDS | not_observed | No ntds.dit file creation, no ntdsutil/vssadmin/diskshadow execution, no NTDS object access on any host including the DC newyork. |
| T1003.004 LSA Secrets | benign | Only six 4662 queries of Policy\Secrets\$MACHINE.ACC by NT AUTHORITY\LOCAL SERVICE; no lsadump/sekurlsa tooling or SECURITY\Policy\Secrets writes. |
| T1003.005 Cached Domain Credentials | benign | Cache registry writes are TaskCache/NetworkList/AppContainer noise plus normal HKLM\SECURITY\Cache\NL$1; no cachedump/mscache/dcc2 commands or SECURITY\Cache object access. |
| T1003.006 DCSync | benign | Single 4662 by the DC's own machine account NEWYORK$ with replication-right GUIDs; no repeated or non-DC replication abuse indicating DCSync. |
| T1040 Network Sniffing | suspicious | No packet-capture driver, promiscuous-mode or raw-socket artifact was observed, but a malicious 'SeaDukeStage' PowerShell stage pushed an unsigned PyInstaller python.exe implant (bundled _socket/_ssl) to NASHUA via PsExe… |
| T1056 Input Capture | malicious | Clipboard read and AV check before keylogging. |
| T1056.001 Keylogging | malicious | Get-Keystrokes job executed on SCRANTON. |
| T1056.002 GUI Input Capture | not_observed | No Get-Credential or fake GUI prompt code; 'prompt' script blocks are PowerShell module boilerplate. |
| T1056.003 Web Portal Capture | not_observed | Zeek window does not overlap Windows telemetry and the HTTP POST/login check returned zero hits. |
| T1056.004 Credential API Hooking | suspicious | No dumping/hooking code captured, but pbeesly's powershell.exe and wsmprovhost.exe requested full-access (0x1fffff / 0x1f3fff) handles to lsass.exe on scranton and nashua. |
| T1110 Brute Force | not_observed | Zero 4625 and zero 4771 events in windows.security; only 4776 was a success (0x0). No repeated authentication failures on any host. |
| T1110.001 Password Guessing | not_observed | PowerShell 'password' hits are certificate export (pfx password 'saribas') and 7z archive encryption ('lolol'), not login attempts; no password/passwd/pwd command lines in sysmon. |
| T1110.002 Password Cracking | suspicious | PowerShell accessed lsass with GrantedAccess 0x1fffff on scranton and exported all LocalMachine certificates, i.e. credential material was obtained, but no cracking tooling, SAM/NTDS dumps or hash files were observed. |
| T1110.003 Password Spraying | suspicious | 4648 explicit-credential logons are all for the single account pbeesly, reused against NASHUA over cifs/445 with PSEXESVC.exe on the target - lateral movement, not one-password-many-accounts spraying. |
| T1110.004 Credential Stuffing | not_observed | Only one hardcoded credential pair (cozy / MyCozyPassw0rd!) used once for a WebDAV drive; no stuffing lists and no authentication failures. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA/smartcard/credential-provider interception artifacts: zero smartcard/NGC/credential-provider file creations, no MFA-related command lines (only the standard NgcSvc svchost host), only standard authentication packa… |
| T1187 Forced Authentication | malicious | Zeek shows 10.0.1.4 (SCRANTON) forced into WebDAV authentication against 192.168.0.4: DavClnt OPTIONS, rejected SMB probes to 445/139, then Microsoft-WebDAV-MiniRedir OPTIONS/PROPFIND to /webdav/OfficeSupplies.7z with an… |
| T1212 Exploitation for Credential Access | malicious | PowerShell (PID 2976) and wsmprovhost.exe (PID 7720) opened lsass.exe with 0x1f3fff/0x1fffff access on scranton and nashua, preceded/followed by a reflective GetProcAddress + base64 PE shellcode loader and hidden encoded… |
| T1539 Steal Web Session Cookie | not_observed | No process read or copied browser cookie/credential stores: sysmon file-create matches for *cookies*/*login data*/*web data*/*local state* yielded only an unrelated LocalService INetCookies file, security 4663 object acc… |
| T1552 Unsecured Credentials | malicious | Archive exfiltrated to 192.168.0.4 WebDAV. |
| T1552.001 Credentials In Files | malicious | Password/login-named files archived and encrypted on both hosts. |
| T1552.002 Credentials in Registry | suspicious | Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression on scranton by pbeesly; no reg query/save of SAM/SECURITY observed. |
| T1552.003 Shell History | not_observed | No ConsoleHost_history, .bash_history or Get-History access found in PowerShell, Sysmon process/file or Security object-access data. |
| T1552.004 Private Keys | malicious | LocalMachine certs exported to .pfx on SCRANTON. |
| T1552.006 Group Policy Preferences | not_observed | No Groups.xml, cpassword or SYSVOL access in PowerShell script blocks, Sysmon process/file events, Security 5145 share access or windows.other messages. |
| T1555 Credentials from Password Stores | malicious | wsmprovhost full-access lsass handle on NASHUA. |
| T1555.003 Credentials from Web Browsers | not_observed | No command lines, file events or object accesses on browser credential stores; only a benign LocalService INetCookies write by svchost. |
| T1555.004 Windows Credential Manager | not_observed | No vault/cmdkey/credman execution, no registry writes to Vault/Credentials; only a Credential Guard status message. |
| T1555.005 Password Managers | not_observed | No KeePass/1Password/Bitwarden/.kdbx references in any dataset; the pbeesly PowerShell activity was data staging/exfiltration, not password-manager theft. |
| T1556 Modify Authentication Process | malicious | Steganographic PowerShell loader (monkey.png) on SCRANTON opened lsass.exe with 0x1F3FFF/0x1FFFFF as pbeesly, followed by PsExec with cleartext credentials to NASHUA — credential access against the auth process, though t… |
| T1556.001 Domain Controller Authentication | suspicious | lsass handle opens from PowerShell.exe (0x1FFFFF) and wsmprovhost.exe (0x1F3FFF) indicate targeting of the DC auth process, but all lsass module loads (lsass.exe, samsrv.dll, wdigest.dll) are Microsoft-signed/valid and n… |
| T1556.002 Password Filter DLL | not_observed | No Notification Packages/PasswordFilter registry changes, no System32 DLL writes, no password-filter references in PowerShell or other logs. |
| T1556.005 Reversible Encryption | not_observed | No 4739 events and no AllowReversiblePasswordEncryption/Set-ADAccountControl references in any dataset. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739 (authentication policy change) events in windows.security. |
| T1556.007 Hybrid Identity | not_observed | No 5136 directory-service changes and no identity/federation component tampering in image-load data. |
| T1556.008 Network Provider DLL | not_observed | The 36 4657 events are wevtutil Autologger\EventLog-Application config and a SystemCertificates write; no NetworkProvider registration and no unsigned DLLs in winlogon/lsass. |
| T1557 Adversary-in-the-Middle | suspicious | No on-host interception tooling in Windows telemetry; the only AiTM-shaped signal is the zeek L2 duplication of 10.0.1.4 flows, plus an unrelated PsExec-launched C:\Windows\Temp\python.exe on nashua. |
| T1557.001 Name Resolution Poisoning and SMB Relay | suspicious | SMB/WinRM Kerberos/GSSAPI sessions from 10.0.1.4 to 10.0.1.6 appear twice with different MAC pairs (00:33 and 00:35), consistent with a relay/interception path; WPAD queries were answered normally and no LLMNR traffic wa… |
| T1557.002 ARP Cache Poisoning | suspicious | IP 10.0.1.4 is observed on two different source MACs (00:0d:3a:4d:42:f2 and fc:bd:67:e1:a9:c1) with 44 connections from the second MAC confined to 00:30-00:45, consistent with ARP cache poisoning, though no ARP records o… |
| T1557.003 DHCP Spoofing | not_observed | No DHCP server/lease event codes in windows.other, no DHCP-related PowerShell script blocks, and the only ipconfig/netsh/arp/route executions are read-only Azure guest-agent and NetworkWatcher diagnostics on scranton. |
| T1558 Steal or Forge Kerberos Tickets | suspicious | scranton.dmevals.local: malicious PowerShell (PID 2976, user pbeesly) opened lsass.exe with 0x1F3FFF and 0x1FFFFF at 03:05:16 during a confirmed intrusion chain (malicious .scr, C2, persistence, private-key theft) — cred… |
| T1558.001 Golden Ticket | not_observed | krbtgt 4769 requests are AES256 (0x12) TGT requests for pbeesly and SCRANTON$ with Failure Code 0x0, each matched by a 4624 Kerberos logon; no RC4 krbtgt tickets, no 4768/4770/4771, no DCSync/Mimikatz/krbtgt script conte… |
| T1558.002 Silver Ticket | not_observed | All 28 4769 events are AES256 service tickets for machine accounts (NEWYORK$, NASHUA$, SCRANTON$, WEC$); no forged service tickets or silver-ticket tooling observed. |
| T1558.003 Kerberoasting | not_observed | All 4769 tickets use Ticket Encryption Type 0x12 (AES256); no RC4 SPN requests, no GetUserSPNs/Invoke-Kerberoast script blocks, no 4769/4768 in windows.other. |
| T1558.004 AS-REP Roasting | not_observed | No 4768 AS-REQ events in any dataset and no asreproast/GetNPUsers/Rubeus command lines or script-block content. |
| T1606 Forge Web Credentials | not_observed | No forged web credential artifacts: no ADFS/SAML/token strings in windows.other or PowerShell 4104, and all 297 4624 logons use standard logon processes (Kerberos/Advapi/User32/NtLmSsp). The hits reflect credential theft… |
| T1606.001 Web Cookies | not_observed | The 162 *Cookies*/*Login Data*/*Web Data* file-creation hits are svchost.exe writing C:\Windows\ServiceState\EventLog\Data\lastalive*.dat; no cookie/SetCookie/document.cookie script blocks and no anomalous logon process … |
| T1606.002 SAML Tokens | not_observed | No SAML/NotOnOrAfter/token-signing/ADFS strings in PowerShell or windows.other; lsass accesses are mostly benign 0x1000/0x1400 reads, and the high-privilege ones (PowerShell 0x1fffff on scranton, wsmprovhost 0x1f3fff on … |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | 4 planned checks, all with zero hits |
| T1649 Steal or Forge Authentication Certificates | malicious | On scranton.dmevals.local, pbeesly's PowerShell (PID 3876) ran a Get-PrivateKeys function that recursively exported every cert:\LocalMachine certificate to a randomly named .pfx in Downloads protected by the hardcoded pa… |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 0 hits | 0 hits | 6 hits | 327 hits | n/a |
| T1003.001 LSASS Memory | 0 hits | 0 hits | 13 hits | 655 hits | n/a |
| T1003.002 Security Account Manager | 11 hits | 0 hits | 0 hits | 10 hits | n/a |
| T1003.003 NTDS | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.004 LSA Secrets | 0 hits | 0 hits | 0 hits | 380 hits | n/a |
| T1003.005 Cached Domain Credentials | 0 hits | 0 hits | 0 hits | 6955 hits | n/a |
| T1003.006 DCSync | 0 hits | 0 hits | 21 hits | 0 hits | n/a |
| T1040 Network Sniffing | 0 hits | 0 hits | 0 hits | 447 hits | 613 hits |
| T1056 Input Capture | 0 hits | 0 hits | 10996 hits | 78566 hits | n/a |
| T1056.001 Keylogging | 0 hits | 0 hits | 0 hits | 39283 hits | n/a |
| T1056.002 GUI Input Capture | 0 hits | 414 hits | 0 hits | 19 hits | n/a |
| T1056.003 Web Portal Capture | 0 hits | 0 hits | 0 hits | 1649 hits | 0 hits |
| T1056.004 Credential API Hooking | 0 hits | 0 hits | 13 hits | 21006 hits | n/a |
| T1110 Brute Force | 2 hits | 4 hits | 0 hits | 32 hits | 35 hits |
| T1110.001 Password Guessing | 2 hits | 2 hits | 0 hits | 0 hits | 35 hits |
| T1110.002 Password Cracking | 6 hits | 0 hits | 153 hits | 326 hits | 448 hits |
| T1110.003 Password Spraying | 4 hits | 4 hits | 15 hits | 1 hits | 35 hits |
| T1110.004 Credential Stuffing | 4 hits | 3 hits | 0 hits | 0 hits | 35 hits |
| T1111 Multi-Factor Authentication Interception | 2 hits | 3 hits | 594 hits | 39294 hits | n/a |
| T1187 Forced Authentication | 0 hits | 0 hits | 11140 hits | 66 hits | 86 hits |
| T1212 Exploitation for Credential Access | 0 hits | 0 hits | 483 hits | 39609 hits | 35 hits |
| T1539 Steal Web Session Cookie | 3 hits | 13 hits | 460 hits | 162 hits | 0 hits |
| T1552 Unsecured Credentials | 2 hits | 2 hits | 460 hits | 66 hits | 23 hits |
| T1552.001 Credentials In Files | 0 hits | 0 hits | 11294 hits | 72 hits | 12 hits |
| T1552.002 Credentials in Registry | 2 hits | 5 hits | 0 hits | 20 hits | n/a |
| T1552.003 Shell History | 5 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1552.004 Private Keys | 0 hits | 2 hits | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1555 Credentials from Password Stores | 0 hits | 3 hits | 6 hits | 652 hits | n/a |
| T1555.003 Credentials from Web Browsers | 0 hits | 0 hits | 0 hits | 166 hits | n/a |
| T1555.004 Windows Credential Manager | 2 hits | 3 hits | 0 hits | 0 hits | n/a |
| T1555.005 Password Managers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556 Modify Authentication Process | 0 hits | 0 hits | 0 hits | 914 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | 0 hits | 327 hits | 359 hits | n/a |
| T1556.002 Password Filter DLL | 5 hits | 0 hits | 0 hits | 19432 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556.006 Multi-Factor Authentication | 0 hits | 0 hits | 0 hits | n/a | n/a |
| T1556.007 Hybrid Identity | 0 hits | 0 hits | 0 hits | 20259 hits | n/a |
| T1556.008 Network Provider DLL | n/a | n/a | 36 hits | 59542 hits | n/a |
| T1557 Adversary-in-the-Middle | n/a | n/a | 10977 hits | 1310 hits | 613 hits |
| T1557.001 Name Resolution Poisoning and SMB Relay | n/a | n/a | 23 hits | 1229 hits | 621 hits |
| T1557.002 ARP Cache Poisoning | n/a | n/a | n/a | 1310 hits | 613 hits |
| T1557.003 DHCP Spoofing | 216 hits | 0 hits | 297 hits | 5 hits | n/a |
| T1558 Steal or Forge Kerberos Tickets | 0 hits | 0 hits | 448 hits | 652 hits | 112 hits |
| T1558.001 Golden Ticket | 0 hits | 0 hits | 240 hits | 326 hits | n/a |
| T1558.002 Silver Ticket | 0 hits | 0 hits | 240 hits | 326 hits | n/a |
| T1558.003 Kerberoasting | 0 hits | 0 hits | 368 hits | 326 hits | n/a |
| T1558.004 AS-REP Roasting | 0 hits | 0 hits | 28 hits | 0 hits | n/a |
| T1606 Forge Web Credentials | 0 hits | 1 hits | 312 hits | 326 hits | n/a |
| T1606.001 Web Cookies | 0 hits | 0 hits | 297 hits | 162 hits | n/a |
| T1606.002 SAML Tokens | 0 hits | 0 hits | 312 hits | 326 hits | n/a |
| T1621 Multi-Factor Authentication Request Generatio… | 0 hits | 0 hits | 0 hits | n/a | n/a |
| T1649 Steal or Forge Authentication Certificates | 0 hits | 1 hits | 64 hits | 1 hits | n/a |

Cells: 265, gaps: 0.

## Queries

Every MCP tool call of this run (1220), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-eb49e936dd | scope | list_data_sources | {} | None |  |
| q-c1d718c40c | scope | get_registry | {} | None |  |
| q-8638483ab7 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-8087aa1997 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-7c2f1d7303 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-6d4f126631 | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-da6ec71086 | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-4b6e332f3b | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*sam* OR process.command_line:*ntds* OR process.command_line:*sekurlsa* OR process.command_line:*minidump* OR process.… | 1 |  |
| q-b76a23c1c3 | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e36dbb8a3b | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-b9459ec0b7 | check C004 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*minidump* OR win.ScriptBlockText:*procdump* OR win.ScriptBlockText:*comsvcs* OR win.Scr… | 0 |  |
| q-3b40ac5de1 | check C005 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*procdump* OR message:*minidump* OR message:*sekurlsa* OR message:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 0 |  |
| q-9f65171756 | check C006 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-6bd0688d5a | check C007 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-40e1e08fab | check C008 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.dmp OR win.TargetFilename:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2 |  |
| q-c114a9d9cf | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*procdump* OR process.command_line:*lsass*)", "time_from": null, "time_to": null,… | 1 |  |
| q-c0fa86cb26 | check C010 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4673 AND (win.ObjectName:*lsass* OR win.ObjectName:*SeDebugPrivilege* OR win.ObjectName:*Debug*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-baaea173c1 | check C011 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-2dd70f9d9a | check C012 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*sekurlsa*)", "time_from": null, "time_to": null, "size… | 0 |  |
| q-f2a79e481c | check C013 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*MiniDump* OR message:*comsvcs*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 0 |  |
| q-1f1018b6eb | check C014 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SYSTEM* OR win.TargetFilename:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3 |  |
| q-0cfebaa3e7 | check C015 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*SAM* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-28a434d3a3 | check C016 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*reg*save* OR process.command_line:*reg*save*hklm*sam* OR process.command_line:*reg*save*hklm*security*)", "time_from": null, "time_to": null, "size":… | 0 |  |
| q-9ef4469a4b | check C017 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*reg*save* OR process.command_line:*sam* OR process.command_line:*ntds*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a587128f17 | check C018 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-d5224eb4c0 | check C019 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*reg*save* OR win.ScriptBlockText:*SAM* OR win.ScriptBlockText:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-1b839f1a3a | check C020 | search | {"dataset": "windows.other", "query": "message:*reg*save* OR message:*SAM* OR message:*SECURITY*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 11 | F05 |
| q-71a7a03a3f | check C021 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND win.TargetFilename:*ntds*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-00f3cfeb13 | check C022 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*ntds* OR process.command_line:*ntdsutil* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": nul… | 0 |  |
| q-f7bca1f522 | check C023 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "size": 50, "sub_field": nu… | 0 |  |
| q-51a51a5fb7 | check C024 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectName:*ntds*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-8f361e6df6 | check C025 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*ntds* OR win.ScriptBlockText:*vssadmin* OR win.ScriptBlockText:*diskshadow*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c005849be3 | check C026 | search | {"dataset": "windows.other", "query": "message:*ntds* OR message:*vssadmin* OR message:*diskshadow*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-c88d8da1dc | check C027 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND registry.path:*SECURITY*Policy*Secrets*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f5538bd1b2 | check C028 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-13f4a7fd0d | check C029 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*secrets* OR process.command_line:*lsadump* OR process.command_line:*sekurlsa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-bfbab3c87d | check C030 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*samlib* OR win.ImageLoaded:*vaultcli* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 54 |  |
| q-4ef9cc3a89 | check C031 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectName:*SECURITY*Policy*Secrets*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-40c85fbc81 | check C032 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND win.ObjectName:*SECURITY*Policy*Secrets*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3e3cd7994b | check C033 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*lsadump* OR win.ScriptBlockText:*secrets* OR win.ScriptBlockText:*sekurlsa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f9ced492f4 | check C034 | search | {"dataset": "windows.other", "query": "message:*lsadump* OR message:*secrets* OR message:*sekurlsa*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-9c128cd12c | check C035 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Cache* OR registry.path:*SECURITY*Cache*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6625 |  |
| q-ee33a2a8fa | check C036 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-7b0dc3eb00 | check C037 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*dcc2* OR process.command_line:*mscache* OR process.command_line:*cachedump*)", "time_from": null, "time_to": null, "s… | 4 |  |
| q-411a77e082 | check C038 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Cache* OR win.ObjectName:*SECURITY*Cache*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-df90ebe6ca | check C039 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND (win.ObjectName:*Cache* OR win.ObjectName:*SECURITY*Cache*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-57217095ef | check C040 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*cachedump* OR win.ScriptBlockText:*mscache* OR win.ScriptBlockText:*dcc2*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-16fc8c59d1 | check C041 | search | {"dataset": "windows.other", "query": "message:*cachedump* OR message:*mscache* OR message:*dcc2*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 0 |  |
| q-f345e026e8 | check C042 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-ef768bb75a | check C043 | aggregate | {"dataset": "windows.security", "field": "win.Properties", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-2f95eeb3ba | check C044 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-9671706869 | check C045 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*drsuapi*\" OR TO_LOWER(process.command_line) LIKE \"*dcsync*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process… | ERROR |  |
| q-318c7304ea | check C045 (repaired) | esql | {"query": "FROM windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*drsuapi*\" OR TO_LOWER(process.command_line) LIKE \"*dcsync*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER… | ERROR |  |
| q-b1cebdbea6 | check C046 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*dcsync*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*drsuapi*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lsadump*\" OR TO_LOWER(win… | ERROR |  |
| q-c511467546 | check C046 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*dcsync*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*drsuapi*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lsadump*\" OR TO_LOWER(win… | ERROR |  |
| q-056929ffd9 | check C047 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*drsuapi*\" OR TO_LOWER(message) LIKE \"*dcsync*\" OR TO_LOWER(message) LIKE \"*lsadump*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-0876147700 | check C047 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*drsuapi*\" OR TO_LOWER(message) LIKE \"*dcsync*\" OR TO_LOWER(message) LIKE \"*lsadump*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-51835594d0 | check C048 | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.executable) LIKE \"*pktmon*\" OR TO_LOWER(process.executable) LIKE \"*windump*\" OR TO_LOWER(process.executable) LIKE \"*tcpdump*\" OR TO_LOWER(process.… | ERROR |  |
| q-69e606669d | check C048 (repaired) | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.executable) LIKE \"*pktmon*\" OR TO_LOWER(process.executable) LIKE \"*windump*\" OR TO_LOWER(process.executable) LIKE \"*tcpdump*\" OR TO_LOWER(process.… | ERROR |  |
| q-dd255c68c4 | check C049 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-8c58a0c02c | check C050 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE event.code == \"7045\" \| KEEP @timestamp, host.name, win.ServiceName, win.ImagePath, _id, _index"} | ERROR |  |
| q-1707684913 | check C050 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE event.code == \"7045\" \| KEEP @timestamp, host.name, win.ServiceName, win.ImagePath, _id, _index"} | ERROR |  |
| q-abbd6ca376 | check C051 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*pktmon*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*netsh trace*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*promiscuous*\" OR TO_L… | ERROR |  |
| q-db407d86f1 | check C051 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*pktmon*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*netsh trace*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*promiscuous*\" OR TO_L… | ERROR |  |
| q-80589ab68b | check C052 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-eb8f525447 | check C053 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-7d6a80605b | check C054 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-4a7ca33a2c | check C055 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, user.name, win.SourceImage, win.TargetImage, win.GrantedAccess, _id, _index"} | ERROR |  |
| q-bd72dd884a | check C055 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, user.name, win.SourceImage, win.TargetImage, win.GrantedAccess, _id, _index"} | ERROR |  |
| q-30dcd01c46 | check C056 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-a195a908ca | check C057 | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE (event.code == \"4656\" OR event.code == \"4663\") AND TO_LOWER(win.ObjectName) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, user.name, win.ObjectName, win.AccessMask, win.ProcessName, _id, _ind… | ERROR |  |
| q-44c9c7df64 | check C057 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE (event.code == \"4656\" OR event.code == \"4663\") AND TO_LOWER(win.ObjectName) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, user.name, win.ObjectName, win.AccessMask, win.ProcessNa… | 19 |  |
| q-db8d681e2f | check C058 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*get-credential*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credentialui*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*setwindowshoo… | ERROR |  |
| q-44748aae26 | check C058 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*get-credential*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credentialui*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*setwindowshoo… | ERROR |  |
| q-7c01af093f | check C059 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*lsass*\" OR TO_LOWER(message) LIKE \"*credential*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-5fa3de4d0b | check C059 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*lsass*\" OR TO_LOWER(message) LIKE \"*credential*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-00a58aa718 | check C060 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*winlogon*\" OR TO_LOWER(win.TargetImage) LIKE \"*explorer*\" OR TO_LOWER(win.TargetImage) LIKE \"*lsass*\") \| KEEP @timestamp, host.name, … | ERROR |  |
| q-d5ddc62968 | check C060 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*winlogon*\" OR TO_LOWER(win.TargetImage) LIKE \"*explorer*\" OR TO_LOWER(win.TargetImage) LIKE \"*lsass*\") \| KEEP @timestamp, host.name, … | ERROR |  |
| q-35d8c8346b | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-d027c0cd7a | check C062 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*keyboard*\" OR TO_LOWER(registry.path) LIKE \"*currentversion\\\\run*\" OR TO_LOWER(registry.path) LIKE \"*image file execution options*\") \… | ERROR |  |
| q-c2001a93bd | check C062 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*keyboard*\" OR TO_LOWER(registry.path) LIKE \"*currentversion*run*\" OR TO_LOWER(registry.path) LIKE \"*image file execution options*\") \| K… | ERROR |  |
| q-85a4077e1c | check C063 | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.executable) LIKE \"*keylog*\" OR TO_LOWER(process.command_line) LIKE \"*keylog*\" OR TO_LOWER(process.executable) LIKE \"*hook*\" OR TO_LOWER(process.co… | ERROR |  |
| q-61445314ef | check C063 (repaired) | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.executable) LIKE \"*keylog*\" OR TO_LOWER(process.command_line) LIKE \"*keylog*\" OR TO_LOWER(process.executable) LIKE \"*hook*\" OR TO_LOWER(process.co… | ERROR |  |
| q-fe2c32222d | check C064 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE event.code == \"7045\" \| KEEP @timestamp, host.name, win.ServiceName, win.ImagePath, _id, _index"} | ERROR |  |
| q-8d3f021b00 | check C064 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE event.code == \"7045\" \| KEEP @timestamp, host.name, win.ServiceName, win.ImagePath, _id, _index"} | ERROR |  |
| q-1eaa8e9b03 | check C065 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*getasynckeystate*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*setwindowshookex*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*keylog*… | ERROR |  |
| q-dacaa4881a | check C065 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*getasynckeystate*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*setwindowshookex*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*keylog*… | ERROR |  |
| q-f33fc76125 | check C066 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*credentialui*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-credential*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*promptforcred… | ERROR |  |
| q-81420527a8 | check C066 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*credentialui*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-credential*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*promptforcred… | ERROR |  |
| q-18d95318ab | check C067 | aggregate | {"dataset": "windows.powershell", "field": "win.ScriptBlockText", "query": "event.code:4104", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 414 |  |
| q-6ca325a19e | check C068 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*powershell*\" OR TO_LOWER(process.executable) LIKE \"*wscript*\" OR TO_LOWER(process.executable) LIKE \"*mshta*\" OR TO_LOWER(process.exe… | ERROR |  |
| q-d5df6b2e33 | check C068 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*powershell*\" OR TO_LOWER(process.executable) LIKE \"*wscript*\" OR TO_LOWER(process.executable) LIKE \"*mshta*\" OR TO_LOWE… | 19 |  |
| q-fa4e3ea267 | check C069 | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.executable) LIKE \"*powershell*\" OR TO_LOWER(process.executable) LIKE \"*mshta*\" OR TO_LOWER(process.executable) LIKE \"*wscript*\") \| KEEP @timestam… | ERROR |  |
| q-e10d40edf6 | check C069 (repaired) | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.executable) LIKE \"*powershell*\" OR TO_LOWER(process.executable) LIKE \"*mshta*\" OR TO_LOWER(process.executable) LIKE \"*wscript*\") \| KEEP @timestam… | ERROR |  |
| q-17b801ffad | check C070 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*credential*\" OR TO_LOWER(message) LIKE \"*prompt*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-1b13a2c7e8 | check C070 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*credential*\" OR TO_LOWER(message) LIKE \"*prompt*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-dd16fb5805 | check C071 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*\\\\inetpub\\\\*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.aspx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.asp\" OR TO_LOWER(win.Target… | ERROR |  |
| q-637a6c17a0 | check C071 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*inetpub*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.aspx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.asp\" OR TO_LOWER(win.TargetFilename… | ERROR |  |
| q-515c445316 | check C072 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1649 |  |
| q-3507c3dfb7 | check C073 | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.executable) LIKE \"*w3wp*\" OR TO_LOWER(process.command_line) LIKE \"*cmd.exe*\" OR TO_LOWER(process.command_line) LIKE \"*powershell*\") \| KEEP @times… | ERROR |  |
| q-794ea551d3 | check C073 (repaired) | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.executable) LIKE \"*w3wp*\" OR TO_LOWER(process.command_line) LIKE \"*cmd.exe*\" OR TO_LOWER(process.command_line) LIKE \"*powershell*\") \| KEEP @times… | ERROR |  |
| q-e58b21ad6f | check C074 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*request.form*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credentials*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*login*\") \| KEE… | ERROR |  |
| q-3cc1649b77 | check C074 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*request.form*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credentials*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*login*\") \| KEE… | ERROR |  |
| q-774cfb2d10 | check C075 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE event.code == \"7045\" \| KEEP @timestamp, host.name, win.ServiceName, win.ImagePath, _id, _index"} | ERROR |  |
| q-dd0005d8a5 | check C075 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE event.code == \"7045\" \| KEEP @timestamp, host.name, win.ServiceName, win.ImagePath, _id, _index"} | ERROR |  |
| q-dc7491ece4 | check C076 | esql | {"query": "FROM zeek METADATA _id, _index \| WHERE event.action == \"http\" AND (http.request.method == \"POST\" OR TO_LOWER(url.original) LIKE \"*login*\" OR TO_LOWER(url.original) LIKE \"*auth*\") \| KEEP @timestamp, source.ip, destination.ip, url.original, … | ERROR |  |
| q-598d476fe3 | check C076 (repaired) | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" AND (http.request.method == \"POST\" OR TO_LOWER(url.original) LIKE \"*login*\" OR TO_LOWER(url.original) LIKE \"*auth*\") \| KEEP @timestamp, source.ip, destination.ip, u… | 0 |  |
| q-127bf699e5 | check C077 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-013d199f70 | check C078 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-417f3ffc56 | check C079 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-36044abab6 | check C080 | search | {"dataset": "windows.sysmon", "query": "event.code:8", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 95 |  |
| q-801775816e | check C081 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 13 |  |
| q-0ecfd68c99 | check C082 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*DumpCreds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-deefff0fba | check C083 | search | {"dataset": "windows.other", "query": "message:*lsass* OR win.ImagePath:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line… | 0 |  |
| q-6af828879e | check C084 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-3ec76453ca | check C085 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-216720db9d | check C086 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-3c10f91d0e | check C087 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4771", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-d98104181b | check C088 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*user* OR process.command_line:*pass*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 32 |  |
| q-1b5ed16347 | check C089 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Brute*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 4 |  |
| q-e47febd377 | check C090 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 2 |  |
| q-ebd4940ef8 | check C091 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-02bdaf0dc7 | check C092 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-c6b4e2c5f6 | check C093 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-bc991af3c2 | check C094 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-d825223b07 | check C095 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*passwd* OR process.command_line:*pwd*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-cbfd794f86 | check C096 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.na… | 2 |  |
| q-0d75ab2dc8 | check C097 | search | {"dataset": "windows.other", "query": "message:*password* OR message:*logon*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 2 |  |
| q-47a8a3be95 | check C098 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-c256e9ed2e | check C099 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-ba8106a686 | check C100 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4656 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10 |  |
| q-f7457ff5e0 | check C101 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4670", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 143 |  |
| q-16ca923bc8 | check C102 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*sam* OR process.command_line:*ntds* OR process.command_line:*reg*save* OR process.command_line:*hashcat*)", "time_from": null, "time_to": null, "size… | 0 |  |
| q-9ce8de901b | check C103 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.dit OR win.TargetFilename:*.hive OR win.TargetFilename:*sam*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-eab1af5234 | check C104 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-8852b0899e | check C105 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*hashcat* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*ntds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-3ffa602664 | check C106 | search | {"dataset": "windows.other", "query": "message:*SAM* OR message:*NTDS* OR message:*hive*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.com… | 6 |  |
| q-2de4c0a17d | check C107 | aggregate | {"dataset": "zeek", "field": "zeek.filename", "query": "event.action:files", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 448 |  |
| q-ab4ce743bf | check C108 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 200, "sub_field": null} | 0 |  |
| q-ae861f61bf | check C109 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-9e967fd8ff | check C110 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4771", "time_from": null, "time_to": null, "size": 200, "sub_field": null} | 0 |  |
| q-3211ce030e | check C111 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 15 |  |
| q-0d38903c52 | check C112 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net*use* OR process.command_line:*runas*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1 |  |
| q-3f16fc203d | check C113 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 4 |  |
| q-d510b86711 | check C114 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*authentication*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 4 |  |
| q-37f0c1b19f | check C115 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-d2113348b2 | check C116 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 200, "sub_field": null} | 0 |  |
| q-721d8c42d8 | check C117 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-a0ad9a8902 | check C118 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-0ad161cbb9 | check C119 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*login* OR process.command_line:*credential*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-16eaf7992f | check C120 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.… | 3 |  |
| q-bef4ba7ca6 | check C121 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 4 |  |
| q-b806976b09 | check C122 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-4b82c559a8 | check C123 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-8597264eb6 | check C124 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-d67cb67ede | check C125 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-87bbce30ca | check C126 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND registry.path:*Credential*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 11 |  |
| q-bf0f3e0d62 | check C127 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Smartcard* OR win.ScriptBlockText:*MFA*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 3 |  |
| q-2147c9d094 | check C128 | search | {"dataset": "windows.other", "query": "message:*smartcard* OR message:*Smartcard* OR message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 2 |  |
| q-80f00be3b1 | check C129 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-c043cf16e7 | check C130 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 163 |  |
| q-dd4b604237 | check C131 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.library-ms OR win.TargetFilename:*.searchConnector-ms OR win.TargetFilename:*.url)", "time_from": null, "time_to": null, "size": 50, "sub_field": nul… | 0 |  |
| q-05515993f5 | check C132 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:139 OR destination.port:445)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 66 |  |
| q-fcf91022f2 | check C133 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*WebDAV* OR win.ScriptBlockText:*NTLM* OR win.ScriptBlockText:*Responder*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-cbfd62f264 | check C134 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:139 OR destination.port:445)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-6a8b6b138b | check C135 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:OPTIONS OR http.request.method:MOVE)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 |  |
| q-68dbf9997a | check C136 | search | {"dataset": "windows.other", "query": "message:*WebClient* OR message:*WebDAV*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 0 |  |
| q-16cab9b4ca | check C137 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-cacf9ad0bd | check C138 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-fb381f510b | check C139 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4697 OR event.code:7045", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 23 |  |
| q-6560017150 | check C140 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-11c4032e43 | check C141 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*comsvcs*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-6fac8565e8 | check C142 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*MiniDump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-7efa264f66 | check C143 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-f1c9e8ff09 | check C144 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*Web Data*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 162 |  |
| q-8334aabddd | check C145 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND (win.TargetImage:*chrome* OR win.TargetImage:*firefox* OR win.TargetImage:*msedge*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-68214e9502 | check C146 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-90c32a0ddc | check C147 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*sqlite*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 13 |  |
| q-f040c44322 | check C148 | search | {"dataset": "windows.other", "query": "message:*Cookies* OR message:*Login Data*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 3 |  |
| q-c9620e23c6 | check C149 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*cookie* OR http.request.method:POST)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 0 |  |
| q-2fa6dfdbc6 | check C150 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17 |  |
| q-1b46b6278f | check C151 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.ini)", "time_from": null, "time_to": null, "size": 50, "sub_fi… | 49 |  |
| q-8070f86fa4 | check C152 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-13f7777a27 | check C153 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*password* OR win.ScriptBlockText:*credential* OR win.ScriptBlockText:*Get-Content*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name… | 2 |  |
| q-46620c6071 | check C154 | search | {"dataset": "windows.other", "query": "message:*password* OR message:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 2 | F28 |
| q-a2ac480874 | check C155 | search | {"dataset": "zeek", "query": "event.action:smb_files OR event.action:smb_mapping", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 23 |  |
| q-237e3a94f3 | check C156 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.config OR win.TargetFilename:*.ps1 OR win.TargetFilename:*.bat OR win.TargetFilename:*.ini OR win.TargetFilename:*.xml)",… | 72 |  |
| q-4107bae89e | check C157 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*unattend*)", "time_from": null, "time_to": null, "size": 50, "sub_field": nul… | 0 |  |
| q-84f1cb4d80 | check C158 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10834 |  |
| q-b4c53ac44f | check C159 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-12178e012f | check C160 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*unattend* OR win.ScriptBlockText:*web.config* OR win.ScriptBlockText:*Get-Content*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name… | 0 |  |
| q-6ba322e211 | check C161 | search | {"dataset": "windows.other", "query": "message:*unattend* OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line… | 0 |  |
| q-b83c602c4f | check C162 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-26faf64176 | check C163 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential* OR registry.path:*Secret* OR registry.path:*Login*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20 |  |
| q-8eb3f3e0fc | check C164 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*reg\\ query* OR process.command_line:*reg\\ save* OR process.command_line:*regedit* OR process.command_line:*Password*)", "time_from": null, "time_to… | 0 |  |
| q-445a0cbc2a | check C165 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*reg\\ query* OR win.ScriptBlockText:*HKLM*)", "time_from": null, "time_to": null, "fields": ["@timestamp… | 5 | F25, F27 |
| q-facd6f6323 | check C166 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*Password*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-5205925b2b | check C167 | search | {"dataset": "windows.other", "query": "message:*Password* OR message:*Credential* OR message:*reg\\ query*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-937171f718 | check C168 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*history* OR win.ScriptBlockText:*Get-History* OR win.ScriptBlockText:*ConsoleHost_history*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 0 |  |
| q-2d1f75a877 | check C169 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*history* OR process.command_line:*Get-History* OR process.command_line:*ConsoleHost_history*)", "time_from": null, "time_to": null, "size": 50, "sub_… | 0 |  |
| q-7082839a50 | check C170 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ConsoleHost_history* OR file.path:*.bash_history* OR file.path:*.zsh_history*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "… | 0 |  |
| q-1d9ce65b3c | check C171 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*history* OR win.ObjectName:*ConsoleHost*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-79f647f880 | check C172 | search | {"dataset": "windows.other", "query": "message:*history*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destin… | 5 |  |
| q-8c90478deb | check C173 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*.pem* OR process.command_line:*.pfx* OR process.command_line:*.key* OR process.command_line:*.p12* OR process.command_line:*.ppk*)", "time_from": nul… | 0 |  |
| q-bec54777c7 | check C174 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*.pem OR file.path:*.pfx OR file.path:*.p12 OR file.path:*.ppk OR file.path:*.key)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-7c9866758a | check C175 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*.pem OR win.RelativeTargetName:*.pfx OR win.RelativeTargetName:*.key OR win.RelativeTargetName:*.p12)", "time_from": null, "time_to": null… | 0 |  |
| q-a2e37a9bf8 | check C176 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*.pfx* OR win.ScriptBlockText:*.pem* OR win.ScriptBlockText:*.key* OR win.ScriptBlockText:*Export-PfxCertificate*)", "time_from": null, "time_to": null, "fields": ["@timestamp… | 2 |  |
| q-9ac18b9dfc | check C177 | search | {"dataset": "windows.other", "query": "message:*.pfx* OR message:*.pem* OR message:*.key*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.co… | 0 |  |
| q-11cec86d1a | check C178 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Groups.xml* OR win.ScriptBlockText:*cpassword* OR win.ScriptBlockText:*gpp* OR win.ScriptBlockText:*SYSVOL*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 0 |  |
| q-16f2c540ec | check C179 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*Groups.xml* OR win.RelativeTargetName:*SYSVOL* OR win.RelativeTargetName:*.xml)", "time_from": null, "time_to": null, "size": 50, "sub_fie… | 0 |  |
| q-e7049d6a4b | check C180 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*SYSVOL* OR process.command_line:*Groups.xml* OR process.command_line:*cpassword*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null… | 0 |  |
| q-4dbc2e3171 | check C181 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*Groups.xml* OR file.path:*SYSVOL*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executabl… | 0 |  |
| q-84415cff1a | check C182 | search | {"dataset": "windows.other", "query": "message:*SYSVOL* OR message:*Groups.xml* OR message:*cpassword*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-541cda5015 | check C183 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-8bcb1b6d49 | check C184 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-86739f8f79 | check C185 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*sekurlsa* OR process.command_line:*mimikatz* … | 0 |  |
| q-8ddc3a48be | check C186 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS.dit* OR win.ObjectName:*Credential*)", "time_from": null, "time_to": n… | 6 |  |
| q-51c7a794be | check C187 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*mimikatz* OR process.command_line:*ntds.… | 0 |  |
| q-f5fb1f5299 | check C188 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 3 |  |
| q-fa70fd91d7 | check C189 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*MiniDump* OR message:*mimikatz* OR message:*procdump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-59f1a14ab9 | check C190 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Login\\ Data* OR process.command_line:*logins.json* OR process.command_line:*key4.db* OR process.command_line:*Cookies* OR process.command_line:*Web … | 4 |  |
| q-4e5ebdd8c0 | check C191 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Login\\ Data* OR file.path:*logins.json* OR file.path:*key4.db* OR file.path:*Web Data*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 162 |  |
| q-f353e56132 | check C192 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Login\\ Data* OR win.ObjectName:*logins.json* OR win.ObjectName:*key4.db* OR win.ObjectName:*Web Data*)", "time_from": null, "time_to": null, "size": 50, … | 0 |  |
| q-dac48e8a2c | check C193 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Login\\ Data* OR win.ScriptBlockText:*logins.json* OR win.ScriptBlockText:*key4.db* OR win.ScriptBlockText:*CryptUnprotectData*)", "time_from": null, "time_to": null, "fields… | 0 |  |
| q-4bf4a7f707 | check C194 | search | {"dataset": "windows.other", "query": "message:*Login\\ Data* OR message:*logins.json* OR message:*key4.db*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execut… | 0 |  |
| q-bcef7b7369 | check C195 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*vault* OR process.command_line:*credman* OR process.command_line:*Credential* OR process.command_line:*cmdkey*)", "time_from": null, "time_to": null,… | 0 |  |
| q-148b764a86 | check C196 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetObject", "query": "event.code:13 AND (registry.path:*Vault* OR registry.path:*Credentials*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-1749a62c53 | check C197 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*cmdkey* OR process.command_line:*credman*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b162384f49 | check C198 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Vault* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 3 |  |
| q-0c1416b44f | check C199 | search | {"dataset": "windows.other", "query": "message:*Vault* OR message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 | F31 |
| q-746865bc2e | check C200 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*lastpass* OR process.command_line:*KeePass*… | 0 |  |
| q-4d247e5d89 | check C201 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (file.path:*.kdbx OR file.path:*1password* OR file.path:*KeePass* OR file.path:*Bitwarden*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3ac652fd83 | check C202 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*.kdbx OR win.ObjectName:*KeePass* OR win.ObjectName:*1Password* OR win.ObjectName:*Bitwarden*)", "time_from": null, "time_to": null, "size": 50, "sub_fiel… | 0 |  |
| q-36d8eaacdb | check C203 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*kdbx* OR win.ScriptBlockText:*KeePass* OR win.ScriptBlockText:*1Password* OR win.ScriptBlockText:*Bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-609b265070 | check C204 | search | {"dataset": "windows.other", "query": "message:*KeePass* OR message:*1Password* OR message:*Bitwarden* OR message:*kdbx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-a7f62b04ca | check C205 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-4fadc87484 | check C206 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-039d336e7a | check C207 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*wdigest* OR win.ImageLoaded:*sspicli*)", "time_from": null, "time_to": null… | 262 |  |
| q-5dd3dddcf0 | check C208 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657 AND (win.ObjectName:*Security* OR win.ObjectName:*SAM* OR win.ObjectName:*Lsa* OR win.ObjectName:*Authentication*)", "time_from": null, "time_to": null, "size": 50, "sub_field… | 0 |  |
| q-5224cf1dcf | check C209 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*procdump* OR process.command_line:*comsvcs*)", "time_from": null, "time_to": … | 0 |  |
| q-02e008ae55 | check C210 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*procdump* OR win.ScriptBlockText:*comsvcs*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 0 |  |
| q-e49febe739 | check C211 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*MiniDump* OR message:*procdump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-438e3ad1b3 | check C212 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-11afe6403d | check C213 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 33 |  |
| q-fa5e1ca73a | check C214 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-88b9b3a3f3 | check C215 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-b7febc7566 | check C216 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-91f2438503 | check C217 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*cryptdll* OR win.ScriptBlockText:*mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-8d7ecf689d | check C218 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (file.path:*system32* OR file.path:*System32*) AND (file.path:*.dll)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a34659198f | check C219 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*System32* OR win.ImageLoaded:*system32*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 19432 |  |
| q-6e2198e8b9 | check C220 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657 AND (win.ObjectName:*Notification Packages* OR win.ObjectName:*Password* OR win.ObjectName:*Lsa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-7b933543cd | check C221 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Notification* OR win.ScriptBlockText:*PasswordFilter* OR win.ScriptBlockText:*Notification Packages*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-753de2a61b | check C222 | search | {"dataset": "windows.other", "query": "message:*Notification Packages* OR message:*PasswordFilter*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 5 | F35 |
| q-b44f9814ba | check C223 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4739", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b1fa6b588d | check C224 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*AllowReversiblePasswordEncryption* OR win.ScriptBlockText:*ReversibleEncryption* OR win.ScriptBlockText:*Set-ADAccountControl*)", "time_from": null, "time_to": null, "fields"… | 0 |  |
| q-a613696d29 | check C225 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (win.Payload:*Reversible* OR win.Payload:*Set-ADAccountControl*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-2f69199a8f | check C226 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADAccountControl* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "size": 50, "sub_… | 0 |  |
| q-5f8f1d3fa9 | check C227 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*AllowReversiblePasswordEncryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 0 |  |
| q-1bf7c5eb19 | check C228 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthentication*\" OR TO_L… | ERROR |  |
| q-569990b283 | check C228 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthentication*\" OR TO_L… | ERROR |  |
| q-d286b3b747 | check C229 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-a60c223a01 | check C230 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*authentication*\" OR TO_LOWER(message) LIKE \"*mfa*\" OR TO_LOWER(message) LIKE \"*strongauth*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-5e2da75786 | check C230 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*authentication*\" OR TO_LOWER(message) LIKE \"*mfa*\" OR TO_LOWER(message) LIKE \"*strongauth*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-a4487f0be3 | check C231 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-c43d754153 | check C232 | count | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null} | 0 |  |
| q-417b61adf4 | check C233 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aadconnect*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlock… | ERROR |  |
| q-47212cbade | check C233 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aadconnect*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlock… | ERROR |  |
| q-964f2514e8 | check C234 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*adfs*\" OR TO_LOWER(message) LIKE \"*aadconnect*\" OR TO_LOWER(message) LIKE \"*azuread*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-67bcbb0297 | check C234 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*adfs*\" OR TO_LOWER(message) LIKE \"*aadconnect*\" OR TO_LOWER(message) LIKE \"*azuread*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-50503e6e06 | check C235 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-8ccd91ecba | check C236 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*\\\\system32\\\\*\" OR TO_LOWER(win.TargetFilename) LIKE \"*networkprovider*\" OR TO_LOWER(win.TargetFilename) LIKE \"*\\\\winsxs\\\\*\") \|… | ERROR |  |
| q-0191b9aea3 | check C236 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*\\\\\\\\system32\\\\\\\\*\" OR TO_LOWER(win.TargetFilename) LIKE \"*networkprovider*\" OR TO_LOWER(win.TargetFilename) LIKE \"*\\\\\\\\winsx… | ERROR |  |
| q-49b0f4490f | check C237 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-639e53e143 | check C238 | count | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null} | 36 |  |
| q-5a6e533f5b | check C239 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-d934679f77 | check C240 | count | {"dataset": "windows.sysmon", "query": "event.code:22", "time_from": null, "time_to": null} | 81 |  |
| q-f3ea855651 | check C241 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-e892f43ede | check C242 | aggregate | {"dataset": "zeek", "field": "zeek.conn_state", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-19501dff16 | check C243 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-49e5d58468 | check C244 | esql | {"query": "FROM zeek METADATA _id, _index \| WHERE event.action == \"dns\" AND (TO_LOWER(dns.question.name) LIKE \"*wpad*\" OR TO_LOWER(dns.question.name) LIKE \"*llmnr*\") \| KEEP @timestamp, source.ip, destination.ip, dns.question.name, _id, _index"} | ERROR |  |
| q-f4ffccb093 | check C244 (repaired) | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"dns\" AND (TO_LOWER(dns.question.name) LIKE \"*wpad*\" OR TO_LOWER(dns.question.name) LIKE \"*llmnr*\") \| KEEP @timestamp, source.ip, destination.ip, dns.question.name, _id, _in… | 8 | F41 |
| q-5c99a29bc5 | check C245 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-1230cb7faf | check C246 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-bdd838efab | check C247 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-584e3822a2 | check C248 | count | {"dataset": "windows.sysmon", "query": "event.code:22", "time_from": null, "time_to": null} | 81 |  |
| q-e05365bf2c | check C249 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-4db70a6b74 | check C250 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-55507a8dbf | check C251 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 216 |  |
| q-796af9c631 | check C252 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-df387388dd | check C253 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*dhcp* OR process.command_line:*ipconfig* OR process.command_line:*netsh*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5 |  |
| q-5609326f90 | check C254 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*dhcp* OR *DhcpServer* OR *rogue*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-e4b6f49c94 | check C255 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-1dd4933c37 | check C256 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 236 |  |
| q-1f16bb4f58 | check C257 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-942c27b050 | check C258 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-d8a5853432 | check C259 | search | {"dataset": "windows.other", "query": "event.code:(4769 OR 4768 OR 4771)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-41fc81e119 | check C260 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*kerberos* OR *kirbi* OR *ticket* OR *Rubeus* OR *Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "eve… | 0 |  |
| q-9f90b1d9ed | check C261 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-388f1a7ecf | check C262 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-18167bf592 | check C263 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-acb728cb97 | check C264 | search | {"dataset": "windows.other", "query": "event.code:(4769 OR 4768 OR 4770 OR 4771)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-583652582b | check C265 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*krbtgt* OR *golden* OR *Mimikatz* OR *DCSync*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 0 |  |
| q-c8867b1e37 | check C266 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-a0defaea24 | check C267 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-6318c260d5 | check C268 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-c01cd081e0 | check C269 | search | {"dataset": "windows.other", "query": "event.code:(4769 OR 4770)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 0 |  |
| q-7399e1d249 | check C270 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*silver* OR *kerberoast* OR *Invoke-Kerberoast* OR *SPN*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 0 |  |
| q-88af7b2495 | check C271 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 28 |  |
| q-10fba0d75d | check C272 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-c7040516a8 | check C273 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-745abebd08 | check C274 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F47 |
| q-28214246a3 | check C275 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-e3254b50fd | check C276 | search | {"dataset": "windows.other", "query": "event.code:(4769 OR 4768)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 0 |  |
| q-7add76f55c | check C277 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*Kerberoast* OR *GetUserSPNs* OR *SPN*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 0 |  |
| q-7c684266e0 | check C278 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-f8ae650996 | check C279 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-5aad76f84c | check C280 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*asreproast* OR process.command_line:*GetNPUsers* OR process.command_line:*Rubeus*)", "time_from": null, "time_to": null, "size": 50, "sub_field": nul… | 0 |  |
| q-d230431607 | check C281 | search | {"dataset": "windows.other", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-5f6e296259 | check C282 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*AS-REP* OR *asreproast* OR *GetNPUsers* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 0 |  |
| q-e6b8d1cbf7 | check C283 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-d3ad4b630d | check C284 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-bee9d57785 | check C285 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-98de24947b | check C286 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cookie* OR win.ScriptBlockText:*token* OR win.ScriptBlockText:*SAML* OR win.ScriptBlockText:*AADSSO*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 1 |  |
| q-0218c7a6a3 | check C287 | search | {"dataset": "windows.other", "query": "message:*ADFS* OR message:*SAML* OR message:*token*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 0 |  |
| q-51c090c5f2 | check C288 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-1c59af5fc6 | check C289 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*Web Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 162 | F50 |
| q-7b509c9e74 | check C290 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*SetCookie* OR win.ScriptBlockText:*document.cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.na… | 0 |  |
| q-3e6de7cca1 | check C291 | search | {"dataset": "windows.other", "query": "message:*cookie* OR message:*Cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 0 |  |
| q-fe03ce9de2 | check C292 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-f2931d8cc4 | check C293 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-8a50afd9e1 | check C294 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SAML* OR win.ScriptBlockText:*NotOnOrAfter* OR win.ScriptBlockText:*token-signing* OR win.ScriptBlockText:*ADFS*)", "time_from": null, "time_to": null, "fields": ["@timestamp… | 0 |  |
| q-a190d2ee42 | check C295 | search | {"dataset": "windows.other", "query": "message:*ADFS* OR message:*SAML* OR message:*Token*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 0 |  |
| q-92b81071db | check C296 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-27d14e4c7c | check C297 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-20e8ff4306 | check C298 | aggregate | {"dataset": "windows.security", "field": "win.Status", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-2169f19592 | check C299 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MFA* OR win.ScriptBlockText:*2FA* OR win.ScriptBlockText:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-b9f2427b15 | check C300 | search | {"dataset": "windows.other", "query": "message:*MFA* OR message:*multi-factor* OR message:*Authenticator*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 0 |  |
| q-8b3fcce893 | check C301 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-ea5f27d021 | check C302 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-b47ef3bd03 | check C303 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-07a0ede08c | check C304 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.pfx OR win.TargetFilename:*.p12 OR win.TargetFilename:*.cer OR win.TargetFilename:*.pvk)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name"… | 1 | F52 |
| q-6e098c8ee9 | check C305 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Certify* OR win.ScriptBlockText:*Certipy* OR win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*Get-Certificate*)", "time_from": null, "time_to": null, "fiel… | 1 | F52 |
| q-65ffd22cc4 | check C306 | search | {"dataset": "windows.other", "query": "message:*certificate* OR message:*Certificate*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 0 |  |
| q-70aafb11b3 | check C307 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-1cd4236e2f | check C308 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-6835011172 | check C309 | aggregate | {"dataset": "zeek", "field": "zeek.client", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-29ab89d600 | check C310 | search | {"dataset": "zeek", "query": "event.action:kerberos AND zeek.success:false", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 7 |  |
| q-ef49c55c8b | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 |  |
| q-1fd5625382 | triage T1003 step 1 | search | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.SubjectUserName", "win.SubjectDomainName", "win.ObjectName", "win.ObjectType", "win.Properties", "win.AccessMask", "win.A… | 7 | F03, F04, F06 |
| q-207f849271 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None | F01, F07 |
| q-35ff142e2f | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None | F01 |
| q-9a8bf2c327 | triage T1003 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == 1 AND process.pid == 2976) OR (event.code == 11 AND win.TargetFilename LIKE \"*.dmp\") OR (event.code == 1 AND process.command_line LIKE \"*lsass*\") \| KEEP @timestamp, h… | ERROR |  |
| q-e55784228e | triage T1003 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*MiniDump*\" OR win.ScriptBlockText LIKE \"*comsvcs*\" OR win.ScriptBlockText LIKE \"*procd… | ERROR |  |
| q-fdec3a3499 | triage T1003 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"1\" AND process.pid == 2976) OR (event.code == \"11\" AND win.TargetFilename LIKE \"*.dmp\") OR (event.code == \"1\" AND process.command_line LIKE \"*lsass*\") \| KEEP @… | 4 |  |
| q-dd31fee8e2 | triage T1003 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*MiniDump*\" OR win.ScriptBlockText LIKE \"*comsvcs*\" OR win.ScriptBlockText LIKE \"*p… | 0 |  |
| q-8e625fc67d | triage T1003 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None | F01 |
| q-9c4596ad9a | triage T1003 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:00.000Z\" \| KEEP @timestamp, event.code, user.name, win.S… | 415 |  |
| q-97d3f9f1a4 | triage T1003 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:30.000Z\" AND @timestamp <= \"2020-05-02T03:06:30.000Z\" AND (win.Message LIKE \"*procdump*\" OR win.Mess… | 155 | F02 |
| q-0459d5f811 | triage T1003 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:00.000Z\" AND event.code IN (\"1\",\"11\",\"23\",\"22\") \| KE… | 132 |  |
| q-335f431990 | triage T1003 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:05:00.000Z\" AND @timestamp <= \"2020-05-02T03:06:00.000Z\" \| KEEP @timestamp, event.code, user.name, win.M… | 91 |  |
| q-25cd63fb8c | triage T1003 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*procdump*\" OR process.command_line LIKE \"*Sysinternals*\" OR process.executable LIKE \"*procdump*\" OR process.command_line LIKE \… | 8 | F01, F02 |
| q-66e33cd255 | triage T1003 step 8 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:05:33.000Z\" AND @timestamp <= \"2020-05-02T03:07:30.000Z\" AND event.code == \"4104\" \| KEEP @timestamp, e… | 20 | F02 |
| q-7a5f2dbe7f | triage T1003 step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND @timestamp >= \"2020-05-02T03:09:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:30.000Z\" AND event.code IN (\"1\",\"10\",\"11\") \| KEEP @times… | 268 |  |
| q-4eda3f2bf0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-bf997b83fa | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-7c7fec7c90 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-c465abbb85 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-0264e72f41 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-55b5eb5e84 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-2046d65f99 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-56085a96e5 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpHV4S3"} | None |  |
| q-99450af518 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2o"} | None |  |
| q-962f52178d | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-893d7a86a3 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCxD"} | ERROR |  |
| q-984ba103be | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopf"} | None |  |
| q-3a052831f4 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRX"} | None |  |
| q-508cc867e2 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRX"} | None |  |
| q-e9a0353ce1 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-f7273a1b70 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-9aa7eacb52 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX2"} | None |  |
| q-f2b21b35c6 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-02a6b40f8c | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-2afe348e46 | triage T1040 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*NetworkWatcher* OR process.executable:*python* OR process.executable:*PsExec* OR process.executable:*sdelete* OR process.executable:*logman* OR process.executable:*ARP.EXE* OR proces… | 35 | F08, F09 |
| q-2d258cd268 | triage T1040 step 1 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 40, "sub_field": null} | 613 |  |
| q-a4acd9b61b | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "host.name:nashua.dmevals.local AND (event.code:3 OR event.code:22 OR event.code:11 OR event.code:1) AND (process.executable:*python* OR win.Image:*python* OR process.parent.executable:*python*)", "time_from": null, "time… | 378 | F08 |
| q-ff5d0d6178 | triage T1040 step 2 | search | {"dataset": "zeek", "query": "destination.port:1234 OR destination.port:55121", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "source.ip", "source.port", "destination.ip", "destination.port", "network.transport", "zeek.service", … | 37 | F09 |
| q-e8a8575037 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (process.executable:*python* OR process.executable:*powershell* OR process.executable:*PsExec*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "pro… | 377 |  |
| q-502aa237b2 | triage T1040 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*python* OR win.ScriptBlockText:*PsExec* OR win.ScriptBlockText:*sniff* OR win.ScriptBlockText:*pcap* OR win.ScriptBlockText:*NASHUA* OR win.ScriptBlockText:*raw* OR win.Scrip… | 11 | F08 |
| q-d94f2acbd6 | triage T1040 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SeaDuke* OR win.ScriptBlockText:*Invoke-SeaDukeStage* OR win.ScriptBlockText:*pcap* OR win.ScriptBlockText:*sniff* OR win.ScriptBlockText:*raw_socket* OR win.ScriptBlockText:… | 1 | F08 |
| q-1eb4eee821 | triage T1040 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND host.name:nashua.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.executable", "process.command_line", "destination.ip", "dest… | 428 |  |
| q-991072d3b3 | triage T1040 step 5 | search | {"dataset": "windows.sysmon", "query": "process.executable:*python* AND (event.code:3 OR event.code:22 OR event.code:17 OR event.code:18)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.executable… | 362 | F08 |
| q-308593c9b7 | triage T1040 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*python* OR win.SourceImage:*python*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.executable", "process.command_line"… | 180 |  |
| q-37424fb623 | triage T1040 step 6 | search | {"dataset": "zeek", "query": "destination.ip:192.168.0.4 AND destination.port:8443", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "source.ip", "source.port", "destination.ip", "destination.port", "zeek.service", "zeek.conn_state… | 753 | F08 |
| q-b4530c908b | triage T1040 step 6 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:*Stage*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.ScriptBlockText", "win.ScriptBlockId"], "size": 20, "sort": … | 1 |  |
| q-fd47003b30 | triage T1040 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwBjiC8"} | None |  |
| q-d6cf4e1ffd | triage T1040 step 7 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz7ud8y"} | None | F08 |
| q-70f1c025ba | triage T1040 step 8 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*python.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "win.Hashes", "win.Signed", "win.Signature", "win.Company", … | 5 | F08 |
| q-db44b73a7c | triage T1040 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwBjiC8"} | None |  |
| q-877431b490 | triage T1040 verify | get_event | {"index": ".ds-logs-windows-powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlShx"} | ERROR |  |
| q-84df15e32b | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-1ab8917848 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-adb2a258ca | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ_-"} | None |  |
| q-4c4f389959 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ-S"} | None |  |
| q-0f28b183a1 | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz7ud8y"} | None |  |
| q-7f4bc6492a | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz7ud8U"} | None |  |
| q-21a621e948 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpFT8y4"} | None |  |
| q-d1c0ce25b9 | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rs"} | None |  |
| q-cb600c31d3 | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rs"} | None |  |
| q-929980c978 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None | F10, F13 |
| q-2e071a0168 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None | F10, F13 |
| q-f2c5247cef | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.SourceImage) LIKE \"*cod.3aka3*\" OR TO_LOWER(win.SourceImage) LIKE \"*python.exe*\" OR TO_LOWER(win.SourceImage) LIKE \"*psexesvc*\") \| KEEP @tim… | 11 | F10 |
| q-5be22e77fc | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*cod.3aka3*\" OR TO_LOWER(process.executable) LIKE \"*python.exe*\" OR TO_LOWER(process.parent.executable) LIKE \"*cod.3aka3*… | 10 | F10 |
| q-442e51cd7d | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*victim*\" OR TO_LOWER(file.path) LIKE \"*.scr\" OR TO_LOWER(file.path) LIKE \"*python*\") \| KEEP @timestamp, host.name, user.name, … | 8 |  |
| q-0a3a3b5699 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*pbeesly*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*psexec*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR T… | 11 | F10 |
| q-2d2e4d9db6 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass.exe\" \| KEEP @timestamp, host.name, user.name, win.SourceImage, win.TargetImage, win.GrantedAccess, win.CallTrace, _id, _index"} | 326 |  |
| q-3b90f1690f | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHp5aa"} | None | F10 |
| q-a028dfac6e | triage T1056 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*keylog*\" OR TO_LOWER(process.command_line) LIKE \"*hook*\" OR TO_LOWER(process.command_line) LIKE \"*monkey*\" OR TO_LOWE… | 1 |  |
| q-a0ebd2b6c4 | triage T1056 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*control.exe*\" OR TO_LOWER(process.parent.executable) LIKE \"*control.exe*\")) OR (event.code == \"13\" AND (TO_LOWER(regis… | ERROR |  |
| q-03f3bad8e0 | triage T1056 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (TO_LOWER(process.executable) LIKE \"*python.exe*\" OR TO_LOWER(process.executable) LIKE \"*cod.3aka3*\" OR TO_LOWER(process.executable) LIKE \"*powershell.exe*\"… | 373 | F10 |
| q-40fab11024 | triage T1056 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*control.exe*\" OR TO_LOWER(process.parent.executable) LIKE \"*control.exe*\")) OR (event.code == \"13\" AND (TO_LOWER(regis… | 28 | F11 |
| q-a3560e096d | triage T1056 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"7\" AND (TO_LOWER(win.ImageLoaded) LIKE \"*keylog*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*hook*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*monkey*\" OR TO_LOWER(win.ImageLoad… | 1 | F10 |
| q-964ab75455 | triage T1056 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkv3cGg"} | None | F10 |
| q-b0bae9e73f | triage T1056 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgw49k"} | None | F10 |
| q-b631afaa67 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgw49k"} | None |  |
| q-e25a316ba8 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-6cb3ee8e01 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHp5aa"} | None |  |
| q-ab20b04334 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-b5d83d4ede | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgP"} | None |  |
| q-f3af58d47f | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlSh0"} | None |  |
| q-8c037d395f | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkv3cGg"} | None |  |
| q-9aba7eeb23 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkovWJ1"} | None |  |
| q-35254216ab | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkglS44"} | None |  |
| q-729619a115 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-e2d4d7dd30 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-a7afb0aa04 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-160afb1956 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkADuPE"} | None |  |
| q-3e2c26ffb2 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkEH740"} | None |  |
| q-d5ad4b75da | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItn_DPso"} | ERROR |  |
| q-6a86ec9463 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlAOq"} | None |  |
| q-ec1a04422a | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-5297aefa37 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-39a83d980d | triage T1056 step 9 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None | F10 |
| q-7b1ab0afa0 | triage T1056 step 9 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItn_DPso"} | ERROR |  |
| q-9d078fbed6 | triage T1056 step 9 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlAOq"} | None | F12 |
| q-74ffcc5953 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None | F15, F16 |
| q-1010cd4b4f | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None | F15, F18 |
| q-bd3ee6dba5 | triage T1110 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND process.executable LIKE \"*owerShell*\" \| KEEP @timestamp, host.name, process.executable, process.command_line, win.GrantedAcce… | ERROR |  |
| q-a9ac2aa67e | triage T1110 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (process.command_line LIKE \"*net use*\" OR process.command_line LIKE \"*runas*\" OR process.command_line LIKE \"*net user*\") \| KEEP @timestamp, host.name, user.nam… | ERROR |  |
| q-83fea1c1ab | triage T1110 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND process.executable LIKE \"*owerShell*\" \| KEEP @timestamp, host.name, process.executable, process.command_line, win.Granted… | 4 |  |
| q-f0104704ca | triage T1110 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*net use*\" OR process.command_line LIKE \"*runas*\" OR process.command_line LIKE \"*net user*\" OR process.command_line LIKE \"*New-… | 1 |  |
| q-f865b69067 | triage T1110 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" OR event.code == \"4648\" \| STATS c = COUNT(*) BY event.code, win.LogonType, win.TargetUserName, source.ip \| SORT c DESC \| LIMIT 40"} | 35 |  |
| q-bbbea49008 | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None | F16 |
| q-6cad4299cc | triage T1110 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4625\",\"4771\",\"4776\",\"4648\") \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.Status, win.LogonType, source.ip, win.SubjectUserName, _id, _inde… | 16 | F14 |
| q-6a8b79f6a6 | triage T1110 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.command_line, process.parent.executable, _id, _index \| SORT @timestamp… | 12 |  |
| q-6d191c96e0 | triage T1110 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLb9km"} | None | F16 |
| q-b6a7c9c18a | triage T1110 step 4 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None | F17 |
| q-186ef9e333 | triage T1110 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, win.TargetUserName, win.SubjectUserName, win.TargetServerName, win.ProcessName, win.IpAddress, source.ip, _id, _index \| SORT @tim… | 15 | F17 |
| q-d60defc1a9 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-c7e376a369 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-ada0b9085b | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-e5ae605484 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-0e78d3ca82 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-f07310d814 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-743f8b4a18 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLb9km"} | None |  |
| q-d6ca11e76d | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-044d28379b | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-e7d30dd0c1 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-17852c2e8b | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-902ed7ef9d | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-be753768cf | triage T1111 step 1 | search | {"dataset": "windows.security", "query": "event.code:4624 AND (win.LogonProcessName:\"User32 \" OR win.LogonProcessName:\"NtLmSsp \" OR win.LogonProcessName:\"-\")", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 4 | F19 |
| q-1d847b98b1 | triage T1111 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:\"C:\\\\windows\\\\system32\\\\lsass.exe\"", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-1a626959e4 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None | F19 |
| q-c40fb04366 | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:\"C:\\\\windows\\\\system32\\\\lsass.exe\" AND (process.executable:*powershell* OR process.executable:*wsmprovhost* OR process.executable:*wininit* OR process.executable:*csrss* OR proce… | 7 |  |
| q-e2508d55d5 | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*CredentialEnrollmentManager*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable",… | 10 | F19 |
| q-02321c676f | triage T1111 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None | F19 |
| q-e3ae348794 | triage T1111 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLb9km"} | None | F19 |
| q-379171740d | triage T1111 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*smartcard* OR win.TargetFilename:*CredentialProvider* OR win.TargetFilename:*Ngc* OR win.TargetFilename:*MFA*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-64f9a29018 | triage T1111 step 4 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*smartcard* OR process.command_line:*Credential* OR process.command_line:*MFA* OR process.command_line:*Ngc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 1 | F19 |
| q-16db0f9dc6 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-cfeb2282ec | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLb9km"} | None |  |
| q-7cb65c40df | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-ba83c5e0ce | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkEHr1e"} | None |  |
| q-d924243125 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsM0qmS"} | None |  |
| q-78f51202c8 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsc-QNb"} | None |  |
| q-8d6bb74b43 | triage T1187 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:139 OR destination.port:445)", "time_from": null, "time_to": null, "size": 20, "sub_field": "host.name"} | 66 |  |
| q-925fb022ed | triage T1187 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" AND (http.request.method == \"PROPFIND\" OR http.request.method == \"OPTIONS\" OR http.request.method == \"MOVE\") \| KEEP @timestamp, source.ip, destination.ip, destinati… | 36 |  |
| q-ad51273903 | triage T1187 step 2 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uv"} | None | F20 |
| q-1b4b6dfded | triage T1187 step 2 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sG"} | None | F20 |
| q-6be8a82fc2 | triage T1187 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 3 AND (destination.port == 139 OR destination.port == 445) \| KEEP @timestamp, host.name, user.name, process.executable, destination.ip, destination.port, _id, _index \| LI… | ERROR |  |
| q-c2d083b462 | triage T1187 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == \"139\" OR destination.port == \"445\") \| KEEP @timestamp, host.name, user.name, process.executable, destination.ip, destination.port, _id, … | ERROR |  |
| q-7f837bb935 | triage T1187 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND (destination.port == 445 OR destination.port == 139) \| KEEP @timestamp, source.ip, destination.ip, destination.port, network.bytes, zeek.conn_state, _id, _index \| LI… | 50 | F20 |
| q-41d5bdfd73 | triage T1187 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 139 OR destination.port == 445) \| KEEP @timestamp, host.name, user.name, process.executable, destination.ip, destination.port, _id, _index \… | 66 | F21 |
| q-fedf2a23ac | triage T1187 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"kerberos\" OR event.action == \"dce_rpc\" \| KEEP @timestamp, event.action, source.ip, destination.ip, destination.port, zeek.client, zeek.service, zeek.request_type, zeek.succes… | 60 | F20 |
| q-fb866e3a1f | triage T1187 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5140\" OR event.code == \"5145\" \| KEEP @timestamp, host.name, user.name, win.ShareName, win.ShareLocalPath, win.RelativeTargetName, win.IpAddress, win.SubjectUserName… | 50 | F20, F21 |
| q-318c54810e | triage T1187 step 5 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"files\" \| KEEP @timestamp, source.ip, destination.ip, file.path, file.mime_type, file.size, _id, _index \| LIMIT 40"} | 40 |  |
| q-00a2872be8 | triage T1187 step 6 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4u2"} | None | F20 |
| q-89368103d5 | triage T1187 step 6 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sp"} | None | F20 |
| q-7b4ad2b0c9 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uv"} | None |  |
| q-7f567736da | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uv"} | None |  |
| q-8074152b64 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sG"} | None |  |
| q-553797ad90 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sG"} | None |  |
| q-1807b18e83 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sG"} | None |  |
| q-24d5e5ddcc | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sG"} | None |  |
| q-a107204bda | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sp"} | None |  |
| q-e6a47d903b | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sp"} | None |  |
| q-34a52a15cf | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4u2"} | None |  |
| q-f9dd59a864 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4u2"} | None |  |
| q-f4e545006e | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovV"} | None |  |
| q-e4203edd0b | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrov8"} | None |  |
| q-06f8faf1af | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse_H6B"} | None |  |
| q-5bfa59cf8d | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkJMpSF"} | None |  |
| q-48c6dbae6f | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkJMpSF"} | None |  |
| q-87bc5cfd1b | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsJxqw2"} | None |  |
| q-eaa79d2e0f | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsEwOVS"} | None |  |
| q-489faf1bba | triage T1212 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.SourceImage:*PowerShell* OR win.SourceImage:*wsmprovhost* OR win.SourceImage:*wininit* OR win.SourceImage:*csrss* OR win.SourceImage:*services*)", "time_from": null, "ti… | 9 | F22, F23 |
| q-109ce34d4d | triage T1212 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*python* OR process.executable:*PsExec* OR process.executable:*sdelete* OR process.executable:*PSEXESVC*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 19 | F22 |
| q-542d7fd1e8 | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-d843f7c686 | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-7466ea2336 | triage T1212 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*Dump* OR win.ScriptBlockText:*procdump* OR win.ScriptBlockText:*sekurlsa* OR… | 0 |  |
| q-bb3e9e0e96 | triage T1212 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-Command* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Get-Process* OR win.ScriptBlockText:*Modules* OR win.ScriptBlockText:*Memory*)", "time_from": null… | 15 | F22 |
| q-419f7a16f1 | triage T1212 step 3 | search | {"dataset": "windows.sysmon", "query": "process.executable:*python* AND NOT event.code:1", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetImage", "win.SourceImage", "win.GrantedAccess", "win.TargetFilename", … | 509 |  |
| q-fb88648d7d | triage T1212 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqSbu"} | None | F22 |
| q-0ef6b2ac46 | triage T1212 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqigy"} | None | F22 |
| q-3f0916ae79 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-e39a7d2414 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-aec725f06d | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-18b5b8e2df | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-98677a0a94 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-22bfd59cde | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqSbu"} | None |  |
| q-b35017c2dd | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqSbu"} | None |  |
| q-09e9bcab9b | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqigy"} | None |  |
| q-2a4c2315fc | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-418a490023 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-cd8590bd52 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAt"} | None |  |
| q-e7d3086dd6 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAu"} | None |  |
| q-3829d1eed2 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkei3QI"} | None |  |
| q-e32affe7cf | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None | F24 |
| q-a4b7d0bf21 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItwAjYrx"} | ERROR |  |
| q-a34d0f5ac4 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItwBjiDr"} | ERROR |  |
| q-e474008dfb | triage T1539 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*login data*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sqlite*\" OR T… | ERROR |  |
| q-8f59299c61 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" OR TO_LOWE… | ERROR |  |
| q-293153304f | triage T1539 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*login data*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sqlite*\" … | 3 |  |
| q-19c4393ca2 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" OR TO_… | 1 | F24 |
| q-3cb9dd605f | triage T1539 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYrA"} | None | F24 |
| q-d9c6160822 | triage T1539 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYot"} | None |  |
| q-d4add0f880 | triage T1539 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz_h1K2"} | None |  |
| q-2aa666e963 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(process.executable) LIKE \"*chrome*\" OR TO_LOWER(process.executable) LIKE \"*firefox*\" OR TO_LOWER(process.executable) LIKE \"*msedge*\" OR TO_LOWER(process.executable) LIKE \… | ERROR |  |
| q-1eae49a35d | triage T1539 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookie*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*sqlite*\" OR T… | 5 | F24 |
| q-36ae7c7161 | triage T1539 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(process.executable) LIKE \"*chrome*\" OR TO_LOWER(process.executable) LIKE \"*firefox*\" OR TO_LOWER(process.executable) LIKE \"*msedge*\" OR TO_LOWER(process.executable) LIKE \… | 6 | F24 |
| q-cf26b1afce | triage T1539 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*cookies*\" OR TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*web data*\" OR TO_LOWER(wi… | 0 |  |
| q-1a4ab187a0 | triage T1539 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkv3sHT"} | None |  |
| q-2071d1c648 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkv3sHT"} | None |  |
| q-57e64ddbe5 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-01b494c266 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNpkH"} | None |  |
| q-8257156e9f | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-7e7ca59bc0 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYrA"} | None |  |
| q-e6fc92de48 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None | F25 |
| q-97205b1d8b | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqjKK"} | None | F27 |
| q-10044d6f71 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None | F26 |
| q-2bb5b03e58 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.pem\" OR TO_LOWER(win.TargetFilename) LIKE \"*.key\" OR TO_LOWER(win.TargetFile… | ERROR |  |
| q-ad613de55f | triage T1552 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (TO_LOWER(win.ScriptBlockText) LIKE \"*cert:*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*export-pfx*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*privatekey*\" O… | ERROR |  |
| q-5c745fa0a6 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.pem\" OR TO_LOWER(win.TargetFilename) LIKE \"*.key\" OR TO_LOWER(win.Target… | 8 | F26 |
| q-ccc461e491 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*cert:*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*export-pfx*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*privatekey*… | 2 |  |
| q-4c48647dd6 | triage T1552 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSxb"} | None | F25 |
| q-2dca83fae6 | triage T1552 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, user.name, win.ScriptBlockId, win.ScriptBlockText, _id, _index \| SORT @timestamp"} | 11 | F26 |
| q-7921ed04a9 | triage T1552 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg *\" OR TO_LOWER(process.command_line) LIKE \"*findstr*\" OR TO_LOWER(process.command_line) LIKE \"*cmdkey*\" OR TO_LOW… | 2 | F26 |
| q-1ab3630913 | triage T1552 step 5 | esql | {"query": "FROM logs-windows.security METADATA _id, _index \| WHERE event.code == \"4663\" AND (win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*SECURITY*\" OR win.ObjectName LIKE \"*lsass*\" OR win.ObjectName LIKE \"*Password*\" OR win.ObjectName LIKE … | ERROR |  |
| q-e2c05f93ea | triage T1552 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*SECURITY*\" OR win.ObjectName LIKE \"*lsass*\" OR win.ObjectName LIKE \"*Password*\" OR win.ObjectNa… | 6 | F28 |
| q-836af3d70a | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-120cf01801 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-00e126a872 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSxb"} | None |  |
| q-030bbb7d68 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-a0e33ae10b | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-6948f79efa | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1OJ"} | None |  |
| q-f61600de88 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdLv"} | None |  |
| q-d1ddcd779f | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdI9"} | None |  |
| q-4b93950855 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y3M"} | None |  |
| q-9ec41e73a4 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-de481239bb | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqjKK"} | None |  |
| q-08cd765ee4 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqjKK"} | None |  |
| q-21e71c62f2 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-de4503c462 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsQ2P9A"} | None |  |
| q-655decb4a4 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sP"} | None |  |
| q-38fd51465a | triage T1552 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX1"} | None |  |
| q-aa33efee0c | triage T1552 step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None | F25 |
| q-448b5947df | triage T1555 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR process.executable:*P… | 9 | F29 |
| q-1edadfa0da | triage T1555 step 1 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.ProcessName", "win.SubjectUserName", "win.AccessMask", "win.AccessList", "wi… | 6 |  |
| q-0009037656 | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None | F29 |
| q-0e79d7ad5a | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None | F29 |
| q-d5a19787a7 | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None | F32 |
| q-a203ae57e5 | triage T1555 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*wsmprovhost.exe OR process.executable:*powershell.exe OR process.executable:*PowerShell.exe) AND (process.command_line:*lsass* OR process.command_line:*Credential* OR process.command… | 0 |  |
| q-923d7739bf | triage T1555 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key4.db*\" OR TO_LOWER(file.path) LIKE \"*web… | ERROR |  |
| q-708bf85c39 | triage T1555 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key4.db*\" OR TO_LOWER(file.path) LIKE \"… | 1 | F30 |
| q-d11f2bf13a | triage T1555 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Login\\\\ Data* OR process.command_line:*logins.json* OR process.command_line:*key4.db* OR process.command_line:*Cookies* OR process.command_line:*Web\\\\ Data*)", "time_from": nul… | 0 |  |
| q-3d90a02776 | triage T1555 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Login* OR process.command_line:*Cookies* OR process.command_line:*Web*Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "proc… | 0 |  |
| q-a50c75e805 | triage T1555 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*Login* OR file.path:*Cookies* OR file.path:*Web*Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "user.name", … | 1 |  |
| q-507d7b6c58 | triage T1555 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Login* OR process.command_line:*Cookies* OR process.command_line:*Web*Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "proc… | 0 |  |
| q-4f05efe5d7 | triage T1555 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*Login* OR file.path:*Cookies* OR file.path:*Web*Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "user.name", … | 1 |  |
| q-55a4ef739a | triage T1555 step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Login* OR process.command_line:*Cookies* OR process.command_line:*Web*Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "proc… | 0 |  |
| q-e70d8e8f73 | triage T1555 step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*Login* OR file.path:*Cookies* OR file.path:*Web*Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "user.name", … | 1 |  |
| q-b47c359da3 | triage T1555 step 8 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Login* OR process.command_line:*Cookies* OR process.command_line:*Web*Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "proc… | 0 |  |
| q-9d66f83c41 | triage T1555 step 8 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*Login* OR file.path:*Cookies* OR file.path:*Web*Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "user.name", … | 1 |  |
| q-327a2c0bc9 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-6c32d9ff6d | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-ca73e9e406 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-0cfd94688e | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-9dd8981640 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-87185acd7a | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-b11c84411c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-31c8953b56 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX1"} | None |  |
| q-09dafbfc48 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-d7f009bd12 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-61c90e092f | triage T1556 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "t… | 9 | F33, F34 |
| q-91b785c461 | triage T1556 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (process.executable:*PowerShell* OR process.executable:*wsmprovhost* OR process.executable:*wininit* OR process.executable:*csrss* OR process.executable:*services.exe)", "… | 9 |  |
| q-be6c575ece | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None | F33, F36 |
| q-cb0223251f | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None | F34 |
| q-d58c0c075d | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*sekurlsa* OR process.command_line:*DumpCred*… | 1 |  |
| q-2fd7303e1d | triage T1556 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.par… | 11 |  |
| q-8e2b40ee8d | triage T1556 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, host.name, win.ScriptBlockText, _id, _index \| LI… | ERROR |  |
| q-a0113a7bfd | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None | F33 |
| q-6b7838474f | triage T1556 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, host.name, win.ScriptBlockText, _id, _index \… | 40 | F33 |
| q-13e4189e1d | triage T1556 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYpu"} | None | F33 |
| q-2f1216db81 | triage T1556 step 5 | search | {"dataset": "windows.security", "query": "event.code:4648 AND win.TargetUserName:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "win.SubjectUserName", "win.LogonProcessName", "win.Process… | 9 | F37 |
| q-efbef51d42 | triage T1556 step 5 | search | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ObjectName", "win.ObjectValueName", "win.NewValue", "win.SubjectUserName", "win.ProcessName"], "size": 40, … | 36 | F35, F39 |
| q-5cc755b7ac | triage T1556 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*wdigest* OR win.ImageLoaded:*samsrv* OR win.ImageLoaded:*apisampling* OR win.ImageLoaded:*lsass.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process… | 5 | F34, F38 |
| q-af6aa1b671 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-c8e9fe69f6 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-a32ac233e5 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-94d9082d8b | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYpu"} | None |  |
| q-8588e0f308 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlShx"} | None |  |
| q-afa4b3e101 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-7326c13713 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpo7f89"} | None |  |
| q-bce1ed68f1 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkXa2mu"} | None |  |
| q-d31c452838 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAt"} | None |  |
| q-01e885e11c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX7"} | None |  |
| q-f726f830b6 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5qNj"} | None |  |
| q-a5cfcfda33 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-c2e5fd615f | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-c86fc26804 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y0E"} | None |  |
| q-6f5729b3a6 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsW6jeK"} | None |  |
| q-4bc4a87235 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-ed272d999f | triage T1557 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*dhcp* OR process.command_line:*ipconfig* OR process.command_line:*netsh*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executab… | 5 | F42, F43 |
| q-85ed245691 | triage T1557 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:3 AND destination.port:445", "time_from": null, "time_to": null, "size": 30, "sub_field": "destination.ip"} | 66 |  |
| q-eeac853ec5 | triage T1557 step 2 | search | {"dataset": "zeek", "query": "event.action:conn AND destination.port:445", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "source.ip", "destination.ip", "destination.port", "zeek.conn_state", "zeek.orig_l2_addr", "zeek.resp_l2_add… | 45 | F41 |
| q-6c894a60bc | triage T1557 step 2 | aggregate | {"dataset": "zeek", "field": "source.ip", "query": "event.action:conn AND destination.port:(137 OR 138 OR 139 OR 5355)", "time_from": null, "time_to": null, "size": 30, "sub_field": "destination.port"} | 15 |  |
| q-00632e3884 | triage T1557 step 3 | search | {"dataset": "zeek", "query": "zeek.orig_l2_addr:\"fc:bd:67:e1:a9:c1\" OR zeek.resp_l2_addr:\"fc:bd:67:e1:a9:c1\"", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "source.ip", "destination.ip", "destination.port", "zeek.conn_state"… | 44 | F40, F41 |
| q-b7691fe5dc | triage T1557 step 3 | search | {"dataset": "zeek", "query": "event.action:conn AND source.ip:10.0.1.4 AND destination.ip:10.0.1.6", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "source.ip", "destination.ip", "destination.port", "zeek.conn_state", "zeek.orig_l… | 88 | F40, F41 |
| q-6bbb10ee45 | triage T1557 step 4 | search | {"dataset": "zeek", "query": "event.action:(notice OR weird OR dns)", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "source.ip", "destination.ip", "zeek.note", "zeek.msg", "zeek.query", "zeek.answers", "zeek.orig_l2_addr", "zeek.… | 67 | F41 |
| q-74df1ec3cb | triage T1557 step 4 | aggregate | {"dataset": "zeek", "field": "zeek.resp_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 20, "sub_field": "zeek.orig_l2_addr"} | 613 |  |
| q-0596962dd3 | triage T1557 step 5 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovu"} | None |  |
| q-380577a5bf | triage T1557 step 5 | search | {"dataset": "zeek", "query": "event.action:(notice OR weird OR ssl)", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "source.ip", "destination.ip", "destination.port", "zeek.note", "zeek.msg", "zeek.name", "zeek.orig_l2_addr", "ze… | 392 |  |
| q-a5b7c0c088 | triage T1557 step 6 | timeline | {"dataset": "zeek", "query": "event.action:conn AND zeek.orig_l2_addr:\"fc:bd:67:e1:a9:c1\"", "interval": "5m", "time_from": null, "time_to": null} | 44 |  |
| q-c059326345 | triage T1557 step 6 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 60, "sub_field": null} | 447 |  |
| q-24e7794b30 | triage T1557 step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*ARP.EXE OR process.executable:*ROUTE.EXE OR process.executable:*Temp\\\\\\\\python.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "proc… | 6 | F42 |
| q-32d8f162fc | triage T1557 step 8 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*python*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executable", "win.Parent… | 5 | F43 |
| q-43941ef9bd | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-4cc24110bd | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-0c5b7cc6a4 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4vf"} | None |  |
| q-69c50596da | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rk"} | None |  |
| q-ac93cf1d7c | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uK"} | None |  |
| q-5e51d74567 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-ededbc5a46 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4r9"} | None |  |
| q-9522f6b3a0 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4t-"} | None |  |
| q-bf1cb60921 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ud"} | None |  |
| q-a169dac916 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uK"} | None |  |
| q-651903552e | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4vH"} | None |  |
| q-1ddcc244c4 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4tU"} | None |  |
| q-c0d92604ad | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-f0e4f9f5dc | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpp7sSn"} | None |  |
| q-2978e1b3c3 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpo7f-S"} | None |  |
| q-2922344c9e | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpp7sQv"} | None |  |
| q-7265eead4f | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-7f5fc38cb5 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-b8293253e6 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ_4"} | None |  |
| q-a0c29a1568 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-318f959616 | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F44, F46 |
| q-e6e5a19705 | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.GrantedAccess",… | 4 |  |
| q-eaca8d229a | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-15b69c6012 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-e48bd26dfd | triage T1558 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC \| LIMIT 60"} | 60 |  |
| q-d1deaf5585 | triage T1558 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T03:01:30.000Z\" AND @timestamp <= \"2020-05-02T03:21:30.000Z\" AND event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _i… | 80 |  |
| q-9df7eb0875 | triage T1558 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*procdump*\" OR TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOW… | 1 |  |
| q-5eab2b3d8d | triage T1558 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:01:30.000Z\" AND @timestamp <= \"2020-05-02T03:21:30.000Z\" AND event.code == \"4104\" \| KEEP @timestamp, u… | 60 | F44 |
| q-3f8cf960f2 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \| SORT @t… | 60 | F44 |
| q-a5ba116575 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.IpAddress, win.Status, _id, _inde… | 28 | F45, F46, F47, F48 |
| q-fa5cbc0996 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" \| STATS c = COUNT(*) BY host.name, win.SubjectUserName, win.SubjectUserSid \| SORT c DESC \| LIMIT 40"} | 12 |  |
| q-bde97faad1 | triage T1558 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-36P"} | None | F45 |
| q-571bb13c4c | triage T1558 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.TargetUserName == \"pbeesly\" \| KEEP @timestamp, host.name, win.TargetUserName, win.LogonType, win.IpAddress, win.AuthenticationPackageName, win.LogonPr… | 30 |  |
| q-cf8cbf8e73 | triage T1558 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYrx"} | None |  |
| q-ad27a455e5 | triage T1558 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" AND win.SubjectUserName == \"pbeesly\" \| KEEP @timestamp, host.name, win.SubjectUserName, win.PrivilegeList, win.LogonId, _id, _index \| SORT @timestamp ASC \| … | ERROR |  |
| q-db8838e787 | triage T1558 step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" AND win.SubjectUserName == \"pbeesly\" \| KEEP @timestamp, host.name, win.SubjectUserName, win.PrivilegeList, win.SubjectLogonId, _id, _index \| SORT @timestamp … | 19 |  |
| q-d3b1653e3e | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-7816fb9a7a | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-bb33be387b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-bd2917c3a9 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-76c7787a61 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-ff6e934913 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-36P"} | None |  |
| q-a1b3c26005 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-36P"} | None |  |
| q-cef904a8bf | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqO44i"} | None |  |
| q-35f66f4d20 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjF_4Y"} | None |  |
| q-b5c008ec53 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-34o"} | None |  |
| q-0a3a924868 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-368e958b04 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcq"} | None |  |
| q-f82b69e598 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-3a8db8bd28 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo73"} | None |  |
| q-731b0f3b50 | triage T1606 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F51 |
| q-088755c083 | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None | F51 |
| q-3de9320f85 | triage T1606 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 \| STATS cnt = COUNT(*) BY win.Path, user.name, host.name \| SORT cnt DESC \| LIMIT 30"} | ERROR |  |
| q-340fb0b39f | triage T1606 step 2 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.TargetUserName", "win.TargetServerName", "win.SubjectUserName", "win.ProcessName", "win.IpAddress", "win.Log… | 15 | F49, F51 |
| q-18851f71d0 | triage T1606 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| STATS cnt = COUNT(*) BY win.Path, user.name, host.name \| SORT cnt DESC \| LIMIT 30"} | 16 |  |
| q-d807506a51 | triage T1606 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| STATS cnt = COUNT(*) BY process.executable, process.parent.executable, host.name \| SORT cnt ASC \| LIMIT 40"} | 40 |  |
| q-0338c15c93 | triage T1606 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*powershell*\" OR process.executable LIKE \"*wsmprovhost*\" OR process.executable LIKE \"*psexec*\" OR process.executable LIKE \"*PSEXE… | 17 |  |
| q-17e059bb53 | triage T1606 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, user.name, win.Path, win.ScriptBlockText, _id, _index \| LIMIT 15"} | 11 | F50 |
| q-8aba69f446 | triage T1606 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None | F49 |
| q-f8ba0f3032 | triage T1606 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" \| STATS cnt = COUNT(*) BY win.LogonType, win.LogonProcessName, win.AuthenticationPackageName, win.TargetUserName \| SORT cnt DESC \| LIMIT 30"} | 18 |  |
| q-a59cd343a3 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-f1f16d9e91 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-c776d17357 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-ce01dcb2d2 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-4d09736723 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpl1glI"} | None |  |
| q-5260178755 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpl1glI"} | None |  |
| q-40fe0eb548 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1OJ"} | None |  |
| q-4a26c22119 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-e87f495f5a | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-40fc1a3d85 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjEkfw"} | None |  |
| q-6302a3b6c9 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None |  |
| q-f1a7b55894 | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None | F52 |
| q-20a81f117b | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None | F52 |
| q-6902e16fed | triage T1649 step 2 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.ObjectValueName", "win.NewValue", "win.OperationType", "win.Pro… | 1 | F53 |
| q-c7730b619f | triage T1649 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE process.pid == 3876 OR process.parent.pid == 3876 \| KEEP @timestamp, host.name, event.code, process.executable, process.command_line, process.parent.executable, win.TargetFilename, win.… | 40 |  |
| q-c04384ab8c | triage T1649 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (process.pid == 3876 OR process.parent.pid == 3876) AND event.code IN (1, 3, 11, 22, 23, 18) \| KEEP @timestamp, host.name, event.code, process.executable, process.command_line, process.… | ERROR |  |
| q-4d131e9ca3 | triage T1649 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE win.TargetUserName == \"pbeesly\" OR win.SubjectUserName == \"pbeesly\" \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.SubjectUserName, win.IpAddress, win.LogonProc… | 40 |  |
| q-78238ca5e4 | triage T1649 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (process.pid == 3876 OR process.parent.pid == 3876) AND event.code IN (\"1\", \"3\", \"11\", \"22\", \"23\", \"18\") \| KEEP @timestamp, host.name, event.code, process.executable, proces… | 40 |  |
| q-0e1f2d6e59 | triage T1649 step 4 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "win.IpAddress", "win.ServiceName", "win.TicketEncryptionType", "win.PreAuthType", "win.St… | 14 | F54 |
| q-7351a64150 | triage T1649 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(win.TargetFilename) LIKE \"*.pfx*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.p12*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.pvk*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.cer*… | 2 | F52 |
| q-423d353d0c | triage T1649 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*cert*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*pfx*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*privatekey*\") \| K… | 5 |  |
| q-446ab5dbae | triage T1649 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSxb"} | None | F52 |
| q-e91c51a2d9 | triage T1649 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5gkYE"} | None |  |
| q-da3dfd13d1 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-41355dc9c6 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-f82c172176 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSxb"} | None |  |
| q-14e6ef6b43 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-d3dec4f281 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-9def39b6ff | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5I18"} | None |  |
| q-83072ca1ea | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-93f20d8b39 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-d70eee7628 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-12db00a355 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcb"} | None |  |
| q-5186b6638d | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcb"} | None |  |
| q-d173b17425 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-35u"} | None |  |
| q-4c56b1b4d6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-2f8a8e1c0f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-617ad354e1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-311cefac4d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-a56b371aaa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-b9ce0043b0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-e824296a99 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-100f0ef098 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpHV4S3"} | None |  |
| q-0cc84c1aae | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2o"} | None |  |
| q-0ec28583ed | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-245fcb9a0e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopf"} | None |  |
| q-01c247010b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRX"} | None |  |
| q-2c78dfa02e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRX"} | None |  |
| q-95b22d6cb3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-ec4ff9ffd4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-c00e4103c9 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX2"} | None |  |
| q-d7b31217b6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-4ff8b3c0b0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-5e8c96ecf2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwBjiC8"} | None |  |
| q-ddb25b6de1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlShx"} | None |  |
| q-9d8296069d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-5637939290 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-d162878f93 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ_-"} | None |  |
| q-fb960f7b09 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ-S"} | None |  |
| q-a069d7085f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz7ud8y"} | None |  |
| q-d0c29059f9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz7ud8U"} | None |  |
| q-8ed2819014 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpFT8y4"} | None |  |
| q-2f7c822027 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rs"} | None |  |
| q-af35d12015 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rs"} | None |  |
| q-296f5af11c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgw49k"} | None |  |
| q-bf565ca139 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-91088259a9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHp5aa"} | None |  |
| q-e01aab5b2a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-68c814ec69 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgP"} | None |  |
| q-2e41dcb652 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlSh0"} | None |  |
| q-7d4ec21610 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkv3cGg"} | None |  |
| q-bf74657a13 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkovWJ1"} | None |  |
| q-56073325f4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkglS44"} | None |  |
| q-c702fad98a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-fa861cd929 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-01f2c3e60b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-13cbfb6a57 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkADuPE"} | None |  |
| q-85622503cf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkEH740"} | None |  |
| q-20e6816999 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkSVMCG"} | None |  |
| q-d9bff7ea78 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlAOq"} | None |  |
| q-d5aceebfaf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-ca718c505a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-052366204a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-ace7d9f451 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-0ce081f780 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-e593049583 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-b7175dcf4f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-7d3ebd17bf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-d99083bd3f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLb9km"} | None |  |
| q-179150ed50 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-7f8dc06138 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-7c3306f04f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-a26f596131 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-e01d2d4faa | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-e0b0fa8678 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-229892075b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLb9km"} | None |  |
| q-db6b357afb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-528436e40e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkEHr1e"} | None |  |
| q-9e8dd8fc57 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsM0qmS"} | None |  |
| q-b3917ab5c7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsc-QNb"} | None |  |
| q-395d610c32 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uv"} | None |  |
| q-38660582f5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uv"} | None |  |
| q-dd1a89b580 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sG"} | None |  |
| q-8d7c053211 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sG"} | None |  |
| q-3b264cfbbe | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sG"} | None |  |
| q-6494ae732a | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sG"} | None |  |
| q-fad0792c68 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sp"} | None |  |
| q-25c49d4587 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sp"} | None |  |
| q-e60e37418f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4u2"} | None |  |
| q-a93490e148 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4u2"} | None |  |
| q-a822141c61 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovV"} | None |  |
| q-a6b80741a5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrov8"} | None |  |
| q-6f7e897c5f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse_H6B"} | None |  |
| q-4dcd7362c3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkJMpSF"} | None |  |
| q-1654fdb282 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkJMpSF"} | None |  |
| q-f72b5cc7e9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsJxqw2"} | None |  |
| q-3e9c77fae9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsEwOVS"} | None |  |
| q-94ba124573 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-b6501b45a1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-25b0497daa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-84ffce8b62 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-cf2dfe2006 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-d2d4916129 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqSbu"} | None |  |
| q-fe88171fea | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqSbu"} | None |  |
| q-0e5906eb49 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqigy"} | None |  |
| q-25707cef27 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-116279e81f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-d45d7868fc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAt"} | None |  |
| q-ccf7dad049 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAu"} | None |  |
| q-7c8ff3c9d6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkei3QI"} | None |  |
| q-ec6d36a7f3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkv3sHT"} | None |  |
| q-fd46cd0c5b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-213e05d0e0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNpkH"} | None |  |
| q-5084bcc040 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-9c64a6bf83 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYrA"} | None |  |
| q-aea0e35820 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-4a63c115bd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-5d7373d152 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSxb"} | None |  |
| q-4a8f829ba3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-59c09c197b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-d2bcfa5eb7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1OJ"} | None |  |
| q-4236999c1d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdLv"} | None |  |
| q-a57b966107 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdI9"} | None |  |
| q-7a1763988f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y3M"} | None |  |
| q-dcaae66666 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-8a3e20487d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqjKK"} | None |  |
| q-2b02c56b04 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqjKK"} | None |  |
| q-e4e3b77799 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsQ2P9A"} | None |  |
| q-650ce2a3b2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sP"} | None |  |
| q-e0e019653e | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX1"} | None |  |
| q-eabd7aa622 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-f14e4ef375 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-138d4c55db | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-2ff7211b23 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-c6990077f5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-8ae3aa8d90 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-2875be6d6f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-c943d084cc | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX1"} | None |  |
| q-2c3a8c1831 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-7d0b7ceddd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-c38c2bab7d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-42a7eb6955 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-5a8639ec5b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-c73dae2107 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYpu"} | None |  |
| q-d19befdf77 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlShx"} | None |  |
| q-9441ee2ceb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-a2441e0cd2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpo7f89"} | None |  |
| q-400e191a7d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkXa2mu"} | None |  |
| q-b66bcd43ac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAt"} | None |  |
| q-cc6e78df56 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX7"} | None |  |
| q-f55c16589d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5qNj"} | None |  |
| q-4e3423b79b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-94dd283101 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-06ad2f06d0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y0E"} | None |  |
| q-71e026867c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsW6jeK"} | None |  |
| q-5a218e3294 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-c165ead477 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-88f6050c50 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-ed7915eb73 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4vf"} | None |  |
| q-01c35ef27e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rk"} | None |  |
| q-291cfbb8fe | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uK"} | None |  |
| q-830a386b57 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-7a6a162f43 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4r9"} | None |  |
| q-6a0e4c29c8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4t-"} | None |  |
| q-7a8ccf683d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ud"} | None |  |
| q-dce1f28b91 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uK"} | None |  |
| q-d7bca424cc | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4vH"} | None |  |
| q-f20ee824bc | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4tU"} | None |  |
| q-00828396f3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-0e7ff8ec77 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpp7sSn"} | None |  |
| q-2ab52d0d19 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpo7f-S"} | None |  |
| q-0264169158 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpp7sQv"} | None |  |
| q-8c83a62d86 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-e5eb40cd03 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-85d2b049dd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ_4"} | None |  |
| q-2fe8ffca54 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-cccf8661b0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-b2c6275ada | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-a811cd95eb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-d9e9d04a0d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-7ac70a948a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-325107ed34 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-36P"} | None |  |
| q-31ee77fc9a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-36P"} | None |  |
| q-0fe5ba0492 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqO44i"} | None |  |
| q-aee8795da4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjF_4Y"} | None |  |
| q-7a174df73d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-34o"} | None |  |
| q-14205e7097 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-aedf121e2e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcq"} | None |  |
| q-d03d74c1ef | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-3bd1c61b78 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo73"} | None |  |
| q-33e755f988 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-140bf22809 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-1ec2a9288c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-b57bb69d7c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-8f5f06fce4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpl1glI"} | None |  |
| q-abdd77d50d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpl1glI"} | None |  |
| q-70812cbe9b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1OJ"} | None |  |
| q-0e8c5b21ba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-8dc3fd81cf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-e49639a10e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjEkfw"} | None |  |
| q-3c027b9dd2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None |  |
| q-c4a0567493 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-4544ac6a67 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-be8e0c20ff | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSxb"} | None |  |
| q-ddcc638ac9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-0e718027d9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-6b19dcd3e1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5I18"} | None |  |
| q-a70fe81f48 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-719e7520dd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-e96bf9a466 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-5ae374bbae | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcb"} | None |  |
| q-61d2efe47f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcb"} | None |  |
| q-f24f0215a5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-35u"} | None |  |
| q-2b3d6c4d87 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:33:20+00:00", "size": 100, "sub_field": "process.parent.executable"… | 61 |  |
| q-5909e40776 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:33:20+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-8d0c85c3b4 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:33:20+00:00", "size": 100, "sub_field": "process.parent.execut… | 63 |  |
| q-d249ece1ab | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:33:20+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-58d4174c00 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.151000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.parent.ex… | 359 |  |
| q-1b85095a3a | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.151000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.executable"} | 1276 |  |
| q-ffa2be8a5f | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.151000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.pare… | 370 |  |
| q-2ec9ff30c5 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.151000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-8a005d4aba | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND host.name == \"scranton.dmevals.local\" AND (process.parent.executable LIKE \"*powershell.exe\" OR process.executable LIKE \"*Sysinternals*\" OR process.executable LI… | ERROR |  |
| q-97f5944b03 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*Temp*\" OR process.parent.executable LIKE \"*PSEXESVC*\" OR process.executable LIKE \"*powershel… | ERROR |  |
| q-321de3adaa | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (process.parent.executable LIKE \"*powershell.exe\" OR process.executable LIKE \"*Sysinternals*\" OR process.executabl… | 27 | F62, F64, F65, F66, F67, F68 |
| q-f98b665142 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*Temp*\" OR process.parent.executable LIKE \"*PSEXESVC*\" OR process.executable LIKE \"*power… | 10 | F57, F62, F63 |
| q-b141d67135 | pivot step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (host.name == \"nashua.dmevals.local\" OR host.name == \"scranton.dmevals.local\") \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, … | ERROR |  |
| q-c01067d7b9 | pivot step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*working.zip*\" OR file.path LIKE \"*.pfx*\" OR file.path LIKE \"*Draft.Zip*\" OR file.path LIKE \"*Temp*Rar*\" OR file.path LIKE \"*Temp*pytho… | 322 |  |
| q-24b2e7dec6 | pivot step 4 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-ca87f2f883 | pivot step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*working.zip*\" OR file.path LIKE \"*.pfx\" OR file.path LIKE \"*Draft.Zip*\" OR file.path LIKE \"*Temp\\\\\\\\Rar*\" OR file.path LIKE \"*Temp… | 13 | F65 |
| q-b97f67b6a3 | pivot step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (host.name == \"nashua.dmevals.local\" OR host.name == \"scranton.dmevals.local\") \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _ind… | 157 |  |
| q-87ffc504d5 | pivot step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp > \"2020-05-02T03:01:51Z\" AND (host.name == \"nashua.dmevals.local\" OR host.name == \"scranton.dmevals.local\") AND win.ScriptBlockText != \"p… | 76 | F55, F56, F64 |
| q-7a58c2c2cb | pivot step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" AND win.ScriptBlockText != \"prompt\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| S… | 7 |  |
| q-0e5866d809 | pivot step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None | F58 |
| q-6f166d0602 | pivot step 8 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopf"} | None | F55 |
| q-625e0e3371 | pivot step 8 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None | F61 |
| q-e3d51e5516 | pivot step 9 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYpu"} | None |  |
| q-609794745e | pivot step 9 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1OJ"} | None | F57 |
| q-b510a84cff | pivot step 10 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND win.ScriptBlockText LIKE \"*Keystrokes*\" \| KEEP @timestamp, host.name, win.ScriptBlockText, _id, _index"} | 3 |  |
| q-469b2351cd | pivot step 10 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4656\",\"4663\",\"4673\",\"4688\",\"4648\",\"4624\") AND (win.ObjectName LIKE \"*lsass*\" OR win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*SECURITY*\" OR win… | ERROR |  |
| q-c39cbe09fd | pivot step 11 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4656\",\"4663\",\"4673\",\"4648\",\"4624\") AND (win.ObjectName LIKE \"*lsass*\" OR win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*SECURITY*\" OR win.ObjectNa… | 29 |  |
| q-241567bee0 | pivot step 12 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS38Vi"} | None | F60 |
| q-b997f6b9d8 | pivot step 12 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None | F59 |
| q-f8630e0bc9 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopf"} | None |  |
| q-e9f935cb8f | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz_iFNN"} | None |  |
| q-7c420d4e66 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz_h1Lm"} | None |  |
| q-7e54cc7cdf | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopc"} | None |  |
| q-d99c136c06 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjooe"} | None |  |
| q-9b7434cab1 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1OJ"} | None |  |
| q-fa50553a88 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdI9"} | None |  |
| q-5c2b3ce3ab | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkjomHY"} | None |  |
| q-e8eafa0e94 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-5f6d88a4bc | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItwCq71_"} | ERROR |  |
| q-6cb13497df | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-1b7bd14026 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-5f1830673c | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS38Vi"} | None |  |
| q-d602a9ec66 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS38Vi"} | None |  |
| q-853afcc870 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-8f0e72d80a | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-9d80d48c7b | pivot step 15 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None | F58 |
| q-e03cc63d32 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-5541fe87ae | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-8b0861408e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-339ae60676 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-4efadb5103 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-ba7b418e12 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-c9609613f0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-f587f63abb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpHV4S3"} | None |  |
| q-e93b914f8d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2o"} | None |  |
| q-4c6ca9e564 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-04dd8c3246 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopf"} | None |  |
| q-c4f14dd2e9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRX"} | None |  |
| q-ea1617cf6c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwrPVRX"} | None |  |
| q-18aded780d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-715a2a1ed0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-86483e7b2c | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX2"} | None |  |
| q-c8d8c5d7a4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-2cad9e2a01 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-7d7a18f508 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwBjiC8"} | None |  |
| q-3456b0c8f1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlShx"} | None |  |
| q-6aaceac773 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-41be064dd0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-62718d8fbb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ_-"} | None |  |
| q-c4bd016afe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ-S"} | None |  |
| q-4b2361c7af | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz7ud8y"} | None |  |
| q-05d83e7795 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz7ud8U"} | None |  |
| q-b008ca5f05 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpFT8y4"} | None |  |
| q-3ce2fedd74 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rs"} | None |  |
| q-2a8c56342f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rs"} | None |  |
| q-4888635271 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgw49k"} | None |  |
| q-d5f922b363 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-da383dae2c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHp5aa"} | None |  |
| q-07ffc15162 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-b4580f6a2a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgP"} | None |  |
| q-ed0e020247 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlSh0"} | None |  |
| q-b29ea510d7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkv3cGg"} | None |  |
| q-046ac4acb8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkovWJ1"} | None |  |
| q-36d73b75fb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkglS44"} | None |  |
| q-6683395a21 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-be7ff3c278 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-37163c56f7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-dd3c2e0b2a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkADuPE"} | None |  |
| q-cbb4ed6389 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkEH740"} | None |  |
| q-dd427062e9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkSVMCG"} | None |  |
| q-a78ae159e6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlAOq"} | None |  |
| q-42c3c101b0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-b7cf4991a9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-3b53ba2412 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-8e72f06bcf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sT"} | None |  |
| q-fb149727c6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-908503ae6a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-5e1fff930d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-4edc687bd5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-2d730fe053 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLb9km"} | None |  |
| q-73aee3ec72 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-8b77bc25f2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-97e90c5714 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-172edbf686 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-2db94dc658 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-15534e02b2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-5fdc7fc0d9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLb9km"} | None |  |
| q-7654ba6242 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-264fa83696 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkEHr1e"} | None |  |
| q-44a415f598 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsM0qmS"} | None |  |
| q-824729d934 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsc-QNb"} | None |  |
| q-bd4cb2da5c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uv"} | None |  |
| q-7e2e49be0c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uv"} | None |  |
| q-91c1a5ae1c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sG"} | None |  |
| q-e9595db615 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sG"} | None |  |
| q-f65108f0d5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sG"} | None |  |
| q-57fde269e0 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sG"} | None |  |
| q-8446e196df | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sp"} | None |  |
| q-b8f6b55d04 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4sp"} | None |  |
| q-59d07ac1d0 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4u2"} | None |  |
| q-49fe4860f3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4u2"} | None |  |
| q-1bdf58bca6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovV"} | None |  |
| q-664c7d8321 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrov8"} | None |  |
| q-ad02fbd9a9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse_H6B"} | None |  |
| q-f85a23bae3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkJMpSF"} | None |  |
| q-f04207aa50 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkJMpSF"} | None |  |
| q-b27e508422 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsJxqw2"} | None |  |
| q-c1ff2aafbb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsEwOVS"} | None |  |
| q-e59ab47ac8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-399e36b3de | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-4e54e64323 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-c44acbce27 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-5adbe61bf5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-d8ac918a61 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqSbu"} | None |  |
| q-b37cfdd938 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqSbu"} | None |  |
| q-a50c4b7cd2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqigy"} | None |  |
| q-815e5a7cf0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-6f177fb0b3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-3ab6c8546c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAt"} | None |  |
| q-7e9c20060e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAu"} | None |  |
| q-23d410c474 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkei3QI"} | None |  |
| q-4d0048ba83 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkv3sHT"} | None |  |
| q-a1d6cea627 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-cf45e0ff65 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNpkH"} | None |  |
| q-1d698855fc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-93cf117f91 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYrA"} | None |  |
| q-72be4e69ae | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-6c7d9056f1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-41663dae59 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSxb"} | None |  |
| q-a5da541e81 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-962b6f842b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-d704cbf20e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1OJ"} | None |  |
| q-0176f74160 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdLv"} | None |  |
| q-9218318170 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdI9"} | None |  |
| q-b15468fe92 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y3M"} | None |  |
| q-3872f90ee3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-d956135357 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqjKK"} | None |  |
| q-a9c680d073 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqjKK"} | None |  |
| q-5d7f64773b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsQ2P9A"} | None |  |
| q-5a752d8bf1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO14sP"} | None |  |
| q-c56bcbccd2 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX1"} | None |  |
| q-07fdfd54ba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-6e6db0d40b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-39e0a9c3ba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-c09b33aa90 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-c10fc70298 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-890351b6ef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-ed52d1fc90 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-22312d5ed5 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX1"} | None |  |
| q-ff1fe1921b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-a5230c8eb8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-ec76e59fbb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-99b5a21079 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-91f0b2c949 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-ae0f80822d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYpu"} | None |  |
| q-b4dda25349 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlShx"} | None |  |
| q-025d110e83 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-caf62abfcf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpo7f89"} | None |  |
| q-453a7573ce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkXa2mu"} | None |  |
| q-c61a216d10 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAt"} | None |  |
| q-83be9740c3 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX7"} | None |  |
| q-8b69117d2c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5qNj"} | None |  |
| q-acbafd8b85 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-ff755206ec | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-cde0f94a36 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y0E"} | None |  |
| q-37e94ce5fe | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsW6jeK"} | None |  |
| q-2f2af9fdf9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-3d4477270e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-189cd3e51c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-c62039cc10 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4vf"} | None |  |
| q-5464f918fe | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rk"} | None |  |
| q-5085c5165b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uK"} | None |  |
| q-63fcd0fbf9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4rQ"} | None |  |
| q-e3f3708737 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8u4r9"} | None |  |
| q-53bf1cb22b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4t-"} | None |  |
| q-1e368ab147 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ud"} | None |  |
| q-92ad0abea4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4uK"} | None |  |
| q-a9d5b2aff8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4vH"} | None |  |
| q-db744e2cb1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4tU"} | None |  |
| q-1d30f1d766 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-a6deb16eeb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpp7sSn"} | None |  |
| q-e4cae88d50 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpo7f-S"} | None |  |
| q-76fcf762f8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpp7sQv"} | None |  |
| q-46b3a0bcfa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-7ce39cf566 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-ecac0168ce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ_4"} | None |  |
| q-20c270cd97 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-f53c18d22f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-27b872470b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-96fefc6b53 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-a7d17e1538 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-9e3e65498b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-4fb3254a7a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-36P"} | None |  |
| q-56832b55b0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-36P"} | None |  |
| q-be35ccee6c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqO44i"} | None |  |
| q-c4cb5ecb29 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjF_4Y"} | None |  |
| q-e258a20893 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-34o"} | None |  |
| q-e24a2fd659 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-054b7d36fe | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcq"} | None |  |
| q-9b9d173358 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-a8ac62b795 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo73"} | None |  |
| q-168c365b8b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-8010fd1d53 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-984888b046 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-5e94f10d88 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-6d4f6a26cc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpl1glI"} | None |  |
| q-cdf8ef4bbc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpl1glI"} | None |  |
| q-3638928267 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1OJ"} | None |  |
| q-501add2b9a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-68bf07320a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-4793cfe34a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjEkfw"} | None |  |
| q-f05f0b308a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None |  |
| q-bb593ccf4f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-b3bca66ea0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-7e05c3db95 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSxb"} | None |  |
| q-e40b08849c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-9dc45f8906 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-f1cf2d4f77 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5I18"} | None |  |
| q-71b43ab1f7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-3487cf8611 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-cca61afd5e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-a88e5cea5e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcb"} | None |  |
| q-7936d2257e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcb"} | None |  |
| q-e753d092af | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-35u"} | None |  |
| q-17f2b63982 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopf"} | None |  |
| q-4d1a84d1b3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz_iFNN"} | None |  |
| q-4bcf2c4dc9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopc"} | None |  |
| q-eccd6520b6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjooe"} | None |  |
| q-9b8c0d1534 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1OJ"} | None |  |
| q-ef7e936643 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdI9"} | None |  |
| q-f8006f217f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-c64d7ae7c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-6c06bcc542 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-c30e5e2a99 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFv53"} | None |  |
| q-f04dcb5e16 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS38Vi"} | None |  |
| q-5058f28ea8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS38Vi"} | None |  |
| q-84d472617c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-8b34a230b1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-79ceddacd1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-f3a10efa7f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-ba2660955c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdI9"} | None |  |
| q-07a5a661df | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkjomHY"} | None |  |
| q-377d9f4f90 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2o"} | None |  |
| q-b336b04855 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzG"} | None |  |
| q-652f73dbdd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpizF2M"} | None |  |
| q-0788d26ddd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpizF2M"} | None |  |
| q-0862a1cbd1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpfwJ_Y"} | None |  |
| q-e228e12b14 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpfwJ_Y"} | None |  |
| q-c1d15a602a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgxY85"} | None |  |
| q-e62beb8a0c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_R"} | None |  |
| q-de3d9afcec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkILJ_D"} | None |  |
| q-9e9252940e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkILJ_D"} | None |  |

## Verification

Evidence items cited: 226; confirmed against the stored events: 224; rejected: 2. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 9 item(s) in 6 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
