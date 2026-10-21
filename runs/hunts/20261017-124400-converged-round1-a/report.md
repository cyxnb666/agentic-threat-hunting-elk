# Threat hunt report — 20261017-124400-converged-round1-a

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 6 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003.001 (F01, F10, F17, F31, F48, F53, F63, F64), I03 T1187 (F21), I05 T1552.001 (F03, F59), I06 T1552.001 (F28, F61), I07 T1552.001 (F60), I08 T1552.004 (F27, F57)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-17T04:44:00+00:00 / 2026-10-17T04:55:41+00:00 (700.5 s) |
| LLM calls / tokens | 219 / {'prompt': 4505338, 'completion': 153337} |
| MCP tool calls | 1383 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003.001 | yes | malicious/high | F01, F10, F17, F31, F48, F53, F63, F64 | PowerShell shellcode loader and full-access LSASS handles on SCRANTON/NASHUA |
| I02 | T1003.006 | yes | suspicious/low | F02 | DS-Replication-Get-Changes access on NEWYORK by machine account |
| I03 | T1187 | yes | malicious/high | F21 | WebDAV forced-authentication from 10.0.1.4 to 192.168.0.4 |
| I04 | T1187 | yes | suspicious/medium | F22 | Shortcut/lure file creation on SCRANTON |
| I05 | T1552.001 | yes | malicious/high | F03, F59 | Credential-harvesting PowerShell file collection on SCRANTON/NASHUA |
| I06 | T1552.001 | yes | malicious/high | F28, F61 | Invoke-Exfil staging and WebDAV exfiltration with embedded credentials |
| I07 | T1552.001 | yes | malicious/high | F60 | PsExec64 from SCRANTON passing cleartext domain password to NASHUA |
| I08 | T1552.004 | yes | malicious/high | F27, F57 | Get-PrivateKeys certificate export to .pfx with hardcoded password on SCRANTON |
| I09 | T1555.004 | yes | suspicious/medium | F62 | Unsigned hostui.exe launched elevated from PowerShell on SCRANTON |
| I10 | T1558.001 | yes | suspicious/medium | F49 | No golden-ticket evidence despite LSASS access |
| I11 | out-of-scope:T1027 | no | malicious/high | F37 | Hidden steganography-decoded PowerShell implant (monkey.png) launched via control.exe on SCRANTON |
| I12 | out-of-scope:T1204 | no | malicious/high | F11, F65 | Malicious .scr dropper in C:\ProgramData\victim executed by pbeesly on SCRANTON |

## Findings

### F03 · malicious / high · T1003 · Credential-harvesting PowerShell on scranton/nashua (file collection of *pass*/*login*/*vpn*, Sysinternals download, hidden encoded loader)

Evidence status: **verified**

Under user pbeesly, PowerShell on scranton.dmevals.local (02:56:17Z) and nashua.dmevals.local (03:15:59Z) enumerated the user profile for *.doc/*.xls/*.pdf/*.pst plus *psw*, *pass*, *login*, *admin*, *sifr*, *sifer*, *vpn* files and compressed them with Compress-Archive — credential harvesting from disk. On scranton the same session expanded SysinternalsSuite.zip into Downloads, created HKCU\Software\Classes\Folder\shell\open command keys, ran a VirtualAlloc/CreateThread shellcode loader, a GetProcAddress/ReflectedDelegate base64 PE loader, and a 'powershell.exe -nop -w hidden -e' encoded command (03:21:28Z). This is attacker tooling on the host, but it is file-based credential collection and in-memory execution, not an OS credential-store dump: no SAM/SECURITY hive read (0 hits for 4663 ObjectName *SAM*/*SECURITY*/*Cache*), no reg save/ntdsutil/vssadmin/procdump/comsvcs command lines, and no dump artefacts were found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWIxak | q-250237a500 | ok |
| 2 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMANA6l9 | q-250237a500 | ok |
| 3 | 2020-05-02 03:21:28.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewAkAGIAPQAkAGUAbgB2ADoAdwBpAG4AZABpAHIAKwAnAFwAcwB5AHMAbgBhAHQ… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWJGOH | q-250237a500 | ok |
| 4 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $cFIrwwpZzGzU = @"  [DllImport("kernel32.dll")]  public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWIxa2 | q-250237a500 | ok |

### F64 · malicious / medium · T1003.001 · accesschk.exe run by PowerShell on SCRANTON before LSASS access

Evidence status: **verified**

pbeesly's PowerShell launched C:\Program Files\SysinternalsSuite\accessChk.exe at 03:04:34 as part of the hands-on-keyboard credential-access toolchain.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63C9mZ | q-41626e84ce | ok |

### F11 · malicious / high · T1056 · Malicious .scr dropper in C:\ProgramData\victim executed by pbeesly on scranton

Evidence status: **verified**

At 2020-05-02T02:55:56Z on scranton.dmevals.local, explorer.exe launched C:\ProgramData\victim\<odd-name>cod.3aka3.scr with argument /S as DMEVALS\pbeesly (Medium integrity, session 2, no version/company metadata, MD5=9D1C5EF38E6073661C74660B3A71A76E). The .scr immediately spawned conhost.exe and cmd.exe, and cmd.exe spawned powershell.exe at 02:56:14Z, 02:57:15Z and 02:59:04Z — the entry point for the input-capture/credential-access tooling (shellcode loader and token enumeration) described under T1056.004. This is the initial execution vehicle for the credential-access activity on this host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7am0gN | q-e7161f7f13 | ok |
| 2 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | win.Hashes | SHA1=4B7FA56A4E85F88B98D11A6E018698AE3FBA5E62,MD5=9D1C5EF38E6073661C74660B3A71A76E,SHA256=0DF38A55D940F498478EB03683C94D4584236E100125B526A67650BA54DF4AE4,IMPHA… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7am0gN | q-e7161f7f13 | ok |
| 3 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\explorer.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7am0gN | q-e7161f7f13 | ok |
| 4 | 2020-05-02 02:56:04.510Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7amkgV | q-358c978af8 | ok |
| 5 | 2020-05-02 02:56:14.894Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\cmd.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7amUh2 | q-358c1347be | ok |

### F65 · malicious / high · T1056 · .scr dropper in C:\ProgramData\victim executed by pbeesly on SCRANTON

Evidence status: **verified**

explorer.exe launched C:\ProgramData\victim\â€®cod.3aka3.scr with /S as pbeesly, spawning cmd.exe and conhost; it was later wiped with sdelete64.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7am0gN | q-41626e84ce | ok |

### F10 · malicious / high · T1056.004 · PowerShell shellcode loader creates remote thread inside LSASS on scranton

Evidence status: **verified**

On scranton.dmevals.local, user DMEVALS\pbeesly executed C:\ProgramData\victim\<odd-name>cod.3aka3.scr (parent C:\Windows\explorer.exe, command line "C:\ProgramData\victim\...cod.3aka3.scr" /S, SHA256=0DF38A55D940F498478EB03683C94D4584236E100125B526A67650BA54DF4AE4) at 2020-05-02T02:55:56Z. The .scr spawned cmd.exe and then powershell.exe (PID 2976), which at 02:58:45Z logged a script block declaring kernel32 VirtualAlloc/CreateThread via Add-Type and a large hex byte array (classic shellcode loader). At 03:05:16.623Z Sysmon event 8 shows that same powershell.exe (SourceProcessId 2976) creating a remote thread in C:\Windows\System32\lsass.exe (TargetProcessId 736, StartAddress 0x00000117610E0000, StartModule '-'), i.e. code injected into the credential-holding process — consistent with credential API hooking / in-memory credential theft. A second, separate powershell (PID 3876, also pbeesly) opened handles to lsass.exe and winlogon.exe with GrantedAccess 0x1000 at 03:01:03-03:01:04Z while running a token/privilege enumeration script (Get-AttributesMask, SE_GROUP_* constants) from C:\Program Files\SysinternalsSuite\readme.ps1. The 0x1fffff/0x101001/0x1f3fff LSASS-adjacent masks in the aggregate belong to normal process-creation/CSRSS activity against the .scr and conhost/cmd, not to LSASS.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\Windows\System32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnI | q-b8b790c374 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnI | q-b8b790c374 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.StartAddress | 0x00000117610E0000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnI | q-b8b790c374 | ok |
| 4 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $cFIrwwpZzGzU = @"  [DllImport("kernel32.dll")]  public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWIxa2 | q-fc6f7064da | ok |
| 5 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ExecutionProcessID | 2976 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWIxa2 | q-fc6f7064da | ok |
| 6 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7BNbI- | q-3d9de06e22 | ok |
| 7 | 2020-05-02 03:01:04.106Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\winlogon.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7BNLI1 | q-3d9de06e22 | ok |
| 8 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mm | q-6661c03e8a | ok |

### F21 · malicious / high · T1187 · WebDAV forced-authentication (DavClnt / WebDAV-MiniRedir) from 10.0.1.4 to 192.168.0.4

Evidence status: **verified**

On 2020-04-30 between 00:32:18 and 00:32:21 UTC, host 10.0.1.4 (the same address that appears as SCRANTON$ / scranton.dmevals.local in the Windows datasets) issued 36 WebDAV-style HTTP requests to 192.168.0.4:80 — 10 OPTIONS and 26 PROPFIND — with user agents 'DavClnt' and 'Microsoft-WebDAV-MiniRedir/10.0.18362', targeting /webdav and /webdav/. The sequence shows the classic forced-authentication handshake: an initial OPTIONS / with DavClnt returned 403, then OPTIONS /webdav returned 401 Unauthorized, a 301 redirect, OPTIONS /webdav/ returned 401 then 200, and PROPFIND /webdav/ returned 401 then 207 Multi-Status. The 401 challenges followed by successful 200/207 responses indicate the client was induced to present credentials to an attacker-controlled WebDAV endpoint, which is exactly the T1187 credential-capture pattern. This is not normal browsing: the destination 192.168.0.4 is outside the 10.0.0.0/10.0.1.0 corporate ranges used for the DC (10.0.0.4) and peers (10.0.1.6), and the WebDAV-MiniRedir/DavClnt user agents are only produced when Windows resolves a UNC/WebDAV path such as a .library-ms/.searchConnector-ms or shortcut lure. Note the zeek window (2020-04-30) does not overlap the Windows event window (2020-05-02), so this network evidence stands on its own.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | DavClnt | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5C | q-771c65cb89 | ok |
| 2 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw17 | q-771c65cb89 | ok |
| 3 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 401 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw17 | q-771c65cb89 | ok |
| 4 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw17 | q-771c65cb89 | ok |
| 5 | 2020-04-30 00:32:21.538Z | simplerockbuild.simplerock.lan | zeek | http.request.method | PROPFIND | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5D | q-771c65cb89 | ok |
| 6 | 2020-04-30 00:32:21.538Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 207 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5D | q-771c65cb89 | ok |
| 7 | 2020-04-30 00:32:21.538Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 192.168.0.4 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5D | q-771c65cb89 | ok |
| 8 | 2020-04-30 00:32:21.538Z | simplerockbuild.simplerock.lan | zeek | source.ip | 10.0.1.4 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5D | q-771c65cb89 | ok |

### F24 · malicious / medium · T1212 · PowerShell stager on scranton opened LSASS with full-access (0x1FFFFF / 0x1F3FFF) masks and UNKNOWN call traces

Evidence status: **NOT verified (6/7 evidence items)** — excluded from the verdict

On scranton.dmevals.local, user pbeesly's PowerShell process (PID 2976, launched 02:58:44Z by control.exe with -noni -noexit -ep bypass -window hidden) decoded shellcode from C:\Users\pbeesly\Downloads\monkey.png and executed it via IEX/Add-Type VirtualAlloc+CreateThread. At 03:05:16Z PowerShell.exe (PID 2976) opened C:\windows\system32\lsass.exe with GrantedAccess 0x1f3fff and then 0x1fffff, with call traces ending in UNKNOWN(000001996D252982)/UNKNOWN(000001996D28200D) — code not backed by a known module, consistent with in-memory shellcode reading LSASS rather than a signed Windows component. A second host, nashua.dmevals.local, shows wsmprovhost.exe opening lsass.exe with 0x1f3fff at 03:09:29Z, but its call trace resolves through System.ni.dll / Microsoft.PowerShell.Commands.Management.ni.dll (managed PowerShell code), more consistent with a PowerShell cmdlet than injected shellcode. No 4688/4104 command line containing lsass, comsvcs, MiniDump or sekurlsa was found, so the access was performed in memory by the injected payload, not by a named dumping utility.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-71f68590a2 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-47560293c5 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-47560293c5 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-71f68590a2 | ok |
| 5 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7ViMbT | q-05ed032a73 | ok |
| 6 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $cFIrwwpZzGzU = @"  [DllImport("kernel32.dll")]  public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWIxa2 | q-71a19184ad | FAILED: claimed value differs from the stored value |
| 7 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-71f68590a2 | ok |

### F28 · malicious / high · T1552.001 · Harvested keys staged into password-protected archive and exfiltrated via WebDAV; plaintext credentials in scripts

Evidence status: **verified**

On scranton.dmevals.local, pbeesly's scriptblock Invoke-Exfil (ScriptBlock ID b2b03a9c-43f0-4285-837d-f22d4600b2ae, Path C:\Program Files\SysinternalsSuite\psversion.ps1) at 2020-05-01T23:08:02-04:00 installs 7Zip4Powershell, compresses $env:USERPROFILE\Downloads\ (where the exported .pfx landed) into $env:APPDATA\OfficeSupplies.7z with password "lolol", and copies it to a WebDAV share \\192.168.0.4\webdav using hardcoded credentials cozy / MyCozyPassw0rd!. Sysmon confirms C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z created by powershell.exe at 03:08:35Z. The same actor then moved to nashua.dmevals.local (via PsExec64 with plaintext password -p Fl0nk3rt0n!T0by) where C:\Windows\Temp\Rar.exe created C:\Users\pbeesly\Desktop\working.zip with password -hpfGzq5yKw, and sdelete64.exe was used to wipe working.zip and Rar.exe. Credentials are stored in cleartext in files/scripts and the collected data is staged and exfiltrated.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-c80e71372f | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-c80e71372f | ok |
| 3 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2lq7zj | q-bd6c02fb04 | ok |
| 4 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2Ze6tB | q-172026f233 | ok |
| 5 | 2020-05-02 03:17:41.290Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Users\pbeesly\Desktop\working.zip" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2UXka_ | q-172026f233 | ok |
| 6 | 2020-05-02 03:14:42.601Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2chAnX | q-7f19af5f60 | ok |

### F59 · malicious / high · T1552.001 · NASHUA: pbeesly PowerShell harvested credential-named files and password-protected them with Temp Rar.exe

Evidence status: **verified**

On nashua.dmevals.local pbeesly's PowerShell enumerated *pass*/*login*/*vpn* files, built working.zip, ran C:\Windows\Temp\Rar.exe -hpfGzq5yKw on it, then wiped it with sdelete64.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMANA6l9 | q-4bf9e66d5e | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | .\Rar.exe a -hpfGzq5yKw "$env:USERPROFILE\Desktop\working.zip" "$env:APPDATA\working.zip" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAOBfbr | q-4bf9e66d5e | ok |
| 3 | 2020-05-02 03:16:52.456Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2WaNu5 | q-41626e84ce | ok |

### F60 · malicious / high · T1552.001 · PsExec64 from SCRANTON passed cleartext domain password to NASHUA

Evidence status: **verified**

pbeesly's PowerShell ran PsExec64 four times with -p Fl0nk3rt0n!T0by to launch C:\Windows\Temp\python.exe on \\NASHUA, producing type-2 PSEXESVC logons there.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ioON3 | q-41626e84ce | ok |
| 2 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2in-NH | q-41626e84ce | ok |
| 3 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXEp | q-db5333b66b | ok |

### F61 · malicious / high · T1552.001 · Invoke-Exfil on SCRANTON embeds WebDAV credentials and archive password

Evidence status: **verified**

Script block loaded from C:\Program Files\SysinternalsSuite\psversion.ps1 compresses Downloads to a password-protected 7z and copies it to \\192.168.0.4\webdav with hardcoded cozy/MyCozyPassw0rd!.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-6e424e3fc0 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-6e424e3fc0 | ok |

### F27 · malicious / high · T1552.004 · PowerShell Get-PrivateKeys exports all LocalMachine certificates to .pfx with hardcoded password

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-01T23:04:56-04:00 (2020-05-02T03:04:56Z), user pbeesly ran a scriptblock named Get-PrivateKeys (ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b, Path C:\Program Files\SysinternalsSuite\readme.ps1) that enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint, writing to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded plaintext password "saribas". One second later Sysmon recorded the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by powershell.exe. This is deliberate private-key/certificate harvesting.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-d951c937f3 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-d951c937f3 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-d951c937f3 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CdmD | q-bd6c02fb04 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CdmD | q-bd6c02fb04 | ok |

### F37 · malicious / high · T1556 · Malicious PowerShell (steganography-decoded IEX payload) opened LSASS with full access on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local, powershell.exe PID 2976 was spawned by control.exe ("C:\Windows\System32\control.exe" /name Microsoft.BackupAndRestoreCenter) at 02:58:44Z with the command line "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');...IEX([System.Text.Encoding]::ASCII.GetString(..." — a hidden, execution-policy-bypassed steganography loader reading a PNG from pbeesly's Downloads. It spawned csc.exe compiling from C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.cmdline, then at 03:05:16Z opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff (and winlogon.exe 0x1f3fff/0x1fffff, plus many svchost/dwm/LogonUI handles at 0x1fffff) — full-access LSASS handle acquisition consistent with credential theft / authentication-process tampering. This is the only non-system process in the dataset taking full-access handles on LSASS; the other high-access LSASS events are Microsoft-signed system binaries (wininit/csrss at boot, Azure guest-agent telemetry, AntimalwareConfig) or a wsmprovhost PowerShell-cmdlet call trace. No registry modification of WDigest/SecurityProviders/LSA keys and no unsigned module loads into LSASS were observed, so the tampering appears to be in-memory access rather than persistent auth-process modification.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7ViMbT | q-69e0edb354 | ok |
| 2 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7ViMbT | q-69e0edb354 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-230fd6ffca | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-230fd6ffca | ok |
| 5 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-77aeb3c1b9 | ok |
| 6 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.cmdline" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7VhsbT | q-69e0edb354 | ok |

### F48 · malicious / high · T1558 · Hands-on-keyboard intrusion on SCRANTON/NASHUA with full-access LSASS reads by PowerShell and wsmprovhost

Evidence status: **verified**

On 2020-05-02 between 02:58 and 03:21 UTC, user pbeesly ran a hidden, encoded PowerShell implant on scranton.dmevals.local (PID 2976, launched by control.exe /name Microsoft.BackupAndRestoreCenter, payload decoded from C:\Users\pbeesly\Downloads\monkey.png via System.Drawing and IEX). The same session executed a staged toolkit: Invoke-Discovery, Invoke-Persistence -PersistStep 1/2, Invoke-ScreenCapture, Invoke-Exfil (7-Zip password-protected archive to %APPDATA%\OfficeSupplies.7z), Invoke-BeachCleanup, and Invoke-SeaDukeStage -ComputerName NASHUA. At 03:05:16 that PowerShell process opened lsass.exe with GrantedAccess 0x1F3FFF and 0x1FFFFF (full access, call trace ending in UNKNOWN modules) — the classic credential/ticket-extraction access mask. At 03:09:29 on nashua.dmevals.local, wsmprovhost.exe (PID 7720, the PowerShell remoting host for the SeaDukeStage push) also opened lsass.exe with 0x1F3FFF. Kerberos activity on the DC newyork.dmevals.local shows repeated 4768/4769 for pbeesly from 10.0.1.4 and 10.0.1.6 with AES256 (0x12) and pre-auth type 2, i.e. normal pre-authenticated requests, with no RC4 (0x17) ticket requests and no 4769 for service accounts — so no roasting signature is visible in this window. The LSASS access is the credential-access step of an active intrusion; the ticket-forging/roasting sub-techniques themselves are not evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-e26d984577 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-e26d984577 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-f7763b1185 | ok |
| 4 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7ViMbT | q-0fdedb235b | ok |
| 5 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAOBExi | q-cd217cf9e9 | ok |
| 6 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Exfil | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E6 | q-a042d1c658 | ok |

### F57 · malicious / high · T1649 · Get-PrivateKeys PowerShell exports LocalMachine certificates to .pfx on scranton

Evidence status: **verified**

As DMEVALS\pbeesly on scranton.dmevals.local, script block 9d153741 (readme.ps1) enumerated cert:\LocalMachine and ran Export-PfxCertificate with hardcoded password 'saribas' into Downloads; Sysmon shows powershell.exe creating C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx at 03:04:57 UTC and deleting it at 03:08:51 UTC, inside a hidden-PowerShell/shellcode chain.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-773e637221 | ok |
| 2 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CdmD | q-77f2456c2f | ok |
| 3 | 2020-05-02 03:08:51.489Z | scranton.dmevals.local | windows.sysmon | win.Hashes | SHA1=A6E731EA51C8809C6FE57DEF73ACD54228E953D7,MD5=8E41F755A152A2C139A922D9626B44C4,SHA256=F33BEEBFBFF89C1A8E51AD688CDDB1A972EDD5444380B93292929987D9618577,IMPHA… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kqttt | q-1244960f5d | ok |

### F01 · suspicious / medium · T1003.001 · PowerShell (pbeesly) opened a handle to lsass.exe on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02T03:01:03Z on scranton.dmevals.local, powershell.exe (PID 3876, running as pbeesly) opened lsass.exe (PID 736) with GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION). The call trace resolves through ntdll/KERNELBASE and managed System.ni.dll frames ending in an UNKNOWN module, i.e. .NET code in PowerShell touching LSASS rather than a sanctioned AV/EDR component. The same user session on scranton ran an in-memory shellcode loader (VirtualAlloc/CreateThread with a 0xfc 0x48 0x83 0xe4 0xf0 byte array), a GetProcAddress/ReflectedDelegate loader with a base64 PE, and a hidden encoded PowerShell command, so the LSASS handle is consistent with credential access from that tooling. However the access mask is query-only (not 0x1010/0x1410/0x1fffff read-memory masks) and no dump file, minidump, comsvcs, procdump or sekurlsa artefact was observed, so actual memory read/dump is not proven. The 4663 object-access event for the same handle (scranton, pbeesly, powershell.exe, AccessMask 0x10) corroborates the LSASS touch. Other LSASS access in the window is benign: svchost.exe (289), Azure AntimalwareConfig.exe (15), WindowsAzureTelemetryService.exe (13), CollectGuestLogs.exe and MsMpEng.exe.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7BNbI- | q-95926fde05 | ok |
| 2 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7BNbI- | q-95926fde05 | ok |
| 3 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7BNbI- | q-95926fde05 | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Qt70r | q-7a3699d1f3 | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Qt70r | q-7a3699d1f3 | ok |
| 6 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $cFIrwwpZzGzU = @"  [DllImport("kernel32.dll")]  public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWIxa2 | q-250237a500 | ok |
| 7 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWJWyf | q-250237a500 | ok |
| 8 | 2020-05-02 03:21:28.949Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewAkAGIAPQAkAGUAbg… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL17AQxS | q-8c812845a6 | ok |

### F63 · suspicious / low · T1003.001 · Additional query-limited LSASS handle by PowerShell on SCRANTON

Evidence status: **verified**

powershell.exe (pbeesly) opened lsass.exe with GrantedAccess 0x1000 via managed System.ni.dll call trace at 03:01:03, distinct from the anchored full-access handles.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7BNbI- | q-9535390798 | ok |

### F02 · suspicious / low · T1003.006 · DS-Replication-Get-Changes (1131f6aa) access on newyork.dmevals.local by machine account NEWYORK$

Evidence status: **verified**

A single 4662 Directory Service Access event on newyork.dmevals.local at 2020-05-02T03:16:15Z (record 152411) shows subject NEWYORK$ (DMEVALS, S-1-5-18, logon 0x167EDA) accessing object %{11487126-e2dc-4f51-acb1-1b0df0573bb5} with AccessMask 0x100 and Properties listing {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} (DS-Replication-Get-Changes) plus {19195a5b-6da0-11d0-afd3-00c04fd930c9}. That is the right GUID for DCSync, but the subject is the host's own machine account on itself, not a remote user/computer account, and only one such event exists in the window. The other six 4662 events are LOCAL SERVICE querying Policy\Secrets\$MACHINE.ACC (routine LSA secret reads). In the non-overlapping Zeek window (2020-04-30) the drsuapi endpoint was used 9 times from 10.0.1.4 and 10.0.1.6 to 10.0.0.4, but only DRSBind/DRSCrackNames/DRSUnbind — no DsGetNCChanges, so no replication of directory data was observed there. No dcsync/drsuapi/lsadump strings appear in PowerShell script blocks or windows.other messages.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.Properties | %%7688  		{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  	{19195a5b-6da0-11d0-afd3-00c04fd930c9}   | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL87ZUOT | q-fc44e9588e | ok |
| 2 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL87ZUOT | q-fc44e9588e | ok |
| 3 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.AccessMask | 0x100 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL87ZUOT | q-fc44e9588e | ok |
| 4 | 2020-04-30 00:12:00.967Z | simplerockbuild.simplerock.lan | zeek | zeek.operation | DRSBind | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA6p | q-42f1f2bbec | ok |
| 5 | 2020-04-30 00:12:00.968Z | simplerockbuild.simplerock.lan | zeek | zeek.operation | DRSCrackNames | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw3L | q-42f1f2bbec | ok |

### F17 · suspicious / medium · T1110.002 · Credential material harvested on scranton (LSASS full-access handle, private-key export, hardcoded passwords) but no offline cracking observed

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976, running as SYSTEM) opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff at 03:05:16Z with an UNKNOWN call trace, and wsmprovhost.exe opened lsass.exe with 0x1f3fff on nashua.dmevals.local at 03:09:29Z. In the same window pbeesly ran a Get-PrivateKeys function exporting all LocalMachine certificates to .pfx files with the hardcoded password 'saribas', and an Invoke-Exfil function containing a hardcoded PSCredential (cozy / MyCozyPaws0rd!). These are credential-access primitives whose output could be cracked offline, but no hashcat/john/Mimikatz/reg save/ntdsutil/vssadmin/esentutl activity was found, and the only SAM handle requests (10) come from lsass.exe itself with 0xf003f, which is normal.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-ba57ce457b | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-ba57ce457b | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-f800f723bc | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-1217005b2a | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-4a6b178a2e | ok |
| 6 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL81V4Qj | q-2564975c6e | ok |

### F22 · suspicious / medium · T1187 · Shortcut/lure file creation on scranton.dmevals.local (Explorer Recent .lnk and PowerShell StartUp hostui.lnk)

Evidence status: **verified**

On scranton.dmevals.local, three shortcut files were created in the 2020-05-02 window: Explorer.EXE created 'Backup and Restore (Windows 7).lnk' and 'System and Security.lnk' in C:\Users\pbeesly\AppData\Roaming\Microsoft\Windows\Recent at 02:58:44, and powershell.exe (PID 3876, running as SYSTEM) created C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk at 03:04:23. The StartUp .lnk written by PowerShell is a persistence-style artifact rather than a forced-auth lure, and the Recent .lnk files are consistent with ordinary Explorer use of Control Panel items. I found no .library-ms, .searchConnector-ms or .url file that would itself point at a remote WebDAV/SMB path, so these shortcut events are not direct T1187 evidence; they are recorded as suspicious context around the same user (pbeesly) whose session also ran archive-and-sdelete staging commands.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL64D_f9 | q-fda607a93c | ok |
| 2 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL64D_f9 | q-fda607a93c | ok |
| 3 | 2020-05-02 02:58:44.405Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\Microsoft\Windows\Recent\Backup and Restore (Windows 7).lnk | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7ViMah | q-4f80aff6ee | ok |
| 4 | 2020-05-02 02:58:44.420Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\Microsoft\Windows\Recent\System and Security.lnk | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7ViMaR | q-4f80aff6ee | ok |

### F31 · suspicious / medium · T1555 · Interactive pbeesly PowerShell session on SCRANTON opened LSASS with full-access masks (0x1F3FFF / 0x1FFFFF) right after running accesschk.exe

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976, user pbeesly) opened a handle to C:\windows\system32\lsass.exe (PID 736) twice within 31 ms at 2020-05-02T03:05:16.623Z and 03:05:16.654Z with GrantedAccess 0x1f3fff and 0x1fffff — full-access masks consistent with memory reading/dumping, not the 0x1000/0x1400 masks seen for the 289 svchost.exe and antivirus/telemetry accesses. The call trace ends in UNKNOWN modules (ntdll.dll+9c584\|KERNELBASE.dll+2732e\|UNKNOWN(...)), i.e. the caller was not a signed system DLL. The same session had just executed Sysinternals accesschk.exe at 03:04:34 (script block '& "C:\Program Files\SysinternalsSuite\accesschk.exe"') and exited at 03:05:08, and the host shows sdelete64.exe wiping files (C:\programdata\victim\???cod.3aka3.scr, Draft.Zip, SysinternalsSuite.zip) and an Invoke-Exfil script block staging data to \\192.168.0.4\webdav — an active hands-on-keyboard intrusion. A matching Security 4663 object-access event on \Device\HarddiskVolume2\Windows\System32\lsass.exe by C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe as pbeesly at 23:05:16 local corroborates the access. No dump file, comsvcs/procdump/mimikatz command line, or credential-store artifact was observed, so the LSASS read is suspicious but the credential theft itself is not proven.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-2a9d3aede0 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D252982) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-86ede6fcf4 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-2a9d3aede0 | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-ba6f7378ad | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Qt70r | q-cb2bfaede2 | ok |
| 6 | 2020-05-02 03:04:34.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | &amp; "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQDVp3 | q-426bdb35c4 | ok |
| 7 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL69HSbI | q-0607ee1826 | ok |

### F62 · suspicious / medium · T1555.004 · Unsigned hostui.exe launched elevated from PowerShell on SCRANTON

Evidence status: **verified**

pbeesly's PowerShell ran Start-Process C:\Windows\System32\hostui.exe -verb runas; the binary has no Company/Description metadata and High integrity, consistent with a credential-theft helper.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx6_ejg | q-ef9de9a64d | ok |
| 2 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | win.Company | - | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx6_ejg | q-ef9de9a64d | ok |

### F49 · suspicious / medium · T1558.001 · No golden-ticket evidence: LSASS access present but no forged-TGT indicators

Evidence status: **verified**

The prerequisite for a golden ticket — reading LSASS on a host holding krbtgt material — is present: PowerShell on scranton.dmevals.local opened lsass.exe with 0x1FFFFF/0x1F3FFF at 03:05:16, and wsmprovhost.exe on nashua.dmevals.local did the same at 03:09:29. However, no forged-ticket artefacts were observed: all 4768 events on the DC newyork.dmevals.local are for pbeesly or SCRANTON$ with PreAuthType 2 and AES256 (0x12), all 4769 requests are for machine accounts (NEWYORK$, NASHUA$, SCRANTON$, WEC$) or krbtgt, and the 4624 logons are the expected machine/system accounts plus pbeesly. No anomalous privileged account authenticated and no 4672 target-user values were returned. The LSASS access is malicious in context, but golden-ticket forging itself is not demonstrated.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-e26d984577 | ok |
| 2 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFP | q-2d232d4755 | ok |
| 3 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFP | q-2d232d4755 | ok |

### F53 · suspicious / medium · T1606 · No forged web credential activity; observed credential-access precursor is LSASS access by PowerShell on SCRANTON and by wsmprovhost on NASHUA

Evidence status: **verified**

No evidence of forged web credentials (no SAML/cookie/token-forgery scripting, no anomalous LogonProcessName, no SSO/ADFS endpoints in Zeek). However, the credential-access precursor is present: on scranton.dmevals.local, C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe (PID 2976, running as SYSTEM) opened lsass.exe with GrantedAccess 0x1f3fff at 2020-05-02T03:05:16.623Z and then 0x1fffff at 03:05:16.654Z, with an UNKNOWN call trace — consistent with LSASS memory access for credential material. On nashua.dmevals.local, wsmprovhost.exe opened lsass.exe with 0x1f3fff at 03:09:29.430Z, but that is explained by the pbeesly PowerShell remoting command 'Get-Process -IncludeUserName' (Invoke-Command -ComputerName NASHUA) seen in 4104 at 23:09:23/23:09:28, i.e. benign. The same user pbeesly also ran Get-PrivateKeys (exporting cert:\LocalMachine certificates to .pfx with password 'saribas') on scranton at 23:04:56, and used PsExec (PSEXESVC.exe) against NASHUA with explicit credentials (4648). Zeek (2020-04-30) does not overlap the Windows window and shows only internal DNS/TLS to 192.168.0.4 with no web-credential endpoints.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-aac0d2e8bb | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-aac0d2e8bb | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-aac0d2e8bb | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-aac0d2e8bb | ok |
| 5 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAMA2AH | q-cae30572ce | ok |
| 6 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-abadd57999 | ok |
| 7 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFR | q-6aaf67caab | ok |
| 8 | 2020-04-30 00:06:38.899Z | simplerockbuild.simplerock.lan | zeek | dns.question.name | newyork.dmevals.local | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw2z | q-3dd2838d0c | ok |

### F04 · benign / high · T1003.002 · No SAM hive access observed

Evidence status: **verified**

No 4663 object-access event references a SAM hive or SAM registry path (0 hits for win.ObjectName:*SAM*), and no reg save / esentutl / ntdsutil command lines appear in the 447 Sysmon process creations or 460 Security 4688 events. The only registry object-access activity is routine: Session Manager\Environment (2968), Control\Lsa (1473) and Winlogon (838).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:02:59.000Z | nashua.dmevals.local | windows.security | win.ObjectName | Policy\Secrets\$MACHINE.ACC | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9W163v | q-fc44e9588e | ok |

### F05 · benign / medium · T1003.003 · No NTDS.dit access or replication of directory data

Evidence status: **verified**

No ntdsutil/vssadmin/esentutl process creations and no NTDS.dit file access in the Windows window. In the non-overlapping Zeek window the drsuapi endpoint carried only DRSBind, DRSCrackNames and DRSUnbind between 10.0.1.4/10.0.1.6 and 10.0.0.4 — name resolution calls, not DsGetNCChanges replication — and the 12 smb_files records show no NTDS.dit transfer.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:38:39.487Z | bobs.bigwheel.local | zeek | zeek.operation | DRSBind | .ds-logs-zeek-default-2026.10.17-000001 / AaFIK6WOc7y0JMA_Nabl | q-42f1f2bbec | ok |
| 2 | 2020-04-30 00:38:39.491Z | bobs.bigwheel.local | zeek | zeek.operation | DRSUnbind | .ds-logs-zeek-default-2026.10.17-000001 / AaFIK6WOc7y0JMA_Nabn | q-42f1f2bbec | ok |

### F06 · benign / high · T1003.004 · LSA Secrets reads are routine LOCAL SERVICE machine-account queries

Evidence status: **verified**

The six 4662 SecretObject events are all subject LOCAL SERVICE (NT AUTHORITY) querying Policy\Secrets\$MACHINE.ACC with AccessMask 0x2 on nashua, scranton and utica between 23:02 and 23:20 local time — normal machine-account secret access by the OS, not an adversary reading LSA secrets. No 4663 event references a SECURITY hive.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:02:59.000Z | nashua.dmevals.local | windows.security | win.SubjectUserName | LOCAL SERVICE | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9W163v | q-fc44e9588e | ok |
| 2 | 2020-05-02 03:03:32.000Z | utica.dmevals.local | windows.security | win.ObjectName | Policy\Secrets\$MACHINE.ACC | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9KmH84 | q-fc44e9588e | ok |

### F07 · benign / high · T1003.005 · No cached domain credential access observed

Evidence status: **verified**

No 4663 object-access event references a Cache registry path (0 hits for win.ObjectName:*Cache*), and no registry hive or SECURITY\Cache access appears among the stacked object names. Nothing indicates cached credential extraction.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | Policy\Secrets\$MACHINE.ACC | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9GibBE | q-fc44e9588e | ok |

### F08 · benign / high · T1040 · netsh trace packet capture on scranton.dmevals.local spawned by Microsoft Azure Network Watcher agent service

Evidence status: **verified**

The only packet-capture activity in the Windows telemetry is a single netsh.exe 'trace start capture=yes' on scranton.dmevals.local at 2020-05-01T23:19:17-04:00 (2020-05-02T03:19:17Z), writing to C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl. Both the Security 4688 record and the Sysmon event 1 show the parent as C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe running as SYSTEM with '/service'. That agent itself was launched by services.exe and carries win.Company 'Microsoft CoreXT', i.e. it is the Azure Network Watcher VM extension, not attacker tooling. The capture was bounded: a matching 'netsh.exe trace stop' was issued by the same parent 7 seconds later (23:19:24), and only 2 netsh process creations exist in the whole sysmon window. No Npcap/WinPcap driver load (event 7), no pcap/tshark/dumpcap/windump/rawcap command line, and no capture-related service installation (7045 shows only PSEXESVC x4 and Java(TM) Virtual Machine Support Service) were observed. The adjacent logman.exe ETL trace creations are likewise children of C:\WindowsAzure\Packages\WaAppAgent.exe (Azure guest agent).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9AdJ6k | q-acc6d09ae9 | ok |
| 2 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9AdJ6k | q-dd8a14d529 | ok |
| 3 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | "C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe" /service | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2LOurf | q-8e06c4f49d | ok |
| 4 | 2020-05-02 03:19:24.835Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2IK5Hc | q-8e06c4f49d | ok |
| 5 | 2020-05-02 03:19:13.877Z | scranton.dmevals.local | windows.sysmon | win.Company | Microsoft CoreXT | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2MP8lJ | q-7b3b62d08b | ok |
| 6 | 2020-05-02 03:19:13.877Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\services.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2MP8lJ | q-7b3b62d08b | ok |
| 7 | 2020-05-02 03:19:29.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\WindowsAzure\Packages\WaAppAgent.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL81VoQs | q-acc6d09ae9 | ok |
| 8 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | win.ServiceName | Java(TM) Virtual Machine Support Service | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3iOe | q-c2bc50c935 | ok |

### F09 · benign / medium · T1040 · Zeek port 1234 session from 10.0.1.4 to 192.168.0.5 is application traffic, not a sniffing artifact

Evidence status: **verified**

The only rare destination port in the zeek conn log is a single TCP session on 2020-04-30T00:08:02Z from 10.0.1.4:60597 to 192.168.0.5:1234 (conn_state RSTO, 70042 bytes out / 910700 bytes in, history ShADadTR), observed by simplerockbuild.simplerock.lan. The same source 10.0.1.4 also talks to 192.168.0.5 over 443/ssl minutes later, including a self-signed-certificate notice, so 192.168.0.5 is a normal peer of that host rather than a capture sink. No zeek service value indicates sniffing/pcap/promiscuous capture, and the zeek window (2020-04-30) does not overlap the Windows window (2020-05-02), so it cannot be tied to the netsh trace. Nothing in this session shows a host in promiscuous mode or a capture relay.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:08:02.361Z | simplerockbuild.simplerock.lan | zeek | destination.port | 1234 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA0K | q-009d6204c2 | ok |
| 2 | 2020-04-30 00:08:02.361Z | simplerockbuild.simplerock.lan | zeek | zeek.conn_state | RSTO | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA0K | q-009d6204c2 | ok |
| 3 | 2020-04-30 00:15:18.365Z | simplerockbuild.simplerock.lan | zeek | destination.port | 443 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA7h | q-91bd8d5c0e | ok |
| 4 | 2020-04-30 00:15:18.392Z | simplerockbuild.simplerock.lan | zeek | zeek.msg | SSL certificate validation failed with (self signed certificate) | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw1X | q-91bd8d5c0e | ok |

### F12 · benign / medium · T1056.001 · No keylogger artifacts found (no hook DLLs, no keyboard-layout persistence, no keylogging script)

Evidence status: **verified**

Checks for keylogging-specific artifacts were negative: no Sysmon image-load events for hook/keylog/interception DLLs (C066), no PowerShell script blocks referencing GetAsyncKeyState/SetWindowsHookEx/RegisterHotKey (C069), and the only keyboard-related registry writes were HKU\.DEFAULT\Keyboard Layout\Preload\1 (3 events) plus one HKLM Run\WindowsDefender value (C065). The only new services were PSEXESVC (4) and Java(TM) Virtual Machine Support Service (1) (C067), neither a keylogger driver. The credential access on scranton was performed in memory against LSASS rather than via a keyboard hook, so no keylogging activity is attributed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | user.name | pbeesly | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7am0gN | q-e7161f7f13 | ok |

### F13 · benign / high · T1056.002 · consent.exe executions are legitimate UAC consent UI, not fake credential prompts

Evidence status: **verified**

The three process creations matching credential/prompt/consent keywords were all C:\Windows\System32\consent.exe (Microsoft 'Consent UI for administrative applications', version 10.0.18362.1) launched by SYSTEM on scranton (02:58:42Z, 03:21:27Z) and nashua (03:14:25Z) with numeric PID/token arguments — normal UAC elevation prompts. No process was launched from a user-writable path impersonating a credential dialog, and no PowerShell used Get-Credential/CredentialPrompt/InputBox (C072 zero hits). The 'Credential Guard configuration: 0x0, 0' message on scranton is a boot-time configuration event, not input capture.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:42.868Z | scranton.dmevals.local | windows.sysmon | process.command_line | consent.exe 3060 300 0000018832821060 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7Wisfl | q-10e88e37df | ok |
| 2 | 2020-05-02 03:21:27.124Z | scranton.dmevals.local | windows.sysmon | process.command_line | consent.exe 8384 306 000001E691026060 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx6_OHx | q-10e88e37df | ok |
| 3 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3yMh | q-a649ff9ca4 | ok |

### F14 · benign / medium · T1056.003 · No web portal capture: no IIS/wwwroot content written, no login-portal HTTP traffic

Evidence status: **verified**

No evidence of web portal capture. No Sysmon file-create events under wwwroot/inetpub or .aspx files (C076), no process command lines referencing iis/appcmd/wwwroot (C077), no 4663 object access to wwwroot/inetpub (C078), and no windows.other messages mentioning wwwroot/inetpub/IIS (C080). The two PowerShell hits for 'login' were a user-profile archive command (Compress-Archive over *.doc/*.pdf/*pass*/*login* files) run by pbeesly on scranton and nashua — collection/staging, not portal credential capture. Zeek HTTP checks for login/vpn/portal/sso URLs returned nothing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWIxak | q-d07406bcbd | ok |
| 2 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | host.name | nashua.dmevals.local | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMANA6l9 | q-d07406bcbd | ok |

### F15 · benign / high · T1110 · No brute-force authentication activity observed; only successful network logons from machine accounts

Evidence status: **verified**

The 218 LogonType 3 successes on newyork.dmevals.local are machine-account (NEWYORK$) logons from loopback/IPv6/10.0.0.4 with no preceding failures. All 4625/4771/4776/4648 checks returned zero hits in windows.security and windows.other, so there is no failed-logon burst, no password guessing, spraying or stuffing pattern in the collected window (2020-05-02 02:55-03:28Z).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Tx5qJ | q-142734d7fc | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | source.ip | 10.0.0.4 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Tx5qJ | q-142734d7fc | ok |
| 3 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | event.code | 4624 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Tx5qJ | q-142734d7fc | ok |

### F16 · benign / medium · T1110.001 · runas/hostui.exe elevation on scranton is local UAC elevation, not password guessing

Evidence status: **verified**

The single sysmon hit for runas/psexec/wmic command lines is pbeesly on scranton.dmevals.local launching 'powershell.exe -c "Start-Process C:\Windows\System32\hostui.exe -verb runas"' from hostui.bat at 03:21:19Z. This is a local privilege-elevation prompt (part of the hostui.bat/hostui.exe chain), not repeated credential guessing; no 4625 failures exist to support guessing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:19.323Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx6-sXC | q-9e17f6ca2e | ok |
| 2 | 2020-05-02 03:21:19.323Z | scranton.dmevals.local | windows.sysmon | host.name | scranton.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx6-sXC | q-9e17f6ca2e | ok |

### F18 · benign / high · T1110.003 · No password spraying: zero failed logons across all hosts

Evidence status: **verified**

All spraying checks (4625 by TargetUserName, by source.ip, 1-minute interval, and windows.other 4625) returned zero hits. The only authentication events in the window are successful 4624/4627/4634/4672 records, so no single-password-many-accounts pattern exists.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | event.code | 4624 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Tx5o4 | q-142734d7fc | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | source.ip | fe80::e40c:95b6:b0a7:6429 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Tx5o4 | q-142734d7fc | ok |

### F19 · benign / high · T1110.004 · No credential stuffing: no failed logons and no external credential-download tooling

Evidence status: **verified**

Credential-stuffing checks returned zero hits: no 4625 events by TargetUserName or IpAddress, and no curl/Invoke-WebRequest/wget process creations in windows.sysmon. The only credential object built in PowerShell (Invoke-Exfil on scranton) uses a single hardcoded account for a WebDAV upload to \\192.168.0.4\webdav, which is exfiltration staging rather than stuffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-4a6b178a2e | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | host.name | scranton.dmevals.local | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-4a6b178a2e | ok |

### F20 · benign / medium · T1111 · No MFA interception activity; credential-access-adjacent hits are certificate-store reads and PsExec explicit-credential logons

Evidence status: **verified**

Hunting for T1111 (Multi-Factor Authentication Interception) across windows.security, windows.sysmon, windows.powershell and windows.other on 2020-05-02 (02:55-03:28Z) found no MFA interception artifacts. The 16 registry hits on SmartCard/Crypto/Credential keys were all Sysmon event.code 12 (registry object access/read), not writes: SmartCardRoot certificate-store reads by powershell.exe, consent.exe, wmiprvse.exe, lsass.exe, rundll32.exe, WerFault.exe and svchost.exe on scranton.dmevals.local, plus normal boot-time Cryptography/CredentialGuard/CredentialEnrollmentManagerUserSvc value sets by smss.exe, lsass.exe, services.exe and taskhostw.exe. No script block referenced SmartCard, MFA, Telephony/TAPI, RADIUS/NPS, OTP, CredentialProvider, Winlogon, netsh or proxy (0 hits). The only 'token' process hit was the standard svchost.exe -k netsvcs -p -s TokenBroker service. The 15 event.code 4648 explicit-credential logons were PsExec service logons (C:\Windows\PSEXESVC.exe) using pbeesly's credentials on nashua.dmevals.local and scranton.dmevals.local, plus routine DWM-/UMFD-/machine-account logons from winlogon.exe, wininit.exe and taskhostw.exe. The two LogonType 10 (RDP) logons were pbeesly from 172.18.39.2 to scranton.dmevals.local with Negotiate/User32 - no smart-card or alternate MFA provider involved. The PowerShell 4104 hit that matched 'Credential' was an Invoke-Exfil function (7-Zip archive of Downloads, hardcoded cozy/MyCozyPassw0rd! credential, WebDAV upload to \\192.168.0.4\webdav) run as pbeesly on scranton.dmevals.local - that is exfiltration tooling, not MFA interception. The 7045 services were PSEXESVC and a Java VM support service. Note: the host does show other malicious activity (encoded/hidden PowerShell, hostui.exe runas, registry-stored Invoke-Expression, python.exe spawning powershell on nashua), but none of it targets MFA/token interception.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:14.969Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\S-1-5-21-1830255721-3727074217-2423397540-1107\Software\Microsoft\SystemCertificates\SmartCardRoot\CTLs | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7ZmIXh | q-23b98e005b | ok |
| 2 | 2020-05-02 02:56:14.969Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7ZmIXh | q-23b98e005b | ok |
| 3 | 2020-05-02 03:20:48.898Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\svchost.exe -k netsvcs -p -s TokenBroker | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx40qiu | q-91d03046da | ok |
| 4 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFR | q-928bee631d | ok |
| 5 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonType | 10 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8vSVsl | q-7c0e9b2984 | ok |
| 6 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.AuthenticationPackageName | Negotiate | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8vSVsl | q-7c0e9b2984 | ok |
| 7 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-59dc757db1 | ok |
| 8 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3iOg | q-13d5a6124e | ok |

### F23 · benign / high · T1187 · SMB share access and outbound 445 traffic are domain baseline, not forced authentication

Evidence status: **verified**

The high-volume SMB hits are normal domain behaviour. All 121 event 5145 share-access events involve only the domain infrastructure shares \\*\SYSVOL (56), \\*\IPC$ (45) and \\*\ADMIN$ (20), performed by machine accounts NEWYORK$ and SCRANTON$ from the DC address 10.0.0.4 and from fe80::e40c:95b6:b0a7:6429 — i.e. Group Policy/SYSVOL replication and admin-share access, not access to an attacker-controlled share. Outbound 445 Sysmon connections (66 total) go only to 10.0.0.4 (26), fe80::e40c:95b6:b0a7:6429 (24) and 10.0.1.6 (16); the 10.0.1.6 connections are periodic SYSTEM/process 'System' connections repeating roughly every 60-75 seconds from scranton and nashua, consistent with DC replication. Zeek SMB connections likewise terminate on 445 (45) and 139 (5) within the internal ranges. No SMB connection to an external or unusual host was observed, so these hits do not support forced authentication.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\SYSVOL | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Tx5o7 | q-881a991e7f | ok |
| 2 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | source.ip | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9KmX__ | q-881a991e7f | ok |
| 3 | 2020-05-02 03:10:23.315Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.1.6 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2jo9Kj | q-5a9a05c91c | ok |
| 4 | 2020-05-02 03:10:23.315Z | scranton.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2jo9Kj | q-5a9a05c91c | ok |

### F25 · benign / high · T1212 · Remaining LSASS handle requests are legitimate Windows components (svchost, wininit, csrss, services, AV/telemetry agents)

Evidence status: **verified**

Of 326 Sysmon event 10 accesses to lsass.exe, 289 came from C:\windows\system32\svchost.exe, 15 from the Azure IaaS Antimalware AntimalwareConfig.exe and 13 from WindowsAzureTelemetryService.exe. The high-mask svchost.exe accesses (0x101001) resolve through lsm.dll, the wininit.exe/csrss.exe/services.exe accesses occur in a single burst at 03:19:09Z with call traces inside wininit.exe/basesrv.DLL/CSRSRV.dll/RPCRT4.dll, and the 0x3000 svchost access resolves through sysmain.dll — all normal OS/AV behaviour, not exploitation. The 0x1000 accesses from powershell.exe at 03:01:03Z resolve through System.ni.dll managed code (PowerShell querying process information).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9def4\|c:\windows\system32\lsm.dll+1aa6e\|c:\windows\system32\lsm.dll+1a9c3\|c:\windows\system32\lsm.dll+65e1\|c:\windows\system32… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2QULdY | q-71f68590a2 | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\system32\basesrv.DLL+2fba\|C:\windows\SYSTEM32\CSRSRV.dll+5af4\|C:\windows\SYSTEM32\ntdll.dll+6cedf | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrt3 | q-71f68590a2 | ok |
| 3 | 2020-05-02 03:19:59.323Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|c:\windows\system32\sysmain.dll+1e689\|c:\windows\system32\sysmain.dll+1e509\|c:\… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx1ssmj | q-71f68590a2 | ok |
| 4 | 2020-05-02 03:19:13.337Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\services.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2MQMm5 | q-83515f5506 | ok |

### F26 · benign / high · T1539 · No web session cookie theft observed; cookie-path hits are benign OS noise and unrelated exfil tooling

Evidence status: **verified**

Hunting for T1539 across windows.sysmon, windows.security, windows.powershell, windows.other and zeek found no evidence of browser cookie/session-store theft. The 162 sysmon file-create hits for *Cookies*/*Login Data*/*Web Data* were almost entirely C:\windows\System32\svchost.exe writing C:\Windows\ServiceState\EventLog\Data\lastalive0.dat / lastalive1.dat on all four hosts (routine EventLog service state files). The only genuine cookie-path event was a single svchost.exe (PID 7200, SYSTEM) creation of C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-...\AC\INetCookies on scranton.dmevals.local at 2020-05-02T03:21:05Z, i.e. the Windows WARP JIT service's own LocalService INetCookies container, not a browser profile. No sysmon process-access (event 10) or file-create (11/23) event touched a Chrome/Firefox/Edge 'User Data' Cookies, Login Data, Web Data or Local State file, and no browser process (chrome/firefox/msedge/iexplore) appears in sysmon process creation or in any cookie-related command line. The 4 security 4688 hits were SearchProtocolHost.exe with the Windows Search user-agent string, and the 13 PowerShell 4104 hits were built-in module manifests / DSC resources on newyork.dmevals.local plus, on scranton.dmevals.local, pbeesly's Invoke-ScreenCapture and Invoke-Exfil functions (screenshotting, 7-Zip archiving of Downloads, WebDAV upload to \\192.168.0.4\webdav) - collection/exfiltration, not cookie theft. Zeek (2020-04-30, non-overlapping window) shows only Microsoft-WebDAV-MiniRedir/DavClnt traffic from 10.0.1.4 to 192.168.0.4 with PUT of /webdav/OfficeSupplies.7z, consistent with that exfil and with no HTTP cookie-replay pattern. T1539 is therefore not observed; the credential-access activity on these hosts lies elsewhere.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx56e_Q | q-709064ca4c | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx56e_Q | q-709064ca4c | ok |
| 3 | 2020-05-02 02:55:28.893Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceState\EventLog\Data\lastalive1.dat | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7anEhE | q-04be8622f1 | ok |
| 4 | 2020-05-02 02:57:01.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\SearchProtocolHost.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Txpr2 | q-3d0bff1166 | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-918109f0e7 | ok |
| 6 | 2020-05-02 03:05:45.000Z | scranton.dmevals.local | windows.powershell | message | Creating Scriptblock text (1 of 1):  <# PsTools Version in this package: 2.44 #> function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAPClpO | q-ce1a18890b | ok |
| 7 | 2020-04-30 00:32:22.010Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA04 | q-b2d7e434f7 | ok |
| 8 | 2020-04-30 00:35:25.658Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA01 | q-b2d7e434f7 | ok |

### F30 · benign / medium · T1552.002 · Registry credential-key writes are OS service activity, no attacker credential reads

Evidence status: **verified**

The 24 registry writes matching Password/Credential/Winlogon on nashua and scranton are made by legitimate system binaries (svchost.exe, winlogon.exe, wininit.exe, lsass.exe, services.exe) and touch benign values such as IdentityCRL ProviderPasswordLength, Winlogon LastLogOffEndTimePerfCounter, CredentialGuard Enabled=0 and CredentialEnrollmentManagerUserSvc service keys. No DefaultPassword/AutoLogon/vault/PuTTY/WinSCP credential values were written or read by attacker tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtv | q-d5eb4e791b | ok |
| 2 | 2020-05-02 03:19:49.485Z | scranton.dmevals.local | windows.sysmon | registry.data.strings | Credential Manager | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx1rWlK | q-15fad7471f | ok |

### F29 · benign / high · T1552.006 · SYSVOL/GPP file writes are routine Group Policy client processing

Evidence status: **verified**

All 22 SYSVOL/GPT hits on scranton.dmevals.local and nashua.dmevals.local are file-create events by C:\windows\system32\svchost.exe writing the local Group Policy DataStore cache (gpt.ini, GptTmpl.inf under Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}). No Groups.xml, cpassword, or attacker-driven SYSVOL access was observed; this is normal Group Policy refresh behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:18.009Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\gpt.ini | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2LOuo5 | q-a3503fff5c | ok |
| 2 | 2020-05-02 03:19:18.009Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2LOuo5 | q-a3503fff5c | ok |

### F32 · benign / high · T1555 · NASHUA wsmprovhost LSASS access with 0x1F3FFF explained by Get-Process -IncludeUserName

Evidence status: **verified**

On nashua.dmevals.local, wsmprovhost.exe (PID 7720, PowerShell remoting host started 03:09:23 as pbeesly) opened lsass.exe (PID 728) with GrantedAccess 0x1f3fff at 2020-05-02T03:09:29.430Z. The call trace runs through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll, and the corresponding script blocks at 03:09:28/03:09:29 are 'Get-Process -IncludeUserName \| Select-Object UserName,SessionId ...' — the documented cause of this access pattern. No credential-store or dump activity followed on that host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-8605f0995c | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-8605f0995c | ok |
| 3 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAMA2AH | q-094a09a612 | ok |

### F33 · benign / high · T1555 · Remaining LSASS handles (svchost, wininit, csrss, AV/telemetry) are standard system access

Evidence status: **verified**

The bulk of the 326 LSASS process-access events are svchost.exe (289, GrantedAccess 0x1000/0x1400/0x101001/0x3000 with lsm.dll and sysmain.dll call traces), Microsoft Azure antimalware/telemetry binaries, and the 03:19:09 wininit.exe/csrss.exe accesses with 0x1fffff/0x1000000 whose call traces are entirely inside wininit.exe/csrss.exe/basesrv.DLL/CSRSRV.dll — normal Windows startup/security-package behaviour. Security 4663 LSASS reads by CollectGuestLogs.exe and MsMpEng.exe (AccessMask 0x10) are likewise routine.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9def4\|c:\windows\system32\lsm.dll+1aa6e\|c:\windows\system32\lsm.dll+1a9c3\|c:\windows\system32\lsm.dll+65e1\|c:\windows\system32… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2QULdY | q-2a9d3aede0 | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\system32\basesrv.DLL+2fba\|C:\windows\SYSTEM32\CSRSRV.dll+5af4\|C:\windows\SYSTEM32\ntdll.dll+6cedf | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrt3 | q-2a9d3aede0 | ok |
| 3 | 2020-05-02 03:20:15.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Program Files\Windows Defender\MsMpEng.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL81VYSA | q-cb2bfaede2 | ok |

### F34 · benign / high · T1555.003 · No browser credential-store access observed

Evidence status: **verified**

No process creation, file creation, 4663 object access, PowerShell script block or other-channel event referenced browser credential files (Login Data, Cookies, Local State, logins.json) on any host. The only cookie-related file event was svchost.exe writing C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-...\AC\INetCookies at 03:21:05 on scranton, a normal LocalService INetCache artifact. The PowerShell hits that matched 'Credential' were the Invoke-Exfil script (which embeds a hard-coded PSCredential for a WebDAV share, not browser theft) and the xActiveDirectory DSC module MSFT_xADCommon.ps1 on newyork.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx56e_Q | q-396d331b4a | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-a7963e9232 | ok |

### F35 · benign / high · T1555.004 · No Windows Credential Manager / vault / DPAPI access observed

Evidence status: **verified**

No cmdkey, vaultcmd, credman or DPAPI command lines appeared in process creation (4688/sysmon 1), no registry event touched Vault/Credentials/Protect keys, and no 4624 LogonType 9 (NewCredentials) logons occurred. The only 'Credential' text in windows.other was the boot-time message 'Credential Guard configuration: 0x0, 0' on scranton at 23:19:09, which is a status report, not credential access. The PowerShell 'Credential' hits were the Invoke-Exfil PSCredential object and the xActiveDirectory DSC module.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3yMh | q-69d34901bf | ok |
| 2 | 2020-05-02 03:16:32.000Z | newyork.dmevals.local | windows.powershell | win.Path | C:\Program Files\WindowsPowerShell\Modules\xActiveDirectory\DscResources\MSFT_xADCommon\MSFT_xADCommon.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAOBekH | q-58894c606e | ok |

### F36 · benign / high · T1555.005 · No password-manager artifacts observed

Evidence status: **verified**

No process creation, file creation, PowerShell script block or other-channel event referenced KeePass (.kdbx), 1Password, LastPass or Bitwarden on any of the four hosts. The only archive-related activity was the attacker's own 7-Zip staging of $env:USERPROFILE\Downloads into $env:APPDATA\OfficeSupplies.7z on scranton, which is collection/exfiltration, not password-manager theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-a7963e9232 | ok |

### F38 · benign / medium · T1556.001 · No domain-controller authentication backdoor observed; LSASS module loads are Microsoft-signed

Evidence status: **verified**

The 33 image-load hits for lsass.exe/cryptdll.dll resolve to Microsoft-signed modules: cryptdll.dll loaded by SearchProtocolHost/SearchFilterHost/WmiPrvSE/svchost/dsregcmd/taskhostw etc. (Signature "Microsoft Windows", Signed true), and lsass.exe loading its own image plus samsrv.dll, cryptdll.dll and wdigest.dll at 03:19:09-03:19:10Z on scranton (all Microsoft-signed). No unsigned or non-System32 module was loaded into lsass.exe, and no 5136/4739 directory-service or policy-change events exist in the security log. The high-access LSASS handles from wininit.exe/csrss.exe (0x1fffff at 03:19:09Z) coincide with a boot/restart sequence on scranton, and the wsmprovhost.exe 0x1f3fff LSASS access on nashua has a call trace through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll (PowerShell cmdlet, not a credential dump). No evidence of DC authentication-process modification.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.850Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\samsrv.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2IKpCB | q-12d6862702 | ok |
| 2 | 2020-05-02 03:19:09.850Z | scranton.dmevals.local | windows.sysmon | win.Signature | Microsoft Windows | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2IKpCB | q-12d6862702 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|C:\windows\assembly\NativeImages_v4.0.30319_64\System\9803982d7bc887e2745bff18a43… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-6f9b8e3091 | ok |
| 4 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtr | q-77aeb3c1b9 | ok |

### F39 · benign / high · T1556.002 · No password-filter DLL registration found

Evidence status: **verified**

Registry writes touching Control\Lsa were limited to LsaCfgFlagsDefault, LsaPid and ProductType (single writes each); no write to HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages or any Password Filter value was observed, and no new DLL was created in System32/SysWOW64. No PowerShell script block or windows.other message referenced Notification Packages or Password Filter. The only LSA-adjacent DLL loads into lsass.exe were Microsoft-signed samsrv.dll/cryptdll.dll/wdigest.dll.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2IK5ET | q-12d6862702 | ok |
| 2 | 2020-05-02 03:19:10.196Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\wdigest.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2HKb5Z | q-12d6862702 | ok |

### F40 · benign / high · T1556.005 · Reversible-encryption PowerShell hit is the Microsoft xActiveDirectory DSC module, not account tampering

Evidence status: **verified**

The single 4104 hit matching Set-ADUser/Set-ADAccountControl/ReversibleEncryption on newyork.dmevals.local is script block cf4c3877-ec07-4e74-80b9-9258113f3933 running as NT AUTHORITY\SYSTEM from Path C:\Program Files\WindowsPowerShell\Modules\xActiveDirectory\DscResources\MSFT_xADCommon\MSFT_xADCommon.ps1 — the stock Microsoft xActiveDirectory DSC helper library (Get-CommonADParameters / ConvertFrom-TimeSpan functions). It is module documentation/helper code, not a command enabling AllowReversiblePasswordEncryption. No 4739 policy-change events, no process command line with AllowReversiblePasswordEncryption, and no windows.other message mentioning Reversible exist in the data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | win.Path | C:\Program Files\WindowsPowerShell\Modules\xActiveDirectory\DscResources\MSFT_xADCommon\MSFT_xADCommon.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMASEsOI | q-31baafe11c | ok |
| 2 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | user.name | SYSTEM | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMASEsOI | q-31baafe11c | ok |
| 3 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | win.ScriptBlockId | cf4c3877-ec07-4e74-80b9-9258113f3933 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMASEsOI | q-1901359ac0 | ok |

### F41 · benign / medium · T1556.006 · No MFA/authentication policy tampering; 4670 hits are routine token permission changes

Evidence status: **verified**

The security log contains no 4739 (domain policy change), 4738 (user account changed) or 5136 (directory attribute modified) events. The 143 hits for 4670 are 'Permissions on an object were changed' on Object Type: Token by machine accounts (SCRANTON$, NEWYORK$) via SearchIndexer.exe, svchost.exe and services.exe — normal service token DACL activity. The 4624 network logons are dominated by machine accounts (NEWYORK$ 123, SCRANTON$ 37, NASHUA$ 25) plus pbeesly (20), with no anomalous account or MFA-bypass pattern. No evidence of MFA or authentication-policy modification.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:57:01.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\SearchIndexer.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9TxprU | q-34435e6923 | ok |
| 2 | 2020-05-02 02:57:01.000Z | scranton.dmevals.local | windows.security | event.code | 4670 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9TxprU | q-34435e6923 | ok |

### F42 · benign / high · T1556.007 · Hybrid-identity DLL loads are stock Microsoft cloud-auth components

Evidence status: **verified**

The 18 hits for cloudap/aad/azure/ngc image loads are all Microsoft-signed (Signature "Microsoft Windows", Signed true): lsass.exe loading cloudAP.dll, aadcloudap.dll and MicrosoftAccountCloudAP.dll on scranton at 03:19:10Z, plus ngccredprov.dll/ngckeyenum.dll in LogonUI.exe, cryptngc.dll in explorer/svchost, ngcsvc.dll in svchost, and dsregcmd.exe activity. No file creation of cloudap/azuread/ngc DLLs was observed (zero hits), and no 5136/4739 directory changes exist. This is normal Windows Hello for Business / Azure AD join behaviour, not hybrid-identity backdooring.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:10.086Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\aadcloudap.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2HKb5i | q-978c62762a | ok |
| 2 | 2020-05-02 03:19:10.086Z | scranton.dmevals.local | windows.sysmon | win.Signature | Microsoft Windows | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2HKb5i | q-978c62762a | ok |
| 3 | 2020-05-02 03:19:10.040Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\cloudAP.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2HKb50 | q-978c62762a | ok |

### F43 · benign / medium · T1556.008 · No network provider DLL registration or credential-provider tampering observed

Evidence status: **verified**

No registry writes to NetworkProvider or credential-provider keys, no new DLL dropped into System32/SysWndrSvc paths, and no windows.other/security events referencing network provider packages were found in the retrieved data. The only credential-related activity is the malicious PowerShell LSASS access on scranton (reported under T1556) and pbeesly's PsExec-driven explicit-credential logons (4648 via C:\Windows\PSEXESVC.exe on nashua, 03:11-03:15Z), which are lateral-movement credential use rather than network-provider DLL installation.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFR | q-6d122dc921 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFR | q-6d122dc921 | ok |

### F44 · benign / medium · T1557 · No AiTM/relay activity observed; credential theft on scranton/nashua was direct (PowerShell + PsExec + python C2), not man-in-the-middle

Evidence status: **verified**

The T1557-family checks that fired were object-access/permission events (4656/4663/4670) and generic network stacks, none of which show interception. The 4663/4656 hits on scranton.dmevals.local are pbeesly's own PowerShell/cmd/conhost accessing LSA and Winlogon registry keys during the hands-on-keyboard intrusion (e.g. C:\ProgramData\victim\â€®cod.3aka3.scr, powershell.exe reading \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa) — that is local credential access, not AiTM. The 4624 logons on newyork.dmevals.local are machine-account (NEWYORK$) type-3 logons from ::1/fe80::/10.0.0.4, i.e. normal DC/service traffic. Zeek (2020-04-30 window, non-overlapping with the Windows data) shows only ordinary DNS/NB name resolution and SMB mapping to 10.0.0.4 with no rogue responder or relay evidence. The real intrusion chain is: pbeesly on scranton.dmevals.local ran Invoke-SeaDukeStage -ComputerName NASHUA, then repeatedly ran .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe", which spawned C:\Windows\Temp\python.exe on nashua.dmevals.local (parent C:\Windows\PSEXESVC.exe) making repeated outbound connections to 192.168.0.4:8443. Credentials were obtained by direct execution, not by poisoning/relay.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAOBExi | q-2fffb1171b | ok |
| 2 | 2020-05-02 03:14:42.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAOBvlS | q-2fffb1171b | ok |
| 3 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2in-NH | q-74fd8e7c45 | ok |
| 4 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2in-NH | q-74fd8e7c45 | ok |
| 5 | 2020-05-02 02:55:56.000Z | scranton.dmevals.local | windows.security | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9TypoS | q-5ed891d99b | ok |
| 6 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Tx5qJ | q-5eddece5e5 | ok |

### F45 · benign / medium · T1557.001 · No LLMNR/NBT-NS poisoning or SMB relay; SMB/NB traffic is routine and the lateral movement used explicit PsExec credentials

Evidence status: **verified**

The name-resolution and SMB checks returned only baseline traffic. Zeek DNS shows ordinary lookups (wpad.dmevals.local NXDOMAIN, wec.dmevals.local, _ldap._tcp SRV, arc.msn.com, www.bing.com) and NBNS broadcasts for SCRANTON/NASHUA to 10.0.1.255 — no rogue responder answering, no spoofed replies. SMB mapping/file records are all 10.0.1.4 / 10.0.1.6 -> 10.0.0.4 (the DC) with no relayed authentication. On the Windows side, the only service installations are PSEXESVC on nashua.dmevals.local (7045, %SystemRoot%\PSEXESVC.exe, user pbeesly) and a Java VM support service on scranton — the PSEXESVC installs are the result of the attacker's own PsExec64 invocation with a plaintext password, not of a relayed SMB session. No PowerShell script block referencing LLMNR/EnableMulticast/name-resolution poisoning was found (zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:35:03.399Z | simplerockbuild.simplerock.lan | zeek | dns.question.name | SCRANTON | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw29 | q-734a156a89 | ok |
| 2 | 2020-04-30 00:34:51.731Z | bobs.bigwheel.local | zeek | destination.ip | 10.0.1.255 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIK6WOc7y0JMA-MPUF | q-734a156a89 | ok |
| 3 | 2020-04-30 00:06:38.912Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 10.0.0.4 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw1R | q-d99547a55b | ok |
| 4 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | process.executable | %SystemRoot%\PSEXESVC.exe | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3iOg | q-fb26851fe3 | ok |
| 5 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | user.name | pbeesly | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3iOg | q-fb26851fe3 | ok |

### F46 · benign / high · T1557.002 · ARP cache inspection on scranton.dmevals.local is Azure guest-agent diagnostics, not ARP poisoning

Evidence status: **verified**

The only ARP-related activity is read-only 'arp.exe /a' execution on scranton.dmevals.local at 2020-05-02T03:19:25Z, 03:19:40Z and 03:20:04Z, each spawned by Azure infrastructure agents (C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe, WindowsAzureTelemetryService.exe, WaAppAgent.exe) alongside ipconfig.exe /all, route.exe print and netsh trace start/stop. These are the standard Azure VM guest-agent/NetworkWatcher diagnostic collection sequence, run as SYSTEM, and no ARP entry modification, gratuitous ARP or duplicate-MAC behaviour was observed. No ARP-poisoning tooling or 5156/5157 UDP anomalies were found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:25.370Z | scranton.dmevals.local | windows.sysmon | process.command_line | "arp.exe" /a | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2IKpDz | q-74fd8e7c45 | ok |
| 2 | 2020-05-02 03:19:25.370Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2IKpDz | q-74fd8e7c45 | ok |
| 3 | 2020-05-02 03:19:40.288Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx0p9y3 | q-74fd8e7c45 | ok |
| 4 | 2020-05-02 03:20:04.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\ARP.EXE | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8-b3HP | q-ffa2b0b0c3 | ok |

### F47 · benign / medium · T1557.003 · No DHCP spoofing or rogue DHCP server activity observed

Evidence status: **verified**

No DHCP-related events were found: the DHCP client/server operational checks (1341/1342/1020/1063) returned zero hits in windows.other, and no UDP 5156/5157 network events indicative of DHCP spoofing appeared in windows.security. Zeek shows only normal broadcast traffic (NBNS to 10.0.1.255, NetBIOS datagram to 10.0.1.255:138) and no rogue DHCP OFFER/ACK. The hosts' network configuration was only read (ipconfig /all, route print) by Azure guest agents on scranton.dmevals.local, not modified.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:32.208Z | nashua.dmevals.local | windows.sysmon | destination.port | 138 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7YlLAM | q-0d6818428f | ok |
| 2 | 2020-05-02 03:19:24.192Z | scranton.dmevals.local | windows.sysmon | process.command_line | "ipconfig.exe" /all | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2JL4RO | q-c8eeb314e5 | ok |
| 3 | 2020-05-02 03:19:24.192Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2JL4RO | q-c8eeb314e5 | ok |

### F50 · benign / medium · T1558.002 · No silver-ticket evidence: no forged service tickets or anomalous service-account logons

Evidence status: **verified**

All 4769 service-ticket requests on newyork.dmevals.local in the window are for machine accounts (NEWYORK$, NASHUA$, SCRANTON$, WEC$) and krbtgt, all with AES256 encryption (0x12) and status 0x0, originating from 10.0.1.4 and 10.0.1.6. No service account (e.g. a user SPN account) requested tickets, and no 4672 special-privilege logon target users were returned. The 4634 logoff distribution is 227 type-3 and 9 type-2, consistent with normal network/interactive sessions. The LSASS reads by PowerShell/wsmprovhost are malicious credential access but there is no evidence of forged service tickets being used.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NASHUA$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrnEj | q-2d232d4755 | ok |
| 2 | 2020-05-02 03:19:14.000Z | newyork.dmevals.local | windows.security | win.ServiceName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Cfa6D | q-2d232d4755 | ok |

### F51 · benign / medium · T1558.003 · No Kerberoasting: no RC4 TGS requests or service-account ticket bursts

Evidence status: **verified**

Kerberoasting would appear as a burst of 4769 requests for user/service SPNs with RC4 (0x17) encryption. In this window the DC newyork.dmevals.local logged only 4769 requests for machine accounts and krbtgt, all AES256 (0x12), and the zeek kerberos log (2020-04-30, non-overlapping window) shows 14 AS and 11 TGS requests, all for pbeesly/DMEVALS.LOCAL against krbtgt, cifs/NEWYORK, cifs/NASHUA, ldap/NEWYORK.dmevals.local and HTTP/NASHUA with aes256-cts-hmac-sha1-96. No roasting tooling (Rubeus, GetUserSPNs, Invoke-Kerberoast) appeared in process creation or PowerShell script blocks. The LSASS access on SCRANTON/NASHUA is malicious but is not Kerberoasting.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrnEj | q-2d232d4755 | ok |
| 2 | 2020-04-30 00:24:19.122Z | simplerockbuild.simplerock.lan | zeek | zeek.service | cifs/NEWYORK | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw1d | q-48f1adf6b3 | ok |
| 3 | 2020-04-30 00:24:19.122Z | simplerockbuild.simplerock.lan | zeek | zeek.cipher | aes256-cts-hmac-sha1-96 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw1d | q-48f1adf6b3 | ok |

### F52 · benign / medium · T1558.004 · No AS-REP roasting: all AS-REQs pre-authenticated, no roasting tooling

Evidence status: **verified**

AS-REP roasting requires AS-REQs for accounts without Kerberos pre-authentication. Every 4768 in the window (for pbeesly and SCRANTON$) carries PreAuthType 2, i.e. pre-authentication was performed, and the zeek kerberos log shows the expected KDC_ERR_PREAUTH_REQUIRED followed by a successful pre-authenticated AS exchange for pbeesly/DMEVALS.LOCAL. No Rubeus/GetNPUsers/ASREP activity was found in process creation or PowerShell script blocks (the dedicated ES\|QL checks returned zero rows).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFP | q-2d232d4755 | ok |
| 2 | 2020-04-30 00:24:19.110Z | simplerockbuild.simplerock.lan | zeek | zeek.error_msg | KDC_ERR_PREAUTH_REQUIRED | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw1f | q-48f1adf6b3 | ok |

### F54 · benign / medium · T1606.001 · No web cookie theft or forgery observed

Evidence status: **verified**

The cookie-focused check (4663 on *Cookies*) returned zero hits, and no PowerShell script block referenced cookies, SAML, ADFS, AADSSO, token duplication or impersonation (4104 search returned 0). The only web traffic in the Zeek window (2020-04-30, non-overlapping with the Windows data) is internal DNS lookups (newyork.dmevals.local, wpad.dmevals.local, wec.dmevals.local, _ldap._tcp.pdc._msdcs.dmevals.local) and TLS to 192.168.0.4 with a single internal issuer; the two HTTP requests are from 10.0.1.4 to 192.168.0.4. Nothing indicates cookie theft or forged session cookies.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:06:38.899Z | simplerockbuild.simplerock.lan | zeek | dns.question.name | newyork.dmevals.local | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw2z | q-3dd2838d0c | ok |
| 2 | 2020-04-30 00:24:18.964Z | simplerockbuild.simplerock.lan | zeek | dns.question.name | _ldap._tcp.pdc._msdcs.dmevals.local | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5- | q-3dd2838d0c | ok |

### F55 · benign / medium · T1606.002 · No SAML token forgery observed; logon activity is normal Kerberos/Advapi plus PsExec and RDP by pbeesly

Evidence status: **verified**

Successful logons (4624) are dominated by machine accounts and SYSTEM with LogonProcessName Kerberos (217) and Advapi (76); the rare values are a single NtLmSsp NTLM network logon (type 3) and two User32 type-10 logons for pbeesly from 172.18.39.2 on scranton.dmevals.local at 23:20:41-23:20:46, plus one '-' type-0 SYSTEM entry — consistent with normal RDP/console logon, not forged SAML assertions. Explicit-credential logons (4648) are pbeesly to NASHUA (10.0.1.6) and PSEXESVC.exe on nashua, plus standard DWM/UMFD/winlogon/taskhostw entries. No SAML/ADFS/AADSSO artifacts appear in PowerShell script blocks or file access events.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | NtLmSsp  | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8tQe-L | q-5025f96e0d | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | User32  | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8vSVsl | q-5025f96e0d | ok |
| 3 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | - | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL88axkf | q-5025f96e0d | ok |
| 4 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFV | q-6aaf67caab | ok |

### F56 · benign / high · T1621 · No MFA request generation observed; hosts show credential theft, lateral movement and archive collection instead

Evidence status: **verified**

Hunted all four Windows datasets (2020-05-02 02:55Z-03:28Z) for T1621 (Multi-Factor Authentication Request Generation). No MFA/authenticator/OTP/verification-prompt tooling or artifacts were found: a sysmon process-creation sweep for mfa/auth/otp/token/push/login/azure/dsregcmd command lines returned only benign Azure guest-agent and OS components (dsregcmd.exe launched by svchost -k netsvcs -p -s Schedule, TokenBroker/PushToInstall svchost services, CollectGuestLogs.exe, logman.exe, NetworkWatcherAgent.exe); a message-text sweep of windows.other for mfa/multi-factor/authenticator/one-time/verification code/phonefactor returned 0 rows; and the security log shows no failed-logon (4625) or NTLM (4776) burst that would accompany prompt bombing - only a single 4776 for pbeesly from workstation 10.0.1.4. The only interactive logons are two LogonType 10 (User32) events for pbeesly on scranton.dmevals.local from 172.18.39.2. The real attacker activity in this window is credential access and lateral movement, not MFA abuse: on scranton.dmevals.local user pbeesly ran PsExec64.exe from PowerShell four times with the plaintext password of dmevals\pbeesly to launch C:\Windows\Temp\python.exe on NASHUA (03:11:18, 03:12:25, 03:13:28, 03:14:42), each producing a 4648 explicit-credential logon on scranton (source 10.0.1.6) and nashua; on NASHUA the python.exe spawned powershell.exe and cmd.exe, ran a recursive file-collection script (ChildItem over *.doc/*.xls/*.pdf/*.zip/*pst/*psw*/*pass*/*login*/*vpn etc. into $env:APPDATA\working.zip) and staged it with .\Rar.exe a -hpfGzq5yKw to Desktop\working.zip; on scranton pbeesly also ran sdelete64.exe against C:\programdata\victim\???cod.3aka3.scr, Draft.Zip and SysinternalsSuite.zip. None of this constitutes MFA request generation.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ioON3 | q-c7003d3218 | ok |
| 2 | 2020-05-02 03:06:14.652Z | newyork.dmevals.local | windows.sysmon | process.command_line | C:\windows\System32\dsregcmd.exe $(Arg0) $(Arg1) $(Arg2) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2x8I_R | q-ec2bcf43fe | ok |
| 3 | 2020-05-02 03:06:14.652Z | newyork.dmevals.local | windows.sysmon | process.parent.command_line | C:\windows\system32\svchost.exe -k netsvcs -p -s Schedule | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2x8I_R | q-ec2bcf43fe | ok |
| 4 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMANA6l9 | q-e919bf758c | ok |
| 5 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | .\Rar.exe a -hpfGzq5yKw "$env:USERPROFILE\Desktop\working.zip" "$env:APPDATA\working.zip" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAOBfbr | q-4b66a27fe0 | ok |
| 6 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFV | q-b7d4b62bbf | ok |
| 7 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Workstation | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8xSa_z | q-b7d4b62bbf | ok |
| 8 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonType | 10 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8vSVsl | q-d0ecaeaf43 | ok |

### F58 · benign / high · T1649 · Benign certificate-store registry write and Kerberos TGT requests

Evidence status: **verified**

The 4657 on nashua is a SYSTEM Sysmon.exe write of an unreadable Blob under SystemCertificates\ROOT, and the 4768s on newyork are normal AES256 preauth krbtgt TGTs.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9FgwRA | q-e9a104693d | ok |
| 2 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFP | q-ab84a8da47 | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Signed Store app; only child is WerFault. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | Dropped in Temp, launched on NASHUA by PSEXESVC after PsExec with cleartext password; spawned the harvesting PowerShell. |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Password-protected the harvested working.zip, then was wiped with sdelete64. |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Anti-forensic wiping of Rar.exe, working.zip, the .scr dropper and Draft.Zip. |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure guest log collector; lsass handle 0x10 only. |
| newyork.dmevals.local | C:\Windows\System32\conhost.exe | 3 | C:\WindowsAzure\Packages\CollectGuestLogs.exe, C:\Windows\System32\cmd.exe, C:\W… | benign | Console host for cmd/dsregcmd. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher extension. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure antimalware extension config. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure Custom Script extension handler. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure domain-join extension. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Google updater service. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Run by pbeesly's PowerShell as part of the LSASS credential-access toolchain. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Used with cleartext domain password to run python.exe on NASHUA. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Anti-forensic wiping of dropper and staged archives on SCRANTON. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Defender service; lsass handle 0x10. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Defender network inspection service. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Dropper executed by explorer as pbeesly with /S, spawning cmd.exe. |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Compiled attacker C# DLLs from temp cmdline files under hidden PowerShell. |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Unsigned non-Microsoft binary in System32 launched elevated via -verb runas. |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | Three launches by cmd.exe just before compilation and .lnk writes; known UAC-bypass binary. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent firewall helper. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure volume discovery helper. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure guest agent service. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | 1 | C:\Windows\System32\services.exe | benign | Azure telemetry service. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\WaAppAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure Windows Agent service. |
| scranton.dmevals.local | C:\WindowsAzure\SecAgent\WaSecAgentProv.exe | 2 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure security agent provider. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\Plugins\VFPl… | 1 | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | benign | Azure network agent plugin. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | 1 | C:\Windows\System32\services.exe | benign | Azure network agent service. |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | pbeesly's PowerShell on scranton and nashua harvested credential-named files (*pass*, *login*, *vpn, *psw*) and archived them, alongside Sysinternals download, shellcode/PE in-memory loaders and a hidden encoded command … |
| T1003.001 LSASS Memory | suspicious | Extra 0x1000 LSASS handle by PowerShell on SCRANTON; full-access handles already anchored. |
| T1003.002 Security Account Manager | not_observed | No SAM hive object access, no reg save/esentutl/ntdsutil command lines in Sysmon or Security process creation. |
| T1003.003 NTDS | not_observed | No NTDS.dit access or ntdsutil/vssadmin; Zeek drsuapi traffic is only Bind/CrackNames/Unbind with no DsGetNCChanges. |
| T1003.004 LSA Secrets | benign | All LSA secret reads are LOCAL SERVICE querying Policy\Secrets\$MACHINE.ACC (AccessMask 0x2) on nashua/scranton/utica — routine OS machine-account access. |
| T1003.005 Cached Domain Credentials | not_observed | No object access to any Cache registry path or SECURITY\Cache hive. |
| T1003.006 DCSync | suspicious | One 4662 on newyork.dmevals.local shows DS-Replication-Get-Changes (1131f6aa) access, but by the host's own machine account NEWYORK$ on itself and only once; no DsGetNCChanges in Zeek and no dcsync/lsadump strings, so DC… |
| T1040 Network Sniffing | benign | The only packet-capture behaviour observed is a bounded netsh.exe 'trace start capture=yes' / 'trace stop' pair on scranton.dmevals.local, both spawned by the Microsoft-signed (win.Company 'Microsoft CoreXT') Azure Netwo… |
| T1056 Input Capture | malicious | .scr dropper executed by pbeesly on SCRANTON (anchor). |
| T1056.001 Keylogging | not_observed | No hook/keylog DLL loads, no GetAsyncKeyState/SetWindowsHookEx script blocks, no keyboard-layout persistence or keylogger service; only benign Preload and WindowsDefender Run writes. |
| T1056.002 GUI Input Capture | benign | All credential/prompt/consent matches were Microsoft consent.exe UAC prompts launched by SYSTEM; no fake credential dialogs from user-writable paths. |
| T1056.003 Web Portal Capture | not_observed | No wwwroot/inetpub file writes, no IIS/appcmd activity, no object access to web roots and no login/portal HTTP traffic in Zeek. |
| T1056.004 Credential API Hooking | malicious | powershell.exe PID 2976 (running a VirtualAlloc/CreateThread shellcode loader) created a remote thread inside lsass.exe on scranton, and a second powershell opened 0x1000 handles to lsass/winlogon while enumerating token… |
| T1110 Brute Force | not_observed | No failed-logon events (4625/4771/4776/4648) in windows.security or windows.other; the 218 LogonType 3 successes are machine-account (NEWYORK$) logons from loopback/IPv6/10.0.0.4 with no failure burst. |
| T1110.001 Password Guessing | not_observed | Only runas-related hit is a local UAC elevation of hostui.exe by pbeesly on scranton; no repeated credential attempts and no 4625 failures to support guessing. |
| T1110.002 Password Cracking | suspicious | Credential material was harvested on scranton (PowerShell.exe as SYSTEM opening lsass.exe with 0x1f3fff/0x1fffff, wsmprovhost.exe opening lsass on nashua, Get-PrivateKeys exporting .pfx with hardcoded password, hardcoded… |
| T1110.003 Password Spraying | not_observed | All spraying checks (4625 by user, by source IP, 1-minute interval, windows.other) returned zero hits; only successful logons present. |
| T1110.004 Credential Stuffing | not_observed | No 4625 by TargetUserName/IpAddress and no curl/Invoke-WebRequest/wget process creations; the only PSCredential use is a single hardcoded account for WebDAV exfiltration staging. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA interception artifacts in any dataset. SmartCard/Crypto/Credential registry hits were all Sysmon event.code 12 reads (SmartCardRoot certificate store accessed by powershell.exe, consent.exe, wmiprvse.exe, lsass.ex… |
| T1187 Forced Authentication | malicious | WebDAV share mapped with hardcoded creds for exfil (anchor). |
| T1212 Exploitation for Credential Access | suspicious | On scranton.dmevals.local the pbeesly PowerShell stager (PID 2976, hidden -ep bypass, shellcode decoded from monkey.png and run via VirtualAlloc/CreateThread) opened lsass.exe with 0x1f3fff and 0x1fffff and UNKNOWN call … |
| T1539 Steal Web Session Cookie | not_observed | No browser cookie/session store was read, copied or replayed. The 162 sysmon file-create hits were svchost.exe writing EventLog lastalive*.dat files; the single INetCookies event was the WARP JIT service's own LocalServi… |
| T1552 Unsecured Credentials | malicious | Unsecured credentials harvested: hardcoded passwords in scripts (saribas, lolol, MyCozyPassw0rd!, Fl0nk3rt0n!T0by) and certificate exports staged/exfiltrated. |
| T1552.001 Credentials In Files | malicious | Credential-named file harvesting plus password-protected RAR on NASHUA and cleartext passwords in PsExec and Invoke-Exfil. |
| T1552.002 Credentials in Registry | benign | Registry credential-key writes were all by legitimate system processes (svchost, winlogon, lsass, services); no attacker credential reads. |
| T1552.003 Shell History | not_observed | No ConsoleHost_history, Get-History or history file access in any dataset. |
| T1552.004 Private Keys | malicious | Get-PrivateKeys exported LocalMachine certs to .pfx on SCRANTON (anchor). |
| T1552.006 Group Policy Preferences | benign | SYSVOL/GPT file writes were routine Group Policy client (svchost.exe) DataStore caching; no Groups.xml/cpassword access. |
| T1555 Credentials from Password Stores | suspicious | On scranton.dmevals.local an interactive pbeesly PowerShell.exe (PID 2976) opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff at 03:05:16 with UNKNOWN-module call traces, immediately after running accesschk.exe an… |
| T1555.003 Credentials from Web Browsers | not_observed | No access to browser credential stores (Login Data, Cookies, Local State, logins.json) in process creation, file creation, 4663, PowerShell or other-channel logs; the single INetCookies write was a LocalService svchost a… |
| T1555.004 Windows Credential Manager | suspicious | Unsigned hostui.exe launched elevated from PowerShell on SCRANTON. |
| T1555.005 Password Managers | not_observed | No KeePass/1Password/LastPass/Bitwarden references in any dataset; only attacker 7-Zip staging of the Downloads folder was seen. |
| T1556 Modify Authentication Process | malicious | Hidden, EP-bypassed PowerShell (PID 2976, parent control.exe) decoded a steganographic payload from C:\Users\pbeesly\Downloads\monkey.png, compiled code via csc.exe from Temp\qkbkqqbs, and opened lsass.exe with 0x1f3fff/… |
| T1556.001 Domain Controller Authentication | benign | All lsass.exe/cryptdll.dll module loads are Microsoft-signed System32 DLLs; no 5136/4739 directory or policy changes; wsmprovhost LSASS access has a PowerShell-cmdlet call trace. |
| T1556.002 Password Filter DLL | not_observed | No writes to LSA Notification Packages or Password Filter values and no new DLLs in System32/SysWOW64; only LsaCfgFlagsDefault/LsaPid/ProductType writes. |
| T1556.005 Reversible Encryption | benign | The only matching 4104 script block is the stock Microsoft xActiveDirectory DSC module MSFT_xADCommon.ps1 run as SYSTEM; no 4739 events or reversible-encryption commands. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739/4738/5136 events; 4670 hits are routine token DACL changes by SearchIndexer/svchost/services on machine accounts. |
| T1556.007 Hybrid Identity | benign | cloudAP/aadcloudap/MicrosoftAccountCloudAP/ngc DLL loads are Microsoft-signed Windows Hello/Azure AD join components; no cloudap/azuread file creation or directory changes. |
| T1556.008 Network Provider DLL | not_observed | No network-provider or credential-provider DLL registration, registry writes, or dropped provider DLLs in the retrieved data. |
| T1557 Adversary-in-the-Middle | not_observed | No interception/relay evidence. The 4663/4656 hits are pbeesly's own PowerShell/cmd access to LSA/Winlogon registry keys on scranton (local credential access), and 4624s on newyork are machine-account type-3 logons. The … |
| T1557.001 Name Resolution Poisoning and SMB Relay | not_observed | Zeek shows only routine DNS/NBNS lookups (wpad NXDOMAIN, SCRANTON/NASHUA NB broadcasts) and SMB mapping to the DC 10.0.0.4; no rogue responder or relayed authentication. PSEXESVC service installs on nashua are the attack… |
| T1557.002 ARP Cache Poisoning | benign | Only read-only 'arp.exe /a' on scranton.dmevals.local, spawned by Azure GuestAgent/Telemetry/WaAppAgent alongside ipconfig/route/netsh trace — standard Azure VM diagnostics. No ARP cache modification or poisoning tooling… |
| T1557.003 DHCP Spoofing | not_observed | Zero hits for DHCP client/server events (1341/1342/1020/1063) and no UDP 5156/5157 anomalies; only normal broadcast NBNS/NetBIOS traffic and read-only ipconfig /all by Azure agents. |
| T1558 Steal or Forge Kerberos Tickets | malicious | Hidden PowerShell implant on scranton.dmevals.local (PID 2976, parent control.exe, steganographic monkey.png payload) opened lsass.exe with 0x1F3FFF and 0x1FFFFF at 03:05:16, and wsmprovhost.exe on nashua.dmevals.local o… |
| T1558.001 Golden Ticket | suspicious | LSASS access that could yield krbtgt material is present, but no forged-TGT indicators: all 4768 are pre-authenticated (PreAuthType 2) AES256 requests for pbeesly/SCRANTON$, no anomalous privileged logons or 4672 target … |
| T1558.002 Silver Ticket | benign | All 4769 requests are for machine accounts and krbtgt with AES256 and status 0x0; no service-account tickets or forged-ticket logon anomalies observed. |
| T1558.003 Kerberoasting | benign | No RC4 (0x17) TGS requests, no service-account SPN ticket burst, and no Kerberoasting tooling in process creation or PowerShell script blocks. |
| T1558.004 AS-REP Roasting | benign | All AS-REQs show PreAuthType 2 (pre-authentication performed) and no Rubeus/GetNPUsers/ASREP activity was found in Sysmon or PowerShell telemetry. |
| T1606 Forge Web Credentials | not_observed | No forged web credential artifacts: no SAML/cookie/token-forgery script blocks, no anomalous LogonProcessName, no SSO/ADFS endpoints. Credential-access precursor (PowerShell->LSASS 0x1f3fff/0x1fffff on scranton, cert pri… |
| T1606.001 Web Cookies | not_observed | 4663 cookie-file check returned zero hits; no cookie/session-token handling in PowerShell; Zeek window (non-overlapping) shows only internal DNS/TLS/HTTP to 192.168.0.4. |
| T1606.002 SAML Tokens | not_observed | Logons are normal Kerberos/Advapi machine and SYSTEM accounts plus pbeesly NTLM/RDP and PsExec 4648 to NASHUA; no SAML/ADFS/AADSSO artifacts in any retrieved event. |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | No MFA/authenticator/OTP/verification-prompt generation artifacts in any dataset: sysmon process-creation sweep for mfa/auth/otp/token/push/login/azure/dsregcmd returned only benign Azure guest-agent and OS components (d… |
| T1649 Steal or Forge Authentication Certificates | malicious | Certificate export to .pfx on SCRANTON (anchor). |

## Context (outside the hypothesis)

Activity reported under techniques outside the hypothesis' scope. Not verified, not part of the verdict.

- T1027 · malicious/high · csc.exe compiles attacker C# from temp cmdline files on SCRANTON (pivot)
- T1548 · suspicious/low · sdclt.exe launched three times by cmd.exe on SCRANTON (pivot)

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 0 hits | 0 hits | 5797 hits | 39730 hits | 2140 hits |
| T1003.001 LSASS Memory | 0 hits | 0 hits | 934 hits | 326 hits | n/a |
| T1003.002 Security Account Manager | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.003 NTDS | 0 hits | 0 hits | 0 hits | 0 hits | 135 hits |
| T1003.004 LSA Secrets | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.005 Cached Domain Credentials | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.006 DCSync | 0 hits | 0 hits | 14 hits | 326 hits | 255 hits |
| T1040 Network Sniffing | 5 hits | 0 hits | 461 hits | 2 hits | 1226 hits |
| T1056 Input Capture | 2 hits | 0 hits | 19 hits | 821 hits | 135 hits |
| T1056.001 Keylogging | 5 hits | 0 hits | 6 hits | 474 hits | 896 hits |
| T1056.002 GUI Input Capture | 2 hits | 414 hits | 460 hits | 450 hits | 124 hits |
| T1056.003 Web Portal Capture | 0 hits | 2 hits | 0 hits | 0 hits | 124 hits |
| T1056.004 Credential API Hooking | 0 hits | 3 hits | 6 hits | 60014 hits | n/a |
| T1110 Brute Force | 0 hits | 4 hits | 218 hits | 0 hits | n/a |
| T1110.001 Password Guessing | 0 hits | 4 hits | 0 hits | 1 hits | n/a |
| T1110.002 Password Cracking | 1 hits | 0 hits | 4494 hits | 329 hits | n/a |
| T1110.003 Password Spraying | 0 hits | 2 hits | 15 hits | 1 hits | n/a |
| T1110.004 Credential Stuffing | 0 hits | 2 hits | 218 hits | 0 hits | n/a |
| T1111 Multi-Factor Authentication Interception | 5 hits | 3 hits | 312 hits | 39299 hits | n/a |
| T1187 Forced Authentication | 4 hits | 0 hits | 11098 hits | 69 hits | 86 hits |
| T1212 Exploitation for Credential Access | 6 hits | 0 hits | 0 hits | 652 hits | 35 hits |
| T1539 Steal Web Session Cookie | 4 hits | 13 hits | 4 hits | 162 hits | 2 hits |
| T1552 Unsecured Credentials | 4 hits | 4 hits | 0 hits | 96 hits | 12 hits |
| T1552.001 Credentials In Files | 4 hits | 0 hits | 312 hits | 49 hits | 12 hits |
| T1552.002 Credentials in Registry | 0 hits | 5 hits | 0 hits | 20 hits | n/a |
| T1552.003 Shell History | 5 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1552.004 Private Keys | 0 hits | 1 hits | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1555 Credentials from Password Stores | 0 hits | 3 hits | 6 hits | 653 hits | n/a |
| T1555.003 Credentials from Web Browsers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1555.004 Windows Credential Manager | 2 hits | 3 hits | 0 hits | 326 hits | n/a |
| T1555.005 Password Managers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556 Modify Authentication Process | 0 hits | 0 hits | 0 hits | 711 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | 0 hits | 233 hits | 359 hits | n/a |
| T1556.002 Password Filter DLL | 0 hits | 0 hits | 0 hits | 18869 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 1 hits | 0 hits | 0 hits | n/a |
| T1556.006 Multi-Factor Authentication | 0 hits | 0 hits | 41145 hits | 0 hits | n/a |
| T1556.007 Hybrid Identity | 0 hits | 1 hits | 41299 hits | 18 hits | n/a |
| T1556.008 Network Provider DLL | 1 hits | 0 hits | 36 hits | 0 hits | n/a |
| T1557 Adversary-in-the-Middle | 0 hits | 0 hits | 16457 hits | 0 hits | 2215 hits |
| T1557.001 Name Resolution Poisoning and SMB Relay | 5 hits | 0 hits | 320 hits | 0 hits | 642 hits |
| T1557.002 ARP Cache Poisoning | 0 hits | 0 hits | 44205 hits | 0 hits | 613 hits |
| T1557.003 DHCP Spoofing | 216 hits | 0 hits | 0 hits | 81 hits | 2140 hits |
| T1558 Steal or Forge Kerberos Tickets | 9 hits | 0 hits | 448 hits | 652 hits | 35 hits |
| T1558.001 Golden Ticket | 5 hits | 0 hits | 509 hits | 326 hits | 35 hits |
| T1558.002 Silver Ticket | 9 hits | 0 hits | 448 hits | 326 hits | 35 hits |
| T1558.003 Kerberoasting | 5 hits | 0 hits | 509 hits | 326 hits | 35 hits |
| T1558.004 AS-REP Roasting | 5 hits | 0 hits | 297 hits | 447 hits | 35 hits |
| T1606 Forge Web Credentials | 0 hits | 0 hits | 312 hits | 39283 hits | 793 hits |
| T1606.001 Web Cookies | 0 hits | 0 hits | 297 hits | 0 hits | n/a |
| T1606.002 SAML Tokens | 0 hits | 0 hits | 312 hits | 0 hits | n/a |
| T1621 Multi-Factor Authentication Request Generatio… | 0 hits | 0 hits | 0 hits | 447 hits | n/a |
| T1649 Steal or Forge Authentication Certificates | 0 hits | 0 hits | 50 hits | 0 hits | n/a |

Cells: 265, gaps: 0.

## Queries

Every MCP tool call of this run (1383), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-2e95c93a3e | scope | list_data_sources | {} | None |  |
| q-446e847b21 | scope | get_registry | {} | None |  |
| q-fae42637d2 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-5dfb46cb40 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-6660c97c2e | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-cf360fea03 | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-7faa4960fc | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-7a8da356ff | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-c7d82aecb4 | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-cbb92fa70e | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5337 |  |
| q-1a0297a15d | check C004 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-061fd2f2d1 | check C005 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*s… | ERROR |  |
| q-e5c88d5073 | check C005 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*s… | ERROR |  |
| q-4c7b244a9c | check C006 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*lsass*\" OR TO_LOWER(message) LIKE \"*sam*\" OR TO_LOWER(message) LIKE \"*ntds*\" OR TO_LOWER(message) LIKE \"*minidump*\" OR TO_LOWER(process.executable) LIKE \"*dump*\" \| … | ERROR |  |
| q-082ad7d403 | check C006 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*lsass*\" OR TO_LOWER(message) LIKE \"*sam*\" OR TO_LOWER(message) LIKE \"*ntds*\" OR TO_LOWER(message) LIKE \"*minidump*\" OR TO_LOWER(process.executable) LIKE \"*dump*\" \| … | ERROR |  |
| q-029371b696 | check C007 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-6eaf55a903 | check C008 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 10 AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, win.SourceImage, _id, _index"} | ERROR |  |
| q-5a3a1958e6 | check C008 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 10 AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, win.SourceImage, _id, _index"} | ERROR |  |
| q-b9ed1391f7 | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-3c0600553c | check C010 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(file.path) LIKE \"*.dmp*\" OR TO_LOWER(file.path) LIKE \"*lsass*\") \| KEEP @timestamp, host.name, process.executable, file.path, _id, _index"} | ERROR |  |
| q-334b849d1a | check C010 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(file.path) LIKE \"*.dmp*\" OR TO_LOWER(file.path) LIKE \"*lsass*\") \| KEEP @timestamp, host.name, process.executable, file.path, _id, _index"} | ERROR |  |
| q-f65f4e86b5 | check C011 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*comsvcs*\" OR TO_LOWER(process.command_line) LIKE \"*minidump*\" OR TO_LOWER(process.command_line) LIKE \"*procdump*\" OR TO_LOWER(process.… | ERROR |  |
| q-cd47080dda | check C011 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*comsvcs*\" OR TO_LOWER(process.command_line) LIKE \"*minidump*\" OR TO_LOWER(process.command_line) LIKE \"*procdump*\" OR TO_LOWER(process.… | ERROR |  |
| q-d450605273 | check C012 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 13 AND TO_LOWER(registry.path) LIKE \"*lsa*\" \| KEEP @timestamp, host.name, process.executable, registry.path, registry.data.strings, _id, _index"} | ERROR |  |
| q-cf89607c17 | check C012 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 13 AND TO_LOWER(registry.path) LIKE \"*lsa*\" \| KEEP @timestamp, host.name, process.executable, registry.path, registry.data.strings, _id, _index"} | ERROR |  |
| q-99be8432fb | check C013 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 934 |  |
| q-a753c38cfc | check C014 | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == 4656 AND TO_LOWER(win.ObjectName) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.ObjectName, win.AccessMask, _id, _index"} | ERROR |  |
| q-20267fd488 | check C014 (repaired) | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == 4656 AND TO_LOWER(win.ObjectName) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.ObjectName, win.AccessMask, _id, _index"} | ERROR |  |
| q-83caa125c8 | check C015 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*i… | ERROR |  |
| q-76d8bed9b9 | check C015 (repaired) | esql | {"query": "FROM windows-powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" OR TO_LOWER(win.ScriptBlockText) L… | ERROR |  |
| q-81c45af59a | check C016 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*lsass*\" OR TO_LOWER(process.executable) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, event.code, message, process.executable, _id, _index"} | ERROR |  |
| q-ae22e004e3 | check C016 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*lsass*\" OR TO_LOWER(process.executable) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, event.code, message, process.executable, _id, _index"} | ERROR |  |
| q-b353e3d44e | check C017 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*hklm\\\\sam*\" OR TO_LOWER(process.command_line) LIKE \"*hklm\\\\security*\" OR TO_LO… | ERROR |  |
| q-df134929f9 | check C017 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*hklm\\\\\\\\sam*\" OR TO_LOWER(process.command_line) LIKE \"*hklm\\\\\\\\security*\" … | ERROR |  |
| q-25ecdb0c1e | check C018 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(file.path) LIKE \"*\\\\sam*\" OR TO_LOWER(file.path) LIKE \"*\\\\security*\" OR TO_LOWER(file.path) LIKE \"*\\\\system*\" OR TO_LOWER(file.path) LIKE \"*.hiv*\") \| KEE… | ERROR |  |
| q-23590d25d4 | check C018 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(file.path) LIKE \"*sam*\" OR TO_LOWER(file.path) LIKE \"*security*\" OR TO_LOWER(file.path) LIKE \"*system*\" OR TO_LOWER(file.path) LIKE \"*.hiv*\") \| KEEP @timestamp… | ERROR |  |
| q-27f63ff945 | check C019 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 2 AND TO_LOWER(file.path) LIKE \"*\\\\config\\\\*\" \| KEEP @timestamp, host.name, process.executable, file.path, win.PreviousCreationUtcTime, _id, _index"} | ERROR |  |
| q-a370b28599 | check C019 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 2 AND TO_LOWER(file.path) LIKE \"*config*\" \| KEEP @timestamp, host.name, process.executable, file.path, win.PreviousCreationUtcTime, _id, _index"} | ERROR |  |
| q-e59b79117a | check C020 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 13 AND (TO_LOWER(registry.path) LIKE \"*\\\\sam\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\security\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\system\\\\*\") \| KEEP @timestamp, h… | ERROR |  |
| q-d493b3335e | check C020 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 13 AND (TO_LOWER(registry.path) LIKE \"*\\\\\\\\sam\\\\\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\\\\\security\\\\\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\\\\\system\\\\\\\\*\… | ERROR |  |
| q-85888ad62a | check C021 | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == 4688 AND (TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*reg.exe*\" OR TO_LOWER(process.command_line) LIKE \"*sam*\" OR TO_LOWER(process.… | ERROR |  |
| q-1fa2ffed3e | check C021 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4688 AND (TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*reg.exe*\" OR TO_LOWER(process.command_line) LIKE \"*sam*\" OR TO_L… | ERROR |  |
| q-cd0121c0e8 | check C022 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectName:*SAM*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-38f879fd2c | check C023 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*reg save*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*hklm\\\\sam*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*hklm\\\\security*\" OR TO_LOWER(process.command_… | ERROR |  |
| q-3cf405e502 | check C023 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*reg save*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*hklm\\\\\\\\sam*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*hklm\\\\\\\\security*\" OR TO_LOWER(process.… | ERROR |  |
| q-c841cf10ab | check C024 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*sam*\" OR TO_LOWER(message) LIKE \"*hive*\" OR TO_LOWER(process.executable) LIKE \"*reg*\" \| KEEP @timestamp, host.name, event.code, message, process.executable, _id, _index… | ERROR |  |
| q-e32551049f | check C024 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*sam*\" OR TO_LOWER(message) LIKE \"*hive*\" OR TO_LOWER(process.executable) LIKE \"*reg*\" \| KEEP @timestamp, host.name, event.code, message, process.executable, _id, _index… | ERROR |  |
| q-83c7889e87 | check C025 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*ntdsutil*\" OR TO_LOWER(process.command_line) LIKE \"*ntds.dit*\" OR TO_LOWER(process.command_line) LIKE \"*vssadmin*\" OR TO_LOWER(process… | ERROR |  |
| q-64dd3c56b9 | check C025 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*ntdsutil*\" OR TO_LOWER(process.command_line) LIKE \"*ntds.dit*\" OR TO_LOWER(process.command_line) LIKE \"*vssadmin*\" OR TO_LOWER(process… | ERROR |  |
| q-2f8016b677 | check C026 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(file.path) LIKE \"*ntds.dit*\" OR TO_LOWER(file.path) LIKE \"*ntds*\" OR TO_LOWER(file.path) LIKE \"*.dit*\") \| KEEP @timestamp, host.name, process.executable, file.pa… | ERROR |  |
| q-94e313e06e | check C026 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(file.path) LIKE \"*ntds.dit*\" OR TO_LOWER(file.path) LIKE \"*ntds*\" OR TO_LOWER(file.path) LIKE \"*.dit*\") \| KEEP @timestamp, host.name, process.executable, file.pa… | ERROR |  |
| q-3295b59729 | check C027 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 2 AND TO_LOWER(file.path) LIKE \"*ntds*\" \| KEEP @timestamp, host.name, process.executable, file.path, win.PreviousCreationUtcTime, _id, _index"} | ERROR |  |
| q-86827195fb | check C027 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 2 AND TO_LOWER(file.path) LIKE \"*ntds*\" \| KEEP @timestamp, host.name, process.executable, file.path, win.PreviousCreationUtcTime, _id, _index"} | ERROR |  |
| q-5317fc3f01 | check C028 | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == 4688 AND (TO_LOWER(process.command_line) LIKE \"*ntdsutil*\" OR TO_LOWER(process.command_line) LIKE \"*vssadmin*\" OR TO_LOWER(process.command_line) LIKE \"*diskshadow*\" OR TO_LOWER(… | ERROR |  |
| q-48f986ea6f | check C028 (repaired) | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == 4688 AND (TO_LOWER(process.command_line) LIKE \"*ntdsutil*\" OR TO_LOWER(process.command_line) LIKE \"*vssadmin*\" OR TO_LOWER(process.command_line) LIKE \"*diskshadow*\" OR TO_LOWER(… | ERROR |  |
| q-f93b7f79bb | check C029 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*shadow*\" OR TO_LOWER(message) LIKE \"*ntds*\" OR TO_LOWER(message) LIKE \"*vss*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-44916effa0 | check C029 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*shadow*\" OR TO_LOWER(message) LIKE \"*ntds*\" OR TO_LOWER(message) LIKE \"*vss*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-36cdcdd42a | check C030 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*ntds*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*vssadmin*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*diskshadow*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*… | ERROR |  |
| q-35dde6bd00 | check C030 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*ntds*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*vssadmin*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*diskshadow*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*… | ERROR |  |
| q-dd47e8a753 | check C031 | esql | {"query": "FROM zeek METADATA _id, _index \| WHERE event.action == \"smb_files\" OR event.action == \"dce_rpc\" \| KEEP @timestamp, observer.name, event.action, zeek.filename, zeek.path, zeek.name, source.ip, destination.ip, _id, _index"} | ERROR |  |
| q-5dc342fc1b | check C031 (repaired) | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"smb_files\" OR event.action == \"dce_rpc\" \| KEEP @timestamp, observer.name, event.action, zeek.filename, zeek.path, zeek.name, source.ip, destination.ip, _id, _index"} | 135 |  |
| q-142a5af1f3 | check C032 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*hklm\\\\security*\" OR TO_LOWER(process.command_line) LIKE \"*secrets*\" OR TO_LOWER(… | ERROR |  |
| q-41c7b26203 | check C032 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*hklm\\\\\\\\security*\" OR TO_LOWER(process.command_line) LIKE \"*secrets*\" OR TO_LO… | ERROR |  |
| q-9a16686928 | check C033 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 13 AND TO_LOWER(registry.path) LIKE \"*\\\\security\\\\policy\\\\secrets*\" \| KEEP @timestamp, host.name, process.executable, registry.path, registry.data.strings, _id, _index"} | ERROR |  |
| q-27908d8740 | check C033 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 13 AND TO_LOWER(registry.path) LIKE \"*security\\\\\\\\policy\\\\\\\\secrets*\" \| KEEP @timestamp, host.name, process.executable, registry.path, registry.data.strings, _id, _index"} | ERROR |  |
| q-efc0650efb | check C034 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 7 AND (TO_LOWER(win.ImageLoaded) LIKE \"*vaultcli*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*samlib*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*cryptdll*\" OR TO_LOWER(win.ImageLoaded) LIKE \"… | ERROR |  |
| q-6e4c941e99 | check C034 (repaired) | esql | {"query": "FROM windows.sysmon-default METADATA _id, _index \| WHERE event.code == 7 AND (TO_LOWER(win.ImageLoaded) LIKE \"*vaultcli*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*samlib*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*cryptdll*\" OR TO_LOWER(win.ImageLoaded)… | ERROR |  |
| q-83496bc285 | check C035 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 10 AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, _id, _index"} | ERROR |  |
| q-ae01c9479b | check C035 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 10 AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, _id, _index"} | ERROR |  |
| q-4dacfc95e1 | check C036 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectName:*SECURITY*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-29e419b1eb | check C037 | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == 4656 AND (TO_LOWER(win.ObjectName) LIKE \"*security*\" OR TO_LOWER(win.ObjectName) LIKE \"*lsa*\" OR TO_LOWER(win.ObjectName) LIKE \"*secrets*\") \| KEEP @timestamp, host.name, proces… | ERROR |  |
| q-2fdc6380bf | check C037 (repaired) | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == 4656 AND (TO_LOWER(win.ObjectName) LIKE \"*security*\" OR TO_LOWER(win.ObjectName) LIKE \"*lsa*\" OR TO_LOWER(win.ObjectName) LIKE \"*secrets*\") \| KEEP @timestamp, host.name, proces… | ERROR |  |
| q-ae1a784f9d | check C038 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsadump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*secrets*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*hklm\\\\security*\" \| KEEP @timestamp, host.name, wi… | ERROR |  |
| q-b022d503ac | check C038 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsadump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*secrets*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*hklm\\\\\\\\security*\" \| KEEP @timestamp, host.name… | ERROR |  |
| q-fa3919ded7 | check C039 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*security*\" OR TO_LOWER(message) LIKE \"*lsa*\" OR TO_LOWER(message) LIKE \"*secret*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-854a1c9859 | check C039 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*security*\" OR TO_LOWER(message) LIKE \"*lsa*\" OR TO_LOWER(message) LIKE \"*secret*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-0003369681 | check C040 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 13 AND (TO_LOWER(registry.path) LIKE \"*\\\\cache*\" OR TO_LOWER(registry.path) LIKE \"*\\\\logoncache*\" OR TO_LOWER(registry.path) LIKE \"*cachedlogons*\" OR TO_LOWER(registry.path) L… | ERROR |  |
| q-3c44121847 | check C040 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 13 AND (TO_LOWER(registry.path) LIKE \"*cache*\" OR TO_LOWER(registry.path) LIKE \"*logoncache*\" OR TO_LOWER(registry.path) LIKE \"*cachedlogons*\" OR TO_LOWER(registry.path) LIKE \"*s… | ERROR |  |
| q-8a0d544631 | check C041 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*cache*\" OR TO_LOWER(process.command_line) LIKE \"*cachedump*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.c… | ERROR |  |
| q-92e904bd30 | check C041 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*cache*\" OR TO_LOWER(process.command_line) LIKE \"*cachedump*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.c… | ERROR |  |
| q-0fea6b38dd | check C042 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 10 AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, _id, _index"} | ERROR |  |
| q-ffaceeb6b3 | check C042 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 10 AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, _id, _index"} | ERROR |  |
| q-2e948b053b | check C043 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectName:*Cache*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-a11fcb740d | check C044 | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == 4656 AND (TO_LOWER(win.ObjectName) LIKE \"*cache*\" OR TO_LOWER(win.ObjectName) LIKE \"*security*\") \| KEEP @timestamp, host.name, process.executable, win.ObjectName, win.AccessMask,… | ERROR |  |
| q-be9f8d1076 | check C044 (repaired) | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == 4656 AND (TO_LOWER(win.ObjectName) LIKE \"*cache*\" OR TO_LOWER(win.ObjectName) LIKE \"*security*\") \| KEEP @timestamp, host.name, process.executable, win.ObjectName, win.AccessMask,… | ERROR |  |
| q-2d46ecc8e2 | check C045 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*cachedump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cache*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*hklm\\\\security*\" \| KEEP @timestamp, host.name, wi… | ERROR |  |
| q-2b31583434 | check C045 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*cachedump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cache*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*hklm\\\\\\\\security*\" \| KEEP @timestamp, host.name… | ERROR |  |
| q-a80cfac5fd | check C046 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*cache*\" OR TO_LOWER(message) LIKE \"*credential*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-3d8603178e | check C046 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*cache*\" OR TO_LOWER(message) LIKE \"*credential*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-0279936b1b | check C047 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-826308fbee | check C048 | aggregate | {"dataset": "windows.security", "field": "win.Properties", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-8691033893 | check C049 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*ntds*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-0eb8206040 | check C050 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*dcsync* OR *drsuapi* OR *lsadump* OR *Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 0 |  |
| q-2b3c02cabd | check C051 | search | {"dataset": "windows.other", "query": "message:(*drsuapi* OR *dcsync* OR *replicat*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 0 |  |
| q-d9afd99c96 | check C052 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-9547416b20 | check C053 | search | {"dataset": "windows.security", "query": "event.code:4688 AND process.command_line:(*pcap* OR *capture* OR *netsh\\ trace* OR *tshark* OR *dumpcap* OR *windump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 1 |  |
| q-792ce23b57 | check C054 | aggregate | {"dataset": "windows.other", "field": "win.ServiceName", "query": "event.code:7045", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5 |  |
| q-6e26f33f0b | check C055 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*pcap* OR win.ImageLoaded:*npf* OR win.ImageLoaded:*wpcap*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-66bded7837 | check C056 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*pcap* OR process.command_line:*tshark* OR process.command_line:*dumpcap* OR process.command_line:*netsh*)", "time_from": null, "time_to": null, "size… | 2 |  |
| q-143f1bb2de | check C057 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*pcap* OR *netsh\\ trace* OR *packet* OR *capture*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proce… | 0 |  |
| q-94eb45e1f8 | check C058 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon* OR win.TargetImage:*csrss*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 495 |  |
| q-c454396809 | check C059 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-0aa154ff23 | check C060 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*winlogon*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-3108d8c39e | check C061 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*winlogon*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-24814dbf25 | check C062 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*GetAsyncKeyState* OR *SetWindowsHookEx* OR *keylog* OR *CredentialProvider* OR *GetForegroundWindow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name",… | 0 |  |
| q-a649ff9ca4 | check C063 | search | {"dataset": "windows.other", "query": "message:(*keylog* OR *hook* OR *credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 2 | F13 |
| q-ca0e83d503 | check C064 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 470 |  |
| q-b34a220033 | check C065 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Keyboard\\ Layout* OR registry.path:*CurrentControlSet\\\\Control\\\\Keyboard* OR registry.path:*Windows\\\\CurrentVersion\\\\Run*)", "time_from": null, "time_t… | 4 |  |
| q-e52f6afcf0 | check C066 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*hook* OR win.ImageLoaded:*keylog* OR win.ImageLoaded:*interception*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-789b3ba995 | check C067 | aggregate | {"dataset": "windows.other", "field": "win.ServiceName", "query": "event.code:7045", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5 |  |
| q-ea0d701366 | check C068 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*winlogon*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-3ffaeb5731 | check C069 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*GetAsyncKeyState* OR *SetWindowsHookEx* OR *RegisterHotKey* OR *keylog*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 0 |  |
| q-008b5e2d0e | check C070 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 200, "sub_field": null} | 447 |  |
| q-10e88e37df | check C071 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*password* OR process.command_line:*prompt* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 3 | F13 |
| q-b0a17246ba | check C072 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*CredentialPrompt* OR *Get-Credential* OR *Windows.Security.Credentials* OR *ShowDialog* OR *InputBox*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name"… | 0 |  |
| q-2d4e38ef58 | check C073 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 414 |  |
| q-62bd762561 | check C074 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-f85cb3a3ba | check C075 | search | {"dataset": "windows.other", "query": "message:(*credential* OR *prompt* OR *consent*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comma… | 2 |  |
| q-031fba695f | check C076 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*wwwroot* OR win.TargetFilename:*inetpub* OR win.TargetFilename:*.aspx OR win.TargetFilename:*.asp OR win.TargetFilename:*.php)", "time_from": null, "t… | 0 |  |
| q-e73e73959f | check C077 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*iis* OR process.command_line:*appcmd* OR process.command_line:*wwwroot*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c2af401457 | check C078 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*wwwroot* OR win.ObjectName:*inetpub*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-d07406bcbd | check C079 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*wwwroot* OR *inetpub* OR *Set-Content* OR *login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proce… | 2 | F14 |
| q-b95d076c2f | check C080 | search | {"dataset": "windows.other", "query": "message:(*wwwroot* OR *inetpub* OR *IIS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-e54e0c84e7 | check C081 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-31e34f45bf | check C082 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*lsa* OR win.TargetImage:*winlogon* OR win.TargetImage:*vaultsvc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name"… | 470 |  |
| q-6ad6b640d4 | check C083 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-fde5673a90 | check C084 | search | {"dataset": "windows.sysmon", "query": "event.code:8 AND (win.SourceImage:*lsass* OR win.TargetImage:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exec… | 2 |  |
| q-852790cdc8 | check C085 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.cod… | 6 |  |
| q-651b4e71e5 | check C086 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*Get-Process*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 3 |  |
| q-4ccc088f86 | check C087 | search | {"dataset": "windows.other", "query": "message:*lsass* OR win.ImagePath:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line… | 0 |  |
| q-24192fc830 | check C088 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b74b5ee057 | check C089 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-64958f9c53 | check C090 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-142734d7fc | check C091 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 218 | F15, F18 |
| q-e2ebf920e4 | check C092 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*net*user* OR process.command_line:*net*group* OR process.command_line:*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-62494ffd78 | check C093 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 4 |  |
| q-7f3712f9fd | check C094 | search | {"dataset": "windows.other", "query": "event.code:4625 OR message:*logon*fail*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 0 |  |
| q-7c23711b34 | check C095 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-2d36afcfe3 | check C096 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-48ef9b8642 | check C097 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-9e17f6ca2e | check C098 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*runas* OR process.command_line:*psexec* OR process.command_line:*wmic*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset"… | 1 | F16 |
| q-e0bc495fa1 | check C099 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*PSCredential* OR win.ScriptBlockText:*ConvertTo-SecureString*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "… | 4 |  |
| q-22efa949f8 | check C100 | search | {"dataset": "windows.other", "query": "event.code:4625", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-0662634240 | check C101 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*NTDS* OR win.ObjectName:*SECURITY* OR win.ObjectName:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 4484 |  |
| q-8fa31bddf2 | check C102 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND (win.ObjectName:*SAM* OR win.ObjectName:*NTDS* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10 |  |
| q-d1d2bd5c2f | check C103 | search | {"dataset": "windows.security", "query": "event.code:4670 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 0 |  |
| q-aefc980d51 | check C104 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*SAM* OR file.path:*NTDS* OR file.path:*SECURITY* OR file.path:*.hive*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 3 |  |
| q-900852fb02 | check C105 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg*save* OR process.command_line:*ntdsutil* OR process.command_line:*vssadmin* OR process.command_line:*esentutl*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-d7eab65d12 | check C106 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 326 |  |
| q-c93f372029 | check C107 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*hashcat* OR win.ScriptBlockText:*john* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*DumpCreds*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-beaafee6e3 | check C108 | search | {"dataset": "windows.other", "query": "message:*SAM* OR message:*NTDS*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 1 |  |
| q-15595f0d43 | check C109 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-c75b8ed38d | check C110 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e3310b373c | check C111 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-7695233f53 | check C112 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-204ff4293d | check C113 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Invoke-* OR process.command_line:*Domain*User*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.na… | 1 |  |
| q-de86972c53 | check C114 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Get-ADUser* OR win.ScriptBlockText:*foreach*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 2 |  |
| q-f158e147da | check C115 | search | {"dataset": "windows.other", "query": "event.code:4625", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-2f055db01b | check C116 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-12384e6fe8 | check C117 | aggregate | {"dataset": "windows.security", "field": "win.IpAddress", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b70ef8cd16 | check C118 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 218 |  |
| q-652626bb1c | check C119 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*curl* OR process.command_line:*Invoke-WebRequest* OR process.command_line:*wget*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-834c242686 | check C120 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-WebRequest* OR win.ScriptBlockText:*DownloadString* OR win.ScriptBlockText:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "o… | 2 |  |
| q-eea22108c9 | check C121 | search | {"dataset": "windows.other", "query": "event.code:4625", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-d632140198 | check C122 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-928bee631d | check C123 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F20 |
| q-33976f359b | check C124 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 39283 |  |
| q-68873af454 | check C125 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*SmartCard* OR registry.path:*Crypto* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 16 |  |
| q-0830dd035c | check C126 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*SmartCard* OR win.ScriptBlockText:*Token*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "e… | 3 |  |
| q-13d5a6124e | check C127 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F20 |
| q-3875cfe3d1 | check C128 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 10977 |  |
| q-881a991e7f | check C129 | search | {"dataset": "windows.security", "query": "event.code:5145 AND win.ShareName:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 121 | F23 |
| q-4f80aff6ee | check C130 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.lnk OR win.TargetFilename:*.url OR win.TargetFilename:*.library-ms OR win.TargetFilename:*.searchConnector-ms)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 3 | F22 |
| q-4c4c6172b5 | check C131 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 66 |  |
| q-b44a84808d | check C132 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*WebDAV* OR win.ScriptBlockText:*NTLM* OR win.ScriptBlockText:*\\\\\\\\)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-dfa895b7ec | check C133 | search | {"dataset": "windows.other", "query": "event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 4 |  |
| q-522d8e361c | check C134 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:OPTIONS OR http.request.method:MOVE)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 |  |
| q-25ed04c5b2 | check C135 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 50 |  |
| q-a7cba0b381 | check C136 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-31fac417a0 | check C137 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-1cb69ec9b6 | check C138 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-4cde4d32bd | check C139 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-d33603b0fa | check C140 | search | {"dataset": "windows.other", "query": "event.code:1 OR event.code:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 6 |  |
| q-2ea50d288c | check C141 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-04be8622f1 | check C142 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*Web Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 162 | F26 |
| q-f00175fd5c | check C143 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND (win.TargetImage:*chrome* OR win.TargetImage:*firefox* OR win.TargetImage:*msedge* OR win.TargetImage:*iexplore*)", "time_from": null, "time_to": null, "size": 50, "sub_field… | 0 |  |
| q-0e01c81f21 | check C144 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", … | 0 |  |
| q-3d0bff1166 | check C145 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Cookies* OR process.command_line:*Login Data* OR process.command_line:*sqlite*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "e… | 4 | F26 |
| q-e24583f184 | check C146 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*sqlite*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 13 |  |
| q-50f9adecab | check C147 | search | {"dataset": "windows.other", "query": "event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 4 |  |
| q-5469c15e00 | check C148 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:GET", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 2 |  |
| q-f074439c53 | check C149 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.ini OR win.TargetFilename:*.ps1)", "time_from": null, "time_to… | 72 |  |
| q-d5eb4e791b | check C150 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential* OR registry.path:*Winlogon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 24 | F30 |
| q-b7587a9b48 | check C151 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*findstr* OR process.command_line:*Select-String* OR process.command_line:*password* OR process.command_line:*credential*)", "time_from": null, "time_to": null, "fields": ["@ti… | 0 |  |
| q-22afdefc16 | check C152 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*password* OR win.ScriptBlockText:*credential* OR win.ScriptBlockText:*ConvertTo-SecureString*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 4 |  |
| q-dd189c5269 | check C153 | search | {"dataset": "windows.other", "query": "event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 4 |  |
| q-b7916f08cf | check C154 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-dbeeb4b6c6 | check C155 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.ini OR win.TargetFilename:*.kdbx OR win.TargetFilename:*.rdg)"… | 49 |  |
| q-8ac9e35816 | check C156 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*unattend* OR process.command_line:*sysprep* OR process.command_line:*web.config* OR process.command_line:*passwords*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 0 |  |
| q-4f0ff8fd55 | check C157 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-972f93beff | check C158 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-422989dbf3 | check C159 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*unattend* OR win.ScriptBlockText:*web.config* OR win.ScriptBlockText:*Get-Content*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name… | 0 |  |
| q-493c032238 | check C160 | search | {"dataset": "windows.other", "query": "event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 4 |  |
| q-64214ffc2e | check C161 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-bc4ecf1574 | check C162 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential* OR registry.path:*Secret* OR registry.path:*Login*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20 |  |
| q-6fa85d528a | check C163 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*reg*query* OR process.command_line:*reg*save* OR process.command_line:*Password* OR process.command_line:*Credential*)", "time_from": null, "time_to"… | 0 |  |
| q-856ef732de | check C164 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*reg*query* OR win.ScriptBlockText:*Get-ItemProperty*)", "time_from": null, "time_to": null, "fields": ["… | 5 |  |
| q-4661ab8251 | check C165 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*Password*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a4e118dcf5 | check C166 | search | {"dataset": "windows.other", "query": "message:*reg* AND (message:*query* OR message:*save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-f4e514c8fc | check C167 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ConsoleHost_history* OR win.ScriptBlockText:*history* OR win.ScriptBlockText:*Get-History*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 0 |  |
| q-11af61d270 | check C168 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ConsoleHost_history* OR process.command_line:*Get-History* OR process.command_line:*history*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 0 |  |
| q-687623eebc | check C169 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*ConsoleHost_history* OR file.path:*history*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c5a82e49b3 | check C170 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectName:*history*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a39cfe49f4 | check C171 | search | {"dataset": "windows.other", "query": "message:*history*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destin… | 5 |  |
| q-4005b32405 | check C172 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*.pfx OR process.command_line:*.pem OR process.command_line:*.key OR process.command_line:*.p12 OR process.command_line:*.ppk OR process.command_line:… | 0 |  |
| q-beb137ce5c | check C173 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*.pfx OR file.path:*.pem OR file.path:*.key OR file.path:*.p12 OR file.path:*.ppk)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-f6736c1311 | check C174 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:5145 AND (win.ObjectName:*.pfx OR win.ObjectName:*.pem OR win.ObjectName:*.key OR win.ObjectName:*.p12 OR win.ObjectName:*.ppk)", "time_from": null, "time_to": null, "size": 50, "s… | 0 |  |
| q-b110f87dd7 | check C175 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*.pfx OR win.ScriptBlockText:*.pem OR win.ScriptBlockText:*.p12 OR win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*certutil*)", "time_from": null, "time_to… | 1 |  |
| q-9dc6bbb2b6 | check C176 | search | {"dataset": "windows.other", "query": "message:(*.pfx OR *.pem OR *.p12 OR *.ppk)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 0 |  |
| q-c1a9587a6b | check C177 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Groups.xml OR win.ScriptBlockText:*cpassword OR win.ScriptBlockText:*gpp* OR win.ScriptBlockText:*SYSVOL* OR win.ScriptBlockText:*AES*)", "time_from": null, "time_to": null, … | 0 |  |
| q-0d5b3f80d0 | check C178 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*SYSVOL* OR process.command_line:*Groups.xml* OR process.command_line:*cpassword*)", "time_from": null, "time_to": null, "size": 50, "sub_field": nu… | 0 |  |
| q-01dd605a92 | check C179 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:5145 AND (win.ObjectName:*SYSVOL* OR win.ObjectName:*Groups.xml* OR win.ObjectName:*Policies*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-67e051932b | check C180 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Groups.xml* OR file.path:*SYSVOL*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-8ef7d6b75c | check C181 | search | {"dataset": "windows.other", "query": "message:(*SYSVOL* OR *Groups.xml* OR *cpassword*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.com… | 0 |  |
| q-48dbd10cf0 | check C182 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a96ad98274 | check C183 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-d1a5006435 | check C184 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*minidump* OR process.command_line:*comsvcs* OR process.command_line:*procdump* OR process.command_line:*sekurlsa* OR process.command_line:*lsass*)", … | 1 |  |
| q-6ef8b145e3 | check C185 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*NTDS* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-577820efae | check C186 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:9", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-cabf3bf4b0 | check C187 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 3 |  |
| q-96216bf1e2 | check C188 | search | {"dataset": "windows.other", "query": "message:(*lsass* OR *MiniDump* OR *procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 0 |  |
| q-bc45439e33 | check C189 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Login Data* OR process.command_line:*Cookies* OR process.command_line:*Local State* OR process.command_line:*chrome* OR process.command_line:*firefox… | 0 |  |
| q-ca76af9077 | check C190 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Login Data* OR file.path:*Cookies* OR file.path:*Local State* OR file.path:*logins.json*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c82483dd05 | check C191 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Login Data* OR win.ObjectName:*Cookies* OR win.ObjectName:*Local State* OR win.ObjectName:*logins.json*)", "time_from": null, "time_to": null, "size": 50,… | 0 |  |
| q-f85459c9e7 | check C192 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*Local State* OR win.ScriptBlockText:*sqlite*)", "time_from": null, "time_to": null, "fields": ["@timestam… | 0 |  |
| q-db8810c2d1 | check C193 | search | {"dataset": "windows.other", "query": "message:(*Login Data* OR *Cookies* OR *Local State*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-2622422ce8 | check C194 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*vault* OR process.command_line:*credman* OR process.command_line:*Credential* OR process.command_line:*cmdkey* OR process.command_line:*rundll32*keym… | 0 |  |
| q-44702354bf | check C195 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetObject", "query": "event.code:15 AND (win.TargetObject:*Vault* OR win.TargetObject:*Credentials* OR win.TargetObject:*Protect*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f29e1b57b1 | check C196 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*explorer.exe)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-f277fce6d4 | check C197 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*cmdkey* OR process.command_line:*credman* OR process.command_line:*keymgr*)", "time_from": null, "time_to": null… | 0 |  |
| q-6733b0b31e | check C198 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Vault* OR win.ScriptBlockText:*cmdkey* OR win.ScriptBlockText:*DPAPI*)", "time_from": null, "time_to": null, "size":… | 3 |  |
| q-69d34901bf | check C199 | search | {"dataset": "windows.other", "query": "message:*Vault* OR message:*Credential* OR message:*cmdkey*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 2 | F35 |
| q-f0c7c4e18c | check C200 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*lastpass* OR process.command_line:*bitwarden* OR process.command_line:*password… | 0 |  |
| q-d4c1aa1f52 | check C201 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.kdbx OR win.TargetFilename:*1password* OR win.TargetFilename:*keepass* OR win.TargetFilename:*.opvault*)", "time_from": null, "time_to": null, "size"… | 0 |  |
| q-c37e0b1213 | check C202 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*lastpass* OR process.command_line:*bitwarden*)", "time_from": null, "time_… | 0 |  |
| q-98bbe521ac | check C203 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*keepass* OR win.ScriptBlockText:*1password* OR win.ScriptBlockText:*lastpass* OR win.ScriptBlockText:*bitwarden* OR win.ScriptBlockText:*password*)", "t… | 0 |  |
| q-e1444067d2 | check C204 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*1password* OR message:*lastpass* OR message:*bitwarden*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 0 |  |
| q-34913b3bd5 | check C205 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-d79a5dea54 | check C206 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*wdigest* OR win.ImageLoaded:*kerberos*)", "time_from": null, "time_to": nul… | 92 |  |
| q-def0e41f2d | check C207 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*WDigest* OR registry.path:*SecurityProviders* OR registry.path:*Lsa* OR registry.path:*Notification Packages*)", "time_from": null, "time_to": null, "size": 50,… | 293 |  |
| q-92b1aeddd3 | check C208 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657 AND (win.ObjectName:*WDigest* OR win.ObjectName:*SecurityProviders* OR win.ObjectName:*Lsa* OR win.ObjectName:*Notification*)", "time_from": null, "time_to": null, "size": 50,… | 0 |  |
| q-f6a5b735a2 | check C209 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*WDigest* OR win.ScriptBlockText:*SecurityProviders* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*Notification*Packages*)", "time_from": null, … | 0 |  |
| q-62f07abdc9 | check C210 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*WDigest* OR message:*SecurityProviders*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 0 |  |
| q-9c889dfb65 | check C211 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass.exe OR win.ImageLoaded:*cryptdll.dll)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 33 |  |
| q-3d0a947d1d | check C212 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-770b27e9e9 | check C213 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND (win.LogonType:3 OR win.LogonType:9)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 218 |  |
| q-ffb0167d97 | check C214 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-a6023bca87 | check C215 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-a5e4dee7af | check C216 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*cryptdll* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*sekurlsa*)", "time_from": null, "time_to": null, "siz… | 0 |  |
| q-4c2d4e7f99 | check C217 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*System32* OR win.TargetFilename:*SysWOW64*) AND (win.TargetFilename:*.dll)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ca0365f13d | check C218 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Notification*Packages* OR registry.path:*Password*Filter* OR registry.path:*Control*Lsa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3 |  |
| q-a62bea9a16 | check C219 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*System32* OR win.ImageLoaded:*SysWOW64*) AND win.ImageLoaded:*.dll", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 18866 |  |
| q-b131783d1e | check C220 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657 AND (win.ObjectName:*Notification*Packages* OR win.ObjectName:*Password*Filter* OR win.ObjectName:*Lsa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-82b537c156 | check C221 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*Notification*Packages* OR win.ScriptBlockText:*Password*Filter* OR win.ScriptBlockText:*Lsa*)", "time_from": null, "time_to": null, "size": 50, "sub_fie… | 0 |  |
| q-1cf449ee8b | check C222 | search | {"dataset": "windows.other", "query": "message:*Notification*Packages* OR message:*Password*Filter*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-07523fb865 | check C223 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*AllowReversiblePasswordEncryption* OR win.ScriptBlockText:*ReversibleEncryption* OR win.ScriptBlockText:*Set-ADAccountControl* OR win.ScriptBlockText:*S… | 1 |  |
| q-ff282c3b22 | check C224 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*AllowReversiblePasswordEncryption* OR process.command_line:*Set-ADAccountControl* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod… | 0 |  |
| q-2905838a65 | check C225 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4739", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-aaf95a8cd0 | check C226 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*AllowReversiblePasswordEncryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 0 |  |
| q-da55be2dee | check C227 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win… | ERROR |  |
| q-26c081d2e2 | check C227 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win… | ERROR |  |
| q-c875e23f8f | check C228 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 41002 |  |
| q-34435e6923 | check C229 | search | {"dataset": "windows.security", "query": "event.code:4739 OR event.code:4738 OR event.code:4670", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proc… | 143 | F41 |
| q-503eda8af8 | check C230 | search | {"dataset": "windows.other", "query": "event.code:4739 OR event.code:4738 OR event.code:5136", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-333f4df0be | check C231 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LIKE \"*dsacls*… | ERROR |  |
| q-0a12e46bd8 | check C231 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LIKE \"*dsacls*… | ERROR |  |
| q-53a5cc8670 | check C232 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"7\" AND (TO_LOWER(win.ImageLoaded) LIKE \"*cloudap*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*aad*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*azure*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*hy… | ERROR |  |
| q-978c62762a | check C232 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"7\" AND (TO_LOWER(win.ImageLoaded) LIKE \"*cloudap*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*aad*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*azure*\" OR TO_LOWER(win.ImageLoade… | 18 | F42 |
| q-4574149f4b | check C233 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*cloudap*\" OR TO_LOWER(file.path) LIKE \"*azuread*\" OR TO_LOWER(file.path) LIKE \"*aad*\" OR TO_LOWER(file.path) LIKE \"*system32\\\\*.dll\") \|… | ERROR |  |
| q-7df356aa04 | check C233 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*cloudap*\" OR TO_LOWER(file.path) LIKE \"*azuread*\" OR TO_LOWER(file.path) LIKE \"*aad*\" OR TO_LOWER(file.path) LIKE \"*system32\\… | 0 |  |
| q-e1eddd3b9d | check C234 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 41002 |  |
| q-d7d9264e0a | check C235 | search | {"dataset": "windows.security", "query": "event.code:5136 OR event.code:4624", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 297 |  |
| q-c58070e44e | check C236 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aad*\" OR TO_LOWER(win.ScriptBlockText) L… | ERROR |  |
| q-8130bf5d81 | check C236 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aad*\" OR TO_LOWER(win.Scrip… | 1 |  |
| q-04ea9607bb | check C237 | search | {"dataset": "windows.other", "query": "event.code:5136 OR event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-155a6d7e34 | check C238 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*system32\\\\*\" OR TO_LOWER(file.path) LIKE \"*networkprovider*\" OR TO_LOWER(file.path) LIKE \"*np*.dll\") \| KEEP @timestamp, host.name, user.n… | ERROR |  |
| q-012b1b7643 | check C238 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*system32\\\\*\" OR TO_LOWER(file.path) LIKE \"*networkprovider*\" OR TO_LOWER(file.path) LIKE \"*np*.dll\") \| KEEP @timestamp, host.name, user.n… | ERROR |  |
| q-8f48d411b4 | check C239 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"7\" AND (TO_LOWER(win.ImageLoaded) LIKE \"*networkprovider*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*np*.dll\" OR TO_LOWER(win.ImageLoaded) LIKE \"*winlogon*\" OR TO_LOWER(win.ImageLoad… | ERROR |  |
| q-2f7a949f3f | check C239 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"7\" AND (TO_LOWER(win.ImageLoaded) LIKE \"*networkprovider*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*np*.dll\" OR TO_LOWER(win.ImageLoaded) LIKE \"*winlogon*\" OR TO_LOWER(win.ImageLoad… | ERROR |  |
| q-dab0fe9204 | check C240 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass*\" OR TO_LOWER(win.TargetImage) LIKE \"*winlogon*\") \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetImage, w… | ERROR |  |
| q-d4ff1e8d2a | check C240 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass*\" OR TO_LOWER(win.TargetImage) LIKE \"*winlogon*\") \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetImage, w… | ERROR |  |
| q-3078f4c006 | check C241 | search | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 36 |  |
| q-1de1b8641e | check C242 | search | {"dataset": "windows.other", "query": "event.code:4657 OR event.code:13", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 1 |  |
| q-b278e4f2bb | check C243 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*hkml*networkprovider*\" OR TO_LOWER(process.command_line) LIKE \"*networkprovider*\" \| KEEP @tim… | ERROR |  |
| q-b41f0faf16 | check C243 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(process.command_line) LIKE \"*networkprovider*\" \| KEEP @timestamp, host.name, user.name, process.command_line, _id, _index"} | ERROR |  |
| q-b678b439e5 | check C244 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"22\" \| KEEP @timestamp, host.name, process.executable, dns.question.name, win.QueryName, win.QueryResults, _id, _index"} | ERROR |  |
| q-babc4799d8 | check C244 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"22\" \| KEEP @timestamp, host.name, process.executable, dns.question.name, win.QueryName, win.QueryResults, _id, _index"} | ERROR |  |
| q-3e43b53dd3 | check C245 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 139 OR destination.port == 88 OR destination.port == 389) \| KEEP @timestamp, host.name, process.executable, destination.ip, de… | ERROR |  |
| q-e49229cc11 | check C245 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 139 OR destination.port == 88 OR destination.port == 389) \| KEEP @timestamp, host.name, process.executable, destination.ip, de… | ERROR |  |
| q-e681724ad8 | check C246 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-5ed891d99b | check C247 | search | {"dataset": "windows.security", "query": "event.code:4670 OR event.code:4663", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 5480 | F44 |
| q-fe4374f342 | check C248 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-5d275fe476 | check C249 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mitm*\" OR TO_LOWER(process.command_line) LIKE \"*i… | ERROR |  |
| q-6d54c207ff | check C249 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mitm*\" OR TO_LOWER(process.command_line) LIKE \"*i… | ERROR |  |
| q-f6257aa041 | check C250 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-56e1caa6c0 | check C251 | search | {"dataset": "zeek", "query": "event.action:conn AND (destination.port:445 OR destination.port:139 OR destination.port:88)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 75 |  |
| q-734a156a89 | check C252 | search | {"dataset": "zeek", "query": "event.action:dns AND (destination.port:5355 OR destination.port:137)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 6 | F45 |
| q-01ee436027 | check C253 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-d99547a55b | check C254 | search | {"dataset": "zeek", "query": "event.action:smb_mapping OR event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 23 | F45 |
| q-5eddece5e5 | check C255 | search | {"dataset": "windows.security", "query": "event.code:4697 OR event.code:4624", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 320 | F44 |
| q-bba68dca8f | check C256 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*dnsclient*\" OR TO_LOWER(registry.path) LIKE \"*enablemulticast*\") \| KEEP @timestamp, host.name, user.name, registry.path, registry.data.st… | ERROR |  |
| q-0a9ca2e721 | check C256 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*dnsclient*\" OR TO_LOWER(registry.path) LIKE \"*enablemulticast*\") \| KEEP @timestamp, host.name, user.name, registry.path, registry.data.st… | ERROR |  |
| q-fb26851fe3 | check C257 | search | {"dataset": "windows.other", "query": "event.code:4697 OR event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 5 | F45 |
| q-e5367d0d3e | check C258 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*enablemulticast*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*nbt-ns*\" OR TO_LOWER(win.ScriptBlockText) LIKE… | ERROR |  |
| q-aec3288de6 | check C258 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*enablemulticast*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*nbt-ns*\" OR TO_LOWER(win.ScriptBl… | 0 |  |
| q-1d2e819061 | check C259 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 139 OR destination.port == 80 OR destination.port == 443) \| KEEP @timestamp, host.name, process.executable, destination.ip, de… | ERROR |  |
| q-b2c67a956b | check C259 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 139 OR destination.port == 80 OR destination.port == 443) \| KEEP @timestamp, host.name, process.executable, destination.ip, de… | ERROR |  |
| q-df2efcbaf0 | check C260 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"22\" \| KEEP @timestamp, host.name, process.executable, dns.question.name, win.QueryResults, _id, _index"} | ERROR |  |
| q-4ecf391ff1 | check C260 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"22\" \| KEEP @timestamp, host.name, process.executable, dns.question.name, win.QueryResults, _id, _index"} | ERROR |  |
| q-b91bb07dfc | check C261 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 41002 |  |
| q-aecc30ae38 | check C262 | search | {"dataset": "windows.security", "query": "event.code:5156 OR event.code:5157", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 3203 |  |
| q-708dea502e | check C263 | search | {"dataset": "windows.other", "query": "event.code:5156 OR event.code:5157", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-bb07df59c6 | check C264 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(process.command_line) LIKE \"*arp -s*\" OR TO_LOWER(process.command_line) LIKE \"*netsh*\" \| KEEP @timestamp, host.name, user.name, proce… | ERROR |  |
| q-33f455b055 | check C264 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(process.command_line) LIKE \"*arp -s*\" OR TO_LOWER(process.command_line) LIKE \"*netsh*\" \| KEEP @timestamp, host.name, user.name, proce… | ERROR |  |
| q-1b2124ca12 | check C265 | search | {"dataset": "zeek", "query": "event.action:conn", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.ip"… | 613 |  |
| q-ad52ad257a | check C266 | search | {"dataset": "windows.other", "query": "event.code:1341 OR event.code:1342 OR event.code:1020 OR event.code:1063", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.ex… | 0 |  |
| q-46fd962e75 | check C267 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 216 |  |
| q-6f39e70c42 | check C268 | search | {"dataset": "windows.security", "query": "event.code:5156 AND network.transport:udp", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-59b7be6886 | check C269 | search | {"dataset": "windows.sysmon", "query": "event.code:22 AND dns.question.name:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 81 |  |
| q-114b7a4c44 | check C270 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(process.command_line) LIKE \"*dhcp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*dhcp*\" \| KEEP @timestamp, host.name, process.command_line, _id, _index"} | ERROR |  |
| q-8646ffd571 | check C270 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(process.command_line) LIKE \"*dhcp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*dhcp*\" \| KEEP @timestamp, host.name, process.command_line, _id, _index"} | ERROR |  |
| q-06432a9b87 | check C271 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-8b9d98b9b5 | check C272 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-20595ee0e3 | check C273 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-a2df5fd3b3 | check C274 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-56609f00a6 | check C275 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 236 |  |
| q-db1b8a75ae | check C276 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 9 |  |
| q-9909eaa1ff | check C277 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*kerberos*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ticket*\" OR TO_LOWER(process.command_line) LIKE \"*klist*\" \| KEEP @timestamp, host.name, process.comm… | ERROR |  |
| q-1ec42b7e38 | check C277 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*kerberos*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ticket*\" OR TO_LOWER(process.command_line) LIKE \"*klist*\" \| KEEP @timestamp, host.name, process.comm… | ERROR |  |
| q-d9f2e25b53 | check C278 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-ed9aea926f | check C279 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-017052eafe | check C280 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-bce217cee5 | check C281 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 297 |  |
| q-367c3e9b23 | check C282 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-23475a6a62 | check C283 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*krbtgt*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*golden*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" \| KEEP @timestamp, host.name, process.com… | ERROR |  |
| q-3351f28376 | check C283 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*krbtgt*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*golden*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" \| KEEP @timestamp, host.name, process.com… | ERROR |  |
| q-b01682008a | check C284 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-e2aed881c6 | check C285 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-8fa06a4ea0 | check C286 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-11efd27b67 | check C287 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 236 |  |
| q-6ada2f17a3 | check C288 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 9 |  |
| q-7d1eda55aa | check C289 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*silver*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*service ticket*\" OR TO_LOWER(process.command_line) LIKE \"*kerberos::golden*\" \| KEEP @timestamp, host.n… | ERROR |  |
| q-a25fa5b13d | check C289 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*silver*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*service ticket*\" OR TO_LOWER(process.command_line) LIKE \"*kerberos::golden*\" \| KEEP @timestamp, host.n… | ERROR |  |
| q-157177a5ec | check C290 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-bd9d53978a | check C291 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 297 |  |
| q-cfe84a8cc7 | check C292 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-6127a275dc | check C293 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-aa691a6ea7 | check C294 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-ece5ee0075 | check C295 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*spn*\" OR TO_LOWER(process.command_line) LIKE \"*kerberoast*\" OR TO_LOWER(process.command_line) LIKE \"*setspn*\" \| KEEP @timestamp, host.name, process.com… | ERROR |  |
| q-35bb22a661 | check C295 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*spn*\" OR TO_LOWER(process.command_line) LIKE \"*kerberoast*\" OR TO_LOWER(process.command_line) LIKE \"*setspn*\" \| KEEP @timestamp, host.name, process.com… | ERROR |  |
| q-4d17725619 | check C296 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-5dc1e949de | check C297 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 297 |  |
| q-aa80289ee4 | check C298 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-9d9c33541c | check C299 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*asrep*\" OR TO_LOWER(process.command_line) LIKE \"*rubeus*\" OR TO_LOWER(process.command_line) LIKE \"*getnpusers*\") \| KEEP @timestam… | ERROR |  |
| q-0c8d79c4a1 | check C299 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*asrep*\" OR TO_LOWER(process.command_line) LIKE \"*rubeus*\" OR TO_LOWER(process.command_line) LIKE \"*getnpusers*\") \| K… | 0 |  |
| q-9f8cf587c1 | check C300 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*asrep*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*rubeus*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*getnpusers*\" \| KEEP @timestamp, host.name, process.com… | ERROR |  |
| q-67057502c1 | check C300 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*asrep*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*rubeus*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*getnpusers*\" \| KEEP @timestamp, host.name… | 0 |  |
| q-da9e32c793 | check C301 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-89a6539875 | check C302 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-ac967511fe | check C303 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-e2dac1154a | check C304 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-c947663c20 | check C305 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-df25181631 | check C306 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*token*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*saml*\" OR TO_LOWER(process.command_line) LIKE \"*token*… | ERROR |  |
| q-4c95c8ad55 | check C306 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*token*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*saml*\" OR TO_LOWER(process.command_line) LIKE \"*token*… | ERROR |  |
| q-49aa1993a2 | check C307 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*token*\" OR TO_LOWER(message) LIKE \"*cookie*\" OR TO_LOWER(message) LIKE \"*saml*\" OR TO_LOWER(message) LIKE \"*adfs*\" \| KEEP @timestamp, host.name, event.code, _id, _ind… | ERROR |  |
| q-718f4c5f3f | check C307 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*token*\" OR TO_LOWER(message) LIKE \"*cookie*\" OR TO_LOWER(message) LIKE \"*saml*\" OR TO_LOWER(message) LIKE \"*adfs*\" \| KEEP @timestamp, host.name, event.code, _id, _ind… | ERROR |  |
| q-5e74c65f80 | check C308 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*\\\\cookies\\\\*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\") \| KEEP @timest… | ERROR |  |
| q-236e3503e6 | check C308 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\") \| KEEP @timestamp, host.name, user.name, win.TargetFilename, _id, _index"… | ERROR |  |
| q-4404db5b66 | check C309 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Cookies* OR win.ObjectName:*cookies*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-2f4db96b8c | check C310 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-136a3b1258 | check C311 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(process.command_line) LIKE \"*cookie*\" \| KEEP @timestamp, host.name, user.name, _id, _index"} | ERROR |  |
| q-c2152d8ae3 | check C311 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(process.command_line) LIKE \"*cookie*\" \| KEEP @timestamp, host.name, user.name, _id, _index"} | ERROR |  |
| q-768d0e8cf1 | check C312 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*cookie*\" \| KEEP @timestamp, host.name, event.code, _id, _index"} | ERROR |  |
| q-d8175252ec | check C312 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*cookie*\" \| KEEP @timestamp, host.name, event.code, _id, _index"} | ERROR |  |
| q-a9c6751042 | check C313 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-433cc07a47 | check C314 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-8288eb49f5 | check C315 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*saml*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*adfs*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*token-signing*\" OR TO_LOWER(process.command_line) LIKE \"*… | ERROR |  |
| q-e9b84c3a15 | check C315 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*saml*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*adfs*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*token-signing*\" OR TO_LOWER(process.command_line) LIKE \"*… | ERROR |  |
| q-ba36bc60bc | check C316 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*saml*\" OR TO_LOWER(message) LIKE \"*adfs*\" OR TO_LOWER(message) LIKE \"*token*\" \| KEEP @timestamp, host.name, event.code, _id, _index"} | ERROR |  |
| q-f95e609215 | check C316 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*saml*\" OR TO_LOWER(message) LIKE \"*adfs*\" OR TO_LOWER(message) LIKE \"*token*\" \| KEEP @timestamp, host.name, event.code, _id, _index"} | ERROR |  |
| q-ff8bf5f628 | check C317 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*adfs*\" OR TO_LOWER(win.TargetFilename) LIKE \"*token*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE… | ERROR |  |
| q-74997b3025 | check C317 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*adfs*\" OR TO_LOWER(win.TargetFilename) LIKE \"*token*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE… | ERROR |  |
| q-93e13ec3df | check C318 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-1dbe2f573f | check C319 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-7a3a68fa77 | check C320 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*mfa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*2fa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*authenticator*\" OR TO_LOWER(process.command_line) LIKE \"*mf… | ERROR |  |
| q-1261cd6ced | check C320 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*mfa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*2fa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*authenticator*\" OR TO_LOWER(process.command_line) LIKE \"*mf… | ERROR |  |
| q-0c03249890 | check C321 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*mfa*\" OR TO_LOWER(message) LIKE \"*multi-factor*\" OR TO_LOWER(message) LIKE \"*authenticator*\" \| KEEP @timestamp, host.name, event.code, _id, _index"} | ERROR |  |
| q-b71de25404 | check C321 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*mfa*\" OR TO_LOWER(message) LIKE \"*multi-factor*\" OR TO_LOWER(message) LIKE \"*authenticator*\" \| KEEP @timestamp, host.name, event.code, _id, _index"} | ERROR |  |
| q-9bfba409e1 | check C322 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-a7ddc24ca2 | check C323 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-7c434e87ee | check C324 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-449e8b15fe | check C325 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.p12\" OR TO_LOWER(win.TargetFilename) LIKE \"*.cer\" OR TO_LOWER(win.TargetFilename) LIKE \"… | ERROR |  |
| q-17bff39b1b | check C325 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.p12\" OR TO_LOWER(win.TargetFilename) LIKE \"*.cer\" OR TO_LOWER(win.TargetFilename) LIKE \"… | ERROR |  |
| q-dc366cba10 | check C326 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*cert*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*export-pfxcertificate*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-selfsignedcertificate*\" OR TO_LOWER(p… | ERROR |  |
| q-cc036bfc81 | check C326 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*cert*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*export-pfxcertificate*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-selfsignedcertificate*\" OR TO_LOWER(p… | ERROR |  |
| q-c9d8fd81be | check C327 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*certificate*\" OR TO_LOWER(message) LIKE \"*certutil*\" OR TO_LOWER(message) LIKE \"*ad cs*\" \| KEEP @timestamp, host.name, event.code, _id, _index"} | ERROR |  |
| q-e4a981142b | check C327 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*certificate*\" OR TO_LOWER(message) LIKE \"*certutil*\" OR TO_LOWER(message) LIKE \"*ad cs*\" \| KEEP @timestamp, host.name, event.code, _id, _index"} | ERROR |  |
| q-6865979b8b | check C328 | aggregate | {"dataset": "zeek", "field": "zeek.operation", "query": "event.action:dce_rpc", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 123 |  |
| q-69f695b6ac | check C329 | search | {"dataset": "zeek", "query": "event.action:dce_rpc AND (zeek.endpoint:*DRSUAPI* OR zeek.operation:*DsGetNCChanges* OR zeek.operation:*DRS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.cod… | 9 |  |
| q-c16ec19213 | check C330 | aggregate | {"dataset": "zeek", "field": "zeek.endpoint", "query": "event.action:dce_rpc", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 123 |  |
| q-6d11c22516 | check C331 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-085c072770 | check C332 | search | {"dataset": "zeek", "query": "event.action:conn AND (zeek.service:*sniff* OR zeek.service:*pcap* OR zeek.service:*promisc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-b6231c4c9c | check C333 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-23fab6e974 | check C334 | aggregate | {"dataset": "zeek", "field": "zeek.name", "query": "event.action:smb_files", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 12 |  |
| q-6fccfc99a0 | check C335 | search | {"dataset": "zeek", "query": "event.action:smb_files AND (zeek.name:*keylog* OR zeek.name:*hook* OR zeek.name:*capture*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-51137b6671 | check C336 | aggregate | {"dataset": "zeek", "field": "zeek.named_pipe", "query": "event.action:dce_rpc", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 123 |  |
| q-313355da66 | check C337 | aggregate | {"dataset": "zeek", "field": "zeek.filename", "query": "event.action:files", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 448 |  |
| q-961dd96cbe | check C338 | search | {"dataset": "zeek", "query": "event.action:files AND (zeek.filename:*keylog* OR zeek.filename:*keys* OR zeek.filename:*hook*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 0 |  |
| q-eab4d1bf36 | check C339 | aggregate | {"dataset": "zeek", "field": "zeek.mime_type", "query": "event.action:files", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 448 |  |
| q-94b5f8ed21 | check C340 | aggregate | {"dataset": "zeek", "field": "url.domain", "query": "event.action:http", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 62 |  |
| q-6e73de3b8b | check C341 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*signin* OR url.original:*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 0 |  |
| q-f28e203c5e | check C342 | aggregate | {"dataset": "zeek", "field": "http.request.method", "query": "event.action:http", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 62 |  |
| q-c47a6df094 | check C343 | aggregate | {"dataset": "zeek", "field": "http.response.status_code", "query": "event.action:http", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 62 |  |
| q-a2ce50b475 | check C344 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*vpn* OR url.original:*portal* OR url.original:*sso*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-1c086a54be | check C345 | aggregate | {"dataset": "zeek", "field": "user_agent.original", "query": "event.action:http", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 62 |  |
| q-7b6975a512 | check C346 | aggregate | {"dataset": "zeek", "field": "zeek.server_name", "query": "event.action:ssl", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 378 |  |
| q-df018c02f1 | check C347 | aggregate | {"dataset": "zeek", "field": "zeek.certificate_issuer", "query": "event.action:x509", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 378 |  |
| q-03e29073bd | check C348 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:POST OR http.request.method:GET)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 2 |  |
| q-d1592c1ad9 | check C349 | aggregate | {"dataset": "zeek", "field": "zeek.uid", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-95926fde05 | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.Ta… | 2 | F01 |
| q-fc44e9588e | triage T1003 step 1 | search | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.SubjectUserName", "win.SubjectDomainName", "win.ObjectName", "win.ObjectType", "win.Properties", "win.AccessMask", "win.A… | 7 | F02, F04, F06, F07 |
| q-d79b9ced55 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL87ZUOT"} | None |  |
| q-47239db5b6 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbI-"} | None |  |
| q-42f1f2bbec | triage T1003 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"dce_rpc\" AND zeek.endpoint == \"drsuapi\" \| KEEP @timestamp, observer.name, zeek.endpoint, zeek.operation, zeek.id_orig_h, zeek.id_resp_h, zeek.id_resp_p, zeek.named_pipe, zeek… | 9 | F02, F05 |
| q-470ad98839 | triage T1003 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*… | 0 |  |
| q-18598a52d3 | triage T1003 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| STATS c = COUNT(*) BY win.ScriptBlockText \| SORT c ASC \| LIMIT 15"} | 15 |  |
| q-7a3699d1f3 | triage T1003 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectName LIKE \"*lsass*\" \| KEEP @timestamp, host.name, win.SubjectUserName, win.SubjectDomainName, win.ObjectName, win.AccessMask, win.AccessList, wi… | 6 | F01 |
| q-250237a500 | triage T1003 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*powershell.exe -nop -w hidden -e*\" OR win.ScriptBlockText LIKE \"*VirtualAlloc*\" OR win.ScriptBlockText LIKE \"*Compress-Arc… | 5 | F01, F03 |
| q-8c812845a6 | triage T1003 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*sam*\" OR TO_LOWER(process.command_line) LIKE \"*ntds*\" OR TO_LOWER(pr… | 2 | F01 |
| q-91209195c0 | triage T1003 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-a6b1599dcd | triage T1003 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJWyf"} | None |  |
| q-2e03c3d880 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbI-"} | None |  |
| q-a2d2b3993a | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbI-"} | None |  |
| q-7c012bc39d | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbI-"} | None |  |
| q-f6bb7af23f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-33d3e089fb | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-61acdc6891 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-56d2c4d0c0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJWyf"} | None |  |
| q-3322a1ea26 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17AQxS"} | None |  |
| q-b5d9fd9180 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL87ZUOT"} | None |  |
| q-a5ea05b0e4 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL87ZUOT"} | None |  |
| q-bb5c22f7fb | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL87ZUOT"} | None |  |
| q-3f1583d87b | triage T1003 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6p"} | None |  |
| q-754e3bc1b9 | triage T1003 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw3L"} | None |  |
| q-2353e8c46e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxak"} | None |  |
| q-b8e577b73c | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-bbbf88356a | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJGOH"} | None |  |
| q-a7ca23824c | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-c36fbe33de | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9W163v"} | None |  |
| q-57162e2879 | triage T1003 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_Nabl"} | None |  |
| q-194dfeddc0 | triage T1003 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_Nabn"} | None |  |
| q-2dbe5b0560 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9W163v"} | None |  |
| q-0764bf6e64 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9KmH84"} | None |  |
| q-fb1683c1fd | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9GibBE"} | None |  |
| q-dd8a14d529 | triage T1040 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9AdJ6k"} | None | F08 |
| q-8e06c4f49d | triage T1040 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*netsh*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executable", "process.par… | 2 | F08 |
| q-7b3b62d08b | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*NetworkWatcherAgent*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executable"… | 4 | F08 |
| q-a18db18937 | triage T1040 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*pcap*\" OR TO_LOWER(process.command_line) LIKE \"*tshark*\" OR TO_LOWER(process.command_line) LIKE \"*dumpcap*\" OR TO_LOWER(p… | ERROR |  |
| q-b74d09eb98 | triage T1040 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*pcap*\" OR TO_LOWER(process.command_line) LIKE \"*tshark*\" OR TO_LOWER(process.command_line) LIKE \"*dumpcap*\" OR TO_LOW… | 0 |  |
| q-009d6204c2 | triage T1040 step 3 | search | {"dataset": "zeek", "query": "event.action:conn AND destination.port:1234", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "source.ip", "source.port", "destination.ip", "destination.port", "zeek.service", "zeek.conn_state", "netwo… | 1 | F09 |
| q-9fa1658138 | triage T1040 step 4 | search | {"dataset": "zeek", "query": "source.ip:10.0.1.4 OR destination.ip:10.0.1.4", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "source.ip", "source.port", "destination.ip", "destination.port", "zeek.service", "zeek.conn_state", "net… | 395 |  |
| q-c2bc50c935 | triage T1040 step 4 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ServiceName", "win.ImagePath", "win.ServiceType", "win.StartType", "win.param1", "win.param2", "message"], "si… | 5 | F08 |
| q-91bd8d5c0e | triage T1040 step 5 | search | {"dataset": "zeek", "query": "destination.ip:192.168.0.5 OR source.ip:192.168.0.5", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "source.ip", "source.port", "destination.ip", "destination.port", "zeek.service", "zeek.conn_state"… | 6 | F09 |
| q-670b78400c | triage T1040 step 5 | search | {"dataset": "windows.other", "query": "event.code:7036 AND win.param1:*Network*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ServiceName", "win.param1", "win.param2", "win.param3", "message"], "size": 10, "sort… | 2 |  |
| q-b600220391 | triage T1040 step 6 | count | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*netsh*", "time_from": null, "time_to": null} | 2 |  |
| q-dd0fb099c5 | triage T1040 step 6 | count | {"dataset": "windows.security", "query": "event.code:4688 AND process.command_line:(*trace* OR *capture*)", "time_from": null, "time_to": null} | 4 |  |
| q-acc6d09ae9 | triage T1040 step 7 | search | {"dataset": "windows.security", "query": "event.code:4688 AND process.command_line:(*trace* OR *capture*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.exe… | 4 | F08 |
| q-028913925c | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9AdJ6k"} | None |  |
| q-46494c849f | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9AdJ6k"} | None |  |
| q-20a13b011b | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2LOurf"} | None |  |
| q-1eafac0a06 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IK5Hc"} | None |  |
| q-8ba58d120b | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2MP8lJ"} | None |  |
| q-5bddb3a0e0 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2MP8lJ"} | None |  |
| q-b1b9e6f44f | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81VoQs"} | None |  |
| q-bfeb8853f6 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOe"} | None |  |
| q-bb22db75b7 | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0K"} | None |  |
| q-2940761063 | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0K"} | None |  |
| q-4d457963be | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA7h"} | None |  |
| q-a7c462824a | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1X"} | None |  |
| q-b8b790c374 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None | F10 |
| q-9edcf8442b | triage T1056 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.GrantedAccess:(0x1fffff OR 0x101001 OR 0x1f3fff OR 0x1000000 OR 0x3000)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.SourceImage", "win.Targ… | 4356 |  |
| q-644ca117fb | triage T1056 step 1 | search | {"dataset": "windows.sysmon", "query": "process.executable:*cod.3aka3* OR win.SourceImage:*cod.3aka3* OR win.TargetFilename:*cod.3aka3* OR win.Image:*cod.3aka3*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.… | 96 |  |
| q-e7161f7f13 | triage T1056 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None | F11, F12 |
| q-358c978af8 | triage T1056 step 2 | search | {"dataset": "windows.sysmon", "query": "process.parent.executable:*cod.3aka3* OR (process.executable:*cod.3aka3* AND event.code:1)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "process.command_… | 5 | F11 |
| q-3d9de06e22 | triage T1056 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.SourceImage:*powershell* AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "… | 6 | F10 |
| q-78dcee2df4 | triage T1056 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Dump* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*token* OR win.ScriptBlockText:*LogonUser* O… | 4 |  |
| q-358c1347be | triage T1056 step 3 | search | {"dataset": "windows.sysmon", "query": "process.parent.executable:*cmd.exe AND host.name:scranton.dmevals.local AND event.code:1 AND @timestamp:[2020-05-02T02:56:00 TO 2020-05-02T03:10:00]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 6 | F11 |
| q-6661c03e8a | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mm"} | None | F10 |
| q-73ab4f266e | triage T1056 step 4 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:4104 AND (win.ScriptBlockText:*OpenProcess* OR win.ScriptBlockText:*CreateRemoteThread* OR win.ScriptBlockText:*VirtualAlloc* OR win.ScriptBlockText:*WriteProcessMemory… | 2 |  |
| q-fc6f7064da | triage T1056 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None | F10 |
| q-3314b7b923 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None |  |
| q-8e743807cd | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None |  |
| q-cb76ccd379 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None |  |
| q-df9645c511 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-9a92ce7ac7 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-87875f9f5b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbI-"} | None |  |
| q-d9280ba7c3 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNLI1"} | None |  |
| q-24d2aa1441 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mm"} | None |  |
| q-0e17d05987 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-e76e10ad13 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-96b1cd9da2 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-828819b13a | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7amkgV"} | None |  |
| q-36f9870200 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7amUh2"} | None |  |
| q-a3cae14fd1 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-f400b05eab | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7Wisfl"} | None |  |
| q-4be9abfa85 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6_OHx"} | None |  |
| q-6b1a7bfdcf | triage T1056 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-51fd37f894 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxak"} | None |  |
| q-e9a40f00d5 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-50dbad5c48 | triage T1110 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*SAM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-2c181e6edd | triage T1110 step 1 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*NTDS* OR win.ObjectName:*SECURITY* OR win.ObjectName:*SYSTEM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": … | 4484 |  |
| q-f800f723bc | triage T1110 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1fffff OR process.executable:*wsmprovhost*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "us… | 5 | F17 |
| q-2564975c6e | triage T1110 step 2 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:SAM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "win.ObjectName", "win.AccessMask", "win.ProcessName"], "size": 20, … | 10 | F17 |
| q-ba57ce457b | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None | F17 |
| q-7a3afe7f14 | triage T1110 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Dump* OR win.ScriptBlockText:*Get-Process*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 3 |  |
| q-90335f9e34 | triage T1110 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND process.executable:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line",… | 11 |  |
| q-60e24d4fd7 | triage T1110 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:scranton.dmevals.local AND user.name:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.ScriptBlockText"], "size": 30, "s… | 146 |  |
| q-ed238934d4 | triage T1110 step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:00:00.000Z TO 2020-05-02T03:10:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "eve… | 99 |  |
| q-1217005b2a | triage T1110 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None | F17 |
| q-ee005a3884 | triage T1110 step 6 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-Command* OR win.ScriptBlockText:*New-PSSession* OR win.ScriptBlockText:*Enter-PSSession* OR win.ScriptBlockText:*CredSSP* OR win.ScriptBlockText:*Get-Credential*)", "t… | 1 |  |
| q-4a6b178a2e | triage T1110 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F17, F19 |
| q-12d55d0958 | triage T1110 step 7 | count | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776 OR event.code:4648", "time_from": null, "time_to": null} | 16 |  |
| q-9621e28e5c | triage T1110 step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (4625, 4771, 4776, 4648) \| KEEP @timestamp, host.name, event.code, user.name, win.TargetUserName, win.IpAddress, source.ip, win.LogonProcessName, win.Status, win.Authent… | ERROR |  |
| q-0ff434abf8 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5qJ"} | None |  |
| q-8bd690b349 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5qJ"} | None |  |
| q-9dd0aa28f5 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5qJ"} | None |  |
| q-3ffdbab752 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6-sXC"} | None |  |
| q-b92a25622c | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6-sXC"} | None |  |
| q-4b0da70bbe | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-646f7dbfe5 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-efe1aa900d | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-caef5ce746 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-1b4db6a17d | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-0a951bcf6e | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-91deafa377 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o4"} | None |  |
| q-5682f78392 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o4"} | None |  |
| q-e8e15024e0 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-b14b7a6cfb | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-59dc757db1 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F20 |
| q-0c19c77765 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-d5aa5bd966 | triage T1111 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-d59df1de70 | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.TargetImage", "… | 2 |  |
| q-91d03046da | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "process.command_line:(*SmartCard* OR *smartcard* OR *MFA* OR *mfa* OR *Telephony* OR *telephony* OR *Tapi* OR *tapi* OR *NPS* OR *RADIUS* OR *radius* OR *OTP* OR *otp* OR *token* OR *Token*)", "time_from": null, "time_to… | 1 | F20 |
| q-efd6b33bfa | triage T1111 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbI-"} | None |  |
| q-23b98e005b | triage T1111 step 3 | search | {"dataset": "windows.sysmon", "query": "(registry.path:*SmartCard* OR registry.path:*Telephony* OR registry.path:*Tapi* OR registry.path:*RADIUS* OR registry.path:*NPS* OR win.TargetFilename:*smartcard* OR win.TargetFilename:*mfa* OR win.TargetFilename:*otp*)"… | 165 | F20 |
| q-4e5a769bdd | triage T1111 step 4 | aggregate | {"dataset": "windows.sysmon", "field": "event.code", "query": "registry.path:*SmartCardRoot*", "time_from": null, "time_to": null, "size": 10, "sub_field": "process.executable"} | 162 |  |
| q-f71c759566 | triage T1111 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executable", "user.name"], "size"… | 12 |  |
| q-5cc680e5c0 | triage T1111 step 5 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*SmartCard* OR *smartcard* OR *MFA* OR *Telephony* OR *tapi* OR *RADIUS* OR *NPS* OR *OTP* OR *CredentialProvider* OR *Winlogon* OR *netsh* OR *proxy*)", "time_from": null, "time_to": null, "fiel… | 0 |  |
| q-7c0e9b2984 | triage T1111 step 5 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "win.LogonType", "win.TargetUserName", "win.IpAddress", "win.AuthenticationPac… | 2 | F20 |
| q-c3256f9309 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ZmIXh"} | None |  |
| q-4fa1dee9bc | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ZmIXh"} | None |  |
| q-70db9734e8 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx40qiu"} | None |  |
| q-33528aa387 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-3bfe5da1f4 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8vSVsl"} | None |  |
| q-608f3e6f22 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8vSVsl"} | None |  |
| q-88e182bcc9 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-c780b75305 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-6d1d70b7cd | triage T1187 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND destination.port:445", "time_from": null, "time_to": null, "size": 30, "sub_field": "host.name"} | 66 |  |
| q-6fd6034b4d | triage T1187 step 1 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5145", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 121 |  |
| q-fda607a93c | triage T1187 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL64D_f9"} | None | F22 |
| q-acc1b2a98a | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:OPTIONS OR http.request.method:MOVE)", "time_from": null, "time_to": null, "size": 30, "sub_field": "http.request.method"} | 36 |  |
| q-771c65cb89 | triage T1187 step 2 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:OPTIONS)", "time_from": null, "time_to": null, "fields": ["@timestamp", "source.ip", "destination.ip", "destination.port", "http.request.method", "url.orig… | 36 | F21 |
| q-cbc289f414 | triage T1187 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*hostui* OR win.ScriptBlockText:*StartUp* OR win.ScriptBlockText:*lnk*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ScriptBlo… | 3 |  |
| q-36c9a085f0 | triage T1187 step 3 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:03:00.000Z TO 2020-05-02T03:06:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.Scrip… | 395 |  |
| q-5a9a05c91c | triage T1187 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND destination.port:445 AND destination.ip:10.0.1.6", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "destination.ip", "destination.port", "win.… | 16 | F23 |
| q-0abc08594d | triage T1187 step 4 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw17"} | None |  |
| q-d7a3c0de43 | triage T1187 step 4 | search | {"dataset": "zeek", "query": "source.ip:10.0.1.4 AND NOT event.action:http", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "source.ip", "destination.ip", "destination.port", "zeek.query", "zeek.rcode_name", "zeek.service", "zeek.… | 333 |  |
| q-c2f61dea1f | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5C"} | None |  |
| q-284b3ec8aa | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw17"} | None |  |
| q-de581e8127 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw17"} | None |  |
| q-178956dac5 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw17"} | None |  |
| q-397b88bffd | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5D"} | None |  |
| q-e4c0f18934 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5D"} | None |  |
| q-2ada8f237e | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5D"} | None |  |
| q-0710c878b7 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5D"} | None |  |
| q-ef547974c4 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL64D_f9"} | None |  |
| q-0f5fcd899d | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL64D_f9"} | None |  |
| q-473ce7a1cc | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMah"} | None |  |
| q-e3360f3ef8 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMaR"} | None |  |
| q-0e2c2734c0 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o7"} | None |  |
| q-bc6cfbb73c | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9KmX__"} | None |  |
| q-edbd2cf6d5 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2jo9Kj"} | None |  |
| q-4f7c1c29dc | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2jo9Kj"} | None |  |
| q-83515f5506 | triage T1212 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND NOT win.SourceImage:\"C:\\\\windows\\\\system32\\\\svchost.exe\" AND NOT win.SourceImage:*AntimalwareConfig.exe AND NOT win.SourceImage:*WindowsAzureTelemetryService.exe", "t… | 9 | F25 |
| q-71f68590a2 | triage T1212 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:\"0x1fffff\" OR win.GrantedAccess:\"0x101001\" OR win.GrantedAccess:\"0x1f3fff\" OR win.GrantedAccess:\"0x1000000\" OR win.GrantedAccess:\"0x3000\")", "tim… | 9 | F24, F25 |
| q-47560293c5 | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None | F24 |
| q-d855d0ec3a | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-1ab3651d2a | triage T1212 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Dump* OR win.ScriptBlockText:*Invoke-Mi… | 3 |  |
| q-0d2705cdd4 | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-3924fabd36 | triage T1212 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND (process.command_line:*lsass* OR process.command_line:*dump* OR process.command_line:*Dump* OR process.command_line:*MiniDump* OR process.command_line:*sekurlsa* OR p… | 1 |  |
| q-05ed032a73 | triage T1212 step 4 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND (process.pid:2976 OR process.parent.pid:2976 OR win.TargetFilename:*dmp OR win.TargetFilename:*.dmp OR process.command_line:*comsvcs* OR process.command_line:*rundll32* OR process.com… | 554 | F24 |
| q-02bc5c9f8e | triage T1212 step 4 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND (process.pid:2976 OR process.pid:3852 OR win.ScriptBlockText:*Get-Process* OR win.ScriptBlockText:*OpenProcess* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Dump* OR … | 1032 |  |
| q-71a19184ad | triage T1212 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None | F24 |
| q-c2f787a97b | triage T1212 step 5 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND event.code:10 AND win.SourceImage:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "process.command_line", … | 448 |  |
| q-24d5cc1fdf | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-1bd07767fb | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-54214c309f | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-57e015d1d9 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-a760c44c24 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-df8646da6c | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-eae8a80f6c | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-4b55432e6b | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2QULdY"} | None |  |
| q-f90e1c01ed | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrt3"} | None |  |
| q-6396312e40 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx1ssmj"} | None |  |
| q-93c95d18b8 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2MQMm5"} | None |  |
| q-1fb90fbacf | triage T1539 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (win.TargetFilename LIKE \"*Cookies*\" OR win.TargetFilename LIKE \"*Login Data*\" OR win.TargetFilename LIKE \"*Web Data*\") \| STATS c = COUNT(*) BY process.execut… | ERROR |  |
| q-4c620be19a | triage T1539 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (win.TargetFilename LIKE \"*Cookies*\" OR win.TargetFilename LIKE \"*Login Data*\" OR win.TargetFilename LIKE \"*Web Data*\") \| KEEP @timestamp, host.name, process.… | ERROR |  |
| q-30b8e5a883 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (win.TargetFilename LIKE \"*Cookies*\" OR win.TargetFilename LIKE \"*Login Data*\" OR win.TargetFilename LIKE \"*Web Data*\") \| STATS c = COUNT(*) BY process.ex… | 1 |  |
| q-ea440e8f96 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (win.TargetFilename LIKE \"*Cookies*\" OR win.TargetFilename LIKE \"*Login Data*\" OR win.TargetFilename LIKE \"*Web Data*\") \| KEEP @timestamp, host.name, proc… | 1 |  |
| q-918109f0e7 | triage T1539 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F26 |
| q-ce1a18890b | triage T1539 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAPClpO"} | None | F26 |
| q-7c79eb99ca | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"10\" OR event.code == \"11\" OR event.code == \"23\") AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LO… | ERROR |  |
| q-e807979ef5 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*chrome*\" OR TO_LOWER(process.executable) LIKE \"*firefox*\" OR TO_LOWER(process.executable) LIKE \"*msedge*\" OR TO_LOWER(p… | 0 |  |
| q-b1b2399b41 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"10\" OR event.code == \"11\" OR event.code == \"23\") AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LO… | 1 |  |
| q-4f8911fc91 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| STATS c = COUNT(*) BY process.executable, host.name \| SORT c ASC \| LIMIT 40"} | 40 |  |
| q-709064ca4c | triage T1539 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None | F26 |
| q-b2d7e434f7 | triage T1539 step 6 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" \| KEEP @timestamp, source.ip, destination.ip, url.original, http.request.method, http.response.status_code, user_agent.original, _id, _index \| LIMIT 30"} | 30 | F26 |
| q-9efabe8a34 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-4bbb3e6929 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-824789c2df | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7anEhE"} | None |  |
| q-ce6e84c41f | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Txpr2"} | None |  |
| q-c46cdc4ff6 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-3d6cc0c53e | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAPClpO"} | None |  |
| q-dde03df291 | triage T1539 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA04"} | None |  |
| q-615086d4f4 | triage T1539 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA01"} | None |  |
| q-d951c937f3 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None | F27 |
| q-c80e71372f | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F28 |
| q-35986a53a5 | triage T1552 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.p12\" OR TO_LOWER(win.TargetFilename) LIKE \"*.7z\" OR TO_LOWER(win.TargetFilen… | ERROR |  |
| q-bd6c02fb04 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.p12\" OR TO_LOWER(win.TargetFilename) LIKE \"*.7z\" OR TO_LOWER(win.TargetF… | 8 | F27, F28 |
| q-7f19af5f60 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*certutil*\" OR TO_LOWER(process.command_line) LIKE \"*export-pfx*\" OR TO_LOWER(process.command_line) LIKE \"*7z*\" OR TO_… | 4 | F28 |
| q-172026f233 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*rar*\" OR TO_LOWER(process.command_line) LIKE \"*working.zip*\" OR TO_LOWER(process.command_line) LIKE \"*python*\" OR TO_… | 13 | F28 |
| q-a3503fff5c | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*gpt.ini*\" OR TO_LOWER(win.TargetFilename) LIKE \"*sysvol*\" OR TO_LOWER(win.TargetFilename) LIKE \"*groups.xml*\") \| KEEP… | 22 | F29 |
| q-bcff8a4eb0 | triage T1552 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, user.name, process.executable, process.command_line, process.parent.executable, _id, _index"} | 61 |  |
| q-15fad7471f | triage T1552 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*defaultpassword*\" OR TO_LOWER(registry.path) LIKE \"*autologon*\" OR TO_LOWER(registry.path) LIKE \"*vault*\" OR TO_LOWER(regis… | 2 | F30 |
| q-8df86192bd | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-ee0f20572c | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-5d3972a2e2 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-1438a49810 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-2d2315aa72 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-329c6bebec | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-c73aab1a87 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-bffd27020b | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7zj"} | None |  |
| q-c19bf9e619 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-bc85e532dc | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2UXka_"} | None |  |
| q-c32bdf0989 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2chAnX"} | None |  |
| q-68cf07b8af | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2LOuo5"} | None |  |
| q-69d67bd322 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2LOuo5"} | None |  |
| q-759e9db59b | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtv"} | None |  |
| q-73fb042403 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx1rWlK"} | None |  |
| q-2a9d3aede0 | triage T1555 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F31, F33 |
| q-a7963e9232 | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F34, F36 |
| q-86ede6fcf4 | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None | F31 |
| q-ba6f7378ad | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None | F31 |
| q-201d2b24f6 | triage T1555 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, host.name, p… | ERROR |  |
| q-0607ee1826 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, host.nam… | 47 | F31 |
| q-86f5dcb1fb | triage T1555 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, h… | 102 |  |
| q-426bdb35c4 | triage T1555 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVp3"} | None | F31 |
| q-4570c0695e | triage T1555 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1l8"} | None |  |
| q-b6379ff04d | triage T1555 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVqk"} | None |  |
| q-cb2bfaede2 | triage T1555 step 5 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "process.executable", "win.SubjectUserName", "win.AccessMask", "win.AccessList", … | 6 | F31, F33 |
| q-8605f0995c | triage T1555 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None | F32 |
| q-094a09a612 | triage T1555 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" AND @timestamp >= \"2020-05-02T03:05:00.000Z\" AND @timestamp <= \"2020-05-02T03:15:00.000Z\" \| KEEP @timestamp, hos… | 2 | F32 |
| q-74ecf7986a | triage T1555 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND @timestamp >= \"2020-05-02T03:05:00.000Z\" AND @timestamp <= \"2020-05-02T03:15:00.000Z\" \| KEEP @timestamp, host.name,… | 26 |  |
| q-90d02e8096 | triage T1555 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*Credential*\" OR win.ScriptBlockText LIKE \"*Vault*\" OR win.ScriptBlockText LIKE \"*cmdkey*\" OR win.ScriptBlockText LIKE \"*… | 3 |  |
| q-396d331b4a | triage T1555 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*Login Data*\" OR file.path LIKE \"*Cookies*\" OR file.path LIKE \"*Local State*\" OR file.path LIKE \"*.kdbx\" OR file.path LIKE \"*keepass*\"… | 1 | F34 |
| q-55ebc5764f | triage T1555 step 8 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMASEsOI"} | None |  |
| q-58894c606e | triage T1555 step 8 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBekH"} | None | F35 |
| q-331981f94c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-f5d7f8c2cf | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-40c0cf23ed | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-0062cd8515 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-6c71910c06 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-71ce0ca6fb | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVp3"} | None |  |
| q-5be7fe2e2f | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HSbI"} | None |  |
| q-7457685d38 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-6d0fc44705 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-798a6d57fe | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-00a34ae285 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2QULdY"} | None |  |
| q-7739a31b80 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrt3"} | None |  |
| q-fbc68b2deb | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81VYSA"} | None |  |
| q-0deabc4dc0 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-a883c20d72 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-c9e3d8b848 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-df00092c7e | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBekH"} | None |  |
| q-da49a0ea83 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-77aeb3c1b9 | triage T1556 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass.exe\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, hos… | 33 | F37, F38 |
| q-31baafe11c | triage T1556 step 1 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*AllowReversiblePasswordEncryption*\" OR win.ScriptBlockText LIKE \"*ReversibleEncryption*\" OR win.ScriptBlockText LIKE \"*Set… | 1 | F40 |
| q-1901359ac0 | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMASEsOI"} | None | F40 |
| q-230fd6ffca | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None | F37 |
| q-69e0edb354 | triage T1556 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"1\" AND (process.pid == 2976 OR process.parent.pid == 2976)) OR (event.code == \"10\" AND win.SourceProcessId == \"2976\") \| KEEP @timestamp, event.code, host.name, pro… | 146 | F37 |
| q-3c4a9b6efc | triage T1556 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass.exe\" AND win.SourceImage LIKE \"*wsmprovhost*\" \| KEEP @timestamp, host.name, win.SourceImage, win.SourceProcessId, win.GrantedAc… | 1 |  |
| q-6f9b8e3091 | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None | F38 |
| q-334bcfd620 | triage T1556 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.TargetServerName, win.ProcessName, win.SubjectUserName, win.IpAddress, _id, _index \| SORT @tim… | 15 |  |
| q-6d122dc921 | triage T1556 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None | F43 |
| q-ab018689e6 | triage T1556 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4697\" OR event.code == \"4611\" OR event.code == \"4702\" OR event.code == \"5058\" OR event.code == \"5061\" \| KEEP @timestamp, event.code, host.name, user.name, win… | 75 |  |
| q-8b6e16ce40 | triage T1556 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qur1j"} | None |  |
| q-d84e538323 | triage T1556 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qtr33"} | None |  |
| q-12d6862702 | triage T1556 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"7\" AND (win.ImageLoaded LIKE \"*cryptdll.dll\" OR win.ImageLoaded LIKE \"*lsass.exe\" OR win.ImageLoaded LIKE \"*wdigest.dll\" OR win.ImageLoaded LIKE \"*samsrv.dll\") \… | 36 | F38, F39 |
| q-efdf4f1c5f | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-c5d96ff789 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-863a77be71 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-f72cb2a0cb | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-1e25a49034 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-d2ce180698 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7VhsbT"} | None |  |
| q-5299c35da8 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IKpCB"} | None |  |
| q-f11a6980cf | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IKpCB"} | None |  |
| q-f029dda413 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-a7cf3495d7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtr"} | None |  |
| q-5e7fa30ec2 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IK5ET"} | None |  |
| q-6646971a08 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2HKb5Z"} | None |  |
| q-17a8099b25 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMASEsOI"} | None |  |
| q-f3d28b791f | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMASEsOI"} | None |  |
| q-dbb212ed0d | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMASEsOI"} | None |  |
| q-7187f0dfdb | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TxprU"} | None |  |
| q-7950038521 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TxprU"} | None |  |
| q-6c6bdb1d1c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2HKb5i"} | None |  |
| q-ad5ab11f6a | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2HKb5i"} | None |  |
| q-07e409600f | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2HKb50"} | None |  |
| q-5460221c98 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-c9d6b13ea0 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-61e69342c8 | triage T1557 step 1 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 40, "sub_field": null} | 10977 |  |
| q-b64055708f | triage T1557 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 60, "sub_field": null} | 447 |  |
| q-74fd8e7c45 | triage T1557 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*ARP.EXE OR process.executable:*ROUTE.EXE OR process.executable:*ipconfig.exe OR process.executable:*netsh.exe OR process.executable:*python.exe)", "time_from": null, "time_to": null,… | 16 | F44, F46 |
| q-ffa2b0b0c3 | triage T1557 step 2 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*arp* OR process.command_line:*route* OR process.command_line:*netsh* OR process.command_line:*ipconfig*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 11 | F46 |
| q-b26df4d65a | triage T1557 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.ScriptBlockText \| LIMIT 60"} | 60 |  |
| q-84e077ae8e | triage T1557 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*python* OR file.path:*Temp* OR file.path:*victim*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "pro… | 183 |  |
| q-9e82a3fded | triage T1557 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND win.ScriptBlockText IS NOT NULL AND (TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*psexec*\" OR TO_LOWER(win.Script… | 37 |  |
| q-0d6818428f | triage T1557 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND host.name:nashua.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executable", "process… | 428 | F47 |
| q-87405c6e1d | triage T1557 step 5 | search | {"dataset": "windows.sysmon", "query": "host.name:nashua.dmevals.local AND (process.executable:*python* OR win.Image:*python* OR process.parent.executable:*python*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "proce… | 520 |  |
| q-c855234b32 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND win.ScriptBlockText IS NOT NULL AND (TO_LOWER(win.ScriptBlockText) LIKE \"*seaduke*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-seadukestage*\" OR TO… | 6 |  |
| q-0205d8f7c2 | triage T1557 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"3\" AND (process.executable LIKE \"*python*\" OR win.Image LIKE \"*python*\") \| KEEP @timestamp, host.name, user.name, process.… | 40 |  |
| q-77498c93d9 | triage T1557 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND win.ScriptBlockText IS NOT NULL AND TO_LOWER(win.ScriptBlockText) LIKE \"*function invoke-seadukestage*\" \| KEEP @timestamp, host.name, user.name, win.Scr… | 0 |  |
| q-9d6d8789a9 | triage T1557 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | ERROR |  |
| q-e484bef411 | triage T1557 step 7 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND destination.port == 8443 \| KEEP @timestamp, observer.name, source.ip, destination.ip, destination.port, zeek.conn_state, zeek.orig_l2_addr, zeek.resp_l2_addr, zeek.se… | 15 |  |
| q-6d740c99d9 | triage T1557 step 8 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND win.ScriptBlockId == \"10d42c28-8b8e-4d93-abb7-f81ba04b2faa\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.ScriptBlockText \| LIMIT 3"} | 1 |  |
| q-0ccd06c232 | triage T1557 step 8 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"dns\" \| KEEP @timestamp, observer.name, source.ip, destination.ip, destination.port, dns.question.name, zeek.qtype_name, zeek.rcode_name \| LIMIT 60"} | 53 |  |
| q-44bc33c50a | triage T1557 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "n/a"} | ERROR |  |
| q-091580726d | triage T1557 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "n/a"} | ERROR |  |
| q-663e46c8e4 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-fc4e83294c | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-f4e5ba3a5a | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TypoS"} | None |  |
| q-f1015972e8 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5qJ"} | None |  |
| q-7fc7553492 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw29"} | None |  |
| q-cd4ca7d558 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA-MPUF"} | None |  |
| q-f57f38ec13 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1R"} | None |  |
| q-6d96b4afa6 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-1febd69149 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-cb75c565a0 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IKpDz"} | None |  |
| q-4044234f59 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IKpDz"} | None |  |
| q-09d296d035 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx0p9y3"} | None |  |
| q-574cf1d7b0 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-b3HP"} | None |  |
| q-a6a49d158a | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7YlLAM"} | None |  |
| q-8e79c180ab | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL4RO"} | ERROR |  |
| q-2fffb1171b | triage T1557 step 10 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND win.ScriptBlockText IS NOT NULL AND (win.ScriptBlockText LIKE \"*Invoke-SeaDukeStage*\" OR win.ScriptBlockText LIKE \"*PsExec64.exe -accepteula*\") \| KEEP… | 5 | F44 |
| q-c8eeb314e5 | triage T1557 step 10 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*ipconfig.exe\" \| KEEP @timestamp, host.name, _id, _index, process.command_line, process.parent.executable \| LIMIT 10"} | 3 | F47 |
| q-e26d984577 | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.GrantedAccess",… | 4 | F48, F49 |
| q-48f1adf6b3 | triage T1558 step 1 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "zeek.request_type", "zeek.client", "zeek.service", "zeek.success", "zeek.error_msg", "zeek.id_orig_h", "zeek.id_resp_h", "zeek.cipher", "zeek.fo… | 35 | F51, F52 |
| q-d99249a8ef | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-d83326a249 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-a042d1c658 | triage T1558 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*kerberos*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ticket*\" OR … | 16 | F48 |
| q-30276fa89a | triage T1558 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*credential*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*dump*\" … | 11 |  |
| q-0fdedb235b | triage T1558 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.pid == 2976 OR process.parent.pid == 2976 OR TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOWE… | 6 | F48 |
| q-893648d581 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4768\",\"4769\",\"4770\",\"4771\",\"4765\",\"4766\",\"4672\",\"4624\") \| STATS cnt = COUNT(*) BY event.code, win.TargetUserName, win.LogonType, win.TicketEncryptionTy… | 28 |  |
| q-f7763b1185 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND process.executable NOT LIKE \"*svchost.exe\" AND process.executable NOT LIKE \"*AntimalwareConfig.exe\" AND process.executab… | 9 | F48 |
| q-2d232d4755 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4769\",\"4768\") \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.IpAddress, win.Status… | 40 | F49, F50, F51, F52 |
| q-93441d03d3 | triage T1558 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-82f68b93d0 | triage T1558 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBExi"} | None |  |
| q-cd217cf9e9 | triage T1558 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*seaduke*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-*\") \| KEEP … | 14 | F48 |
| q-dd5eb6b950 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-640e866158 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-2d43f85588 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-c43e799e5f | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-15f91f9bbe | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBExi"} | None |  |
| q-ac2eb2cb5a | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E6"} | None |  |
| q-4d1105693b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-3dbd3a630b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFP"} | None |  |
| q-a816a4f718 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFP"} | None |  |
| q-0535a853bd | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrnEj"} | None |  |
| q-c82a732605 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Cfa6D"} | None |  |
| q-fae1881327 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrnEj"} | None |  |
| q-b3149bc0c1 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1d"} | None |  |
| q-ec6623c0aa | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1d"} | None |  |
| q-df6fbe6278 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFP"} | None |  |
| q-e2d718bd09 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1f"} | None |  |
| q-5025f96e0d | triage T1606 step 1 | search | {"dataset": "windows.security", "query": "event.code:4624 AND (win.LogonProcessName:\"NtLmSsp \" OR win.LogonProcessName:\"User32 \" OR win.LogonProcessName:\"-\")", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.Ta… | 4 | F55 |
| q-6aaf67caab | triage T1606 step 1 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.TargetUserName", "win.SubjectUserName", "win.ProcessName", "win.IpAddress", "win.TargetServerName"], "size":… | 15 | F53, F55 |
| q-55f7d6b2d4 | triage T1606 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x121440 OR win.GrantedAccess:0x101541 OR win.GrantedAccess:0x101441 OR win.GrantedAccess:0x103800 OR win.GrantedAccess:0x1… | 1298 |  |
| q-3402d5a760 | triage T1606 step 2 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-aac0d2e8bb | triage T1606 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.SourceImage:*PowerShell.exe OR win.SourceImage:*wsmprovhost.exe OR win.SourceImage:*wininit.exe OR win.SourceImage:*csrss.exe)", "time_from": null, "time_to": null, "fie… | 6 | F53 |
| q-b072f11190 | triage T1606 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*procdump* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*Credenti… | 4 |  |
| q-29e53dc7f2 | triage T1606 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-8cb803d780 | triage T1606 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-656a8e1b38 | triage T1606 step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND @timestamp:[2020-05-02T03:00:00.000Z TO 2020-05-02T03:15:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.ScriptBlockText", "pro… | 232 |  |
| q-18a0202cbc | triage T1606 step 5 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*SAML* OR *saml* OR *cookie* OR *Cookie* OR *AADSSO* OR *ADFS* OR *Golden* OR *Skeleton* OR *Impersonat* OR *LogonUser* OR *DuplicateToken*)", "time_from": null, "time_to": null, "fields": ["@tim… | 0 |  |
| q-7e2ee75baf | triage T1606 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*procdump* OR process.command_line:*MiniDump* OR process.command_line:*comsvcs* OR process.command_line:*sekurlsa* OR process.command_line:*Invoke-Mi… | 1 |  |
| q-cae30572ce | triage T1606 step 6 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND @timestamp:[2020-05-02T03:04:00.000Z TO 2020-05-02T03:10:00.000Z] AND (win.ScriptBlockText:*procdump* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*Out-Minidump* OR win.ScriptBlockText:*G… | 3 | F53 |
| q-abadd57999 | triage T1606 step 7 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND @timestamp:[2020-05-02T03:04:30.000Z TO 2020-05-02T03:06:30.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.ScriptBlockText", "pro… | 18 | F53 |
| q-04518dd1a8 | triage T1606 step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND @timestamp:[2020-05-02T03:04:00.000Z TO 2020-05-02T03:07:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "p… | 31 |  |
| q-3dd2838d0c | triage T1606 step 8 | search | {"dataset": "zeek", "query": "event.action:http OR event.action:dns", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "source.ip", "destination.ip", "destination.port", "url.domain", "url.original", "http.request.method", "http.res… | 115 | F53, F54 |
| q-454558c8b4 | triage T1606 step 8 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*Login* OR win.ObjectName:*Web* OR win.ObjectName:*Token* OR win.ObjectName:*Credential* OR win.ObjectName:*sso* OR win.ObjectName:*adfs*)", "time_from": null, "time_to": null, "fiel… | 0 |  |
| q-692d1cdb2d | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-b1e71048db | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-3911f2a3d6 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-92d4dd5537 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-9666e14257 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-3d6a0eddd8 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-21d796bff3 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-6ec102fa37 | triage T1606 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2z"} | None |  |
| q-67075c3cd3 | triage T1606 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2z"} | None |  |
| q-ddf162e4ea | triage T1606 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5-"} | None |  |
| q-6ccb1899da | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8tQe-L"} | None |  |
| q-6b88db6a0f | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8vSVsl"} | None |  |
| q-221b8de569 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL88axkf"} | None |  |
| q-382b2bfa99 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFV"} | None |  |
| q-2181fabd59 | triage T1621 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*dsregcmd* OR process.executable:*LogonUI* OR process.executable:*consent* OR process.executable:*python* OR process.executable:*PsExec* OR process.executable:*sdelete*)", "time_from"… | 26 |  |
| q-e7a828b41c | triage T1621 step 1 | aggregate | {"dataset": "windows.powershell", "field": "process.command_line", "query": "event.code:4104", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 414 |  |
| q-ec2bcf43fe | triage T1621 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*mfa*\" OR TO_LOWER(process.command_line) LIKE \"*auth*\" OR TO_LOWER(process.command_line) LIKE \"*otp*\" OR TO_LOWER(proc… | 33 | F56 |
| q-d471047f49 | triage T1621 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*python*\" OR process.parent.executable LIKE \"*python*\" OR process.executable LIKE \"*PSEXESVC*\") \| KEEP @timestamp, host.name, use… | 15 |  |
| q-4b66a27fe0 | triage T1621 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 11 | F56 |
| q-cea77d88e7 | triage T1621 step 3 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": "win.LogonType"} | 297 |  |
| q-36bc6fb7c0 | triage T1621 step 4 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonProcessName:\"User32\"", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.TargetUserName", "win.LogonType", "win.LogonProcessName", "win.IpAddress… | 0 |  |
| q-22522bffaa | triage T1621 step 4 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*mfa*\" OR TO_LOWER(message) LIKE \"*multi-factor*\" OR TO_LOWER(message) LIKE \"*authenticator*\" OR TO_LOWER(message) LIKE \"*one-time*\" OR TO_LOWER(message) L… | 0 |  |
| q-d0ecaeaf43 | triage T1621 step 5 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.TargetUserName", "win.LogonType", "win.LogonProcessName", "win.IpAddress", "win.Worksta… | 2 | F56 |
| q-b7d4b62bbf | triage T1621 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" OR event.code == \"4625\" OR event.code == \"4776\" \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.IpAddress, win.Workstation, _id, _index \|… | 16 | F56 |
| q-e919bf758c | triage T1621 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None | F56 |
| q-c7003d3218 | triage T1621 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None | F56 |
| q-4d2cf45ac5 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-a00be8e326 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2x8I_R"} | None |  |
| q-6424a1a24e | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2x8I_R"} | None |  |
| q-d3d57ce9e6 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-4de64698d2 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBfbr"} | None |  |
| q-4398c22249 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFV"} | None |  |
| q-fa2dba4cd8 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-e6369eb604 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8vSVsl"} | None |  |
| q-54e81d80ba | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.ObjectValueName", "win.NewValue", "win.OldValue", "win.ProcessN… | 1 |  |
| q-ab84a8da47 | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.IpAddress", "win.TicketEncryptionType", "win.TicketOptions", "win.Status", "win.PreAuthType", "win.… | 14 | F58 |
| q-e9a104693d | triage T1649 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None | F58 |
| q-ba52c5c585 | triage T1649 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(process.command_line) LIKE \"*certutil*\" OR TO_LOWER(process.command_line) LIKE \"*cert*\" OR TO_LOWER(process.command_line) LIKE \"*crypto*\" OR TO_LOWER(process.command_line)… | 1 |  |
| q-4318854108 | triage T1649 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == 11 OR event.code == 12 OR event.code == 13) AND (TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*.p12\" OR TO_LOWER(file.path) LIKE \"*.cer\" OR TO_LOWER… | ERROR |  |
| q-773e637221 | triage T1649 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*cert*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*x509*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*pkcs*\" OR TO_LOWER(win.ScriptBlockText) LIKE … | 3 | F57 |
| q-be78a758c3 | triage T1649 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-77f2456c2f | triage T1649 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*.p12\" OR TO_LOWER(process.command_line) LIKE \"*get-privatekeys*\" OR TO_LOWER(process.command_line) LIKE \"*.pfx*\" \|… | 2 | F57 |
| q-1244960f5d | triage T1649 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None | F57 |
| q-96f1a4ea92 | triage T1649 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND user.name == \"pbeesly\" AND event.code == \"4104\" \| KEEP @timestamp, win.ScriptBlockText, _id, _index \| LIMIT 20"} | 20 |  |
| q-9552fae18d | triage T1649 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*readme.ps1*\" OR TO_LOWER(process.command_line) LIKE \"*powershell*\" OR TO_LO… | 11 |  |
| q-10703fa49e | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-6998d711f5 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-ad1630548d | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-6e2f8da094 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-3a697b15af | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-473bc819e0 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None |  |
| q-6a85545c3b | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None |  |
| q-4461665dcf | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-84c1d1a104 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6__si"} | None |  |
| q-93829c699d | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None |  |
| q-85a0a42ac7 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None |  |
| q-4e4216d403 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFP"} | None |  |
| q-4212e48d51 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbI-"} | None |  |
| q-da3f510e1e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbI-"} | None |  |
| q-59647362e3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbI-"} | None |  |
| q-685c8f5691 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-2524f9513b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-a378e7829e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-86543a74a7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJWyf"} | None |  |
| q-37176a018c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17AQxS"} | None |  |
| q-2360cf4abe | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL87ZUOT"} | None |  |
| q-7f49796e58 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL87ZUOT"} | None |  |
| q-2728dcd205 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL87ZUOT"} | None |  |
| q-d2bac0da46 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6p"} | None |  |
| q-42d10de4b3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw3L"} | None |  |
| q-9643fb5281 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxak"} | None |  |
| q-c44cfeaec2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-e2332bbec8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJGOH"} | None |  |
| q-2deb5f5ddf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-593f963804 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9W163v"} | None |  |
| q-0dd915ceb3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_Nabl"} | None |  |
| q-de49d3cbe6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_Nabn"} | None |  |
| q-601724527e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9W163v"} | None |  |
| q-f2aa5c6859 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9KmH84"} | None |  |
| q-b79b12db9a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9GibBE"} | None |  |
| q-e7f1518017 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9AdJ6k"} | None |  |
| q-27c5bb75b7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9AdJ6k"} | None |  |
| q-5a8617a9a1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2LOurf"} | None |  |
| q-f8dcbb8a92 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IK5Hc"} | None |  |
| q-a663d2e91f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2MP8lJ"} | None |  |
| q-b9b2ec250f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2MP8lJ"} | None |  |
| q-ec97f59cf8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81VoQs"} | None |  |
| q-70b0dcb1ed | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOe"} | None |  |
| q-1ba28810d8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0K"} | None |  |
| q-0fd573e3f8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0K"} | None |  |
| q-23da2ab343 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA7h"} | None |  |
| q-0e07730c39 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1X"} | None |  |
| q-5cc0b3c067 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None |  |
| q-556d9e6b68 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None |  |
| q-d70b08de75 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None |  |
| q-a5ebd10c75 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-8aa953a17c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-85aa2e98a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbI-"} | None |  |
| q-4af10a343c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNLI1"} | None |  |
| q-59644221d4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mm"} | None |  |
| q-71bf9d82c0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-3603460de1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-35a5725ab4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-8573a97999 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7amkgV"} | None |  |
| q-3a153b86ad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7amUh2"} | None |  |
| q-5bab920a89 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-4287be9e5d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7Wisfl"} | None |  |
| q-b5d6d028d8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6_OHx"} | None |  |
| q-e7a9ad95cb | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-fae4976037 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxak"} | None |  |
| q-c7d8c8096b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-a302007dcd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5qJ"} | None |  |
| q-1897d1756f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5qJ"} | None |  |
| q-1614eb1925 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5qJ"} | None |  |
| q-3f12efc87c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6-sXC"} | None |  |
| q-950ab91896 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6-sXC"} | None |  |
| q-454a16dd34 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-2215cf2294 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-196f029307 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-82f25e2d7d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-e709d1d43e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-210ebffc5d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-892456cb57 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o4"} | None |  |
| q-95dfc2c641 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o4"} | None |  |
| q-80db7c7a77 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-00d005b53a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-bb97222156 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ZmIXh"} | None |  |
| q-4ba7ed6ccb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ZmIXh"} | None |  |
| q-d3b9b048e4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx40qiu"} | None |  |
| q-92ba25c66a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-fb175d6577 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8vSVsl"} | None |  |
| q-be3af142f4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8vSVsl"} | None |  |
| q-e0df06bd86 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-b22df26a4d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-c6fba7a526 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5C"} | None |  |
| q-33c842bda3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw17"} | None |  |
| q-b7d79aee64 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw17"} | None |  |
| q-9d5adaed71 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw17"} | None |  |
| q-b664c011c6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5D"} | None |  |
| q-741ce4c5d3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5D"} | None |  |
| q-110aa21953 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5D"} | None |  |
| q-67d2e13f09 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5D"} | None |  |
| q-45a03a7059 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL64D_f9"} | None |  |
| q-b4f48a9f54 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL64D_f9"} | None |  |
| q-36b0031649 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMah"} | None |  |
| q-9a13a6a9c3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMaR"} | None |  |
| q-3f970385e6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o7"} | None |  |
| q-0c9fcacdd7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9KmX__"} | None |  |
| q-cc80f45575 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2jo9Kj"} | None |  |
| q-ec46b7086f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2jo9Kj"} | None |  |
| q-885b8c189b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-c7a2d329ec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-19bf79cb85 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-d20f406a39 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-cb48c8006e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-bcbb20002c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-fb9fbde39c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-b10b67efbc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2QULdY"} | None |  |
| q-02f16cd204 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrt3"} | None |  |
| q-4ce0a7b28a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx1ssmj"} | None |  |
| q-8cbebd161a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2MQMm5"} | None |  |
| q-38932d4109 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-8a48fdb429 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-b811f7392e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7anEhE"} | None |  |
| q-4bb7c78010 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Txpr2"} | None |  |
| q-304ac02650 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-4d7de558ac | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAPClpO"} | None |  |
| q-48d4f01c47 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA04"} | None |  |
| q-94c31a60fe | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA01"} | None |  |
| q-6bccd3c4e8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-f8693211c4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-64331010b6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-73459276db | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-3c0d798c15 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-6dec6723fb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-76b40abe38 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-34eecd483e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7zj"} | None |  |
| q-950a477b11 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-1779c2fed8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2UXka_"} | None |  |
| q-ae5f366ea8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2chAnX"} | None |  |
| q-76d43f7ffe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2LOuo5"} | None |  |
| q-61aa42a94c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2LOuo5"} | None |  |
| q-d5485cd190 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtv"} | None |  |
| q-fe132ab128 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx1rWlK"} | None |  |
| q-31f0a4d36a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-84beee466a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-18d5978a1d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-13adfc0cfe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-89421a4990 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-de46570131 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVp3"} | None |  |
| q-9fdc4ffede | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HSbI"} | None |  |
| q-49dd94902e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-d3d4a490a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-e09f28fb69 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-61aad0ecaa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2QULdY"} | None |  |
| q-931fbbeb48 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrt3"} | None |  |
| q-11b5039993 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81VYSA"} | None |  |
| q-7ca2beb7e5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-a9def6875e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-e7ccbcf401 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-ec491aac83 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBekH"} | None |  |
| q-72437f0c34 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-4d0c017806 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-aa9d63c9aa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-62ac083fab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-ed1994321a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-2de7e847f5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-ac30a86ad8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7VhsbT"} | None |  |
| q-12e5ae7297 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IKpCB"} | None |  |
| q-b3aa00841a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IKpCB"} | None |  |
| q-4d71bf1ec4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-11953850d5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtr"} | None |  |
| q-5f60e04e31 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IK5ET"} | None |  |
| q-8adf545dc9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2HKb5Z"} | None |  |
| q-b7f1d36db8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMASEsOI"} | None |  |
| q-f4e56c24f0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMASEsOI"} | None |  |
| q-bd6d0898a2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMASEsOI"} | None |  |
| q-112834c83c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TxprU"} | None |  |
| q-d15331fed8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TxprU"} | None |  |
| q-5ca57b1b74 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2HKb5i"} | None |  |
| q-337071e8ec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2HKb5i"} | None |  |
| q-0ea414b57f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2HKb50"} | None |  |
| q-2489e21dd7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-a901e6a1d0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-e2d90c3874 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBExi"} | None |  |
| q-496d019a72 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBvlS"} | None |  |
| q-269eb37b19 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-451665e570 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-bf1a395221 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TypoS"} | None |  |
| q-136fc64251 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5qJ"} | None |  |
| q-e8b26fa17f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw29"} | None |  |
| q-4a8219000f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA-MPUF"} | None |  |
| q-9f45ce9df3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1R"} | None |  |
| q-895323285c | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-be45638c14 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-9e8429d494 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IKpDz"} | None |  |
| q-83d28908e8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IKpDz"} | None |  |
| q-7d2a2b61dc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx0p9y3"} | None |  |
| q-1d4b3f48c6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-b3HP"} | None |  |
| q-dc10648016 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7YlLAM"} | None |  |
| q-8448112f81 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2JL4RO"} | None |  |
| q-36516fdcbd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2JL4RO"} | None |  |
| q-2883d614dc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-563b03af4a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-8c7c089931 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-1e9cb6b3c8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-85b0325624 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBExi"} | None |  |
| q-3cdaefd9be | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E6"} | None |  |
| q-36959ae4df | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-ad604b30a3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFP"} | None |  |
| q-3dce96112a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFP"} | None |  |
| q-af88a31cdf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrnEj"} | None |  |
| q-d7bcde16d9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Cfa6D"} | None |  |
| q-f841d257cb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrnEj"} | None |  |
| q-6320f3068f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1d"} | None |  |
| q-c863fc2341 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1d"} | None |  |
| q-48df95aaa8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFP"} | None |  |
| q-45566f85fc | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1f"} | None |  |
| q-5bb1386517 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-9e2505ad57 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-23417a1f10 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-f2c3e0a963 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-bb3f0889ec | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-abc3ba14ac | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-c72374333c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-359f4fc2b5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2z"} | None |  |
| q-b01ed2700f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2z"} | None |  |
| q-7c2a202452 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5-"} | None |  |
| q-8f229aa7fb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8tQe-L"} | None |  |
| q-73944177a9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8vSVsl"} | None |  |
| q-2043f3c802 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL88axkf"} | None |  |
| q-ee305a36c3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFV"} | None |  |
| q-ee6e44a7ba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-b94fdc89a9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2x8I_R"} | None |  |
| q-0b43935adb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2x8I_R"} | None |  |
| q-9cc866fe3b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-eab73305f7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBfbr"} | None |  |
| q-2135d75828 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFV"} | None |  |
| q-201e0e6365 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-ec60fb9957 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8vSVsl"} | None |  |
| q-21fd5f4dbb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-5aba129959 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-1cb9b16ea3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None |  |
| q-1472744a3b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None |  |
| q-0c7722da02 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFP"} | None |  |
| q-0b9a7f5c80 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:32:41.290000+00:00", "size": 100, "sub_field": "process.parent.exec… | 61 |  |
| q-e13e684263 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:32:41.290000+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-5706961294 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:32:41.290000+00:00", "size": 100, "sub_field": "process.parent… | 63 |  |
| q-76af1d674a | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:32:41.290000+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-91ac11f56e | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:56:18+00:00", "time_to": "2020-05-02T03:31:15+00:00", "size": 100, "sub_field": "process.parent.executable… | 18 |  |
| q-9a952b7a87 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:56:18+00:00", "time_to": "2020-05-02T03:31:15+00:00", "size": 100, "sub_field": "process.executable"} | 80 |  |
| q-305819877e | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:56:18+00:00", "time_to": "2020-05-02T03:31:15+00:00", "size": 100, "sub_field": "process.parent.execu… | 18 |  |
| q-c92c9e18e1 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:56:18+00:00", "time_to": "2020-05-02T03:31:15+00:00", "size": 100, "sub_field": null} | 2185 |  |
| q-a25340d920 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.parent.ex… | 359 |  |
| q-bd152e5963 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.executable"} | 1276 |  |
| q-213e246436 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.pare… | 370 |  |
| q-2147986a0a | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-41626e84ce | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*hostui*\" OR process.executable LIKE \"*.scr\" OR process.executable LIKE \"*csc.exe\" OR process.executable LIKE \"*sdclt*\" OR proce… | 24 | F59, F60, F64, F65 |
| q-22e26b1e39 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*\\\\\\\\Temp\\\\\\\\*\" OR file.path LIKE \"*victim*\" OR file.path LIKE \"*.pfx\" OR file.path LIKE \"*.rar\" OR file.path LIKE \"*.zip\" OR … | 201 |  |
| q-d46b4ea19f | pivot step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, user.name, powershell.file.script_block_text, _id, _index \| SORT @timestamp ASC"} | ERROR |  |
| q-929099b54b | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (win.target.process.executable LIKE \"*lsass*\" OR win.target.process.executable LIKE \"*sam*\" OR win.target.process.executable LIKE \"*security*\") \| KEEP @ti… | ERROR |  |
| q-45b39bb2c2 | pivot step 3 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-dd72673d09 | pivot step 3 | get_fields | {"dataset": "windows.sysmon", "prefix": "win"} | None |  |
| q-4bf9e66d5e | pivot step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 11 | F59 |
| q-9535390798 | pivot step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetImage, win.GrantedAccess, win.CallTrace, _id, _index \| … | 326 | F63 |
| q-ccc37913b9 | pivot step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"newyork.dmevals.local\" \| STATS c = COUNT(*) BY win.ScriptBlockText \| SORT c ASC \| LIMIT 40"} | 40 |  |
| q-260cb8da2f | pivot step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*SECURITY*\" OR win.ObjectName LIKE \"*lsass*\" OR win.ObjectName LIKE \"*\\\\\\\\config\\\\\\\\*\" O… | 6 |  |
| q-0faf74380d | pivot step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"newyork.dmevals.local\" AND (win.Payload LIKE \"*pass*\" OR win.Payload LIKE \"*cred*\" OR win.Payload LIKE \"*lsass*\" OR win.Payload LIKE \"*Invoke-*\" OR win.Payloa… | 13 |  |
| q-db5333b66b | pivot step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.LogonType, win.IpAddress, win.ProcessName, _id, _index \| SORT @timestamp… | 25 | F60 |
| q-dcf07c74c2 | pivot step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"newyork.dmevals.local\" AND event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*Replicat*\" OR win.ScriptBlockText LIKE \"*DCSync*\" OR win.ScriptBlockText LIKE \"… | 30 |  |
| q-07233a65dd | pivot step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"utica.dmevals.local\" AND event.code == \"1\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \|… | 9 |  |
| q-91e7d290a9 | pivot step 8 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*pass*\" OR win.ScriptBlockText LIKE \"*PrivateKey*\" OR win.ScriptBlockText LIKE \… | 8 |  |
| q-a9dcb5d2c6 | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND (file.path LIKE \"*Draft*\" OR file.path LIKE \"*working*\" OR file.path LIKE \"*.zip\" OR file.path LIKE \"*.pfx\" O… | 15 |  |
| q-6e424e3fc0 | pivot step 9 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F61 |
| q-ef9de9a64d | pivot step 9 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6_ejg"} | None | F62 |
| q-c935f600c7 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-e4bf1d10e1 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBfbr"} | None |  |
| q-4cc47ef7f7 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-62faa13870 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2WaNu5"} | None |  |
| q-7d380bc9c6 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-9459b5b033 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-da8107a7ab | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXEp"} | None |  |
| q-3c47f96b74 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXEp"} | None |  |
| q-799bfbcde4 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-c38b7dad2d | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-dbb39d5800 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-8df2568a32 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6_ejg"} | None |  |
| q-93360699a4 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6_ejg"} | None |  |
| q-182fb639b8 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6_ejg"} | None |  |
| q-414e1c6d95 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAVH79h"} | None |  |
| q-ca57afafd8 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbI-"} | None |  |
| q-843ff6e783 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbI-"} | None |  |
| q-2fe32564db | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbI-"} | None |  |
| q-1dbd091f1a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbI-"} | None |  |
| q-edd90b2bee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbI-"} | None |  |
| q-fab1874e5b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-c55d40c857 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-8fbace2cb9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-3791ae704b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJWyf"} | None |  |
| q-4405890e24 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17AQxS"} | None |  |
| q-c3a137da01 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL87ZUOT"} | None |  |
| q-7bff5fc26a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL87ZUOT"} | None |  |
| q-76d9aee8ed | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL87ZUOT"} | None |  |
| q-3090fc2d25 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6p"} | None |  |
| q-50a74a325d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw3L"} | None |  |
| q-053253c9f4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxak"} | None |  |
| q-99a7bd7871 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-79d15b7d3e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJGOH"} | None |  |
| q-a457edb625 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-519c83be59 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9W163v"} | None |  |
| q-21a79b4d78 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_Nabl"} | None |  |
| q-b0a107f9e9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_Nabn"} | None |  |
| q-8d9a98933b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9W163v"} | None |  |
| q-9a4d932d6e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9KmH84"} | None |  |
| q-6db5992f04 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9GibBE"} | None |  |
| q-e4b75450d7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9AdJ6k"} | None |  |
| q-a3ef598c49 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9AdJ6k"} | None |  |
| q-dc5e6ecda2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2LOurf"} | None |  |
| q-8480d77662 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IK5Hc"} | None |  |
| q-77118db5e8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2MP8lJ"} | None |  |
| q-09307ef80e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2MP8lJ"} | None |  |
| q-c34921304c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81VoQs"} | None |  |
| q-01759f674b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOe"} | None |  |
| q-32a14ba6e4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0K"} | None |  |
| q-73cdc741e6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0K"} | None |  |
| q-bcc33062fd | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA7h"} | None |  |
| q-7a80db6392 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1X"} | None |  |
| q-4703ad4f84 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None |  |
| q-958b2dda14 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None |  |
| q-b71386ff01 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None |  |
| q-f966db22a7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-53e180df60 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-b773a78671 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbI-"} | None |  |
| q-05abea8366 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNLI1"} | None |  |
| q-775d7b96e8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mm"} | None |  |
| q-69215f13e2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-91bbefb109 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-0c5f035de9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-076207555c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7amkgV"} | None |  |
| q-09082b3200 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7amUh2"} | None |  |
| q-507d0b0216 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-b7527aaf84 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7Wisfl"} | None |  |
| q-7ee16250f9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6_OHx"} | None |  |
| q-20a8ce701d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-0b5f7f695b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxak"} | None |  |
| q-d6eb1df2dc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-9dd88001b1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5qJ"} | None |  |
| q-18a468aabe | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5qJ"} | None |  |
| q-16eb58c9e0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5qJ"} | None |  |
| q-97a0ccf631 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6-sXC"} | None |  |
| q-fa32b38ada | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6-sXC"} | None |  |
| q-ce639d74ee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-7a31bca00c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-1cb6bf63e0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-27f45a1a38 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-594b1e7856 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-4096f95d88 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-10be7cf9c5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o4"} | None |  |
| q-6877522591 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o4"} | None |  |
| q-4257540dff | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-0a278a6728 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-9c3aa30a19 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ZmIXh"} | None |  |
| q-f125f9e36d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ZmIXh"} | None |  |
| q-2cdf205615 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx40qiu"} | None |  |
| q-d97eed9452 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-8c30440e2c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8vSVsl"} | None |  |
| q-7926d3a037 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8vSVsl"} | None |  |
| q-cac4029f61 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-020ebd31bb | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-a86424f2b7 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5C"} | None |  |
| q-e57f41bc97 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw17"} | None |  |
| q-1f96028fda | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw17"} | None |  |
| q-9cb55020df | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw17"} | None |  |
| q-0eff6c84fe | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5D"} | None |  |
| q-8909c124e6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5D"} | None |  |
| q-4e927b6e02 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5D"} | None |  |
| q-c54020b20d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5D"} | None |  |
| q-0396bf0227 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL64D_f9"} | None |  |
| q-bb3ffd0b6d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL64D_f9"} | None |  |
| q-4f935e4b74 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMah"} | None |  |
| q-4257484c94 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMaR"} | None |  |
| q-517c95b827 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o7"} | None |  |
| q-d53fd48ee0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9KmX__"} | None |  |
| q-75678ae67e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2jo9Kj"} | None |  |
| q-d06a5689c6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2jo9Kj"} | None |  |
| q-1314777fbc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-21da69eae6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-fba5a1167a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-72f8a60684 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-77ed8a5b62 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-6523a6bf32 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-bcefd3c60a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-8dc72d9ffa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2QULdY"} | None |  |
| q-01ecebe7f9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrt3"} | None |  |
| q-944f038cbc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx1ssmj"} | None |  |
| q-9d648609f7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2MQMm5"} | None |  |
| q-7d9e9e6715 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-2d0a691414 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-213c76ae3b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7anEhE"} | None |  |
| q-7cd26f5b2c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Txpr2"} | None |  |
| q-f7f8ac1cb0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-385db59120 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAPClpO"} | None |  |
| q-9dabe4c478 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA04"} | None |  |
| q-0bffef9e4b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA01"} | None |  |
| q-04a14ac82c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-838b2c8e48 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-0dff7b90a4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-56b3fc232a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-082293a830 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-5d75dec814 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-3644bae02e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-49a6961afb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7zj"} | None |  |
| q-590c5ce2b1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-1c4659ca25 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2UXka_"} | None |  |
| q-410169b1a4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2chAnX"} | None |  |
| q-1cab8bb8da | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2LOuo5"} | None |  |
| q-7fa029e9d6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2LOuo5"} | None |  |
| q-fb7b0e38fd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtv"} | None |  |
| q-12cb3dea7c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx1rWlK"} | None |  |
| q-a05a1198a9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-f07b6f03ee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-12cad3960c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-6432eb8962 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-9f3838eed1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-3a7fac3442 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVp3"} | None |  |
| q-725621873a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HSbI"} | None |  |
| q-3ffac182e0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-b248b7b8ff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-da036083e2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-2804aed208 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2QULdY"} | None |  |
| q-48c8682bba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrt3"} | None |  |
| q-849c255ba1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81VYSA"} | None |  |
| q-e9e970e386 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-5654706054 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-0821e97b05 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-4e1e873529 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBekH"} | None |  |
| q-fa634d9a83 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-14bba58680 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-d1eac99006 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-006b64ce7e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-31cc92b0da | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-e5a6a8baa0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-e4989297e7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7VhsbT"} | None |  |
| q-cc54a57189 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IKpCB"} | None |  |
| q-f54b40f9ef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IKpCB"} | None |  |
| q-c5f160d208 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-60411bbd15 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtr"} | None |  |
| q-4e1b912702 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IK5ET"} | None |  |
| q-fdadafcecf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2HKb5Z"} | None |  |
| q-55fde39d03 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMASEsOI"} | None |  |
| q-9a8755e908 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMASEsOI"} | None |  |
| q-152f4d93ae | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMASEsOI"} | None |  |
| q-62e33b6262 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TxprU"} | None |  |
| q-8781f28dc4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TxprU"} | None |  |
| q-a14393f0b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2HKb5i"} | None |  |
| q-c2e37927d2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2HKb5i"} | None |  |
| q-803fbd94ca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2HKb50"} | None |  |
| q-a3cd7f5cde | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-0f1ee7edbb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-68a0629c74 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBExi"} | None |  |
| q-55cd68fbb0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBvlS"} | None |  |
| q-3cb7e0d597 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-0f9c46fe12 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-c3ff54e8c3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TypoS"} | None |  |
| q-1fccc26c01 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5qJ"} | None |  |
| q-f2b753202b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw29"} | None |  |
| q-2145900a54 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA-MPUF"} | None |  |
| q-8b60812448 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1R"} | None |  |
| q-7639377f79 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-59d927eef8 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-10bd314e43 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IKpDz"} | None |  |
| q-805cfabfb7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IKpDz"} | None |  |
| q-d1b548e7c4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx0p9y3"} | None |  |
| q-04a96b71ba | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-b3HP"} | None |  |
| q-bfa2dfaa95 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7YlLAM"} | None |  |
| q-c0d4deff5d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2JL4RO"} | None |  |
| q-78fa73ed0a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2JL4RO"} | None |  |
| q-56d053bbc6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-5ef5ed1835 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-f1389313e6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-d8e55b8dab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-d304630322 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBExi"} | None |  |
| q-02ef5f7399 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E6"} | None |  |
| q-9cd33da051 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-43a1d21d7e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFP"} | None |  |
| q-37baceb44c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFP"} | None |  |
| q-e30e5a89dd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrnEj"} | None |  |
| q-4de8a999ac | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Cfa6D"} | None |  |
| q-e33aebb1f5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrnEj"} | None |  |
| q-b138f88a4d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1d"} | None |  |
| q-f22bea3e73 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1d"} | None |  |
| q-0d88e7db06 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFP"} | None |  |
| q-10272c5f96 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1f"} | None |  |
| q-d513551fd6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-0b4d9a3273 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-2ac0eab33a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-5fa9c18294 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-62890e5480 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-35a0a46e39 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-a58cd62757 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-24c52c8695 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2z"} | None |  |
| q-042541cecb | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2z"} | None |  |
| q-1b6b7032d2 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5-"} | None |  |
| q-8d66c6d2c1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8tQe-L"} | None |  |
| q-3135a0660a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8vSVsl"} | None |  |
| q-57bf4034dc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL88axkf"} | None |  |
| q-b182fa7b4d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFV"} | None |  |
| q-b7a75715a3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-fe32470ac1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2x8I_R"} | None |  |
| q-0f928b1787 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2x8I_R"} | None |  |
| q-1ea270139f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-a1aeb3b6da | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBfbr"} | None |  |
| q-c53302cde0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFV"} | None |  |
| q-d1fa0e1ff1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-79a1e78604 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8vSVsl"} | None |  |
| q-103f8f302f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-463f2b961b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-63a79c0726 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None |  |
| q-08afb86b04 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None |  |
| q-1a2f6da8f0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFP"} | None |  |
| q-87f910d868 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-e3638ce4e6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBfbr"} | None |  |
| q-778c8903f7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2WaNu5"} | None |  |
| q-bc5983d7fa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-44dda1d33e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-a8d604ff44 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXEp"} | None |  |
| q-18eaa5a562 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-f142adfa4b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-f12a773fcc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6_ejg"} | None |  |
| q-45d797b7f6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6_ejg"} | None |  |
| q-8e309af812 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbI-"} | None |  |
| q-045f1f577c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mZ"} | None |  |
| q-2d90e08359 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |

## Verification

Evidence items cited: 241; confirmed against the stored events: 240; rejected: 1. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 8 item(s) in 4 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
