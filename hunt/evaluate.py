"""Score a hunt report against the published attack plan (never shown to the hunt agent).

Ground truth: MITRE ATT&CK Evaluations APT29 Day 1 emulation plan, Step 6 "Credential Access"
(https://github.com/mitre-attack/attack-arsenal/tree/master/adversary_emulation/APT29/Emulation_Plan/Day%201):
  6.A execute a Chrome password collector disguised as C:\\Program Files\\SysinternalsSuite\\accesschk.exe
  6.B steal a PFX certificate with Get-PrivateKeys (the plan cites ATT&CK T1145, today T1552.004 Private Keys)
  6.C dump password hashes with meterpreter post/windows/gather/credentials/credential_collector
The predicates below describe the traces each sub-step left in this dataset; they were located on 2026-10-17
by direct queries (Sysmon EID 1 accessChk.exe on scranton 03:04:34Z; PowerShell 4104 Get-PrivateKeys and Sysmon
EID 11 *.pfx 03:04:56-57Z; Sysmon EID 10 PowerShell -> lsass.exe with 0x1f3fff/0x1fffff and Security 4656/4663
on lsass.exe by powershell.exe 03:05:16Z).
A sub-step counts as found when a verified evidence event of a malicious or suspicious finding matches it.
"""
import json
import pathlib

from . import config


def _g(src, dotted):
    cur = src
    for p in dotted.split("."):
        cur = cur.get(p) if isinstance(cur, dict) else None
    return cur


def _s(src, *fields):
    return " ".join(str(_g(src, f) or "") for f in fields).lower()


GROUND_TRUTH = [
    {"step": "6.A", "family": "T1555", "what": "Chrome password collector run as ...\\SysinternalsSuite\\accesschk.exe",
     "match": lambda s: "accesschk" in _s(s, "process.executable", "process.command_line", "win.Image", "win.NewProcessName")},
    {"step": "6.B", "family": "T1552", "what": "Get-PrivateKeys run in PowerShell, PFX file written",
     "match": lambda s: "get-privatekeys" in _s(s, "powershell.script_block_text", "win.ScriptBlockText", "message")
     or _s(s, "file.path", "win.TargetFilename").strip().endswith(".pfx")},
    {"step": "6.C", "family": "T1003", "what": "password hashes dumped (PowerShell process opening lsass.exe)",
     "match": lambda s: ("lsass.exe" in _s(s, "win.TargetImage") and "powershell" in _s(s, "process.executable")
                         and str(_g(s, "win.GrantedAccess")).lower() in ("0x1f3fff", "0x1fffff"))
     or ("lsass.exe" in _s(s, "win.ObjectName") and "powershell" in _s(s, "win.ProcessName"))},
]


def evaluate(run_dir) -> dict:
    report = json.loads((pathlib.Path(run_dir) / "report.json").read_text(encoding="utf-8"))
    counted = set(report["findings_counted"])
    es = config.es("reader")
    result = {s["step"]: {"found": False, "by": [], "technique_ok": False, "what": s["what"]} for s in GROUND_TRUTH}
    other = []
    for f in report["findings"]:
        if f["finding_id"] not in counted or f.get("assessment") not in ("malicious", "suspicious"):
            continue
        matched_any = False
        for v in f.get("verification", []):
            if not v.get("ok"):
                continue
            src = es.get(index=v["index"], id=v["id"])["_source"]
            for gt in GROUND_TRUTH:
                if gt["match"](src):
                    matched_any = True
                    r = result[gt["step"]]
                    r["found"] = True
                    if f["finding_id"] not in r["by"]:
                        r["by"].append(f["finding_id"])
                    r["technique_ok"] = r["technique_ok"] or str(f.get("technique", "")).startswith(gt["family"])
        if not matched_any:
            other.append(f"{f['finding_id']} {f.get('technique')} {f.get('title')}")
    return {"run": report["run"], "verdict": report["verdict"]["verdict"], "steps": result,
            "found": sum(r["found"] for r in result.values()), "of": len(GROUND_TRUTH),
            "other_malicious_or_suspicious_findings": other}
