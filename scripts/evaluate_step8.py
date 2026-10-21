"""Score a hunt run against APT29 Day 1 Step 8 (Lateral Movement), the same way hunt/evaluate.py scores Step 6:
a sub-step is found when a verified evidence event of a malicious/suspicious finding matches its trace. Also shows,
for every incident, whether consolidation put it in or out of scope, so in-scope findings marked out-of-scope show.

Ground truth: Step 8 "Lateral Movement" of the same MITRE APT29 Day 1 emulation plan that hunt/evaluate.py uses.
Traces (located on 2026-10-20 by direct queries; all on nashua unless noted, 2020-05-02 UTC):
  8.A WinRM: wsmprovhost.exe started 03:09:23
  8.B python.exe written to C:\\Windows\\Temp by System 03:10:23
  8.C PsExec64.exe on scranton 03:11-03:14, PSEXESVC service (7045/4697) and PSEXESVC.exe -> C:\\Windows\\Temp\\python.exe
Usage: .venv\\Scripts\\python scripts\\evaluate_step8.py RUN_DIR
"""
import collections
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hunt import config  # noqa: E402
from hunt.evaluate import _g, _s  # noqa: E402

GT = [
    ("8.A", "WinRM (Invoke-Command / 5985 / wsmprovhost)",
     lambda s: "wsmprovhost.exe" in _s(s, "process.executable", "process.parent.executable")
     or "invoke-command -computername" in _s(s, "win.ScriptBlockText", "process.command_line")
     or (str(_g(s, "destination.port")) == "5985" and str(_g(s, "data_stream.dataset")).startswith("windows"))),
    ("8.B", "python.exe copied to C:\\Windows\\Temp",
     lambda s: _s(s, "file.path", "win.TargetFilename").strip().endswith("\\windows\\temp\\python.exe")),
    ("8.C", "PsExec / PSEXESVC runs python.exe",
     lambda s: "psexe" in _s(s, "process.executable", "process.parent.executable", "win.ServiceName", "win.ImagePath",
                            "file.path", "process.command_line")),
]

run = pathlib.Path(sys.argv[1])
rep = json.loads((run / "report.json").read_text(encoding="utf-8"))
es = config.es("reader")
counted = set(rep["findings_counted"])
inc_of = {fid: i for i in rep.get("incidents", []) for fid in i["finding_ids"]}
scope = set(rep.get("technique_status", {}))
print(f"run {rep['run']}  verdict {rep['verdict']['verdict']}: {rep['verdict']['rationale'][:300]}")
print(f"frame tactics {rep['frame'].get('tactics')}  in-scope techniques {len(scope)}  seconds {rep['seconds']}  "
      f"llm_calls {rep['llm_calls']}  mcp_calls {rep['mcp_calls']}")
found = collections.defaultdict(list)
for f in rep["findings"]:
    if f["finding_id"] not in counted or f.get("assessment") not in ("malicious", "suspicious"):
        continue
    for v in f.get("verification", []):
        if v.get("ok"):
            src = es.get(index=v["index"], id=v["id"])["_source"]
            for step, _, m in GT:
                if m(src) and f["finding_id"] not in found[step]:
                    found[step].append(f["finding_id"])
for step, what, _ in GT:
    fids = found.get(step, [])
    incs = sorted({f"{inc_of[x]['incident_id']} {inc_of[x]['technique']} in_scope={inc_of[x]['in_scope']}" for x in fids if x in inc_of})
    print(f"  {step} {what:42s} found={bool(fids)} by {fids} -> incidents {incs}")
print("incidents:")
for i in rep.get("incidents", []):
    print(f"  {i['incident_id']} in_scope={i['in_scope']!s:5s} {i['technique']:24s} {i['assessment']:10s} {i['confidence']:6s} "
          f"{i['finding_ids']} {str(i.get('title'))[:90]}")
oos = [i for i in rep.get("incidents", []) if not i["in_scope"] and i["technique"].split(":", 1)[-1] in scope]
print(f"out-of-scope incidents whose technique IS in the in-scope list: {len(oos)}")
for i in oos:
    print(f"  {i['incident_id']} {i['technique']} {str(i.get('title'))[:100]} | rationale: {str(i.get('rationale'))[:200]}")
