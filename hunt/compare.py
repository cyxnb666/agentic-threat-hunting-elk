"""Compare two hunt runs of the same hypothesis: verdict, findings, evidence, queries, coverage, cost, ground truth."""
import json
import pathlib
import re

from . import config
from .evaluate import evaluate


def _load(run):
    p = pathlib.Path(run)
    if not p.is_absolute():
        p = config.ROOT / p
    return p, json.loads((p / "report.json").read_text(encoding="utf-8"))


def _jaccard(a: set, b: set) -> float:
    return round(len(a & b) / len(a | b), 3) if a | b else 1.0


def _norm_query(q: dict) -> str:
    s = json.dumps({k: q["args"].get(k) for k in sorted(q["args"]) if k not in ("size", "fields", "sort")}, sort_keys=True)
    return re.sub(r"\s+", " ", s.lower())


def summarize(rep: dict) -> dict:
    counted = set(rep["findings_counted"])
    fs = [f for f in rep["findings"] if f["finding_id"] in counted]
    bad = [f for f in fs if f.get("assessment") in ("malicious", "suspicious")]
    incidents = rep.get("incidents") or []
    # techniques the run says were used: in-scope incidents when the run consolidated, otherwise the findings
    flagged = ({i["technique"] for i in incidents if i["in_scope"]} if incidents else {str(f.get("technique")) for f in bad})
    return {
        "verdict": rep["verdict"]["verdict"],
        "techniques_flagged": sorted(flagged),
        "incidents": len(incidents),
        "evidence_events": {v["id"] for f in bad for v in f.get("verification", []) if v.get("ok")},
        "hosts": sorted({v.get("host") for f in bad for v in f.get("verification", []) if v.get("ok") and v.get("host")}),
        "findings": len(rep["findings"]), "findings_bad": len(bad),
        "rejected_evidence": sum(1 for f in rep["findings"] for v in f.get("verification", []) if not v.get("ok")),
        "checks": len(rep["checks"]), "queries": len(rep["queries"]),
        "planned_queries": {_norm_query(q) for q in rep["queries"] if q["phase"].startswith("check")},
        "coverage": {(t, d): v for t, c in rep["coverage"].items() for d, v in c["cells"].items()},
        "llm_calls": rep.get("llm_calls"), "tokens": rep.get("llm_tokens"), "seconds": rep.get("seconds"),
    }


def compare_runs(run_a: str, run_b: str) -> str:
    pa, ra = _load(run_a)
    pb, rb = _load(run_b)
    a, b = summarize(ra), summarize(rb)
    ea, eb = evaluate(pa), evaluate(pb)
    cov_keys = set(a["coverage"]) | set(b["coverage"])
    cov_diff = sum(1 for k in cov_keys if str(a["coverage"].get(k, "-"))[:5] != str(b["coverage"].get(k, "-"))[:5])
    rows = [
        ("Verdict", a["verdict"], b["verdict"]),
        ("Ground truth sub-steps found (6.A/6.B/6.C)", f"{ea['found']}/{ea['of']} " + _steps(ea), f"{eb['found']}/{eb['of']} " + _steps(eb)),
        ("Techniques with malicious/suspicious findings", ", ".join(a["techniques_flagged"]), ", ".join(b["techniques_flagged"])),
        ("Hosts implicated", ", ".join(a["hosts"]), ", ".join(b["hosts"])),
        ("Findings (malicious+suspicious / all)", f"{a['findings_bad']} / {a['findings']}", f"{b['findings_bad']} / {b['findings']}"),
        ("Incidents after consolidation", a["incidents"], b["incidents"]),
        ("Verified evidence events", len(a["evidence_events"]), len(b["evidence_events"])),
        ("Rejected evidence items", a["rejected_evidence"], b["rejected_evidence"]),
        ("Planned checks / all queries", f"{a['checks']} / {a['queries']}", f"{b['checks']} / {b['queries']}"),
        ("LLM calls / tokens", f"{a['llm_calls']} / {a['tokens']}", f"{b['llm_calls']} / {b['tokens']}"),
        ("Duration (s)", a["seconds"], b["seconds"]),
    ]
    sim = {
        "verdict_equal": a["verdict"] == b["verdict"],
        "techniques_jaccard": _jaccard(set(a["techniques_flagged"]), set(b["techniques_flagged"])),
        "technique_families_jaccard": _jaccard({t.split(".")[0] for t in a["techniques_flagged"]},
                                               {t.split(".")[0] for t in b["techniques_flagged"]}),
        "evidence_jaccard": _jaccard(a["evidence_events"], b["evidence_events"]),
        "planned_query_jaccard": _jaccard(a["planned_queries"], b["planned_queries"]),
        "coverage_cells_differing": f"{cov_diff} of {len(cov_keys)}",
        "ground_truth_equal": [ea["steps"][s]["found"] for s in ea["steps"]] == [eb["steps"][s]["found"] for s in eb["steps"]],
    }
    L = [f"# Run comparison: {pa.name} vs {pb.name}", "", f"Hypothesis: {ra['hypothesis']}", "",
         f"| | {pa.name} | {pb.name} |", "|---|---|---|"]
    L += [f"| {k} | {str(x).replace('|', '/')} | {str(y).replace('|', '/')} |" for k, x, y in rows]
    L += ["", "| Similarity | Value |", "|---|---|"] + [f"| {k} | {v} |" for k, v in sim.items()]
    L += ["", "Jaccard = |A∩B| / |A∪B| (1.0 = identical sets). Planned queries are compared after lower-casing and "
          "dropping size/fields/sort.", "",
          f"Only in {pa.name} (techniques): {sorted(set(a['techniques_flagged']) - set(b['techniques_flagged']))}",
          f"Only in {pb.name} (techniques): {sorted(set(b['techniques_flagged']) - set(a['techniques_flagged']))}"]
    out = config.RUNS_DIR / "compare"
    out.mkdir(parents=True, exist_ok=True)
    name = f"{pa.name}__vs__{pb.name}"
    (out / f"{name}.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    (out / f"{name}.json").write_text(json.dumps({"a": pa.name, "b": pb.name, "rows": rows, "similarity": sim,
                                                  "evaluation": [ea, eb]}, indent=2, default=str), encoding="utf-8")
    return "\n".join(L)


def _steps(e):
    return "(" + ", ".join(f"{s}:{'yes' if r['found'] else 'no'}" for s, r in e["steps"].items()) + ")"
