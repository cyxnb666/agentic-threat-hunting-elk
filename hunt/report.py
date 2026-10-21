"""Hunt report: report.json (machine-readable, complete) and report.md rendered from it (for people).

render_markdown(run_dir) can re-create report.md from report.json at any time (python -m hunt render <run>).
"""
import datetime as dt
import json
import pathlib

from . import config

ORDER = {"malicious": 0, "suspicious": 1, "benign": 2}


def utc(ts) -> str:
    if not ts:
        return ""
    try:
        t = dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"
    except ValueError:
        return str(ts)


def cell(v, n=160) -> str:
    s = json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else str(v)
    s = s.replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    return s[:n] + "…" if len(s) > n else s


def _jsonl(path):
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()] if path.exists() else []


def technique_status(agent, results) -> dict:
    """Final status per in-scope technique: the agent's triage status, else derived from checks and coverage."""
    by_tech = {}
    for r in results:
        by_tech.setdefault(r["technique"], []).append(r)
    out = {}
    for tid, name in sorted(agent.scope_techniques.items()):
        st = agent.technique_status.get(tid)
        if not st or not st.get("status"):
            rs = by_tech.get(tid, [])
            cells = agent.coverage.get(tid, {}).get("cells", {})
            if rs:
                hits = sum(r.get("total") or 0 for r in rs)
                st = {"status": "not_observed" if not hits else "not_triaged", "reason": f"{len(rs)} checks, {hits} hits"}
            elif cells and all(str(v).startswith("n/a") for v in cells.values()):
                st = {"status": "not_observable", "reason": "every dataset marked not applicable (reasons in coverage)"}
            else:
                st = {"status": "gap", "reason": "no check ran"}
        out[tid] = {"name": name, "status": st.get("status"), "reason": st.get("reason")}
    return out


def write_report(agent, frame, checks, results, findings, verdict, incidents=None) -> str:
    run_dir = agent.run_dir
    audit = _jsonl(run_dir / "mcp_audit.jsonl")
    phases = {r["query_id"]: r["phase"] for r in _jsonl(run_dir / "tool_calls.jsonl") if r.get("query_id")}
    cited = {}
    for f in findings:
        for ev in f.get("verification", []):
            cited.setdefault(ev.get("query_id"), set()).add(f["finding_id"])
    findings = sorted(findings, key=lambda f: (ORDER.get(f.get("assessment"), 3), str(f.get("technique")), f["finding_id"]))
    counted = [f["finding_id"] for f in findings if f.get("verified") or not agent.p["gate"]]
    report = {
        "hypothesis": agent.hypothesis, "run": run_dir.name, **agent.state,
        "profile_settings": agent.p, "frame": frame, "verdict": verdict, "data": agent.inventory,
        "datasets": agent.datasets, "coverage": agent.coverage, "technique_status": technique_status(agent, results),
        "checks": results, "findings": findings, "findings_counted": counted, "incidents": incidents or [],
        "context_out_of_scope": agent.context, "evidence_corrections": agent.corrections,
        "queries": [{"query_id": a["query_id"], "phase": phases.get(a["query_id"], ""), "tool": a["tool"], "args": a["args"],
                     "hits": a.get("hits_total") if a.get("hits_total") is not None else a.get("rows"),
                     "error": a.get("error"), "cited_by": sorted(cited.get(a["query_id"], []))} for a in audit],
    }
    (run_dir / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    render_markdown(run_dir)
    return f"{run_dir.relative_to(config.ROOT)}  verdict={verdict['verdict']}  findings={len(findings)}  queries={len(audit)}"


def render_markdown(run_dir) -> None:
    run_dir = pathlib.Path(run_dir)
    R = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    p, v = R["profile_settings"], R["verdict"]
    counted = set(R["findings_counted"])
    L = [f"# Threat hunt report — {R['run']}", "", f"**Hypothesis:** {R['hypothesis']}", "",
         f"**Verdict: {v['verdict']}** — {v['rationale']}", "",
         f"Verdict method: {v['method']}" + (f" ({v['rule']})" if v.get("rule") else ""), "",
         "| Run | Value |", "|---|---|",
         f"| Profile | {R['profile']} (thinking={p['thinking']}, temperature={p['temperature'] if not p['thinking'] else 'n/a (ignored in thinking mode)'}) |",
         f"| Model | {R['model']} |",
         f"| Started / finished (UTC) | {R['started_at']} / {R['finished_at']} ({R['seconds']} s) |",
         f"| LLM calls / tokens | {R['llm_calls']} / {R['llm_tokens']} |",
         f"| MCP tool calls | {R['mcp_calls']} (server tools: {', '.join(R['mcp_tools'])}) |",
         f"| ATT&CK tactics | {', '.join(R['frame'].get('tactics', []))} — {R['frame'].get('restated', '')} |"]
    if R.get("pivot_error"):
        L.append(f"| Pivot phase error | {cell(R['pivot_error'], 200)} |")
    L += ["", "## Data examined", "", "| Dataset | Events | First event (UTC) | Last event (UTC) | Hosts / observers | Sources (channel → template) |",
          "|---|---|---|---|---|---|"]
    for d in sorted(R["data"]["datasets"], key=lambda x: x["dataset"]):
        src = "; ".join(f"{s} ({m.get('channel')} → {m.get('template')})" for s, m in d["sources"].items())
        L.append(f"| {d['dataset']} | {d['documents']} | {utc(d['first_event'])} | {utc(d['last_event'])} | "
                 f"{cell(', '.join(list(d['hosts']) + list(d['observers'])), 120)} | {cell(src, 200)} |")
    for g in R["data"].get("non_overlapping_time_windows", []):
        L.append(f"\n> Time windows: {g}. Events of these datasets were not correlated by time.")
    L.append("\nThe whole stored time range of every dataset was searched (planned checks carry no time filter).")

    if R.get("incidents"):
        L += ["", "## Incidents", "", "Verified malicious/suspicious findings grouped by attacker action, each with the single "
              "best-fitting technique (consolidation step). In-scope incidents decide the verdict.", "",
              "| Incident | Technique | In scope | Assessment | Findings | Title |", "|---|---|---|---|---|---|"]
        for i in R["incidents"]:
            L.append(f"| {i['incident_id']} | {i['technique']} | {'yes' if i['in_scope'] else 'no'} | {i['assessment']}/{i['confidence']} | "
                     f"{', '.join(i['finding_ids'])} | {cell(i['title'], 140)} |")
    L += ["", "## Findings", ""]
    if not R["findings"]:
        L.append("No findings were submitted.")
    for f in R["findings"]:
        ev_state = "verified" if f.get("verified") else f"NOT verified ({f.get('verified_evidence', 0)}/{len(f.get('verification', []))} evidence items)"
        note = "" if f["finding_id"] in counted else " — excluded from the verdict"
        L += [f"### {f['finding_id']} · {f.get('assessment')} / {f.get('confidence')} · {f.get('technique')} · {cell(f.get('title'), 200)}",
              "", f"Evidence status: **{ev_state}**{note}", "", cell(f.get("summary"), 2000), "",
              "| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |",
              "|---|---|---|---|---|---|---|---|---|"]
        for i, e in enumerate(f.get("verification", []), 1):
            L.append(f"| {i} | {utc(e.get('timestamp'))} | {cell(e.get('host'), 40)} | {cell(e.get('dataset'), 30)} | {cell(e.get('field'), 40)} | "
                     f"{cell(e.get('actual', e.get('claimed')), 160)} | {cell(e.get('index'), 60)} / {e.get('id')} | {e.get('query_id')} | "
                     f"{'ok' if e['ok'] else 'FAILED: ' + '; '.join(e['problems'])} |")
        L.append("")

    pc = R.get("pivot_candidates") or {}
    if pc.get("candidates"):
        got = {str(a.get("executable", "")).lower(): a for a in pc.get("assessments", [])}
        L += ["## Pivot candidates", "", "Processes the pivot reviewer had to assess (started by a script host or from outside "
              "the Windows directory, rare in the 15-minute windows around verified activity).", "",
              "| Host | Executable | Starts | Parents | Assessment | Reason |", "|---|---|---|---|---|---|"]
        for c in pc["candidates"]:
            a = got.get(c["executable"].lower()) or next((v for k, v in got.items() if k and c["executable"].lower().endswith(k.split(chr(92))[-1])), {})
            L.append(f"| {c['host']} | {cell(c['executable'], 80)} | {c['starts']} | {cell(', '.join(c['parents']), 80)} | "
                     f"{a.get('assessment', 'not assessed')} | {cell(a.get('reason', ''), 160)} |")
        L.append("")
    st = R.get("technique_status", {})
    L += ["## Technique conclusions", "",
          "One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; "
          "`not_observable` = no dataset records it.", "", "| Technique | Status | Reason |", "|---|---|---|"]
    for tid in sorted(st):
        L.append(f"| {tid} {cell(st[tid]['name'], 45)} | {st[tid]['status']} | {cell(st[tid]['reason'], 220)} |")
    if R.get("context_out_of_scope"):
        L += ["", "## Context (outside the hypothesis)", "",
              "Activity reported under techniques outside the hypothesis' scope. Not verified, not part of the verdict.", ""]
        for c in R["context_out_of_scope"]:
            L.append(f"- {c.get('technique')} · {c.get('assessment')}/{c.get('confidence')} · {cell(c.get('title'), 160)} ({c.get('phase')})")

    hits_by_cell = {}
    for r in R["checks"]:
        hits_by_cell[(r["technique"], r["dataset"])] = hits_by_cell.get((r["technique"], r["dataset"]), 0) + (r.get("total") or 0)
    datasets = sorted(R["datasets"])
    L += ["", "## Coverage", "", "Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.", "",
          "| Technique | " + " | ".join(datasets) + " |", "|---|" + "---|" * len(datasets)]
    for tid in sorted(R["coverage"]):
        c = R["coverage"][tid]
        row = []
        for ds in datasets:
            val = c["cells"].get(ds, "—")
            row.append(f"{hits_by_cell.get((tid, ds), 0)} hits" if val == "check" else ("n/a" if val.startswith("n/a") else cell(val, 30)))
        L.append(f"| {tid} {cell(c['name'], 45)} | " + " | ".join(row) + " |")
    gaps = sum(1 for c in R["coverage"].values() for val in c["cells"].values() if str(val).startswith("GAP"))
    L.append(f"\nCells: {sum(len(c['cells']) for c in R['coverage'].values())}, gaps: {gaps}.")

    L += ["", "## Queries", "", f"Every MCP tool call of this run ({len(R['queries'])}), in order (source: mcp_audit.jsonl written by the MCP server).", "",
          "| Query | Phase | Tool | Arguments | Hits / rows | Cited by |", "|---|---|---|---|---|---|"]
    for q in R["queries"]:
        L.append(f"| {q['query_id']} | {cell(q['phase'], 30)} | {q['tool']} | {cell(q['args'], 260)} | "
                 f"{'ERROR' if q['error'] else q['hits']} | {', '.join(q['cited_by'])} |")

    nv = sum(len(f.get("verification", [])) for f in R["findings"])
    ok = sum(e["ok"] for f in R["findings"] for e in f.get("verification", []))
    corr = R.get("evidence_corrections", [])
    L += ["", "## Verification", "",
          f"Evidence items cited: {nv}; confirmed against the stored events: {ok}; rejected: {nv - ok}. Each item was re-fetched "
          "with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited "
          "query_id is a query of this run that returned that event.",
          f"Evidence sent back to the agents for correction during the run: {sum(c['failed_items'] for c in corr)} item(s) in "
          f"{len(corr)} submission(s) (one correction round each; what still failed was rejected).", "",
          "## Limitations", "",
          "- Findings describe what the stored logs show; activity these sources did not log cannot be seen.",
          "- Datasets with non-overlapping time windows (see Data examined) were analysed separately.",
          "- Long field values are shortened in this report; full events are retrievable by _index/_id."]
    (run_dir / "report.md").write_text("\n".join(L) + "\n", encoding="utf-8")
