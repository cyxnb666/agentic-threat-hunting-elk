"""Hunt agent: plain-language hypothesis in, evidenced verdict out. All data access goes through the MCP server.

Phases (each one leaves files in runs/hunts/<run>/):
  0 scope        list_data_sources + get_registry + get_fields  (which data exists, which time windows)
  1 frame        LLM maps the hypothesis to ATT&CK tactics
  2 plan         coverage matrix technique x dataset (techniques from the ATT&CK v20.0 knowledge base): every
                 cell gets checks or a stated reason why the dataset cannot show the technique; reasons that only
                 cite a different time window are refused; a second pass fills the cells the first pass skipped
  3 execute      every planned check runs through MCP; failed queries get one LLM repair
  4 triage       one bounded tool loop per technique family with hits (fresh context each): investigate, then
                 submit findings + a status per technique. Evidence is verified at submission and failures are
                 returned once for correction; if no valid resubmission arrives, the verified part of the first
                 submission is kept. A submission cut off at the output limit (finish_reason "length", or arguments
                 that are not valid JSON) is never accepted: the agent is asked for a shorter one within the same
                 budget. Findings outside the hypothesis' techniques go to "context".
  5 pivot        code runs fixed queries (process creations, files written, 4688, PowerShell) on the hosts of
                 verified malicious/suspicious evidence, 15 min around it; one bounded loop reviews them
  6 verify       final check of every cited event (exists, cited field holds the cited value, cited query
                 returned it); unsupported claims are rejected
  7 consolidate  findings describing the same attacker action are grouped into incidents, each with the one
                 best-fitting technique (or marked outside the hypothesis)
  8 verdict      rules over in-scope incidents of verified findings, and coverage
  8 report       report.md + report.json

Profiles (the repeatability experiment compares them):
  baseline   DeepSeek default thinking mode (temperature has no effect there), techniques and checks chosen
             freely by the LLM, one free investigation loop, the LLM decides the verdict, unverified claims stay
             in the report (annotated only)
  converged  thinking off + temperature 0, phases 2-8 as above, verdict by fixed rules over verified evidence
"""
import asyncio
import collections
import datetime as dt
import json
import os
import re
import sys
import time

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from . import config
from .llm import LLM

KB_PATH = config.ROOT / "knowledge" / "attack_enterprise_v20.0_windows.json"
PROFILES = {
    "converged": {"thinking": False, "temperature": 0.0, "structured": True, "verdict": "rules", "gate": True},
    "baseline": {"thinking": True, "temperature": 0.0, "structured": False, "verdict": "llm", "gate": False},
}
FREE_STEPS = 40          # baseline: one investigation loop
TRIAGE_STEPS = 8         # converged: tool calls per technique family
FIX_STEPS = 4            # extra tool calls allowed after a failed verification
PIVOT_STEPS = 12
PLAN_BATCH = 6
QUERY_TOOLS = ["search", "count", "aggregate", "timeline", "esql", "get_event", "get_fields"]
CHECK_TOOLS = ("search", "count", "aggregate", "esql", "timeline")
NA_REFUSED = re.compile(r"overlap|time[- ]window", re.IGNORECASE)
RESUBMIT_SHORTER = ("Nothing of that submission was received. Call submit_findings again with the complete submission "
                    "(all findings, candidate_assessments and technique_status), written much shorter: summary and every "
                    "reason in one short sentence, at most 3 evidence items per finding, long field values cited as a short "
                    "exact excerpt (20-80 characters), benign findings in a few words, technique_status only for the "
                    "techniques you were asked about.")

AGENT_RULES = """Rules you must follow:
- Every statement must rest on events you retrieved through the tools in this session. Never invent field
  values, hosts, ids or counts. If you did not see it in a tool result, you do not know it.
- Evidence item = {index, id, field, value, query_id}: the event's _index and _id (from search hits, or ES|QL rows
  with METADATA _id, _index), ONE field of that event, a value copied verbatim from that field (an exact excerpt
  is allowed for long text; never add words, parentheses or context), and the query_id of the tool call that
  returned that event (or of your get_event call for it).
- Lucene query_string: operators AND/OR/NOT in upper case; keyword values are case-sensitive (Windows paths
  appear as C:\\Windows and C:\\windows); escape backslashes as \\\\ and quote values with spaces. For
  case-insensitive or multi-condition matching use ES|QL, e.g.
  FROM logs-windows.sysmon-default METADATA _id, _index | WHERE TO_LOWER(process.executable) LIKE "*x*" | KEEP @timestamp, host.name, _id, _index
- Field names must exist in the dataset (see the field lists). Zeek records have no event.code; their log type is
  event.action (conn, dns, http, kerberos, dce_rpc, smb_files, ...).
- Datasets whose time windows do not overlap cannot be correlated by time, but each dataset still shows the
  activity of its own window and must be hunted on its own.
- High-volume results: stack them (aggregate by process.executable, host.name, user.name, win.GrantedAccess ...)
  and look at the rare values before reading individual events."""


# ---------------------------------------------------------------------------------------------------------
class Tools:
    """MCP client side: call tools on the elk-threat-hunting server and keep a client-side log."""

    def __init__(self, session: ClientSession, log_path):
        self.session = session
        self.log_path = log_path
        self.calls = 0

    async def call(self, name: str, args: dict | None = None, phase: str = "") -> dict:
        args = {k: v for k, v in (args or {}).items() if v is not None}
        res = await self.session.call_tool(name, args)
        data = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
        if not data:
            text = res.content[0].text if res.content else "{}"
            try:
                data = json.loads(text)
            except ValueError:
                data = {"error": text}
        if isinstance(data, dict) and set(data) == {"result"} and isinstance(data["result"], dict):
            data = data["result"]
        self.calls += 1
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"phase": phase, "tool": name, "args": args, "query_id": data.get("query_id"),
                                "total": data.get("total"), "error": data.get("error")}, default=str) + "\n")
        return data


def _json_from(msg_content: str) -> dict:
    text = (msg_content or "").strip()
    if text.startswith("```"):
        text = text.strip("`").split("\n", 1)[1] if "\n" in text else text
        text = text.rsplit("```", 1)[0]
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        # an empty or non-JSON answer must be retried, never read as an empty plan (seen in run exp-A1: thinking
        # mode answered the planning prompt with blanks)
        raise ValueError("answer contains no JSON object")
    return json.loads(text[start:end + 1])


def _tool_args(raw) -> dict | None:
    """Arguments of a tool call; None if they are not a JSON object (e.g. cut off at the output limit)."""
    try:
        args = json.loads(raw or "{}")
    except ValueError:
        return None
    return args if isinstance(args, dict) else None


def _verified_part(findings: list[dict], checked: list[dict]) -> list[dict]:
    """The verified part of a submission (checked = verify() of a copy, same order): each finding keeps only the
    evidence items that passed verification; findings left without verified evidence are dropped."""
    out = []
    for f, c in zip(findings, checked):
        ev = [e for e, v in zip(f.get("evidence") or [], c.get("verification", [])) if v.get("ok")]
        if ev:
            out.append({**f, "evidence": ev})
    return out


def _last_finish_reason(log_path) -> str | None:
    """finish_reason of the newest record in llm_calls.jsonl (LLM.chat logs it but returns only the message). The
    key is written after the response, so it lies in the last few KB even when the record holds a long conversation."""
    try:
        with open(log_path, "rb") as f:
            f.seek(max(0, f.seek(0, os.SEEK_END) - 8192))
            tail = f.read().decode("utf-8", "replace")
    except OSError:
        return None
    found = re.findall(r'"finish_reason": (?:"(\w+)"|null)', tail)
    return (found[-1] or None) if found else None


class HuntAgent:
    def __init__(self, hypothesis: str, profile: str, run_dir, plan_from=None):
        self.plan_from = plan_from
        self.hypothesis = hypothesis
        self.profile_name = profile
        self.p = PROFILES[profile]
        self.run_dir = run_dir
        self.llm = LLM(run_dir, temperature=self.p["temperature"], thinking=self.p["thinking"])
        self.kb = json.loads(KB_PATH.read_text(encoding="utf-8"))
        self.state = {"hypothesis": hypothesis, "profile": profile, "model": self.llm.model,
                      "started_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
        self.coverage, self.technique_status, self.context, self.corrections = {}, {}, [], []

    def save(self, name: str, obj) -> None:
        (self.run_dir / name).write_text(json.dumps(obj, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    def ask_json(self, system: str, user: str, purpose: str) -> dict:
        for _ in range(3):
            msg = self.llm.chat([{"role": "system", "content": system}, {"role": "user", "content": user}],
                                json_mode=True, purpose=purpose)
            try:
                return _json_from(msg.content)
            except (ValueError, json.JSONDecodeError):
                user += "\n\nYour previous answer was not valid JSON. Answer with one JSON object only."
        raise RuntimeError(f"no JSON from LLM for {purpose}")

    # ---- phase 0 -----------------------------------------------------------------------------------------
    async def scope(self, tools: Tools):
        inv = await tools.call("list_data_sources", phase="scope")
        reg = await tools.call("get_registry", phase="scope")
        fields = {}
        for ds in sorted(d["dataset"] for d in inv["datasets"]):
            f = await tools.call("get_fields", {"dataset": ds}, phase="scope")
            fields[ds] = [x["field"] for x in f.get("fields", []) if not x["field"].endswith(".text")]
        self.inventory, self.registry, self.fields = inv, reg, fields
        self.datasets = sorted(fields)
        self.save("00_scope.json", {"inventory": inv, "registry": reg, "fields": fields})

    def inventory_brief(self, datasets=None, with_fields=True) -> str:
        lines = []
        for d in sorted(self.inventory["datasets"], key=lambda x: x["dataset"]):
            if datasets and d["dataset"] not in datasets:
                continue
            lines.append(f"- dataset {d['dataset']}: {d['documents']} events, {d['first_event']} .. {d['last_event']}; "
                         f"hosts {list(d['hosts'])[:8]}; observers {list(d['observers'])}; "
                         f"event codes {dict(list(d['top_event_codes'].items())[:25])}; "
                         f"event actions {dict(list(d.get('top_event_actions', {}).items())[:15])}")
            if with_fields:
                lines.append(f"  fields: {', '.join(self.fields[d['dataset']][:230])}")
        lines += [f"- NOTE: {g}" for g in self.inventory.get("non_overlapping_time_windows", [])]
        return "\n".join(lines)

    # ---- phase 1 -----------------------------------------------------------------------------------------
    def frame(self) -> dict:
        tactics = sorted(self.kb["tactics"])
        out = self.ask_json(
            "You are a threat hunter. Map a hunting hypothesis to MITRE ATT&CK tactics. Answer in JSON.",
            f"Hypothesis: {self.hypothesis}\nValid tactic short names: {tactics}\n"
            'Answer {"tactics": [short names the hypothesis is about, most specific only], "restated": "one precise sentence", '
            '"what_would_confirm": "observable evidence", "what_would_refute": "observable absence"}', "frame")
        out["tactics"] = sorted(t for t in out.get("tactics", []) if t in tactics)
        self.save("01_frame.json", out)
        return out

    def techniques_for(self, tactics) -> list[dict]:
        return sorted((t for t in self.kb["techniques"] if set(t["tactics"]) & set(tactics)), key=lambda t: t["id"])

    # ---- phase 2 -----------------------------------------------------------------------------------------
    def plan(self, frame: dict) -> list[dict]:
        checks = []
        if self.p["structured"]:
            techs = self.techniques_for(frame["tactics"])
            self.scope_techniques = {t["id"]: t["name"] for t in techs}
            for i in range(0, len(techs), PLAN_BATCH):
                self._plan_batch(frame, techs[i:i + PLAN_BATCH], None, checks, f"plan batch {i // PLAN_BATCH + 1}")
            gaps = {t: [ds for ds, v in c["cells"].items() if v.startswith("GAP")] for t, c in self.coverage.items()}
            gaps = {t: g for t, g in gaps.items() if g}
            gap_techs = [t for t in techs if t["id"] in gaps]
            for i in range(0, len(gap_techs), PLAN_BATCH):
                self._plan_batch(frame, gap_techs[i:i + PLAN_BATCH], gaps, checks, f"plan gap-fill {i // PLAN_BATCH + 1}")
        else:
            self._plan_free(frame, checks)
            self.scope_techniques = {t: c["name"] for t, c in self.coverage.items()}
        for n, c in enumerate(checks, 1):
            c["check_id"] = f"C{n:03d}"
        self.save("02_plan.json", {"checks": checks, "coverage": self.coverage})
        return checks

    def _plan_batch(self, frame, batch, only, checks, purpose):
        spec = [{"id": t["id"], "name": t["name"], "description": t["description"][:350],
                 "datasets_to_decide": only[t["id"]] if only else self.datasets,
                 "attack_log_sources": sorted({f"{ls['log_source']} {ls.get('channel') or ''}".strip()
                                               for s in t["detection_strategies"] for ls in s["log_sources"]})[:12]}
                for t in batch]
        system = "You are a threat hunter planning queries against Elasticsearch through MCP tools.\n" + AGENT_RULES + "\nAnswer in JSON."
        user = (f"Hypothesis: {self.hypothesis}\nFraming: {json.dumps(frame)}\n\nAvailable data:\n{self.inventory_brief()}\n\n"
                f"ATT&CK techniques to cover (with the log sources ATT&CK v20.0 associates with them):\n{json.dumps(spec, indent=1)}\n\n"
                "For EVERY technique and EVERY dataset in its datasets_to_decide, decide: either at least one check that could "
                "reveal the technique in that dataset, or a not_applicable entry with the concrete reason why that dataset "
                "cannot record it (e.g. it does not log that kind of event). A different time window is NOT a reason. "
                "Checks use one tool with arguments exactly as the tool expects:\n"
                '  search {"dataset", "query", "size"}, count {"dataset", "query"}, aggregate {"dataset", "field", "query", "size"}, '
                'esql {"query"} (also name the "dataset" it reads), timeline {"dataset", "query", "interval"}.\n'
                "Prefer aggregate (stacking) for broad conditions. No time filter: the whole retention of each dataset is searched.\n"
                'Answer {"techniques": [{"technique": "T....", "checks": [{"dataset": "...", "tool": "...", "args": {...}, '
                '"purpose": "..."}], "not_applicable": [{"dataset": "...", "reason": "..."}]}]}')
        out = self.ask_json(system, user, purpose)
        got = {p.get("technique"): p for p in out.get("techniques", [])}
        for t in batch:
            p = got.get(t["id"], {})
            decide = set(only[t["id"]] if only else self.datasets)
            cells = self.coverage.setdefault(t["id"], {"name": t["name"], "cells": {}})["cells"]
            for c in p.get("checks", []):
                if c.get("dataset") in decide and c.get("tool") in CHECK_TOOLS:
                    checks.append({"technique": t["id"], **c})
                    cells[c["dataset"]] = "check"
            for na in p.get("not_applicable", []):
                ds, why = na.get("dataset"), str(na.get("reason", ""))[:240]
                if ds in decide and cells.get(ds) != "check":
                    cells[ds] = ("GAP: n/a refused (time window is not a reason): " + why) if NA_REFUSED.search(why) else "n/a: " + why
            for ds in decide:
                if cells.get(ds, "GAP").startswith("GAP") and cells.get(ds) != "check":
                    cells.setdefault(ds, "GAP: not assessed by the planner")

    def _plan_free(self, frame, checks):
        system = "You are a threat hunter planning queries against Elasticsearch through MCP tools.\n" + AGENT_RULES + "\nAnswer in JSON."
        out = self.ask_json(system,
            f"Hypothesis: {self.hypothesis}\nFraming: {json.dumps(frame)}\nAvailable data:\n{self.inventory_brief()}\n\n"
            'Plan the hunt. Choose the ATT&CK techniques you consider relevant and the queries to run. Answer '
            '{"techniques": [{"technique": "T....", "name": "...", "checks": [{"dataset": "...", "tool": "search|count|aggregate|esql|timeline", '
            '"args": {...tool arguments...}, "purpose": "..."}]}]}', "plan free")
        for p in out.get("techniques", []):
            cells = self.coverage.setdefault(p.get("technique"), {"name": p.get("name", ""), "cells": {}})["cells"]
            for c in p.get("checks", []):
                if c.get("dataset") in self.datasets and c.get("tool") in CHECK_TOOLS:
                    checks.append({"technique": p.get("technique"), **c})
                    cells[c["dataset"]] = "check"

    # ---- phase 3 -----------------------------------------------------------------------------------------
    async def execute(self, tools: Tools, checks: list[dict]) -> list[dict]:
        results = []
        for c in checks:
            args = dict(c.get("args") or {})
            args = {"query": args.get("query", "")} if c["tool"] == "esql" else {**args, "dataset": args.get("dataset", c["dataset"])}
            res = await tools.call(c["tool"], args, phase=f"check {c['check_id']}")
            if res.get("error"):
                fixed = self.ask_json("You fix Elasticsearch queries. " + AGENT_RULES + " Answer in JSON.",
                    f"This {c['tool']} call failed.\nArguments: {json.dumps(args)}\nError: {res['error'][:600]}\n"
                    f"Fields of dataset {c['dataset']}: {', '.join(self.fields.get(c['dataset'], [])[:230])}\n"
                    'Answer {"args": {...corrected arguments for the same tool...}}', f"repair {c['check_id']}")
                args = fixed.get("args", args)
                if c["tool"] != "esql":
                    args.setdefault("dataset", c["dataset"])
                res = await tools.call(c["tool"], args, phase=f"check {c['check_id']} (repaired)")
            results.append({**c, "args": args, "query_id": res.get("query_id"), "error": res.get("error"),
                            "total": res.get("total", res.get("rows")), "result": _compact(res)})
        self.save("03_results.json", results)
        return results

    # ---- phase 4 (baseline): one free loop ---------------------------------------------------------------
    async def investigate_free(self, tools: Tools, results: list[dict]) -> list[dict]:
        hits = [r for r in results if (r.get("total") or 0) > 0]
        zero = [r["check_id"] for r in results if not r.get("error") and not (r.get("total") or 0)]
        brief = [_brief(r) for r in hits]
        system = ("You are a senior threat hunter. You investigate the results of planned checks with read-only tools, "
                  "separate attacker activity from normal system behaviour, and submit findings.\n" + AGENT_RULES +
                  f"\nYou have at most {FREE_STEPS} tool calls. Finish by calling submit_findings exactly once.")
        user = (f"Hypothesis: {self.hypothesis}\n\nAvailable data:\n{self.inventory_brief()}\n\n"
                f"Checks with hits ({len(hits)}):\n{json.dumps(brief, ensure_ascii=False)[:60000]}\n\nChecks with zero hits: {zero}\n\n"
                "Investigate, then call submit_findings.")
        findings, _ = await self._loop(tools, system, user, FREE_STEPS, "investigate", verify_on_submit=False)
        return findings

    # ---- phase 4 (converged): per technique family -------------------------------------------------------
    async def triage(self, tools: Tools, results: list[dict]) -> list[dict]:
        by_family = collections.defaultdict(list)
        for r in results:
            by_family[r["technique"].split(".")[0]].append(r)
        findings = []
        for fam in sorted(by_family):
            rs = by_family[fam]
            techs = sorted({r["technique"] for r in rs} | {t for t in self.scope_techniques if t.split(".")[0] == fam})
            if not any((r.get("total") or 0) > 0 for r in rs):
                for t in techs:
                    n = sum(1 for r in rs if r["technique"] == t)
                    self.technique_status[t] = {"status": "not_observed" if n else "not_checked",
                                                "reason": f"{n} planned checks, all with zero hits" if n else "no check planned"}
                continue
            datasets = sorted({r["dataset"] for r in rs})
            hits = [_brief(r) for r in rs if (r.get("total") or 0) > 0]
            zero = [f"{r['check_id']} {r['technique']} {r['dataset']}: {json.dumps(r['args'])[:200]}" for r in rs
                    if not r.get("error") and not (r.get("total") or 0)]
            system = ("You are a senior threat hunter triaging one ATT&CK technique family. Investigate the hits with the "
                      "read-only tools, separate attacker activity from normal system behaviour, then call submit_findings "
                      "with findings and one status per technique.\n" + AGENT_RULES +
                      f"\nFindings may only use these techniques: {techs}. You have at most {TRIAGE_STEPS} tool calls.")
            user = (f"Hypothesis: {self.hypothesis}\n\nTechnique family {fam}: "
                    f"{json.dumps({t: self.scope_techniques.get(t, '') for t in techs})}\n\n"
                    f"Data:\n{self.inventory_brief(datasets)}\n\nChecks with hits:\n{json.dumps(hits, ensure_ascii=False)[:45000]}\n\n"
                    f"Checks with zero hits:\n" + "\n".join(zero)[:6000] +
                    "\n\nInvestigate (stack high-volume hits, read full events with get_event before citing them), then call "
                    "submit_findings. Benign explanations of hits are findings with assessment 'benign'.")
            fs, statuses = await self._loop(tools, system, user, TRIAGE_STEPS, f"triage {fam}", verify_on_submit=True, allowed=set(techs))
            findings += fs
            for t in techs:
                st = statuses.get(t) or self.technique_status.get(t) or {"status": "not_observed", "reason": "no status submitted"}
                self.technique_status[t] = st
        return findings

    async def pivot(self, tools: Tools, findings: list[dict]) -> list[dict]:
        """Time-window pivot. Code first runs the same fixed queries around every host/time window of verified
        malicious or suspicious Windows evidence (process creations with parents, files written, Security 4688,
        PowerShell events), then one bounded LLM loop reviews them for credential activity the checks missed."""
        windows = {}
        for f in findings:
            if f.get("verified") and f.get("assessment") in ("malicious", "suspicious"):
                for v in f.get("verification", []):
                    if v.get("ok") and v.get("host") and v.get("timestamp") and str(v.get("dataset", "")).startswith("windows"):
                        t = dt.datetime.fromisoformat(str(v["timestamp"]).replace("Z", "+00:00")).astimezone(dt.timezone.utc)
                        lo, hi = windows.get(v["host"], (t, t))
                        windows[v["host"]] = (min(lo, t), max(hi, t))
        if not windows:
            return []
        seeds = []
        pad = dt.timedelta(minutes=15)
        for host in sorted(windows):
            lo, hi = windows[host]
            tf, tt = (lo - pad).isoformat(), (hi + pad).isoformat()
            hq = f'host.name:"{host}"'
            for ds, field, sub, q in [
                    ("windows.sysmon", "process.executable", "process.parent.executable", f"event.code:1 AND {hq}"),
                    ("windows.sysmon", "file.path", "process.executable", f"event.code:11 AND {hq}"),
                    ("windows.security", "process.executable", "process.parent.executable", f"event.code:4688 AND {hq}"),
                    ("windows.powershell", "event.code", None, hq)]:
                res = await tools.call("aggregate", {"dataset": ds, "field": field, "query": q, "time_from": tf, "time_to": tt,
                                                     "size": 100, "sub_field": sub}, phase="pivot seed")
                seeds.append({"host": host, "window": [tf, tt], "dataset": ds, "query": q, "field": field,
                              "query_id": res.get("query_id"), "total": res.get("total"), "buckets": res.get("buckets", [])[:100]})
        candidates = pivot_candidates(seeds)
        self.pivot_candidates = {"candidates": candidates, "assessments": []}
        techs = sorted(self.scope_techniques)
        activity = _activity_words(getattr(self, "tactics", []))
        system = ("You are a senior threat hunter. Verified attacker activity was found. Below are fixed pivot queries around it: "
                  "every process created, every file written and the PowerShell events on the same hosts, 15 minutes before "
                  f"and after. Review EVERY entry: look for {activity} the technique checks missed (unusual binaries, "
                  "tools run from unusual folders or started by script hosts, renamed tools, credential files written). "
                  "Read the events with search/get_event before citing them. Report only activity that is new compared with "
                  "the anchors.\n" + AGENT_RULES +
                  f"\nFindings may only use these techniques: {techs}. You have at most {PIVOT_STEPS} tool calls.")
        anchors = [{"technique": f.get("technique"), "title": f.get("title")} for f in findings
                   if f.get("verified") and f.get("assessment") in ("malicious", "suspicious")]
        user = (f"Hypothesis: {self.hypothesis}\n\nAnchors (verified findings): {json.dumps(anchors, ensure_ascii=False)[:6000]}\n\n"
                f"Pivot query results:\n{json.dumps(seeds, ensure_ascii=False)[:50000]}\n\nData:\n{self.inventory_brief(with_fields=False)}\n\n"
                "Candidates you MUST assess, one entry each in candidate_assessments (processes started by a script host or "
                "from outside the Windows directory, rare in the window):\n" + json.dumps(candidates, ensure_ascii=False) + "\n\n"
                f"Investigate the candidates and any other entry that could be {activity}. For every candidate you assess "
                "as malicious or suspicious also submit a finding with evidence. Then call submit_findings (status only for "
                "techniques you newly assessed).")
        required = {c["executable"].lower() for c in candidates}
        fs, statuses = await self._loop(tools, system, user, PIVOT_STEPS, "pivot", verify_on_submit=True, allowed=set(techs),
                                        required=required)
        for t, st in statuses.items():
            if st.get("status") in ("malicious", "suspicious"):
                self.technique_status[t] = st
        return fs

    # ---- consolidate (structured profile) ----------------------------------------------------------------
    def consolidate(self, findings: list[dict]) -> list[dict]:
        """Group verified malicious/suspicious findings that describe the same attacker action into incidents and give
        each incident the single best-fitting ATT&CK technique (or mark it outside the hypothesis)."""
        cands = [f for f in findings if f.get("verified") and f.get("assessment") in ("malicious", "suspicious")]
        if not cands:
            return []
        payload = [{"finding_id": f["finding_id"], "technique": f.get("technique"), "assessment": f.get("assessment"),
                    "confidence": f.get("confidence"), "title": f.get("title"), "summary": str(f.get("summary"))[:500],
                    "evidence": [{"id": v["id"], "host": v.get("host"), "time": v.get("timestamp"), "field": v.get("field"),
                                  "value": str(v.get("actual"))[:160]} for v in f.get("verification", []) if v.get("ok")]}
                   for f in cands]
        scope = dict(sorted(self.scope_techniques.items()))
        words, others = _scope_words(getattr(self, "tactics", []))
        out = self.ask_json(
            "You consolidate threat hunt findings. Answer in JSON. Use only the findings given; never add facts.",
            f"Hypothesis: {self.hypothesis}\nIn-scope ATT&CK techniques: {json.dumps(scope)}\n\nVerified findings:\n"
            f"{json.dumps(payload, ensure_ascii=False)}\n\n"
            "Group findings that describe the same attacker action (they share events, or describe the same action on the "
            "same host) into incidents. For each incident pick the ONE in-scope technique whose ATT&CK definition fits the "
            f"observed action best; if the action is not {words} (e.g. {others}), "
            'set technique to "out-of-scope:<best ATT&CK id>". Every finding id must appear in exactly one incident.\n'
            'Answer {"incidents": [{"title": "...", "technique": "T....", "assessment": "malicious|suspicious", '
            '"finding_ids": ["F.."], "rationale": "..."}]}', "consolidate")
        ids = {f["finding_id"]: f for f in cands}
        rank = {"low": 0, "medium": 1, "high": 2}
        incidents, seen = [], set()
        for inc in out.get("incidents", []):
            fids = [i for i in inc.get("finding_ids", []) if i in ids and i not in seen]
            tech = str(inc.get("technique", ""))
            if not fids or not (tech in scope or tech.startswith("out-of-scope:")):
                continue
            seen.update(fids)
            incidents.append({"title": inc.get("title"), "technique": tech, "in_scope": tech in scope,
                              "assessment": "malicious" if any(ids[i].get("assessment") == "malicious" for i in fids) else "suspicious",
                              "confidence": max((ids[i].get("confidence") for i in fids), key=lambda c: rank.get(c, 0)),
                              "finding_ids": fids, "rationale": inc.get("rationale")})
        for i, f in ids.items():     # anything the LLM left out stays as its own incident
            if i not in seen:
                incidents.append({"title": f.get("title"), "technique": f.get("technique"), "in_scope": f.get("technique") in scope,
                                  "assessment": f.get("assessment"), "confidence": f.get("confidence"), "finding_ids": [i],
                                  "rationale": "not grouped by the consolidation step"})
        incidents.sort(key=lambda x: (not x["in_scope"], x["technique"], x["finding_ids"]))
        for n, inc in enumerate(incidents, 1):
            inc["incident_id"] = f"I{n:02d}"
        self.save("06_incidents.json", incidents)
        return incidents

    # ---- shared tool loop -----------------------------------------------------------------------------------
    def _chat(self, messages, tools, purpose):
        """One loop step: the message and its finish_reason ("length" = cut off at the output token limit)."""
        msg = self.llm.chat(messages, tools=tools, purpose=purpose)
        return msg, _last_finish_reason(self.llm.log_path)

    async def _loop(self, tools, system, user, steps, phase, verify_on_submit, allowed=None, required=None):
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        tool_defs = _mcp_tool_defs() + [_SUBMIT]
        findings, statuses, submissions, budget, used = None, {}, 0, steps, 0
        first = None      # (findings, statuses) of the last returned submission, kept if no valid resubmission arrives:
        kept = None       # the verified part of a returned first submission, or a second one returned for the candidate rule
        while True:
            force = used >= budget
            if force:
                messages.append({"role": "user", "content": "Tool budget used up. Call submit_findings now."})
            msg, finish = self._chat(messages, [_SUBMIT] if force else tool_defs, f"{phase} step {used + 1}")
            turn = msg.model_dump(exclude_none=True)
            messages.append(turn)
            if not msg.tool_calls:
                messages.append({"role": "user", "content": "Continue with tool calls; finish with submit_findings."})
                used += 1
                if used > budget + 2:
                    break
                continue
            done = False
            for i, tc in enumerate(msg.tool_calls):
                args = _tool_args(tc.function.arguments)
                if args is None:     # cut-off JSON: keep the history a valid request for the next call
                    turn["tool_calls"][i]["function"]["arguments"] = "{}"
                if tc.function.name == "submit_findings" and (args is None or finish == "length"):
                    # demo2 pivot: the resubmission hit the 8,192-token output limit, its JSON was read as {} and
                    # accepted as an empty submission. A cut-off submission is not counted and never accepted.
                    raw = tc.function.arguments or ""
                    self.state.setdefault("cut_off_submissions", []).append(
                        {"phase": phase, "step": used + 1, "finish_reason": finish, "argument_chars": len(raw),
                         "valid_json": args is not None})
                    content = {"accepted": False,
                               "error": (f"submit_findings was cut off at the output limit after {len(raw)} characters"
                                         if finish == "length" else "submit_findings arguments are not valid JSON"),
                               "instruction": RESUBMIT_SHORTER}
                elif tc.function.name == "submit_findings":
                    submissions += 1
                    fs = args.get("findings", []) or []
                    if allowed is not None:
                        for f in fs:
                            if f.get("technique") not in allowed:
                                self.context.append({**f, "phase": phase})
                        fs = [f for f in fs if f.get("technique") in allowed]
                    if verify_on_submit:   # structured profile: "nothing observed" belongs in technique_status
                        for f in fs:
                            if not f.get("evidence"):
                                self.technique_status.setdefault(f.get("technique"), {"status": "not_observed", "reason": f.get("summary") or f.get("title")})
                        fs = [f for f in fs if f.get("evidence")]
                    sts = {s.get("technique"): {"status": s.get("status"), "reason": s.get("reason")}
                           for s in args.get("technique_status", []) or [] if s.get("technique")}
                    content = {"accepted": True}
                    assessed = args.get("candidate_assessments", []) or []
                    if required is not None:
                        self.pivot_candidates["assessments"] = assessed
                    if verify_on_submit and submissions == 1:
                        checked = await self.verify(tools, json.loads(json.dumps(fs)), phase=f"{phase} verify")
                        failed = [{"finding": f.get("title"), "evidence": {k: v.get(k) for k in ("index", "id", "field", "claimed", "query_id")},
                                   "problems": v["problems"], "stored_value": v.get("actual"), "queries_that_returned_it": v.get("returned_by")}
                                  for f in checked for v in f.get("verification", []) if not v["ok"]]
                        missing = missing_candidates(required, assessed)
                        unsupported = unsupported_candidates(assessed, fs) if required is not None else []
                        if failed or missing or unsupported:
                            first, kept = (_verified_part(fs, checked), sts), "verified part of the first submission"
                            if failed:
                                self.corrections.append({"phase": phase, "failed_items": len(failed)})
                            content = {"accepted": False, "verification_failures": failed[:20], "missing_candidate_assessments": missing,
                                       "candidates_without_finding": unsupported,
                                       "instruction": "Fix or drop the failed evidence items (copy the stored value exactly, cite a "
                                                      "query that returned the event), assess every missing candidate, submit a "
                                                      "finding with evidence for every candidate you assessed malicious or "
                                                      "suspicious (or change its assessment with a reason), and call "
                                                      "submit_findings again with the complete corrected submission. You may use up "
                                                      f"to {FIX_STEPS} more tool calls."}
                            budget = used + FIX_STEPS + 1
                    elif verify_on_submit and required is not None and submissions == 2:
                        # run 20261020-195702-converged-rehearsal: the resubmission still had no finding for the
                        # suspicious candidate accessChk.exe and was accepted, so 6.A was lost. The pivot's candidate
                        # rule is checked once more; the third submission is accepted as it is.
                        missing = missing_candidates(required, assessed)
                        unsupported = unsupported_candidates(assessed, fs)
                        if missing or unsupported:
                            first, kept = (fs, sts), "second submission (returned for the candidate rule only)"
                            content = {"accepted": False, "missing_candidate_assessments": missing,
                                       "candidates_without_finding": unsupported,
                                       "instruction": "Still open: assess every missing candidate and submit a finding with "
                                                      "evidence for every candidate you assessed malicious or suspicious (or "
                                                      "change its assessment with a reason), then call submit_findings again "
                                                      "with the complete submission. This is the last return. You may use up "
                                                      f"to {FIX_STEPS} more tool calls."}
                            budget = used + FIX_STEPS + 1
                    if content["accepted"]:
                        findings, statuses, done = fs, sts, True
                elif tc.function.name in QUERY_TOOLS:
                    content = ({"error": "arguments are not valid JSON (cut off?); the call was not run"} if args is None
                               else _compact(await tools.call(tc.function.name, args, phase=f"{phase} step {used + 1}")))
                else:
                    content = {"error": f"unknown tool {tc.function.name}"}
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps(content, ensure_ascii=False, default=str)[:15000]})
            used += 1
            if done or used > budget + 2:
                break
        if findings is None and first is not None:
            findings, statuses = first
            self.state.setdefault("submission_fallbacks", []).append({"phase": phase, "kept": kept, "findings": len(findings)})
        return findings or [], statuses

    # ---- phase 6 -----------------------------------------------------------------------------------------
    async def verify(self, tools: Tools, findings: list[dict], phase: str = "verify") -> list[dict]:
        audit = _read_jsonl(self.run_dir / "mcp_audit.jsonl")
        by_qid = {a["query_id"]: a for a in audit}
        returned_by = collections.defaultdict(list)
        for a in audit:
            for i in a.get("returned_ids") or []:
                returned_by[i].append(a["query_id"])
            if a["tool"] == "get_event":
                returned_by[a["args"].get("id")].append(a["query_id"])
        for f in findings:
            checked = []
            for ev in f.get("evidence", []) or []:
                v = {"index": ev.get("index"), "id": ev.get("id"), "field": ev.get("field"), "claimed": ev.get("value"),
                     "query_id": ev.get("query_id"), "ok": False, "problems": [], "returned_by": returned_by.get(ev.get("id"), [])[:5]}
                q = by_qid.get(ev.get("query_id") or "")
                if not q:
                    v["problems"].append("cited query_id does not exist in this run")
                elif ev.get("query_id") not in returned_by.get(ev.get("id"), []):
                    v["problems"].append("cited query did not return this event")
                got = await tools.call("get_event", {"index": ev.get("index", ""), "id": ev.get("id", "")}, phase=phase)
                if got.get("error") or not got.get("found"):
                    v["problems"].append("event not found")
                else:
                    src = got["source"]
                    actual = _field(src, ev.get("field") or "")
                    v["actual"] = _clip(actual)
                    v["timestamp"] = src.get("@timestamp")
                    v["host"] = (src.get("host") or {}).get("name") or (src.get("observer") or {}).get("name")
                    v["dataset"] = (src.get("data_stream") or {}).get("dataset")
                    if actual is None:
                        v["problems"].append(f"field {ev.get('field')} not in the event")
                    elif not _value_matches(ev.get("value"), actual):
                        v["problems"].append("claimed value differs from the stored value")
                v["ok"] = not v["problems"]
                checked.append(v)
            f["verification"] = checked
            f["verified"] = bool(checked) and all(c["ok"] for c in checked)
            f["verified_evidence"] = sum(c["ok"] for c in checked)
        return findings

    # ---- phase 7 -----------------------------------------------------------------------------------------
    def verdict(self, findings: list[dict], incidents: list[dict] | None = None) -> dict:
        counted = [f for f in findings if f.get("verified") or not self.p["gate"]]
        if self.p["verdict"] == "llm":
            out = self.ask_json("You are a threat hunting lead. Decide the verdict of a hunt. Answer in JSON.",
                f"Hypothesis: {self.hypothesis}\nFindings: {json.dumps(counted, ensure_ascii=False, default=str)[:40000]}\n"
                'Answer {"verdict": "Confirmed|Refuted|Inconclusive", "rationale": "..."}', "verdict")
            return {"verdict": out.get("verdict"), "rationale": out.get("rationale"), "method": "LLM judgement"}
        inc = [i for i in (incidents or []) if i["in_scope"]]
        mal = [i for i in inc if i["assessment"] == "malicious" and i["confidence"] in ("high", "medium")]
        sus = [i for i in inc if i["assessment"] in ("malicious", "suspicious")]
        gaps = sorted(t for t, c in self.coverage.items() if any(v.startswith("GAP") for v in c["cells"].values()))
        if mal:
            v, why = "Confirmed", f"{len(mal)} in-scope incident(s) of verified malicious findings (confidence >= medium): " + ", ".join(
                f"{i['incident_id']} {i['technique']} ({', '.join(i['finding_ids'])})" for i in mal)
        elif sus:
            v, why = "Inconclusive", "only low-confidence or suspicious in-scope incidents: " + ", ".join(i["incident_id"] for i in sus)
        elif not gaps:
            v, why = "Refuted", "every technique was checked or shown not observable in every dataset, and nothing malicious was found"
        else:
            v, why = "Inconclusive", f"no malicious finding, but coverage gaps remain for {gaps}"
        return {"verdict": v, "rationale": why, "method": "rules over verified evidence",
                "rule": "Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive "
                        "if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding"}

    # ---- frozen playbook ------------------------------------------------------------------------------------
    def load_playbook(self, run_dir):
        """Re-use the framing and the planned checks of an earlier run (a frozen hunt playbook): the planning LLM is
        not called, so every run with the same playbook executes exactly the same queries."""
        import pathlib
        src = pathlib.Path(run_dir)
        frame = json.loads((src / "01_frame.json").read_text(encoding="utf-8"))
        plan = json.loads((src / "02_plan.json").read_text(encoding="utf-8"))
        checks = [{k: v for k, v in c.items() if k in ("technique", "dataset", "tool", "args", "purpose", "check_id")}
                  for c in plan["checks"]]
        self.coverage = plan["coverage"]
        self.scope_techniques = ({t["id"]: t["name"] for t in self.techniques_for(frame["tactics"])} if self.p["structured"]
                                 else {t: c["name"] for t, c in self.coverage.items()})
        self.state["playbook_from"] = src.name
        self.save("01_frame.json", {**frame, "playbook_from": src.name})
        self.save("02_plan.json", {"checks": checks, "coverage": self.coverage, "playbook_from": src.name})
        return frame, checks

    # ---- run ---------------------------------------------------------------------------------------------
    async def run(self) -> str:
        env = dict(os.environ, HUNT_AUDIT_FILE=str(self.run_dir / "mcp_audit.jsonl"), PYTHONIOENCODING="utf-8")
        params = StdioServerParameters(command=sys.executable, args=["-m", "hunt", "mcp"], cwd=str(config.ROOT), env=env)
        t0 = time.time()
        errlog = open(self.run_dir / "mcp_server.log", "w", encoding="utf-8")
        async with stdio_client(params, errlog=errlog) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                self.state["mcp_tools"] = [t.name for t in (await session.list_tools()).tools]
                tools = Tools(session, self.run_dir / "tool_calls.jsonl")
                await self.scope(tools)
                if self.plan_from:
                    frame, checks = self.load_playbook(self.plan_from)
                else:
                    frame = await asyncio.to_thread(self.frame)
                    checks = await asyncio.to_thread(self.plan, frame)
                self.tactics = frame.get("tactics") or []
                results = await self.execute(tools, checks)
                if self.p["structured"]:
                    findings = await self.triage(tools, results)
                    findings = await self.verify(tools, findings)
                    self.save("04a_triage.json", {"findings": findings, "technique_status": self.technique_status})
                    self.pivot_candidates = {"candidates": [], "assessments": []}
                    try:
                        findings += await self.pivot(tools, findings)
                    except Exception as exc:   # keep the triage results even if the pivot fails
                        self.state["pivot_error"] = f"{type(exc).__name__}: {exc}"
                else:
                    findings = await self.investigate_free(tools, results)
                for n, f in enumerate(findings, 1):
                    f["finding_id"] = f"F{n:02d}"
                self.save("04_findings_raw.json", findings)
                findings = await self.verify(tools, findings)
                self.save("05_verified.json", findings)
                self.state["pivot_candidates"] = getattr(self, "pivot_candidates", None)
                incidents = await asyncio.to_thread(self.consolidate, findings) if self.p["structured"] else []
                verdict = self.verdict(findings, incidents)
        errlog.close()
        self.state.update({"finished_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                           "seconds": round(time.time() - t0, 1), "llm_calls": self.llm.calls, "llm_tokens": self.llm.tokens,
                           "mcp_calls": tools.calls})
        from .report import write_report
        return write_report(self, frame, checks, results, findings, verdict, incidents)


# ---------------------------------------------------------------------------------------------------------
_EVIDENCE = {"type": "object", "required": ["index", "id", "field", "value", "query_id"],
             "properties": {"index": {"type": "string"}, "id": {"type": "string"},
                            "field": {"type": "string", "description": "one field of the event"},
                            "value": {"type": "string", "description": "copied verbatim from that field (exact excerpt for long text); no added words"},
                            "query_id": {"type": "string", "description": "query_id of the call that returned this event"}}}
_SUBMIT = {"type": "function", "function": {
    "name": "submit_findings", "description": "Submit the findings (and per-technique status) of this investigation.",
    "parameters": {"type": "object", "required": ["findings"], "properties": {
        "findings": {"type": "array", "items": {
            "type": "object", "required": ["technique", "title", "assessment", "confidence", "summary", "evidence"],
            "properties": {
                "technique": {"type": "string", "description": "ATT&CK id, e.g. T1003.001"},
                "title": {"type": "string"},
                "assessment": {"type": "string", "enum": ["malicious", "suspicious", "benign"]},
                "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                "summary": {"type": "string", "description": "what happened, on which host, by which process/user, when"},
                "evidence": {"type": "array", "items": _EVIDENCE}}}},
        "candidate_assessments": {"type": "array", "description": "pivot phase only: one entry per listed candidate",
                                  "items": {"type": "object", "required": ["executable", "assessment", "reason"], "properties": {
                                      "executable": {"type": "string"},
                                      "assessment": {"type": "string", "enum": ["malicious", "suspicious", "benign"]},
                                      "reason": {"type": "string"}}}},
        "technique_status": {"type": "array", "description": "one entry per technique you were asked about",
                             "items": {"type": "object", "required": ["technique", "status", "reason"], "properties": {
                                 "technique": {"type": "string"},
                                 "status": {"type": "string", "enum": ["malicious", "suspicious", "benign", "not_observed", "not_observable"]},
                                 "reason": {"type": "string"}}}}}}}}


def _mcp_tool_defs() -> list[dict]:
    s = {"type": "string"}
    return [
        {"type": "function", "function": {"name": "search", "description": "Lucene query_string search in a dataset; returns total, hits with _index/_id and fields, query_id.",
         "parameters": {"type": "object", "required": ["dataset", "query"], "properties": {"dataset": s, "query": s, "time_from": s, "time_to": s,
                        "fields": {"type": "array", "items": s}, "size": {"type": "integer"}, "sort": s}}}},
        {"type": "function", "function": {"name": "count", "description": "Exact count of events matching a query.",
         "parameters": {"type": "object", "required": ["dataset", "query"], "properties": {"dataset": s, "query": s, "time_from": s, "time_to": s}}}},
        {"type": "function", "function": {"name": "aggregate", "description": "Top values of a field (terms aggregation), optional sub_field breakdown.",
         "parameters": {"type": "object", "required": ["dataset", "field"], "properties": {"dataset": s, "field": s, "query": s, "size": {"type": "integer"},
                        "sub_field": s, "time_from": s, "time_to": s}}}},
        {"type": "function", "function": {"name": "timeline", "description": "Event counts per time bucket.",
         "parameters": {"type": "object", "required": ["dataset", "query"], "properties": {"dataset": s, "query": s, "interval": s, "time_from": s, "time_to": s}}}},
        {"type": "function", "function": {"name": "esql", "description": "Run an ES|QL query (FROM logs-<dataset>-default METADATA _id, _index | WHERE ... | KEEP ...).",
         "parameters": {"type": "object", "required": ["query"], "properties": {"query": s}}}},
        {"type": "function", "function": {"name": "get_event", "description": "Full stored record of one event by _index and _id.",
         "parameters": {"type": "object", "required": ["index", "id"], "properties": {"index": s, "id": s}}}},
        {"type": "function", "function": {"name": "get_fields", "description": "Field names/types of a dataset, optional prefix.",
         "parameters": {"type": "object", "required": ["dataset"], "properties": {"dataset": s, "prefix": s}}}},
    ]


def _scope_words(tactics) -> tuple[str, str]:
    """The hypothesis' tactics in words, and example actions outside them, for the consolidation prompt. For
    ["credential-access"] (every run so far) this gives exactly the wording those runs used."""
    words = [t.replace("-", " ") for t in tactics] or ["credential access"]
    others = [x for x in ("credential access", "lateral movement", "execution", "collection", "exfiltration") if x not in words]
    return " or ".join(words), ", ".join(others)


def _activity_words(tactics) -> str:
    """What the pivot reviewer looks for; "credential theft" for a credential-access hypothesis, as before."""
    words, _ = _scope_words(tactics)
    return "credential theft" if words == "credential access" else f"{words} activity"


SCRIPT_HOSTS = ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
                "regsvr32.exe", "wmiprvse.exe", "psexesvc.exe")
BS = "\\"
WINDOWS_DIR = "c:" + BS + "windows" + BS


def pivot_candidates(seeds: list[dict], max_count: int = 5, limit: int = 40) -> list[dict]:
    """Processes the pivot reviewer must assess: started by a script host or from outside the Windows directory, and
    rare (at most max_count starts in the window). Deterministic, so every run asks about the same processes."""
    written = {}
    for s in seeds:
        if s["field"] == "file.path":
            for b in s["buckets"]:
                for proc in (b.get("process.executable") or {}):
                    written.setdefault((s["host"], str(proc).lower()), []).append(str(b["value"]))
    out = {}
    for s in seeds:
        if s["field"] != "process.executable":
            continue
        for b in s["buckets"]:
            exe = str(b["value"])
            parents = [str(x) for x in (b.get("process.parent.executable") or {})]
            by_script = any(x.lower().endswith(SCRIPT_HOSTS) for x in parents)
            outside = not exe.lower().startswith(WINDOWS_DIR)
            if (by_script or outside) and b["count"] <= max_count and exe.lower() not in out:
                out[exe.lower()] = {"executable": exe, "host": s["host"], "starts": b["count"], "parents": parents,
                                    "files_written": sorted(written.get((s["host"], exe.lower()), []))[:10],
                                    "query_id": s["query_id"]}
    return sorted(out.values(), key=lambda c: (c["host"], c["executable"].lower()))[:limit]


def unsupported_candidates(assessed, findings) -> list[str]:
    """Candidates assessed malicious/suspicious that no submitted finding mentions (title, summary or evidence)."""
    text = json.dumps(findings, ensure_ascii=False).lower()
    out = []
    for a in assessed:
        if a.get("assessment") in ("malicious", "suspicious"):
            base = str(a.get("executable", "")).lower().split(BS)[-1].rsplit(".", 1)[0]   # "accesschk" matches accessChk.exe
            base = re.sub(r"^[^a-z0-9]+", "", base)   # mangled RLO prefix "â€®" dropped: "cod.3aka3" matches
            if base and base not in text:
                out.append(a.get("executable"))
    return out


def missing_candidates(required, assessed) -> list[str]:
    """Required executables (lower-case paths) that have no assessment; an assessment may name the full path or the file."""
    if not required:
        return []
    names = {str(a.get("executable", "")).lower().strip() for a in assessed}
    bases = {n.split(BS)[-1] for n in names if n}
    return sorted(r for r in required if r not in names and r.split(BS)[-1] not in bases)


def _brief(r: dict) -> dict:
    return {"check_id": r["check_id"], "technique": r["technique"], "dataset": r["dataset"], "tool": r["tool"],
            "args": r["args"], "purpose": r.get("purpose"), "query_id": r["query_id"], "total": r["total"], "result": r["result"]}


def _compact(res: dict) -> dict:
    """Keep tool results small enough for the LLM context."""
    if not isinstance(res, dict):
        return res
    out = dict(res)
    if "hits" in out:
        out["hits"] = out["hits"][:15]
    if "values" in out:
        out["values"] = out["values"][:40]
    if "_ids" in out:
        out.pop("_ids")
    if "buckets" in out:
        out["buckets"] = out["buckets"][:40]
    if "source" in out:
        out["source"] = _clip_doc(out["source"])
    return out


def _clip(v, n=600):
    return v[:n] + "...(truncated)" if isinstance(v, str) and len(v) > n else v


def _clip_doc(d):
    if isinstance(d, dict):
        return {k: _clip_doc(v) for k, v in d.items()}
    if isinstance(d, list):
        return [_clip_doc(x) for x in d[:20]]
    return _clip(d, 1500)


def _field(src: dict, dotted: str):
    if dotted in src:
        return src[dotted]
    cur = src
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _norm(x) -> str:
    return str(x).strip().strip('"').replace("\\\\", "\\").lower()


def _value_matches(claimed, actual) -> bool:
    if claimed is None:
        return False
    c, a = _norm(claimed), (_norm(actual) if not isinstance(actual, list) else " | ".join(_norm(x) for x in actual))
    if c == a:
        return True
    return len(c) >= 6 and c in a        # an exact excerpt of a long value (command line, script block) counts


def _read_jsonl(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_hunt(hypothesis: str, profile: str = "converged", run_name: str | None = None, plan_from: str | None = None) -> str:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = config.RUNS_DIR / "hunts" / f"{stamp}-{profile}{('-' + run_name) if run_name else ''}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return asyncio.run(HuntAgent(hypothesis, profile, run_dir, plan_from=plan_from).run())
