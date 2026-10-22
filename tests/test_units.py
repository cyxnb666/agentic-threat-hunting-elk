"""Unit tests for the deterministic parts (no Elasticsearch, no LLM). Run: .venv\\Scripts\\python -m pytest -q"""
import json

from hunt import evaluate, hunting, report, sampling, templates

SYSMON = json.dumps({"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Hostname": "H.dom",
                     "EventTime": "2020-05-01 22:55:23", "UtcTime": "2020-05-02 02:55:23.551"})
SECURITY = json.dumps({"Channel": "security", "EventID": 4624, "Hostname": "H.dom", "EventTime": "2020-05-01 22:55:23"})
SPEC = json.loads(open("templates/builtin/windows-sysmon.json", encoding="utf-8").read())


def test_match_ratio_respects_equals():
    assert templates.match_ratio(SPEC, [SYSMON, SYSMON]) == 1.0
    assert templates.match_ratio(SPEC, [SYSMON, SECURITY]) == 0.5
    assert templates.match_ratio(SPEC, ["not json"]) == 0.0


def test_specificity_prefers_equals_constraints():
    broad = {"match": {"format": "json", "required_keys": ["a", "b", "c", "d"]}}
    narrow = {"match": {"format": "json", "required_keys": ["a"], "equals": {"Channel": ["x"]}}}
    assert templates.specificity(narrow) > templates.specificity(broad)


def test_processor_whitelist():
    assert templates.check_processors([{"set": {"field": "a", "value": 1}}]) == []
    assert any("not allowed" in p for p in templates.check_processors([{"script": {"source": "ctx.a=1"}}]))
    assert any("not allowed" in p for p in templates.check_processors([{"set": {"field": "a", "value": 1,
                                                                          "on_failure": [{"pipeline": {"name": "x"}}]}}]))
    assert templates.check_processors([]) == ["processors must be a non-empty list"]


def test_contract():
    good = {"@timestamp": "2020-05-02T02:55:23.551Z", "host": {"name": "h"}, "event": {"module": "sysmon",
            "dataset": "windows.sysmon", "original": "{}"}, "hunt": {"template": "windows-sysmon"}}
    assert templates.contract_failures(good, SPEC) == []
    bad = json.loads(json.dumps(good))
    bad["@timestamp"] = templates.SENTINEL_TS
    bad["error"] = {"message": "boom"}
    fails = " ".join(templates.contract_failures(bad, SPEC))
    assert "@timestamp" in fails and "processor failure" in fails


def test_format_detection_and_fingerprint():
    assert sampling.detect_format([SYSMON] * 10) == "json"
    assert sampling.detect_format(["<134>Oct 16 23:59:59 host app: hi"] * 10) == "syslog"
    fp = sampling.fingerprint([SYSMON, SYSMON])
    assert fp["discriminators"]["Channel"] == {"Microsoft-Windows-Sysmon/Operational": 2}
    assert "UtcTime" in fp["time_fields"]


def test_evidence_value_matching():
    assert hunting._value_matches("C:\\Program Files\\x.exe", "c:\\program files\\x.exe")
    assert hunting._value_matches("Get-PrivateKeys", "function Get-PrivateKeys { ... }")
    assert not hunting._value_matches("lsass", "explorer.exe")
    assert not hunting._value_matches("abc", "xxabcxx")          # short excerpts must match exactly
    assert hunting._field({"a": {"b": 1}}, "a.b") == 1 and hunting._field({"a.b": 2}, "a.b") == 2


def test_report_utc_normalisation():
    assert report.utc("2020-05-01T23:04:56.000-04:00") == "2020-05-02 03:04:56.000Z"
    assert report.utc("2020-05-02T03:04:56Z") == "2020-05-02 03:04:56.000Z"


def test_ground_truth_predicates():
    gt = {g["step"]: g["match"] for g in evaluate.GROUND_TRUTH}
    assert gt["6.A"]({"process": {"executable": "C:\\Program Files\\SysinternalsSuite\\accessChk.exe"}})
    assert gt["6.B"]({"powershell": {"script_block_text": "function Get-PrivateKeys {}"}})
    assert gt["6.B"]({"file": {"path": "C:\\Users\\u\\Downloads\\a.pfx"}})
    assert gt["6.C"]({"win": {"TargetImage": "C:\\Windows\\system32\\lsass.exe", "GrantedAccess": "0x1fffff"},
                      "process": {"executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}})
    assert not gt["6.C"]({"win": {"TargetImage": "C:\\Windows\\system32\\lsass.exe", "GrantedAccess": "0x1000"},
                          "process": {"executable": "C:\\Windows\\system32\\svchost.exe"}})


def test_query_operator_normalisation():
    from hunt.mcp_server import normalize_query as n
    assert n("event.code:10 and win.TargetImage:*lsass*") == "event.code:10 AND win.TargetImage:*lsass*"
    assert n("a:1 or (b:2 and not c:3)") == "a:1 OR (b:2 AND NOT c:3)"
    assert n('message:"rock and roll" and x:1') == 'message:"rock and roll" AND x:1'   # quoted text untouched
    assert n("win.ObjectName:*and* AND notes:1") == "win.ObjectName:*and* AND notes:1"  # wildcard term untouched
    assert n("path:C\\Windows\\and.exe") == "path:C\\Windows\\and.exe"


def test_planner_refuses_time_window_reasons_and_marks_gaps():
    agent = hunting.HuntAgent.__new__(hunting.HuntAgent)       # no LLM / MCP needed
    agent.hypothesis, agent.datasets, agent.coverage = "h", ["windows.sysmon", "zeek"], {}
    agent.inventory, agent.fields = {"datasets": [], "non_overlapping_time_windows": []}, {}
    agent.ask_json = lambda system, user, purpose: {"techniques": [
        {"technique": "T1", "checks": [{"dataset": "windows.sysmon", "tool": "search", "args": {"query": "x"}}],
         "not_applicable": [{"dataset": "zeek", "reason": "zeek does not overlap the Windows time window"}]},
        {"technique": "T2", "not_applicable": [{"dataset": "zeek", "reason": "zeek has no process events"}]}]}
    batch = [{"id": t, "name": t, "description": "", "detection_strategies": []} for t in ("T1", "T2")]
    checks = []
    agent._plan_batch({}, batch, None, checks, "test")
    assert len(checks) == 1 and checks[0]["technique"] == "T1"
    assert agent.coverage["T1"]["cells"]["windows.sysmon"] == "check"
    assert agent.coverage["T1"]["cells"]["zeek"].startswith("GAP: n/a refused")
    assert agent.coverage["T2"]["cells"]["zeek"].startswith("n/a:")
    assert agent.coverage["T2"]["cells"]["windows.sysmon"].startswith("GAP: not assessed")


def test_json_answer_must_contain_an_object():
    import pytest
    assert hunting._json_from('```json\n{"a": 1}\n```') == {"a": 1}
    with pytest.raises(ValueError):
        hunting._json_from("   ")          # exp-A1: blank answer must be retried, not read as an empty plan


def test_pivot_candidates_are_deterministic_and_complete():
    seeds = [{"field": "process.executable", "host": "scranton", "query_id": "q1", "buckets": [
        {"value": r"C:\Program Files\SysinternalsSuite\accessChk.exe", "count": 1,
         "process.parent.executable": {r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe": 1}},
        {"value": r"C:\Windows\System32\svchost.exe", "count": 3, "process.parent.executable": {r"C:\Windows\System32\services.exe": 3}},
        {"value": r"C:\Windows\System32\whoami.exe", "count": 1, "process.parent.executable": {r"C:\Windows\System32\cmd.exe": 1}}]}]
    c = hunting.pivot_candidates(seeds)
    assert [x["executable"].split("\\")[-1] for x in c] == ["accessChk.exe", "whoami.exe"]   # svchost: normal parent, Windows dir
    req = {x["executable"].lower() for x in c}
    assert hunting.missing_candidates(req, [{"executable": "accessChk.exe"}]) == [r"c:\windows\system32\whoami.exe"]
    assert hunting.missing_candidates(req, [{"executable": "accesschk.exe"}, {"executable": "whoami.exe"}]) == []


def test_tool_args():
    assert hunting._tool_args('{"findings": []}') == {"findings": []}
    assert hunting._tool_args("") == {} and hunting._tool_args(None) == {}
    assert hunting._tool_args('{"findings": [{"title": "cut') is None      # demo2 pivot step 13
    assert hunting._tool_args("[1, 2]") is None


def _fake_llm(tmp_path, finish):
    """LLM whose API client answers at once with a long message and the given finish_reason (no network)."""
    import threading
    from types import SimpleNamespace as NS
    from hunt.llm import LLM
    llm = LLM.__new__(LLM)
    llm.model, llm.temperature, llm.thinking, llm.max_retries = "m", 0.0, False, 1
    llm.log_path, llm.calls, llm.tokens, llm._lock = tmp_path / "llm_calls.jsonl", 0, {"prompt": 0, "completion": 0}, threading.Lock()

    class Msg:
        content = "x" * 50000

        def model_dump(self, exclude_none=True):
            return {"role": "assistant", "content": self.content}

    def create(**kwargs):
        usage = NS(prompt_tokens=10, completion_tokens=2, model_dump=lambda: {"prompt_tokens": 10, "completion_tokens": 2})
        return NS(model="m", choices=[NS(message=Msg(), finish_reason=finish)], usage=usage)
    llm.client = NS(chat=NS(completions=NS(create=create)))
    return llm


def test_llm_call_returns_its_own_finish_reason_and_parallel_calls_log_whole_records(tmp_path):
    # until 2026-10-22 the hunt read finish_reason from the last line of llm_calls.jsonl, which belongs to another
    # call once triage families run in parallel
    import concurrent.futures
    llm = _fake_llm(tmp_path, "length")
    msg, finish = llm.chat_with_finish([{"role": "user", "content": "hi"}], purpose="p")
    assert finish == "length" and llm.chat([{"role": "user", "content": "hi"}]).content == "x" * 50000
    with concurrent.futures.ThreadPoolExecutor(16) as pool:
        list(pool.map(lambda n: llm.chat_with_finish([{"role": "user", "content": str(n)}], purpose=f"p{n}"), range(40)))
    recs = [json.loads(line) for line in llm.log_path.read_text(encoding="utf-8").splitlines()]
    assert len(recs) == 42 == llm.calls and llm.tokens == {"prompt": 420, "completion": 84}
    assert {r["finish_reason"] for r in recs} == {"length"}


def test_audit_records_stay_whole_when_tools_run_in_parallel(tmp_path, monkeypatch):
    import concurrent.futures
    from hunt import mcp_server
    monkeypatch.setenv("HUNT_AUDIT_FILE", str(tmp_path / "mcp_audit.jsonl"))
    hits = {"total": 1, "hits": [{"_id": "x" * 20, "v": "y" * 20000}]}
    with concurrent.futures.ThreadPoolExecutor(16) as pool:
        list(pool.map(lambda n: mcp_server._audited("search", {"n": n}, {}, lambda: hits), range(64)))
    recs = [json.loads(line) for line in (tmp_path / "mcp_audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert sorted(r["args"]["n"] for r in recs) == list(range(64))


def test_read_jsonl_skips_only_an_unfinished_last_line(tmp_path):
    import pytest
    p = tmp_path / "a.jsonl"
    p.write_text('{"a": 1}\n{"a": 2}\n{"a": 3, "b": "unfini', encoding="utf-8")
    assert hunting._read_jsonl(p) == [{"a": 1}, {"a": 2}]          # another loop's record still being written
    p.write_text('{"a": 1}\n{"a": \n{"a": 3}\n', encoding="utf-8")
    with pytest.raises(ValueError):
        hunting._read_jsonl(p)                                      # a broken record in the middle is an error


def _plan_agent():
    agent = hunting.HuntAgent.__new__(hunting.HuntAgent)
    agent.hypothesis, agent.datasets, agent.coverage = "h", ["windows.sysmon"], {}
    agent.inventory, agent.fields = {"datasets": [], "non_overlapping_time_windows": []}, {}
    return agent


def test_plan_batches_are_asked_together_and_applied_in_batch_order():
    import threading
    import time
    agent, running, peak, lock = _plan_agent(), [0], [0], threading.Lock()

    def ask_json(system, user, purpose):
        n = int(purpose.split()[-1])
        with lock:
            running[0] += 1
            peak[0] = max(peak[0], running[0])
        time.sleep(0.05 * (6 - n))                                  # later batches answer first
        with lock:
            running[0] -= 1
        return {"techniques": [{"technique": f"T{n}", "checks": [{"dataset": "windows.sysmon", "tool": "count", "args": {"query": "x"}}]}]}
    agent.ask_json = ask_json
    batches = [([{"id": f"T{n}", "name": "", "description": "", "detection_strategies": []}], None, f"plan batch {n}")
               for n in range(1, 6)]
    checks = []
    agent._plan_batches({}, batches, checks)
    assert peak[0] == 5                                             # all five were waiting at the same time
    assert [c["technique"] for c in checks] == ["T1", "T2", "T3", "T4", "T5"]
    assert list(agent.coverage) == ["T1", "T2", "T3", "T4", "T5"]
    sequential = _plan_agent()
    sequential.ask_json = lambda system, user, purpose: ask_json(system, user, purpose)
    seq_checks = []
    for batch, only, purpose in batches:
        sequential._plan_batch({}, batch, only, seq_checks, purpose)
    assert seq_checks == checks and sequential.coverage == agent.coverage


def test_triage_families_run_together_and_merge_in_family_order():
    import asyncio
    agent = hunting.HuntAgent.__new__(hunting.HuntAgent)
    agent.state, agent.context, agent.technique_status, agent.corrections = {}, [], {}, []
    agent.scope_techniques = {"T1003": "a", "T1003.001": "b", "T1110": "c", "T1555": "d"}
    agent.inventory, agent.fields, agent.hypothesis = {"datasets": [], "non_overlapping_time_windows": []}, {}, "h"
    running, peak = [0], [0]

    async def loop(tools, system, user, steps, phase, verify_on_submit, allowed=None, required=None):
        fam = phase.split()[1]
        running[0] += 1
        peak[0] = max(peak[0], running[0])
        agent.technique_status.setdefault(max(allowed), {"status": "not_observed", "reason": "set inside the loop"})
        await asyncio.sleep({"T1003": 0.15, "T1555": 0.01}[fam])     # T1555 finishes first
        running[0] -= 1
        agent.context.append({"phase": phase, "title": fam})
        return [{"technique": min(allowed), "title": fam}], {min(allowed): {"status": "malicious", "reason": fam}}
    agent._loop = loop
    r = {"dataset": "d", "tool": "count", "args": {}, "query_id": "q", "result": {}}
    results = [{**r, "technique": "T1003.001", "total": 3, "check_id": "C1"}, {**r, "technique": "T1555", "total": 1, "check_id": "C2"},
               {**r, "technique": "T1110", "total": 0, "check_id": "C3"}]
    fs = asyncio.run(agent.triage(None, results))
    assert peak[0] == 2 and [f["title"] for f in fs] == ["T1003", "T1555"]
    assert [c["title"] for c in agent.context] == ["T1003", "T1555"]
    assert list(agent.technique_status) == ["T1003", "T1003.001", "T1110", "T1555"]
    assert agent.technique_status["T1003"]["status"] == "malicious"
    assert agent.technique_status["T1003.001"]["reason"] == "set inside the loop"
    assert agent.technique_status["T1110"] == {"status": "not_observed", "reason": "1 planned checks, all with zero hits"}


def test_verified_part_keeps_only_verified_evidence():
    ok, bad = {"id": "a"}, {"id": "b"}
    fs = [{"title": "x", "evidence": [ok, bad]}, {"title": "y", "evidence": [bad]}]
    checked = [{"verification": [{"ok": True}, {"ok": False}]}, {"verification": [{"ok": False}]}]
    assert hunting._verified_part(fs, checked) == [{"title": "x", "evidence": [ok]}]
    assert fs[0]["evidence"] == [ok, bad]                                 # input not changed


EV_OK = {"index": "i", "id": "good", "field": "process.executable", "value": "C:\\x\\accessChk.exe", "query_id": "q1"}
EV_BAD = {**EV_OK, "id": "bad"}
SUB1 = {"findings": [{"technique": "T1555", "title": "accessChk password collector", "assessment": "malicious",
                      "confidence": "high", "summary": "s", "evidence": [EV_OK, EV_BAD]},
                     {"technique": "T1003", "title": "only a failed item", "assessment": "suspicious", "confidence": "low",
                      "summary": "s", "evidence": [EV_BAD]}],
        "candidate_assessments": [{"executable": "accessChk.exe", "assessment": "malicious", "reason": "r"}],
        "technique_status": [{"technique": "T1555", "status": "malicious", "reason": "r"}]}


def _loop_agent(replies):
    """HuntAgent with a scripted LLM (list of (tool calls, finish_reason); the last one repeats) and a stub verify
    that rejects evidence id 'bad'. Returns the agent and the list of message histories the LLM received."""
    from types import SimpleNamespace as NS
    agent = hunting.HuntAgent.__new__(hunting.HuntAgent)
    agent.state, agent.context, agent.technique_status, agent.corrections = {}, [], {}, []
    agent.pivot_candidates = {"candidates": [], "assessments": []}
    seen, verified = [], []

    class Msg:
        def __init__(self, calls):
            self.tool_calls = [NS(id=f"c{n}", function=NS(name=name, arguments=a)) for n, (name, a) in enumerate(calls)]

        def model_dump(self, exclude_none=True):
            return {"role": "assistant", "tool_calls": [{"id": t.id, "type": "function", "function": {
                "name": t.function.name, "arguments": t.function.arguments}} for t in self.tool_calls]}

    async def chat(messages, tools, purpose):
        seen.append(json.loads(json.dumps(messages)))
        calls, finish = replies.pop(0) if len(replies) > 1 else replies[0]
        return Msg(calls), finish

    async def verify(tools, findings, phase=""):
        verified.append(phase)
        for f in findings:
            f["verification"] = [{**e, "ok": e["id"] != "bad", "problems": [] if e["id"] != "bad" else ["cited query did not return this event"]}
                                 for e in f["evidence"]]
        return findings
    agent._chat, agent.verify = chat, verify
    return agent, seen, verified


def _submit(obj, cut=0):
    text = json.dumps(obj)
    return [("submit_findings", text[:-cut] if cut else text)]


def test_cut_off_resubmission_is_refused_then_shorter_one_accepted():
    import asyncio
    short = {"findings": [{**SUB1["findings"][0], "evidence": [EV_OK]}], "candidate_assessments": SUB1["candidate_assessments"],
             "technique_status": SUB1["technique_status"]}
    agent, seen, verified = _loop_agent([(_submit(SUB1), "tool_calls"), (_submit(SUB1, cut=40), "length"),
                                         (_submit(short), "tool_calls")])
    fs, st = asyncio.run(agent._loop(None, "sys", "user", 12, "pivot", True, allowed={"T1555", "T1003"},
                                     required={"c:\\x\\accesschk.exe"}))
    assert fs == short["findings"] and st == {"T1555": {"status": "malicious", "reason": "r"}}
    assert verified == ["pivot verify"]                                   # only the first valid submission is verified here
    cut_turn, cut_reply = seen[2][-2], seen[2][-1]
    assert cut_turn["tool_calls"][0]["function"]["arguments"] == "{}"     # broken JSON is not sent back to the API
    assert json.loads(cut_reply["content"])["accepted"] is False and "cut off" in cut_reply["content"]
    assert agent.state["cut_off_submissions"][0]["finish_reason"] == "length"
    assert "submission_fallbacks" not in agent.state


def test_no_valid_resubmission_falls_back_to_verified_part_of_first():
    import asyncio
    agent, seen, verified = _loop_agent([(_submit(SUB1), "tool_calls"), (_submit(SUB1, cut=40), "length")])
    fs, st = asyncio.run(agent._loop(None, "sys", "user", 12, "pivot", True, allowed={"T1555", "T1003"},
                                     required={"c:\\x\\accesschk.exe"}))
    assert [f["title"] for f in fs] == ["accessChk password collector"] and fs[0]["evidence"] == [EV_OK]
    assert st == {"T1555": {"status": "malicious", "reason": "r"}}
    assert agent.pivot_candidates["assessments"] == SUB1["candidate_assessments"]   # not wiped by the cut-off calls
    assert len(seen) == 1 + hunting.FIX_STEPS + 1 + 2                    # stays within the existing budget
    assert agent.state["submission_fallbacks"][0]["findings"] == 1


def test_triage_loop_refuses_complete_json_with_length_and_verifies_next():
    import asyncio
    clean = {"findings": [{**SUB1["findings"][0], "evidence": [EV_OK]}], "technique_status": SUB1["technique_status"]}
    agent, seen, verified = _loop_agent([(_submit(clean), "length"), (_submit(clean), "tool_calls")])
    fs, st = asyncio.run(agent._loop(None, "sys", "user", 8, "triage T1555", True, allowed={"T1555"}))
    assert fs == clean["findings"] and verified == ["triage T1555 verify"]   # first counted submission is verified
    assert agent.state["cut_off_submissions"][0]["valid_json"] is True
    assert seen[1][-2]["tool_calls"][0]["function"]["arguments"] == json.dumps(clean)   # valid JSON kept as sent


def test_suspicious_candidates_need_a_finding():
    a = [{"executable": "C:" + hunting.BS + "x" + hunting.BS + "accessChk.exe", "assessment": "suspicious"}]
    assert hunting.unsupported_candidates(a, [{"title": "other activity"}]) == [a[0]["executable"]]
    assert hunting.unsupported_candidates(a, [{"title": "accesschk wrote passwordsDB"}]) == []
    assert hunting.unsupported_candidates([{**a[0], "assessment": "benign"}], []) == []


def test_scope_and_activity_words_follow_the_framed_tactics():
    old = ("credential access", "lateral movement, execution, collection, exfiltration")
    assert hunting._scope_words(["credential-access"]) == old and hunting._activity_words(["credential-access"]) == "credential theft"
    assert hunting._scope_words([]) == old and hunting._activity_words([]) == "credential theft"   # no framing: old wording
    assert hunting._scope_words(["lateral-movement"]) == ("lateral movement", "credential access, execution, collection, exfiltration")
    assert hunting._activity_words(["lateral-movement"]) == "lateral movement activity"
    assert hunting._scope_words(["credential-access", "lateral-movement"]) == ("credential access or lateral movement",
                                                                                "execution, collection, exfiltration")


def test_consolidate_prompt_names_the_hypothesis_tactic():
    # run 20261020-195130 (lateral movement): T1021.002/T1021.006 were labelled out-of-scope because the prompt said
    # "if the action is not credential access (e.g. lateral movement, ..."
    prompts = []
    agent = hunting.HuntAgent.__new__(hunting.HuntAgent)
    agent.hypothesis, agent.scope_techniques, agent.save = "H", {"T1021.002": "SMB"}, lambda *a: None
    agent.ask_json = lambda system, user, purpose: prompts.append(user) or {"incidents": []}
    f = {"finding_id": "F01", "verified": True, "assessment": "malicious", "technique": "T1021.002", "confidence": "high",
         "verification": [{"ok": True, "id": "x", "actual": "v"}]}
    for agent.tactics in (["credential-access"], ["lateral-movement"]):
        agent.consolidate([f])
    assert "if the action is not credential access (e.g. lateral movement, execution, collection, exfiltration), set" in prompts[0]
    assert "if the action is not lateral movement (e.g. credential access, execution, collection, exfiltration), set" in prompts[1]


EV_K = {**EV_OK, "id": "k", "field": "powershell.script_block.text", "value": "Get-Keystrokes"}
CAND = {"executable": "C:\\x\\accessChk.exe", "assessment": "suspicious", "reason": "r"}
KEYLOG = {"technique": "T1056.001", "title": "keylogger", "assessment": "malicious", "confidence": "high", "summary": "s",
          "evidence": [EV_K]}
NO_ACCESSCHK = {"findings": [KEYLOG], "candidate_assessments": [CAND],
                "technique_status": [{"technique": "T1056.001", "status": "malicious", "reason": "r"}]}
WITH_ACCESSCHK = {**NO_ACCESSCHK, "findings": [KEYLOG, {**KEYLOG, "technique": "T1555", "title": "accessChk wrote passwordsDB",
                                                        "evidence": [EV_OK]}]}


def test_pivot_second_submission_without_candidate_finding_is_returned_once_more():
    # run 20261020-195702: step 14 still had no finding for the suspicious candidate accessChk.exe and was accepted
    import asyncio
    agent, seen, verified = _loop_agent([(_submit(NO_ACCESSCHK), "tool_calls"), (_submit(NO_ACCESSCHK), "tool_calls"),
                                         (_submit(WITH_ACCESSCHK), "tool_calls")])
    fs, st = asyncio.run(agent._loop(None, "sys", "user", 12, "pivot", True, allowed={"T1056.001", "T1555"},
                                     required={"c:\\x\\accesschk.exe"}))
    assert fs == WITH_ACCESSCHK["findings"] and len(seen) == 3
    assert verified == ["pivot verify"]                                   # evidence is still verified on the first only
    second = json.loads(seen[2][-1]["content"])
    assert second["accepted"] is False and second["candidates_without_finding"] == ["C:\\x\\accessChk.exe"]
    assert "last return" in second["instruction"] and "verification_failures" not in second


def test_pivot_third_submission_is_accepted_as_it_is():
    import asyncio
    agent, seen, _ = _loop_agent([(_submit(NO_ACCESSCHK), "tool_calls")])
    fs, _ = asyncio.run(agent._loop(None, "sys", "user", 12, "pivot", True, allowed={"T1056.001", "T1555"},
                                    required={"c:\\x\\accesschk.exe"}))
    assert fs == NO_ACCESSCHK["findings"] and len(seen) == 3


def test_pivot_falls_back_to_second_submission_if_no_third_arrives():
    import asyncio
    agent, seen, _ = _loop_agent([(_submit(NO_ACCESSCHK), "tool_calls"), (_submit(NO_ACCESSCHK), "tool_calls"),
                                  (_submit(WITH_ACCESSCHK, cut=40), "length")])
    fs, st = asyncio.run(agent._loop(None, "sys", "user", 12, "pivot", True, allowed={"T1056.001", "T1555"},
                                     required={"c:\\x\\accesschk.exe"}))
    assert fs == NO_ACCESSCHK["findings"] and st == {"T1056.001": {"status": "malicious", "reason": "r"}}
    assert agent.state["submission_fallbacks"][0]["kept"].startswith("second submission")   # what the old code accepted
    assert len(seen) == 2 + hunting.FIX_STEPS + 1 + 2                    # one more FIX_STEPS budget, then stop


def test_triage_second_submission_is_still_accepted_as_it_is():
    import asyncio
    agent, seen, verified = _loop_agent([(_submit(SUB1), "tool_calls"), (_submit(SUB1), "tool_calls")])
    fs, _ = asyncio.run(agent._loop(None, "sys", "user", 8, "triage T1555", True, allowed={"T1555", "T1003"}))
    assert fs == SUB1["findings"] and len(seen) == 2 and verified == ["triage T1555 verify"]


def test_candidate_name_match_ignores_a_mangled_prefix():
    scr = "C:" + hunting.BS + "victim" + hunting.BS + "\u00e2\u20ac\u00aecod.3aka3.scr"
    a = [{"executable": scr, "assessment": "malicious"}]
    assert hunting.unsupported_candidates(a, [{"title": "screensaver payload cod.3aka3.scr wrote monkey.png"}]) == []
    assert hunting.unsupported_candidates(a, [{"title": "other activity"}]) == [scr]
