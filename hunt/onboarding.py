"""Onboarding agent: inspect a new log source, select or create a parsing template, validate it, register it.

The LLM decides (tool calling); the code enforces the rules it cannot break:
  * a source can only be registered to a template that passed validation on THIS source's sample
    (simulate pipeline API + output contract, every sampled record must pass);
  * a generated template is installed only after it passed validation, may only use whitelisted
    processors, may not reuse an existing template name or dataset, and is saved to templates/generated/;
  * the loop is bounded (MAX_STEPS tool calls).
Everything the agent saw and did is written to runs/onboarding/<timestamp>-<source_id>/.
"""
import datetime as dt
import json

from . import config, registry, sampling, templates
from .llm import LLM

MAX_STEPS = 14

SYSTEM = """You are the log-onboarding agent of a security operations platform built on Elasticsearch.
A new log source has arrived. Your job: make sure every record of it gets the right parsing template.

Procedure:
1. inspect_sample to see the structure of the records.
2. list_templates: each template comes with its match ratio on this sample.
3. If templates match (ratio 1.0), test the most specific one first (highest specificity = most equals
   constraints). If it passes, register_source with it.
4. If no template matches or none passes, create a new template with create_template, fix it until it passes,
   then register_source with it. Do not create a template when an existing one passes.
5. If the records cannot be parsed reliably, call give_up with the reason.

A template is an Elasticsearch ingest pipeline. Input documents look like
  {"@timestamp": "1970-01-01T00:00:00.000Z", "message": "<raw record>", "event": {"original": "<raw record>"},
   "hunt": {"source_id": "...", "channel": "..."}}
Output contract (checked on every sampled record):
  - @timestamp: the event time parsed from the record itself (replace the 1970 placeholder);
  - host.name (the machine the record is about) or observer.name (the sensor that produced it). Records from a
    network sensor (Zeek, IDS, firewall) describe traffic of other machines: set observer.name to the sensor and
    do NOT put the sensor in host.name;
  - event.module (log family) and event.dataset (exactly the template's dataset);
  - event.original kept; hunt.template set to the template name; no processor failure.
Guidelines for new templates:
  - parse JSON records with {"json": {"field": "message", "target_field": "<namespace>"}} and keep every original
    field under that namespace (for example win for Windows event exports, zeek for Zeek logs);
  - map the obvious ECS fields: host.name, user.name, process.executable, process.command_line, process.pid,
    source.ip, source.port, destination.ip, destination.port, network.transport, dns.question.name, url.original,
    file.path, event.code, event.provider; set message to a human-readable text field if the record has one;
  - use "if" conditions (Painless, null-safe ?. access) for fields that are not in every record, and
    "ignore_missing": true where available; convert ports and pids to long with ignore_failure;
  - allowed processor types: {allowed}. script, pipeline, reroute, enrich and foreach are not allowed;
  - the match rule must select exactly this kind of record and nothing else: when inspect_sample lists
    discriminators (low-cardinality fields such as Channel or @proc), restrict them with "equals" to the values
    seen in the sample, otherwise the template would also claim other sources;
  - name: lowercase letters, digits and dashes; dataset: lowercase dotted words, e.g. windows.powershell, zeek;
  - look at an existing template with get_template and reuse its patterns when the records are similar.
Facts verified on this site's data (use them, do not guess timezones):
{facts}
Reply only with tool calls until you have called register_source or give_up."""

SITE_FACTS = """  - Windows records exported by NXLog (fields EventTime, Hostname, EventID, Channel, SourceName, Message ...):
    EventTime is the collector's local time, UTC-4 (UtcTime - EventTime = 240 min on all 143,883 Sysmon records
    that have both). Use the date processor on EventTime with "timezone": "-04:00" and format "yyyy-MM-dd HH:mm:ss"
    unless the record has a UTC field.
  - Epoch-second timestamps (e.g. 1588205198.89971) are parsed with the date format "UNIX"."""

TOOLS = [
    {"type": "function", "function": {"name": "inspect_sample", "description": "Structure of the sampled raw records: format, key frequencies, discriminator values, time-like fields, one example record.",
                                      "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "list_templates", "description": "Installed parsing templates with their match ratio on this sample (1.0 = every sampled record satisfies the template's match rule).",
                                      "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "get_template", "description": "Full definition (match rule and processors) of an installed template.",
                                      "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}}},
    {"type": "function", "function": {"name": "test_template", "description": "Run an installed template on every sampled record (simulate pipeline API) and check the output contract.",
                                      "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}}},
    {"type": "function", "function": {"name": "create_template",
        "description": "Validate a new template on the sample; if every record passes it is installed and saved for reuse. Returns the validation result either way.",
        "parameters": {"type": "object", "required": ["name", "dataset", "description", "match", "processors"], "properties": {
            "name": {"type": "string"}, "dataset": {"type": "string"}, "description": {"type": "string"},
            "match": {"type": "object", "description": "{\"format\": \"json\", \"required_keys\": [...], \"equals\": {\"field\": [values]}} - must select exactly the records this template parses"},
            "processors": {"type": "array", "items": {"type": "object"}, "description": "Elasticsearch ingest processors"}}}}},
    {"type": "function", "function": {"name": "register_source", "description": "Route this source to a template (only possible after the template passed on this sample).",
                                      "parameters": {"type": "object", "properties": {"template": {"type": "string"}, "reason": {"type": "string"}}, "required": ["template", "reason"]}}},
    {"type": "function", "function": {"name": "give_up", "description": "Stop without registering; the source stays unparsed.",
                                      "parameters": {"type": "object", "properties": {"reason": {"type": "string"}}, "required": ["reason"]}}},
]


class OnboardingAgent:
    def __init__(self, source_id: str, lines: list[str], channel: str = "", llm_model: str | None = None):
        self.source_id = source_id
        self.lines = lines
        self.channel = channel
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        self.run_dir = config.RUNS_DIR / "onboarding" / f"{stamp}-{source_id}"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.llm = LLM(self.run_dir, temperature=0.0, thinking=False, model=llm_model)
        self.passed = {}        # template name -> validation result on this sample
        self.created = []
        self.trace = []
        self.outcome = None

    # ---- tools -------------------------------------------------------------------------------------
    def inspect_sample(self):
        return sampling.fingerprint(self.lines)

    def list_templates(self):
        out = []
        for name, spec in templates.installed().items():
            out.append({"name": name, "dataset": spec["dataset"], "origin": spec.get("origin"),
                        "description": spec.get("description"), "match": spec.get("match"),
                        "specificity": templates.specificity(spec),
                        "match_ratio_on_sample": round(templates.match_ratio(spec, self.lines), 4)})
        return sorted(out, key=lambda t: (-t["match_ratio_on_sample"], -t["specificity"], t["name"]))

    def get_template(self, name):
        spec = templates.installed().get(name)
        return spec if spec else {"error": f"no template named {name}"}

    def test_template(self, name):
        spec = templates.installed().get(name)
        if not spec:
            return {"error": f"no template named {name}"}
        result = templates.validate(spec, self.lines, self.source_id)
        if result["passed"]:
            self.passed[name] = result
        return result

    def create_template(self, name, dataset, description, match, processors):
        existing = templates.installed()
        if name in existing:
            return {"passed": False, "problems": [f"a template named {name} already exists; choose another name"]}
        if any(s["dataset"] == dataset for s in existing.values()):
            return {"passed": False, "problems": [f"dataset {dataset} is already used by another template"]}
        discriminators = sampling.fingerprint(self.lines).get("discriminators", {})
        constrained = set((match or {}).get("equals", {}))
        if discriminators and not constrained & set(discriminators):
            return {"passed": False, "problems": [
                "the match rule is too broad: restrict at least one discriminator with equals, e.g. "
                + json.dumps({k: sorted(v) for k, v in list(discriminators.items())[:2]})]}
        spec = {"name": name, "version": 1, "origin": "generated", "dataset": dataset, "description": description,
                "match": match, "processors": processors}
        result = templates.validate(spec, self.lines, self.source_id)
        if result["passed"] and result["match_ratio"] < 1.0:
            result["passed"] = False
            result["problems"] = [f"match rule selects only {result['match_ratio']:.0%} of the sample; it must select all of it"]
        if result["passed"]:
            spec.update({"created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                         "created_by": f"onboarding agent ({self.llm.model}) for source {self.source_id}",
                         "validation": {"records": result["records"], "records_ok": result["records_ok"],
                                        "source_id": self.source_id}})
            templates.install(spec)
            result["saved_to"] = templates.save_spec(spec)
            self.passed[name] = result
            self.created.append(name)
        return result

    def register_source(self, template, reason):
        if template not in self.passed:
            return {"error": f"template {template} has not passed validation on this sample; call test_template or create_template first"}
        spec = templates.installed()[template]
        v = self.passed[template]
        registry.register(self.source_id, spec, {
            "channel": self.channel, "decision": "created" if template in self.created else "reused",
            "reason": reason, "sample_records": v["records"], "sample_records_ok": v["records_ok"],
            "onboarding_run": str(self.run_dir.relative_to(config.ROOT))})
        self.outcome = {"decision": "created" if template in self.created else "reused", "template": template,
                        "dataset": spec["dataset"], "reason": reason, "validation": {k: v[k] for k in ("records", "records_ok", "match_ratio")}}
        return {"registered": True, **self.outcome}

    def give_up(self, reason):
        self.outcome = {"decision": "gave_up", "reason": reason}
        return self.outcome

    # ---- loop --------------------------------------------------------------------------------------
    def run(self) -> dict:
        system = SYSTEM.replace("{allowed}", ", ".join(sorted(templates.ALLOWED_PROCESSORS))).replace("{facts}", SITE_FACTS)
        messages = [{"role": "system", "content": system},
                    {"role": "user", "content": f"New source '{self.source_id}' (channel: {self.channel or 'unknown'}), "
                                                f"{len(self.lines)} sampled records. Onboard it."}]
        for step in range(1, MAX_STEPS + 1):
            msg = self.llm.chat(messages, tools=TOOLS, purpose=f"onboard {self.source_id} step {step}")
            messages.append(msg.model_dump(exclude_none=True))
            if not msg.tool_calls:
                messages.append({"role": "user", "content": "Use the tools: finish with register_source or give_up."})
                continue
            for tc in msg.tool_calls:
                args = None
                try:
                    args = json.loads(tc.function.arguments or "{}")
                    if tc.function.name not in {t["function"]["name"] for t in TOOLS}:
                        raise ValueError(f"unknown tool {tc.function.name}")
                    result = getattr(self, tc.function.name)(**args)
                except Exception as exc:   # bad arguments or unknown tool: tell the model, keep going
                    result = {"error": f"{type(exc).__name__}: {str(exc)[:300]}"}
                self.trace.append({"step": step, "tool": tc.function.name, "args": args, "result_summary": _summary(result)})
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps(result, ensure_ascii=False, default=str)[:12000]})
            if self.outcome:
                break
        if not self.outcome:
            self.outcome = {"decision": "gave_up", "reason": f"no decision within {MAX_STEPS} steps"}
        report = {"source_id": self.source_id, "channel": self.channel, "sample_records": len(self.lines),
                  "outcome": self.outcome, "created_templates": self.created, "tool_trace": self.trace,
                  "llm_calls": self.llm.calls, "llm_tokens": self.llm.tokens, "model": self.llm.model}
        (self.run_dir / "result.json").write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        return report


def _summary(result):
    if not isinstance(result, dict):
        return f"{type(result).__name__} of {len(result)}" if isinstance(result, list) else str(result)[:200]
    keys = ("passed", "records", "records_ok", "match_ratio", "failure_counts", "problems", "error", "registered", "decision", "template")
    return {k: result[k] for k in keys if k in result}
