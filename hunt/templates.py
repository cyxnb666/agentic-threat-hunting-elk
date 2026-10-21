"""Parsing-template library.

A template is an Elasticsearch ingest pipeline named hunt-tpl-<name> whose _meta describes it:
  {"hunt_template": true, "name", "version", "description", "dataset", "origin": "builtin"|"generated",
   "match": {"format": "json", "required_keys": [...], "equals": {"field": [allowed values]}}}
Elasticsearch is the registry of templates (the agent lists them from there); every template is also kept as a
JSON spec file under templates/builtin or templates/generated so it is versioned in git.

Validation = run the template with the simulate pipeline API on raw sample records, then check an output
contract on every resulting document (see CONTRACT below).
"""
import datetime as dt
import json
import re

from . import config

SENTINEL_TS = "1970-01-01T00:00:00.000Z"   # input @timestamp; a template must replace it with the event time
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")
DATASET_RE = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)*$")

# Processors a *generated* template may use. Excluded on purpose: script (arbitrary code), pipeline/reroute
# (would escape the template), enrich/inference/geoip (external state), foreach (unbounded fan-out).
ALLOWED_PROCESSORS = {
    "json", "date", "set", "rename", "remove", "lowercase", "uppercase", "convert", "grok", "dissect", "kv",
    "csv", "gsub", "split", "trim", "append", "join", "urldecode", "dot_expander", "fail", "drop",
}

CONTRACT = [
    ("@timestamp", "event time parsed from the record (must replace the input sentinel and be plausible)"),
    ("host.name|observer.name", "who produced the record"),
    ("event.module", "log family, e.g. sysmon, zeek"),
    ("event.dataset", "same value as the template's dataset"),
    ("event.original", "the raw record, kept for evidence"),
    ("hunt.template", "name of the template that parsed the record"),
    ("no error.message", "no processor failure"),
]


def pipeline_id(name: str) -> str:
    return config.TEMPLATE_PREFIX + name


def to_pipeline(spec: dict) -> dict:
    meta = {"hunt_template": True, **{k: spec[k] for k in ("name", "version", "description", "dataset", "origin", "match")}}
    for k in ("created_at", "created_by", "validation", "notes"):
        if k in spec:
            meta[k] = spec[k]
    return {"description": spec["description"], "_meta": meta, "processors": spec["processors"],
            "on_failure": [
                {"set": {"field": "error.message", "value": "{{ _ingest.on_failure_message }}"}},
                {"set": {"field": "event.kind", "value": "pipeline_error"}},
            ]}


def install(spec: dict, role: str = "agent") -> None:
    config.es(role).ingest.put_pipeline(id=pipeline_id(spec["name"]), **to_pipeline(spec))


def installed(role: str = "agent") -> dict:
    """name -> spec, read back from Elasticsearch."""
    try:
        resp = config.es(role).ingest.get_pipeline(id=config.TEMPLATE_PREFIX + "*")
    except Exception:   # NotFoundError when none are installed
        return {}
    out = {}
    for pid, body in resp.body.items():
        meta = body.get("_meta") or {}
        if meta.get("hunt_template"):
            out[meta["name"]] = {**meta, "processors": body["processors"], "pipeline_id": pid}
    return out


def match_ratio(spec: dict, lines: list[str]) -> float:
    rule = spec.get("match") or {}
    if rule.get("format") != "json":
        pattern = re.compile(rule.get("regex", r"(?!)"))
        return sum(1 for line in lines if pattern.search(line)) / max(1, len(lines))
    ok = 0
    for line in lines:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        if any(k not in rec for k in rule.get("required_keys", [])):
            continue
        if any(str(rec.get(k)) not in [str(x) for x in allowed] for k, allowed in rule.get("equals", {}).items()):
            continue
        ok += 1
    return ok / max(1, len(lines))


def specificity(spec: dict) -> int:
    """How narrow a match rule is: equals constraints count most, required keys add a little."""
    rule = spec.get("match") or {}
    return 10 * len(rule.get("equals", {})) + len(rule.get("required_keys", []))


def check_processors(processors: list) -> list[str]:
    """Problems with a generated processor list (whitelist + structure)."""
    problems = []
    if not isinstance(processors, list) or not processors:
        return ["processors must be a non-empty list"]
    for i, proc in enumerate(processors):
        if not isinstance(proc, dict) or len(proc) != 1:
            problems.append(f"processor #{i} must be an object with exactly one key")
            continue
        (ptype, body), = proc.items()
        if ptype not in ALLOWED_PROCESSORS:
            problems.append(f"processor #{i} type '{ptype}' is not allowed (allowed: {sorted(ALLOWED_PROCESSORS)})")
        if isinstance(body, dict) and "on_failure" in body:
            problems += [f"processor #{i}: " + p for p in check_processors(body["on_failure"])]
    return problems


def _get(doc: dict, dotted: str):
    cur = doc
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, dict) and dotted in cur:   # flat dotted key
            return cur[dotted]
        else:
            return None
    return cur


def _ts_ok(value) -> bool:
    if not value or value == SENTINEL_TS:
        return False
    try:
        t = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return dt.datetime(1990, 1, 1, tzinfo=dt.timezone.utc) <= t <= dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)


def contract_failures(doc: dict, spec: dict) -> list[str]:
    f = []
    if not _ts_ok(doc.get("@timestamp")):
        f.append(f"@timestamp not parsed from the record (got {doc.get('@timestamp')!r})")
    if not (_get(doc, "host.name") or _get(doc, "observer.name")):
        f.append("host.name/observer.name missing")
    if not _get(doc, "event.module"):
        f.append("event.module missing")
    if _get(doc, "event.dataset") != spec["dataset"]:
        f.append(f"event.dataset is {_get(doc, 'event.dataset')!r}, expected {spec['dataset']!r}")
    if not _get(doc, "event.original"):
        f.append("event.original missing")
    if _get(doc, "hunt.template") != spec["name"]:
        f.append(f"hunt.template is {_get(doc, 'hunt.template')!r}, expected {spec['name']!r}")
    if _get(doc, "error.message"):
        f.append(f"processor failure: {str(_get(doc, 'error.message'))[:200]}")
    return f


def simulate(spec: dict, lines: list[str], source_id: str = "sample", role: str = "agent") -> list[dict]:
    docs = [{"_source": {"@timestamp": SENTINEL_TS, "message": line, "event": {"original": line},
                         "hunt": {"source_id": source_id, "channel": "simulate"}}} for line in lines]
    resp = config.es(role).ingest.simulate(pipeline=to_pipeline(spec), docs=docs)
    out = []
    for d in resp["docs"]:
        if "error" in d:
            out.append({"error": {"message": json.dumps(d["error"])[:300]}})
        else:
            out.append((d.get("doc") or {}).get("_source", {}))
    return out


def validate(spec: dict, lines: list[str], source_id: str = "sample", role: str = "agent") -> dict:
    """Simulate on every sample record and apply the contract. passed == every record satisfies it."""
    problems = []
    if not NAME_RE.match(spec.get("name", "")):
        problems.append("name must match " + NAME_RE.pattern)
    if not DATASET_RE.match(spec.get("dataset", "")) or spec.get("dataset") == "hunt.unparsed":
        problems.append("dataset must match " + DATASET_RE.pattern + " and not be hunt.unparsed")
    if spec.get("origin") == "generated":
        problems += check_processors(spec.get("processors"))
    if problems:
        return {"passed": False, "problems": problems, "records": len(lines)}
    try:
        outputs = simulate(spec, lines, source_id, role)
    except Exception as exc:   # invalid pipeline definition
        return {"passed": False, "problems": [f"simulate rejected the pipeline: {str(exc)[:500]}"], "records": len(lines)}
    failures = {}
    for i, doc in enumerate(outputs):
        fl = contract_failures(doc, spec)
        if fl:
            failures[i] = fl
    counts = {}
    for fl in failures.values():
        for item in fl:
            key = item.split(":")[0].split(" (")[0]
            counts[key] = counts.get(key, 0) + 1
    ok_docs = len(outputs) - len(failures)
    example_ok = next((outputs[i] for i in range(len(outputs)) if i not in failures), None)
    return {
        "passed": len(outputs) > 0 and not failures,
        "records": len(outputs),
        "records_ok": ok_docs,
        "match_ratio": round(match_ratio(spec, lines), 4),
        "failure_counts": counts,
        "first_failures": [{"record": i, "problems": fl, "raw": lines[i][:300]} for i, fl in list(failures.items())[:3]],
        "example_output": _trim(example_ok) if example_ok else None,
    }


def _trim(doc: dict, limit: int = 160) -> dict:
    """Shorten long values so an example document fits in an LLM message."""
    if isinstance(doc, dict):
        return {k: _trim(v, limit) for k, v in doc.items()}
    if isinstance(doc, list):
        return [_trim(v, limit) for v in doc[:5]]
    if isinstance(doc, str) and len(doc) > limit:
        return doc[:limit] + "...(truncated)"
    return doc


def save_spec(spec: dict) -> str:
    folder = config.TEMPLATES_DIR / ("builtin" if spec["origin"] == "builtin" else "generated")
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{spec['name']}.json"
    path.write_text(json.dumps(spec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    return str(path.relative_to(config.ROOT))


def load_specs(folder: str) -> list[dict]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted((config.TEMPLATES_DIR / folder).glob("*.json"))]
