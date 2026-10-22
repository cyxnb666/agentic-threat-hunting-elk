"""MCP server exposing the hunt capabilities of the Elastic stack (read-only) to AI agents.

Built on the official Model Context Protocol Python SDK (package `mcp` 2.3.0, `mcp.server.MCPServer`,
stdio transport). It connects to Elasticsearch as hunt_mcp (role hunt_reader: read + view_index_metadata on
logs-*, monitor, read_pipeline), so no tool can change data.

Every tool call is appended to an audit log (env HUNT_AUDIT_FILE, default runs/mcp_audit/<date>.jsonl) with a
query_id, the exact Elasticsearch request, the hit count, the returned document ids and a SHA-256 of the
result. Reports cite query_ids, so every claim can be traced to the query that produced it.

Run: python -m hunt mcp      (an MCP client starts this as a subprocess and talks JSON-RPC over stdio)
"""
import datetime as dt
import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid

from mcp.server import MCPServer

from . import config, registry, templates

logging.getLogger("elastic_transport").setLevel(logging.WARNING)   # stdout is the MCP channel; keep stderr quiet

MAX_SIZE = 100
TRUNCATE = 400
_AUDIT_LOCK = threading.Lock()
DEFAULT_FIELDS = ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",
                  "process.executable", "process.command_line", "source.ip", "destination.ip", "message"]

mcp = MCPServer(
    "elk-threat-hunting",
    instructions=(
        "Read-only access to security logs in Elasticsearch. Start with list_data_sources (datasets, time "
        "windows, hosts, event codes), then get_fields for field names. Query with search/count/aggregate/"
        "timeline (Lucene query_string syntax) or esql (ES|QL). Every result carries a query_id; cite it. "
        "Fetch the full original record of any hit with get_event(index, id) before relying on it."),
)


def _audit_path():
    p = os.environ.get("HUNT_AUDIT_FILE") or str(config.RUNS_DIR / "mcp_audit" / f"{dt.date.today():%Y%m%d}.jsonl")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    return p


def _audited(tool: str, args: dict, request: dict, run):
    qid = "q-" + uuid.uuid4().hex[:10]
    t0 = time.time()
    try:
        result = run()
        error = None
    except Exception as exc:   # surface ES errors (bad query syntax, unknown field) to the agent
        info = getattr(exc, "info", None) or getattr(exc, "body", None)
        reason = json.dumps(info)[:800] if info else str(exc)[:800]
        result, error = {"error": f"{type(exc).__name__}: {reason}"}, reason
    result = {"query_id": qid, **result}
    blob = json.dumps(result, sort_keys=True, default=str)
    record = json.dumps({
        "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"), "query_id": qid,
        "tool": tool, "args": args, "request": request, "error": error,
        "hits_total": result.get("total"),
        "returned_ids": [h.get("_id") for h in result.get("hits", [])] + list(result.get("_ids", [])),
        "rows": len(result.get("values", [])) if "values" in result else None,
        "result_sha256": hashlib.sha256(blob.encode()).hexdigest(), "duration_ms": int((time.time() - t0) * 1000),
    }, default=str) + "\n"
    with _AUDIT_LOCK:      # sync tools run in worker threads; parallel hunt loops call them at the same time
        with open(_audit_path(), "a", encoding="utf-8") as f:
            f.write(record)
    return result


def _index(dataset: str) -> str:
    """'windows.sysmon' -> logs-windows.sysmon-default; '*' -> every parsed data stream."""
    if dataset in ("*", "all", ""):
        return "logs-*,-logs-hunt.unparsed-*"
    if dataset.startswith("logs-") or dataset.startswith(".ds-"):
        return dataset
    return f"logs-{dataset}-default"


_BOOL = re.compile(r'(?<![\w:*.\\-])(and|or|not)(?![\w:*.\\-])', re.IGNORECASE)


def normalize_query(query: str) -> str:
    """Lucene only treats upper-case AND/OR/NOT as operators; a lower-case 'and' silently becomes a search term
    and the query returns nothing (measured: 0 vs 326 hits). Upper-case stand-alone and/or/not outside quotes."""
    parts = re.split(r'("(?:[^"\\]|\\.)*")', query or "*")
    return "".join(p if p.startswith('"') else _BOOL.sub(lambda m: m.group(1).upper(), p) for p in parts)


def _filter(query: str, time_from: str | None, time_to: str | None) -> dict:
    must = [{"query_string": {"query": normalize_query(query), "default_operator": "AND", "analyze_wildcard": True}}]
    if time_from or time_to:
        rng = {}
        if time_from:
            rng["gte"] = time_from
        if time_to:
            rng["lte"] = time_to
        must.append({"range": {"@timestamp": rng}})
    return {"bool": {"filter": must}}


def _short(v):
    if isinstance(v, str) and len(v) > TRUNCATE:
        return v[:TRUNCATE] + f"...(+{len(v) - TRUNCATE} chars; use get_event)"
    return v


def _pick(src: dict, fields: list[str]) -> dict:
    out = {}
    for f in fields:
        cur = src
        for part in f.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        if cur is not None:
            out[f] = _short(cur)
    return out


@mcp.tool()
def list_data_sources() -> dict:
    """Inventory of the parsed log data: one entry per dataset with document count, first/last event time,
    hosts, observers, top event codes, the sources feeding it and their parsing template. Also reports which
    datasets' time windows do not overlap (events from non-overlapping windows cannot be correlated by time)."""
    def run():
        es = config.es("reader")
        meta = registry.meta()
        out = []
        for ds in sorted(d["name"] for d in es.indices.get_data_stream(name="logs-*")["data_streams"]):
            if ds.startswith("logs-hunt."):
                continue
            r = es.search(index=ds, size=0, track_total_hits=True, aggs={
                "tmin": {"min": {"field": "@timestamp"}}, "tmax": {"max": {"field": "@timestamp"}},
                "hosts": {"terms": {"field": "host.name", "size": 20}},
                "observers": {"terms": {"field": "observer.name", "size": 10}},
                "codes": {"terms": {"field": "event.code", "size": 40}},
                "actions": {"terms": {"field": "event.action", "size": 30}},
                "sources": {"terms": {"field": "hunt.source_id", "size": 20}}})
            a = r["aggregations"]
            sources = [b["key"] for b in a["sources"]["buckets"]]
            out.append({
                "dataset": ds.removeprefix("logs-").removesuffix("-default"), "data_stream": ds,
                "documents": r["hits"]["total"]["value"],
                "first_event": a["tmin"].get("value_as_string"), "last_event": a["tmax"].get("value_as_string"),
                "hosts": {b["key"]: b["doc_count"] for b in a["hosts"]["buckets"]},
                "observers": {b["key"]: b["doc_count"] for b in a["observers"]["buckets"]},
                "top_event_codes": {str(b["key"]): b["doc_count"] for b in a["codes"]["buckets"]},
                "top_event_actions": {str(b["key"]): b["doc_count"] for b in a["actions"]["buckets"]},
                "sources": {s: {k: meta.get(s, {}).get(k) for k in ("template", "channel", "decision")} for s in sources},
            })
        gaps = []
        for i, x in enumerate(out):
            for y in out[i + 1:]:
                if x["first_event"] and y["first_event"] and (x["last_event"] < y["first_event"] or y["last_event"] < x["first_event"]):
                    gaps.append(f"{x['dataset']} [{x['first_event']} .. {x['last_event']}] and {y['dataset']} "
                                f"[{y['first_event']} .. {y['last_event']}] do not overlap")
        return {"datasets": out, "non_overlapping_time_windows": gaps}
    return _audited("list_data_sources", {}, {"api": "data_streams + per-stream aggregations"}, run)


@mcp.tool()
def get_fields(dataset: str, prefix: str = "") -> dict:
    """Field names and types of a dataset (e.g. 'windows.sysmon', 'zeek', '*'), optionally only those starting
    with prefix (e.g. 'process.' or 'win.'). Use this before writing queries."""
    def run():
        caps = config.es("reader").field_caps(index=_index(dataset), fields=f"{prefix}*" if prefix else "*")["fields"]
        fields = []
        for name, types in sorted(caps.items()):
            if name.startswith("_"):
                continue
            t, info = next(iter(types.items()))
            if t == "object":
                continue
            fields.append({"field": name, "type": t, "aggregatable": info.get("aggregatable")})
        return {"dataset": dataset, "count": len(fields), "fields": fields[:400],
                "note": "keyword/wildcard fields: exact and wildcard matching; *.text sub-fields: full-text"}
    return _audited("get_fields", {"dataset": dataset, "prefix": prefix}, {"api": "field_caps", "index": _index(dataset)}, run)


@mcp.tool()
def search(dataset: str, query: str = "*", time_from: str | None = None, time_to: str | None = None,
           fields: list[str] | None = None, size: int = 20, sort: str = "asc") -> dict:
    """Find events. query uses Lucene query_string syntax, e.g.
    'event.code:10 AND win.TargetImage:*lsass.exe'. Operators AND/OR/NOT must be upper case (lower-case ones are
    upper-cased for you). Keyword values are CASE-SENSITIVE (*lsass* does not match LSASS); for case-insensitive
    matching use esql with TO_LOWER(field) LIKE "*lsass*". Values with spaces or backslashes must be quoted or escaped. time_from/time_to are ISO timestamps (inclusive). Returns the exact total and up to `size`
    (max 100) hits with _index and _id (cite them; fetch full records with get_event). sort: asc|desc by time."""
    size = max(1, min(int(size), MAX_SIZE))
    fields = fields or DEFAULT_FIELDS
    body = {"query": _filter(query, time_from, time_to), "size": size, "track_total_hits": True,
            "sort": [{"@timestamp": "desc" if sort == "desc" else "asc"}]}

    def run():
        r = config.es("reader").search(index=_index(dataset), **body)
        hits = [{"_index": h["_index"], "_id": h["_id"], **_pick(h["_source"], fields)} for h in r["hits"]["hits"]]
        out = {"total": r["hits"]["total"]["value"], "returned": len(hits), "hits": hits}
        if normalize_query(query) != query:
            out["query_used"] = normalize_query(query)
        return out
    return _audited("search", {"dataset": dataset, "query": query, "time_from": time_from, "time_to": time_to,
                               "fields": fields, "size": size, "sort": sort}, {"index": _index(dataset), "body": body}, run)


@mcp.tool()
def count(dataset: str, query: str = "*", time_from: str | None = None, time_to: str | None = None) -> dict:
    """Exact number of events matching a Lucene query_string query in a dataset and optional time range."""
    q = _filter(query, time_from, time_to)

    def run():
        return {"total": config.es("reader").count(index=_index(dataset), query=q)["count"]}
    return _audited("count", {"dataset": dataset, "query": query, "time_from": time_from, "time_to": time_to},
                    {"index": _index(dataset), "query": q}, run)


@mcp.tool()
def aggregate(dataset: str, field: str, query: str = "*", time_from: str | None = None, time_to: str | None = None,
              size: int = 20, sub_field: str | None = None) -> dict:
    """Top values of a field (terms aggregation) among events matching query, with counts; optionally broken
    down by sub_field. Use for stacking/frequency analysis (rare values are often interesting)."""
    size = max(1, min(int(size), 200))
    agg = {"top": {"terms": {"field": field, "size": size}}}
    if sub_field:
        agg["top"]["aggs"] = {"sub": {"terms": {"field": sub_field, "size": 10}}}
    q = _filter(query, time_from, time_to)

    def run():
        r = config.es("reader").search(index=_index(dataset), query=q, size=0, aggs=agg, track_total_hits=True)
        buckets = []
        for b in r["aggregations"]["top"]["buckets"]:
            item = {"value": b["key"], "count": b["doc_count"]}
            if sub_field:
                item[sub_field] = {s["key"]: s["doc_count"] for s in b["sub"]["buckets"]}
            buckets.append(item)
        return {"total": r["hits"]["total"]["value"], "field": field, "buckets": buckets,
                "other_count": r["aggregations"]["top"]["sum_other_doc_count"]}
    return _audited("aggregate", {"dataset": dataset, "field": field, "query": query, "time_from": time_from,
                                  "time_to": time_to, "size": size, "sub_field": sub_field},
                    {"index": _index(dataset), "query": q, "aggs": agg}, run)


@mcp.tool()
def timeline(dataset: str, query: str = "*", interval: str = "1m", time_from: str | None = None,
             time_to: str | None = None) -> dict:
    """Event counts over time (date histogram, fixed interval such as 30s, 1m, 5m) for events matching query."""
    q = _filter(query, time_from, time_to)
    agg = {"t": {"date_histogram": {"field": "@timestamp", "fixed_interval": interval, "min_doc_count": 1}}}

    def run():
        r = config.es("reader").search(index=_index(dataset), query=q, size=0, aggs=agg, track_total_hits=True)
        return {"total": r["hits"]["total"]["value"],
                "buckets": [{"time": b["key_as_string"], "count": b["doc_count"]} for b in r["aggregations"]["t"]["buckets"]]}
    return _audited("timeline", {"dataset": dataset, "query": query, "interval": interval, "time_from": time_from,
                                 "time_to": time_to}, {"index": _index(dataset), "query": q, "aggs": agg}, run)


@mcp.tool()
def esql(query: str) -> dict:
    """Run an ES|QL query (read-only language), e.g.
    'FROM logs-windows.sysmon-default | WHERE event.code == "10" | STATS n = COUNT(*) BY process.executable | SORT n DESC | LIMIT 20'.
    At most 500 rows are returned. Include _id via 'FROM ... METADATA _id, _index' to cite events.
    Case-insensitive match: WHERE TO_LOWER(process.executable) LIKE "*accesschk*". Strings use double quotes."""
    def run():
        r = config.es("reader").esql.query(query=query, format="json")
        cols = [c["name"] for c in r["columns"]]
        values = [[_short(v) for v in row] for row in r["values"][:500]]
        out = {"columns": cols, "values": values, "rows": len(r["values"]), "truncated": len(r["values"]) > 500}
        if "_id" in cols:
            out["_ids"] = [row[cols.index("_id")] for row in values]
        return out
    return _audited("esql", {"query": query}, {"esql": query}, run)


@mcp.tool()
def get_event(index: str, id: str) -> dict:
    """The complete stored record of one event (all parsed fields plus event.original, the raw log line),
    by the _index and _id returned from search/esql. Use it to verify evidence before citing it."""
    def run():
        r = config.es("reader").get(index=index, id=id)
        return {"_index": r["_index"], "_id": r["_id"], "found": r["found"], "source": r["_source"]}
    return _audited("get_event", {"index": index, "id": id}, {"api": "get", "index": index, "id": id}, run)


@mcp.tool()
def get_registry() -> dict:
    """How the data got here: every registered log source with its ingestion channel, parsing template and the
    onboarding decision, plus every parsing template (name, dataset, origin builtin/generated, match rule)."""
    def run():
        tpl = {n: {k: s.get(k) for k in ("dataset", "origin", "description", "match")}
               for n, s in templates.installed("reader").items()}
        return {"sources": registry.meta(), "templates": tpl}
    return _audited("get_registry", {}, {"api": "registry files + GET _ingest/pipeline/hunt-tpl-*"}, run)


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
