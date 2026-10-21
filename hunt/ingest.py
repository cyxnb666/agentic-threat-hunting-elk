"""Ingestion channels, backlog backfill and the watcher that hands new sources to the onboarding agent.

Channels (all deliver raw records tagged with a source_id; Logstash routes them, see elk/logstash/pipeline):
  pull   - copy a file or folder into dropzone/<source_id>/ (staged under dropzone/.staging, then renamed,
           so Logstash's read mode never sees a half-written file); Logstash deletes each file once read
  push   - endpoint agent: POST newline-delimited records to the Logstash http input (basic auth)
  stream - syslog sender: RFC 3164 lines over TCP to the Logstash syslog input, rate-limited, source_id as
           the syslog program name
The push and stream senders replay dataset files; they stand in for a real endpoint agent / syslog relay.
"""
import base64
import datetime as dt
import gzip
import json
import os
import pathlib
import shutil
import socket
import time
import urllib.request
import uuid

from . import config, registry, sampling
from .onboarding import OnboardingAgent

PUSH_URL = "http://127.0.0.1:8080/"
SYSLOG_ADDR = ("127.0.0.1", 5514)
MIN_SAMPLE = 200            # onboard once this many records are waiting ...
QUIET_CYCLES = 2            # ... or once the count has not grown for this many watcher cycles
LOGSTASH_REFRESH_S = 7      # translate refresh_interval is 5 s


def _lines(path: pathlib.Path):
    files = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
    for p in files:
        opener = gzip.open if p.suffix == ".gz" else open
        with opener(p, "rt", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\r\n")
                if line.strip():
                    yield line


# ---- channels ------------------------------------------------------------------------------------------
def pull(path: str, source_id: str) -> dict:
    src = pathlib.Path(path)
    staging = config.DROPZONE / ".staging"
    staging.mkdir(parents=True, exist_ok=True)
    files = sorted(p for p in src.rglob("*") if p.is_file()) if src.is_dir() else [src]
    count = 0
    for p in files:
        rel = p.relative_to(src) if src.is_dir() else pathlib.Path(p.name)
        tmp = staging / f"{uuid.uuid4().hex}-{p.name}"
        shutil.copyfile(p, tmp)
        dest = config.DROPZONE / source_id / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        os.replace(tmp, dest)
        count += sum(1 for _ in _lines(p))      # not dest: Logstash may already have read and deleted it
    return {"channel": "pull", "source_id": source_id, "files": len(files), "records": count}


def push(path: str, source_id: str, batch: int = 500) -> dict:
    auth = "Basic " + base64.b64encode(f"endpoint:{config.env()['PUSH_PASSWORD']}".encode()).decode()
    sent, buf = 0, []

    def flush():
        nonlocal sent, buf
        if not buf:
            return
        body = ("\n".join(buf) + "\n").encode("utf-8")
        for attempt in range(5):
            try:
                req = urllib.request.Request(PUSH_URL, data=body, method="POST", headers={
                    "Content-Type": "application/x-ndjson", "X-Hunt-Source": source_id, "Authorization": auth})
                urllib.request.urlopen(req, timeout=60)
                break
            except Exception:
                time.sleep(2 ** attempt)
        else:
            raise RuntimeError("push failed after 5 attempts")
        sent += len(buf)
        buf = []

    for line in _lines(pathlib.Path(path)):
        buf.append(line)
        if len(buf) >= batch:
            flush()
    flush()
    return {"channel": "push", "source_id": source_id, "records": sent}


def stream(path: str, source_id: str, eps: int = 500) -> dict:
    """Send records as a continuous syslog stream at about `eps` events per second."""
    sock = socket.create_connection(SYSLOG_ADDR, timeout=30)
    sent, t0 = 0, time.time()
    try:
        for line in _lines(pathlib.Path(path)):
            try:
                host = str(json.loads(line).get("Hostname", "collector")).split(".")[0].lower()
            except ValueError:
                host = "collector"
            stamp = dt.datetime.now().strftime("%b %d %H:%M:%S")
            sock.sendall(f"<134>{stamp} {host} {source_id}: {line}\n".encode("utf-8"))
            sent += 1
            ahead = sent / eps - (time.time() - t0)
            if ahead > 0:
                time.sleep(ahead)
    finally:
        sock.close()
    return {"channel": "stream", "source_id": source_id, "records": sent, "seconds": round(time.time() - t0, 1)}


# ---- backlog -------------------------------------------------------------------------------------------
def unparsed_counts() -> dict:
    es = config.es("agent")
    if not es.indices.exists(index=config.UNPARSED_DS):
        return {}
    es.indices.refresh(index=config.UNPARSED_DS)
    aggs = es.search(index=config.UNPARSED_DS, size=0, aggs={
        "src": {"terms": {"field": "hunt.source_id", "size": 500},
                "aggs": {"ch": {"terms": {"field": "hunt.channel", "size": 3}}}}})["aggregations"]["src"]["buckets"]
    return {b["key"]: {"count": b["doc_count"], "channel": (b["ch"]["buckets"] or [{"key": ""}])[0]["key"]} for b in aggs}


def backfill(source_id: str, page: int = 1000) -> dict:
    """Re-ingest a registered source's unparsed records through its template, then delete exactly those records."""
    es = config.es("agent")
    route = registry.routes()[source_id]
    target = f"logs-{route['dataset']}-default"
    es.indices.refresh(index=config.UNPARSED_DS)
    pit = es.open_point_in_time(index=config.UNPARSED_DS, keep_alive="2m")["id"]
    moved = failed = 0
    after = None
    try:
        while True:
            body = {"size": page, "query": {"term": {"hunt.source_id": source_id}}, "sort": ["_shard_doc"],
                    "pit": {"id": pit, "keep_alive": "2m"}}
            if after:
                body["search_after"] = after
            hits = es.search(**body)["hits"]["hits"]
            if not hits:
                break
            after = hits[-1]["sort"]
            ops = []
            for h in hits:
                src = h["_source"]
                src["data_stream"] = {"type": "logs", "dataset": route["dataset"], "namespace": "default"}
                ops += [{"create": {"_index": target}}, src]
            resp = es.bulk(operations=ops, pipeline=route["pipeline"], refresh=False)
            delete_ops = []
            for h, item in zip(hits, resp["items"]):
                if item["create"].get("status") in (200, 201):
                    delete_ops.append({"delete": {"_index": h["_index"], "_id": h["_id"]}})
                else:
                    failed += 1
            if delete_ops:
                es.bulk(operations=delete_ops, refresh=False)
            moved += len(delete_ops)
    finally:
        es.close_point_in_time(id=pit)
    es.indices.refresh(index=config.UNPARSED_DS)
    return {"source_id": source_id, "target": target, "moved": moved, "failed": failed}


# ---- watcher -------------------------------------------------------------------------------------------
_history = {}   # source_id -> backlog size seen in the previous watcher cycle (shared across calls)


def watch(once: bool = False, interval: int = 10, idle_exit: int | None = None, log=print) -> list[dict]:
    """Discover unknown sources in the unparsed data stream, onboard them, backfill their backlog."""
    history, events, idle = _history, [], 0
    while True:
        counts = unparsed_counts()
        routes = registry.routes()
        acted = False
        for sid, info in sorted(counts.items()):
            if sid in routes:
                r = backfill(sid)
                events.append({"event": "backfill", **r})
                log(f"[watch] backfilled {r['moved']} records of {sid} into {r['target']} (failed {r['failed']})")
                acted = True
                continue
            prev = history.get(sid)
            history[sid] = info["count"]
            ready = once or info["count"] >= MIN_SAMPLE or prev == info["count"]
            if not ready:
                log(f"[watch] {sid}: {info['count']} records waiting, collecting more before onboarding")
                continue
            log(f"[watch] onboarding new source {sid} ({info['count']} records, channel {info['channel']})")
            lines = sampling.sample_unparsed(sid, MIN_SAMPLE)
            report = OnboardingAgent(sid, lines, info["channel"]).run()
            events.append({"event": "onboard", **report})
            log(f"[watch] {sid}: {report['outcome']}")
            acted = True
            if report["outcome"]["decision"] in ("reused", "created"):
                time.sleep(LOGSTASH_REFRESH_S)        # let Logstash load the new route before backfilling
                r = backfill(sid)
                events.append({"event": "backfill", **r})
                log(f"[watch] backfilled {r['moved']} records of {sid} into {r['target']} (failed {r['failed']})")
        idle = 0 if acted or counts else idle + interval
        if once or (idle_exit is not None and idle >= idle_exit):
            return events
        time.sleep(interval)


def quality(source_id: str) -> dict:
    """Full-data check after parsing: records that hit the template's on_failure handler, and @timestamp range."""
    route = registry.routes().get(source_id)
    if not route:
        return {}
    es = config.es("agent")
    target = f"logs-{route['dataset']}-default"
    es.indices.refresh(index=target)
    q = {"term": {"hunt.source_id": source_id}}
    r = es.search(index=target, size=0, query=q, track_total_hits=True, aggs={
        "errors": {"filter": {"term": {"event.kind": "pipeline_error"}}},
        "tmin": {"min": {"field": "@timestamp"}}, "tmax": {"max": {"field": "@timestamp"}}})
    a = r["aggregations"]
    return {"parsed": r["hits"]["total"]["value"], "pipeline_errors": a["errors"]["doc_count"],
            "first_event": a["tmin"].get("value_as_string"), "last_event": a["tmax"].get("value_as_string")}


def parsed_count(source_id: str) -> int:
    route = registry.routes().get(source_id)
    if not route:
        return 0
    es = config.es("agent")
    target = f"logs-{route['dataset']}-default"
    if not es.indices.exists(index=target):
        return 0
    es.indices.refresh(index=target)
    return es.count(index=target, query={"term": {"hunt.source_id": source_id}})["count"]
