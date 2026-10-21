"""Step-1 acceptance checks for the Elastic stack. Prints PASS/FAIL per check; never prints secrets.

Prerequisite: the CA certificate exported to elk/certs/ca.crt:
    docker compose cp es01:/usr/share/elasticsearch/config/certs/ca/ca.crt elk/certs/ca.crt
Usage: .venv\\Scripts\\python scripts\\verify_stack.py
"""
import base64
import json
import pathlib
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
CA = ROOT / "elk" / "certs" / "ca.crt"
ES = "https://localhost:9200"
KIBANA = "http://localhost:5601"
results = []


def load_env():
    env = {}
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def call(url, user=None, password=None, method="GET", ctx=None, body=None):
    """Return (status, parsed_json_or_text). HTTP errors are returned, not raised."""
    req = urllib.request.Request(url, method=method, data=body)
    if user:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            raw = r.read().decode()
            status = r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read().decode(), e.code
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, raw


def check(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))


def main():
    env = load_env()
    epw, lpw = env["ELASTIC_PASSWORD"], env["LOGSTASH_WRITER_PASSWORD"]
    ctx = ssl.create_default_context(cafile=str(CA))   # verifies the server certificate against our CA

    # 1. TLS: a client that does NOT trust our CA must be rejected
    try:
        urllib.request.urlopen(ES, context=ssl.create_default_context(), timeout=10)
        check("TLS rejects clients without our CA", False, "connection was accepted")
    except urllib.error.URLError as e:
        check("TLS rejects clients without our CA", "CERTIFICATE_VERIFY_FAILED" in str(e.reason), type(e.reason).__name__)

    # 2. Authentication is required
    st, _ = call(ES, ctx=ctx)
    check("anonymous request rejected", st == 401, f"HTTP {st}")

    # 3. Version and health as the superuser
    st, info = call(ES, "elastic", epw, ctx=ctx)
    check("Elasticsearch version is 9.5.5", st == 200 and info["version"]["number"] == "9.5.5",
          f"HTTP {st}, version {info.get('version', {}).get('number') if isinstance(info, dict) else '?'}")
    st, health = call(f"{ES}/_cluster/health", "elastic", epw, ctx=ctx)
    check("cluster health green or yellow", health.get("status") in ("green", "yellow"), f"status={health.get('status')}")
    st, nodes = call(f"{ES}/_nodes/stats/jvm", "elastic", epw, ctx=ctx)
    heap = next(iter(nodes["nodes"].values()))["jvm"]["mem"]["heap_max_in_bytes"]
    print(f"INFO  Elasticsearch heap max = {heap / 2**30:.2f} GiB")

    # 4. Least privilege: logstash_internal can authenticate but cannot read
    st, who = call(f"{ES}/_security/_authenticate", "logstash_internal", lpw, ctx=ctx)
    check("logstash_internal authenticates with role logstash_writer",
          st == 200 and who.get("roles") == ["logstash_writer"], f"roles={who.get('roles') if isinstance(who, dict) else '?'}")
    st, _ = call(f"{ES}/logs-*/_search", "logstash_internal", lpw, ctx=ctx)
    check("logstash_internal is denied search on logs-*", st == 403, f"HTTP {st}")
    st, _ = call(f"{ES}/_security/user", "logstash_internal", lpw, ctx=ctx)
    check("logstash_internal is denied user management", st == 403, f"HTTP {st}")

    # 5. The Logstash -> Elasticsearch path (TLS + writer user + data stream auto-creation) delivered events.
    #    Skipped with --pre-ingest (a freshly built stack has no data yet); verify_all.py runs it after ingest.
    #    (Step 1 used a one-event smoke pipeline for this; it was removed once the real channels existed.)
    st, ds = call(f"{ES}/_data_stream/logs-*", "elastic", epw, ctx=ctx)
    names = [d["name"] for d in ds.get("data_streams", [])] if isinstance(ds, dict) else []
    filled = []
    for n in names:
        if n == "logs-hunt.unparsed-default":
            continue
        st, cnt = call(f"{ES}/{n}/_count", "elastic", epw, ctx=ctx)
        if isinstance(cnt, dict) and cnt.get("count"):
            filled.append(n)
    if "--pre-ingest" in sys.argv:
        print("SKIP  Logstash delivered events into parsed data streams  (--pre-ingest)")
    else:
        check("Logstash delivered events into parsed data streams", bool(filled), f"{len(filled)} non-empty data streams")

    # 6. Kibana is up and connected to Elasticsearch
    st, status = call(f"{KIBANA}/api/status", "elastic", epw)
    level = status.get("status", {}).get("overall", {}).get("level") if isinstance(status, dict) else None
    check("Kibana overall status available", level == "available", f"HTTP {st}, level={level}")

    # 7. Published ports are bound to 127.0.0.1 only
    out = subprocess.run(["docker", "compose", "ps", "--format", "json"], cwd=ROOT, capture_output=True,
                         text=True, encoding="utf-8").stdout
    pubs = []
    for line in out.splitlines():
        for p in json.loads(line).get("Publishers") or []:
            if p.get("PublishedPort"):
                pubs.append((p["URL"], p["PublishedPort"]))
    check("all published ports bind to 127.0.0.1", bool(pubs) and all(u == "127.0.0.1" for u, _ in pubs), str(pubs))

    print(f"\n{sum(results)}/{len(results)} checks passed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
