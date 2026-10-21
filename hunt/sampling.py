"""Deterministic sampling of raw records and a structural fingerprint the onboarding agent can reason about."""
import collections
import gzip
import json
import pathlib
import re

from . import config

SYSLOG_RE = re.compile(r"^<\d{1,3}>")
KV_RE = re.compile(r"^(\s*[\w.\-]+=(\"[^\"]*\"|\S+))+\s*$")


def _open(path: pathlib.Path):
    return gzip.open(path, "rt", encoding="utf-8") if path.suffix == ".gz" else open(path, encoding="utf-8")


def sample_file(path, n: int = 200) -> list[str]:
    """First n/4 lines plus lines spread evenly over the rest (two passes; deterministic)."""
    files = sorted(p for p in pathlib.Path(path).rglob("*") if p.is_file()) if pathlib.Path(path).is_dir() else [pathlib.Path(path)]
    lines = []
    per_file = max(1, n // len(files))
    for p in files:
        with _open(p) as f:
            total = sum(1 for line in f if line.strip())
        head = min(per_file // 4, total)
        rest = min(per_file - head, total - head)
        wanted = set(range(head)) | {head + (k * (total - head)) // rest for k in range(rest)} if rest > 0 else set(range(head))
        with _open(p) as f:
            i = 0
            for line in f:
                if not line.strip():
                    continue
                if i in wanted:
                    lines.append(line.rstrip("\r\n"))
                i += 1
    return lines[:n]


def sample_unparsed(source_id: str, n: int = 200) -> list[str]:
    """Raw records of one source waiting in the unparsed data stream: n/2 oldest + n/2 seeded-random."""
    es = config.es("agent")
    q = {"term": {"hunt.source_id": source_id}}
    oldest = es.search(index=config.UNPARSED_DS, query=q, size=n // 2, sort=[{"@timestamp": "asc"}],
                       source=["event.original"])["hits"]["hits"]
    rnd = es.search(index=config.UNPARSED_DS, size=n - n // 2, source=["event.original"],
                    query={"function_score": {"query": q, "random_score": {"seed": 42, "field": "_seq_no"}}})["hits"]["hits"]
    seen, out = set(), []
    for h in oldest + rnd:
        if h["_id"] not in seen:
            seen.add(h["_id"])
            out.append(h["_source"]["event"]["original"])
    return out


def detect_format(lines: list[str]) -> str:
    def ratio(pred):
        return sum(1 for line in lines if pred(line)) / max(1, len(lines))

    def is_json(line):
        try:
            return isinstance(json.loads(line), dict)
        except ValueError:
            return False

    if ratio(is_json) >= 0.95:
        return "json"
    if ratio(lambda l: bool(SYSLOG_RE.match(l))) >= 0.95:
        return "syslog"
    if ratio(lambda l: bool(KV_RE.match(l))) >= 0.95:
        return "kv"
    if ratio(lambda l: l.count(",") >= 3) >= 0.95:
        return "csv"
    return "text"


def fingerprint(lines: list[str]) -> dict:
    """What the agent sees: format, key frequencies, low-cardinality discriminator values, time-like fields."""
    fmt = detect_format(lines)
    fp = {"records": len(lines), "format": fmt}
    if fmt != "json":
        fp["examples"] = [line[:300] for line in lines[:5]]
        return fp
    recs = [json.loads(line) for line in lines]
    keys = collections.Counter(k for r in recs for k in r)
    values = collections.defaultdict(collections.Counter)
    for r in recs:
        for k, v in r.items():
            if isinstance(v, (str, int, float, bool)):
                values[k][str(v)[:80]] += 1
    fp["keys"] = {k: round(c / len(recs), 3) for k, c in keys.most_common()}
    fp["discriminators"] = {k: dict(values[k].most_common(8)) for k in keys
                            if 1 <= len(values[k]) <= 8 and keys[k] / len(recs) >= 0.95}
    time_like = re.compile(r"(time|date|timestamp|^ts$|utc)", re.I)
    fp["time_fields"] = {k: list(values[k])[:3] for k in keys if time_like.search(k)}
    fp["example_record"] = {k: (str(v)[:120] if not isinstance(v, (int, float, bool)) else v)
                            for k, v in list(recs[0].items())[:60]}
    return fp
