"""Source registry: which parsing template each source_id uses.

registry/sources.json      -> read by the Logstash translate filter (source_id -> {pipeline, dataset})
registry/sources_meta.json -> provenance for people and the MCP server (who/when/why, validation numbers)
Both are replaced atomically (write to a temp file, then os.replace) because Logstash re-reads the
dictionary every few seconds and must never see a half-written file.
"""
import datetime as dt
import json
import os

from . import config, templates

ROUTES = config.REGISTRY_DIR / "sources.json"
META = config.REGISTRY_DIR / "sources_meta.json"


def _read(path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _write(path, data: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def routes() -> dict:
    return _read(ROUTES)


def meta() -> dict:
    return _read(META)


def register(source_id: str, spec: dict, info: dict) -> None:
    r = routes()
    r[source_id] = {"pipeline": templates.pipeline_id(spec["name"]), "dataset": spec["dataset"]}
    _write(ROUTES, r)
    m = meta()
    m[source_id] = {"template": spec["name"], "template_version": spec.get("version"), "dataset": spec["dataset"],
                    "registered_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), **info}
    _write(META, m)


def reset() -> None:
    _write(ROUTES, {})
    _write(META, {})
