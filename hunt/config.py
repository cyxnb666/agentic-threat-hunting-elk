"""Paths, settings from .env, and Elasticsearch clients per role (least privilege)."""
import functools
import os
import pathlib

from elasticsearch import Elasticsearch

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
DROPZONE = ROOT / "dropzone"
REGISTRY_DIR = ROOT / "registry"
TEMPLATES_DIR = ROOT / "templates"
RUNS_DIR = ROOT / "runs"
CA_CERT = ROOT / "elk" / "certs" / "ca.crt"
ES_URL = "https://localhost:9200"

UNPARSED_DS = "logs-hunt.unparsed-default"
TEMPLATE_PREFIX = "hunt-tpl-"


@functools.lru_cache(maxsize=1)
def env() -> dict:
    """Variables from .env (process environment wins, so CI can override)."""
    values = {}
    path = ROOT / ".env"
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
    values.update({k: v for k, v in os.environ.items() if k in values})
    return values


# role -> (user, .env password variable)
_USERS = {
    "admin": ("elastic", "ELASTIC_PASSWORD"),
    "agent": ("hunt_agent", "HUNT_AGENT_PASSWORD"),
    "reader": ("hunt_mcp", "HUNT_MCP_PASSWORD"),
}


@functools.lru_cache(maxsize=None)
def es(role: str = "reader") -> Elasticsearch:
    user, var = _USERS[role]
    return Elasticsearch(ES_URL, ca_certs=str(CA_CERT), basic_auth=(user, env()[var]), request_timeout=120)


def llm_settings() -> dict:
    e = env()
    return {"api_key": e.get("DEEPSEEK_API_KEY", ""), "base_url": e.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
            "model": e.get("DEEPSEEK_MODEL", "deepseek-flash")}
