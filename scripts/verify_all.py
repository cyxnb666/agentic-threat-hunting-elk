"""End-to-end verification of the whole system (run it after ingest; repeat after every reset/re-run).

Checks, in order:
  1. stack: scripts/verify_stack.py (TLS, auth, least privilege, health, localhost-only ports)
  2. data: every source in data/sources/sources_manifest.json is fully parsed into its data stream, with zero
     pipeline errors and an empty unparsed backlog; Logstash pipelines pull/push/stream are running
  3. templates/registry: every registered source points to an installed template that is also saved as a file
  4. MCP: scripts/mcp_smoke.py talks to the server over stdio and exercises every tool
  5. unit tests: pytest
Prints PASS/FAIL per check and exits non-zero on any failure.

Usage: .venv\\Scripts\\python scripts\\verify_all.py
"""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from hunt import config, ingest, registry, templates  # noqa: E402

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)


def run(cmd):
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return p.returncode, p.stdout + p.stderr


def main():
    code, out = run([sys.executable, "scripts/verify_stack.py"])
    check("stack checks (scripts/verify_stack.py)", code == 0, out.strip().splitlines()[-1] if out.strip() else "")

    manifest = json.loads((ROOT / "data" / "sources" / "sources_manifest.json").read_text(encoding="utf-8"))
    expected = {
        "apt29-sysmon": manifest["sysmon.ndjson.gz"]["lines"],
        "apt29-security": manifest["security.ndjson.gz"]["lines"],
        "apt29-windows-other": manifest["windows-other.ndjson.gz"]["lines"],
        "apt29-powershell": manifest["powershell.ndjson.gz"]["lines"],
        "zeek-scranton": sum(v["lines"] for k, v in manifest.items() if k.startswith("zeek/SCRANTON/")),
        "zeek-nashua": sum(v["lines"] for k, v in manifest.items() if k.startswith("zeek/NASHUA/")),
    }
    for sid, n in expected.items():
        q = ingest.quality(sid)
        check(f"source {sid}: {n} records parsed, no pipeline errors",
              q.get("parsed") == n and q.get("pipeline_errors") == 0, json.dumps(q))
    backlog = ingest.unparsed_counts()
    check("unparsed backlog empty", not backlog, json.dumps(backlog))
    code, out = run(["docker", "compose", "exec", "-T", "logstash", "curl", "-s", "localhost:9600/_node/pipelines"])
    names = set(json.loads(out).get("pipelines", {})) if code == 0 and out.strip().startswith("{") else set()
    check("logstash pipelines pull/push/stream running", {"pull", "push", "stream"} <= names, str(sorted(names)))

    installed = templates.installed()
    files = {p.stem for folder in ("builtin", "generated") for p in (config.TEMPLATES_DIR / folder).glob("*.json")}
    for sid, m in sorted(registry.meta().items()):
        t = m["template"]
        check(f"registry {sid} -> template {t} installed and saved", t in installed and t in files)

    code, out = run([sys.executable, "scripts/mcp_smoke.py"])
    tools_line = next((l for l in out.splitlines() if l.startswith("tools:")), "")
    check("MCP server over stdio: 9 tools listed and exercised", code == 0 and tools_line.count("'") == 18 and "found=True" in out,
          tools_line)

    code, out = run([sys.executable, "-m", "pytest", "-q", "tests"])
    check("unit tests", code == 0, out.strip().splitlines()[-1] if out.strip() else "")

    print(f"\n{sum(results)}/{len(results)} checks passed", flush=True)
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
