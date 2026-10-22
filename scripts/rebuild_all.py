"""Rebuild the whole system from nothing and verify it, in one command.

Steps: docker compose down -v (Elasticsearch data, certificates, Logstash state) -> clear the project's state on the
host (generated templates, registry, dropzone, exported CA) -> docker compose up -> wait until Elasticsearch, Kibana
and Logstash are healthy -> export the CA certificate -> stack checks -> install templates -> ingest every source
(onboarding agent included) -> check that the agent onboarded every source -> Kibana data views -> full verification.
Every step's output is printed; the script stops at the first failure.

Every rebuild starts from nothing, whether the stack is running or stopped: no step before "start the stack" talks
to Elasticsearch. Until 2026-10-22 the first step was "hunt reset", which does; with the stack stopped after a
restart, or a stale elk/certs/ca.crt, it failed, the failure was ignored, and the rebuild went on with the old
templates and registry, so the onboarding agent never ran and REBUILD OK was still printed.

Usage: .venv\\Scripts\\python scripts\\rebuild_all.py   (--wipe is still accepted and changes nothing)
"""
import argparse
import json
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
PY = sys.executable
CA = ROOT / "elk" / "certs" / "ca.crt"
sys.path.insert(0, str(ROOT))
from hunt import admin, config, registry  # noqa: E402


def step(title, cmd, check=True):
    print(f"\n=== {title} ===\n$ {' '.join(cmd)}", flush=True)
    t0 = time.time()
    p = subprocess.run(cmd, cwd=ROOT, text=True, encoding="utf-8", errors="replace")
    print(f"--- exit {p.returncode} after {time.time() - t0:.0f} s", flush=True)
    if check and p.returncode != 0:
        sys.exit(f"step failed: {title}")
    return p.returncode


def wait_healthy(services=("es01", "kibana", "logstash"), timeout=600):
    t0 = time.time()
    while time.time() - t0 < timeout:
        out = subprocess.run(["docker", "compose", "ps", "--format", "{{.Service}}={{.Health}}"], cwd=ROOT,
                             capture_output=True, text=True).stdout
        state = dict(line.split("=", 1) for line in out.split() if "=" in line)
        if all(state.get(s) == "healthy" for s in services):
            print(f"healthy: {state}", flush=True)
            return
        time.sleep(5)
    sys.exit(f"services not healthy after {timeout} s: {state}")


def clear_host_state():
    """What docker compose down -v leaves on the host. The exported CA goes too: the new stack makes a new CA."""
    print("\n=== clear the project's state on the host (generated templates, registry, dropzone, exported CA) ===", flush=True)
    admin.reset_files()
    CA.unlink(missing_ok=True)
    print("deleted elk/certs/ca.crt", flush=True)
    left = [p.name for p in (config.TEMPLATES_DIR / "generated").glob("*.json")]
    left += [f"registry {sid}" for sid in {**registry.routes(), **registry.meta()}]
    left += [p.name for p in config.DROPZONE.iterdir() if p.is_dir() and p.name != ".staging"]
    left += ["elk/certs/ca.crt"] if CA.exists() else []
    if left:
        sys.exit(f"step failed: still on the host after clearing: {left}")


def check_onboarding():
    """Every source must have been onboarded in this rebuild. A source routed by a registry left over from an
    earlier run is parsed without the agent, and its ingest log has no decision."""
    print("\n=== check that the onboarding agent onboarded every source ===", flush=True)
    summary = json.loads((ROOT / "runs" / "ingest" / "summary.json").read_text(encoding="utf-8"))
    for s in summary:
        print(f"{s['source_id']:22s} {s['onboarding'][:60]}", flush=True)
    missing = [s["source_id"] for s in summary
               if "'decision': 'reused'" not in s["onboarding"] and "'decision': 'created'" not in s["onboarding"]]
    if len(summary) != 6 or missing:
        sys.exit(f"step failed: sources not onboarded by the agent in this rebuild: {missing}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wipe", action="store_true", help="accepted for older commands; every rebuild starts from nothing")
    ap.parse_args()
    step("remove containers and volumes", ["docker", "compose", "down", "-v"])
    clear_host_state()
    step("start the stack", ["docker", "compose", "up", "-d"])
    wait_healthy()
    CA.parent.mkdir(parents=True, exist_ok=True)
    step("export CA certificate", ["docker", "compose", "cp", "es01:/usr/share/elasticsearch/config/certs/ca/ca.crt", "elk/certs/ca.crt"])
    step("stack checks", [PY, "scripts/verify_stack.py", "--pre-ingest"])
    step("install parsing templates", [PY, "-m", "hunt", "templates", "install"])
    step("ingest all sources", [PY, "scripts/ingest_all.py"])
    check_onboarding()
    step("Kibana data views", [PY, "scripts/kibana_dataviews.py"])
    step("full verification", [PY, "scripts/verify_all.py"])
    print("\nREBUILD OK", flush=True)


if __name__ == "__main__":
    main()
