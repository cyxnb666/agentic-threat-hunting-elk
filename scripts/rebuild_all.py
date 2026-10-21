"""Rebuild the whole system and verify it, in one command.

Steps: [--wipe: delete all project data, generated templates and the Docker volumes] -> docker compose up ->
wait until Elasticsearch, Kibana and Logstash are healthy -> export the CA certificate -> stack checks ->
install templates -> ingest every source (onboarding agent included) -> Kibana data views -> full verification.
Every step's output is printed; the script stops at the first failure.

Usage: .venv\\Scripts\\python scripts\\rebuild_all.py [--wipe]
"""
import argparse
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
PY = sys.executable


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wipe", action="store_true", help="delete ingested data, generated templates and Docker volumes first")
    a = ap.parse_args()
    if a.wipe:
        step("reset project data (data streams, generated templates, registry, dropzone)", [PY, "-m", "hunt", "reset", "--yes"], check=False)
        step("remove containers and volumes", ["docker", "compose", "down", "-v"])
    step("start the stack", ["docker", "compose", "up", "-d"])
    wait_healthy()
    (ROOT / "elk" / "certs").mkdir(parents=True, exist_ok=True)
    step("export CA certificate", ["docker", "compose", "cp", "es01:/usr/share/elasticsearch/config/certs/ca/ca.crt", "elk/certs/ca.crt"])
    step("stack checks", [PY, "scripts/verify_stack.py", "--pre-ingest"])
    step("install parsing templates", [PY, "-m", "hunt", "templates", "install"])
    step("ingest all sources", [PY, "scripts/ingest_all.py"])
    step("Kibana data views", [PY, "scripts/kibana_dataviews.py"])
    step("full verification", [PY, "scripts/verify_all.py"])
    print("\nREBUILD OK", flush=True)


if __name__ == "__main__":
    main()
