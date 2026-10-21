"""Ingest every prepared source through the channel it is assigned to, one after another.

Each step is the single user action "point the system at a source"; delivery, onboarding (template
selection or creation by the agent), backfill and the full-data quality check are automatic.
The output of every step goes to runs/ingest/<n>-<source>.log and a summary to runs/ingest/summary.json.

Usage: .venv\\Scripts\\python scripts\\ingest_all.py
"""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PY = sys.executable
PLAN = [
    ("pull", "data/sources/sysmon.ndjson.gz", "apt29-sysmon"),
    ("push", "data/sources/security.ndjson.gz", "apt29-security"),
    ("push", "data/sources/windows-other.ndjson.gz", "apt29-windows-other"),
    ("stream", "data/sources/powershell.ndjson.gz", "apt29-powershell"),
    ("pull", "data/sources/zeek/SCRANTON", "zeek-scranton"),
    ("pull", "data/sources/zeek/NASHUA", "zeek-nashua"),
]


def main():
    out_dir = ROOT / "runs" / "ingest"
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = []
    for n, (channel, path, sid) in enumerate(PLAN, 1):
        log = out_dir / f"{n:02d}-{sid}.log"
        with open(log, "w", encoding="utf-8") as f:
            subprocess.run([PY, "-m", "hunt", "ingest", channel, path, "--source-id", sid], cwd=ROOT, stdout=f,
                           stderr=subprocess.STDOUT, check=True)
        lines = log.read_text(encoding="utf-8").splitlines()
        result = json.loads(lines[-1])
        decision = next((l.split(": ", 1)[1] for l in lines if l.startswith(f"[watch] {sid}: ")), "")
        summary.append({"source_id": sid, "channel": channel, **result, "onboarding": decision})
        print(f"{sid:22s} {channel:6s} records={result['records']:>7} parsed={result['parsed']:>7} "
              f"errors={result['pipeline_errors']} {decision[:110]}")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()
