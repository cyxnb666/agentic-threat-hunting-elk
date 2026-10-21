"""Split the APT29 Day 1 host-log archive into one source file per log type.

Why: the archive is a single Windows Event Forwarding export that mixes every channel. Splitting it by
channel simulates the separate collectors a real network would have (a Sysmon collector, a Security-log
collector, a PowerShell-log collector), so each one can be onboarded through a different ingestion channel.
Records are copied byte-for-byte (no field is changed); only the grouping changes.

Output (data/sources/, not in git). Host-log groups are written gzip-compressed: the PowerShell records
contain the attackers' real script blocks, and Microsoft Defender blocks a plain-text copy of them
(detected as Trojan:PowerShell/Rozena.HNAA!MTB on 2026-10-16). The gzip copies are not blocked, and the
Logstash file input reads gzip natively in read mode, so plain text never has to touch the Windows disk.
  sysmon.ndjson.gz        Microsoft-Windows-Sysmon/Operational
  security.ndjson.gz      Security + security (both spellings occur in the data)
  powershell.ndjson.gz    Microsoft-Windows-PowerShell/Operational + Windows PowerShell
  windows-other.ndjson.gz every remaining channel (System, WMI-Activity, TerminalServices-*, Firewall, Bits-Client)
  zeek/<SENSOR>/<type>.log  copies of the Zeek JSON logs, one folder per sensor
  sources_manifest.json     record counts and SHA-256 (of the file as stored) of every output file

Usage: .venv\\Scripts\\python scripts\\prepare_sources.py
"""
import collections
import gzip
import hashlib
import json
import pathlib
import shutil
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw" / "apt29_day1"
OUT = ROOT / "data" / "sources"

GROUPS = {
    "Microsoft-Windows-Sysmon/Operational": "sysmon",
    "Security": "security",
    "security": "security",
    "Microsoft-Windows-PowerShell/Operational": "powershell",
    "Windows PowerShell": "powershell",
}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    handles, counts = {}, collections.Counter()
    with zipfile.ZipFile(RAW / "apt29_evals_day1_manual.zip") as z:
        member = [i for i in z.infolist() if not i.is_dir()][0]
        with z.open(member) as f:
            for raw in f:
                if not raw.strip():
                    continue
                channel = json.loads(raw).get("Channel")
                group = GROUPS.get(channel, "windows-other")
                if group not in handles:
                    handles[group] = gzip.open(OUT / f"{group}.ndjson.gz", "wb")
                handles[group].write(raw if raw.endswith(b"\n") else raw + b"\n")
                counts[group] += 1
    for h in handles.values():
        h.close()

    zeek_src = RAW / "zeek" / "individual_zeek_logs"
    for p in sorted(zeek_src.glob("*.log")):
        sensor, ztype = p.stem.split("_", 1)
        dest = OUT / "zeek" / sensor / f"{ztype}.log"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, dest)

    manifest = {}
    for p in sorted(OUT.rglob("*")):
        if p.is_file() and p.name != "sources_manifest.json":
            opener = gzip.open if p.suffix == ".gz" else open
            with opener(p, "rb") as f:
                lines = sum(1 for line in f if line.strip())
            manifest[p.relative_to(OUT).as_posix()] = {"lines": lines, "sha256": sha256(p)}
    (OUT / "sources_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("records per group:", dict(counts), "total:", sum(counts.values()))
    zeek_lines = sum(v["lines"] for k, v in manifest.items() if k.startswith("zeek/"))
    print("zeek files:", sum(1 for k in manifest if k.startswith("zeek/")), "lines:", zeek_lines)


if __name__ == "__main__":
    main()
