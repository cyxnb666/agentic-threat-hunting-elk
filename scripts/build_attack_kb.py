"""Build the ATT&CK knowledge base the hunt agent uses for technique coverage.

Source: MITRE ATT&CK Enterprise STIX 2.1 data, release v20.0 (2026-10-13),
https://github.com/mitre-attack/attack-stix-data (file enterprise-attack/enterprise-attack-20.0.json).
The download is verified against the git blob SHA-1 the GitHub API reports for that file.

Output knowledge/attack_enterprise_v20.0_windows.json: every non-revoked, non-deprecated technique and
sub-technique that lists the Windows platform, with its tactics, a short description, and (when the STIX data
links them) the detection strategies / analytics / log sources ATT&CK associates with it.

© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE
Corporation (ATT&CK license: https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt).

Usage: .venv\\Scripts\\python scripts\\build_attack_kb.py
"""
import collections
import hashlib
import json
import pathlib
import re
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
VERSION = "20.0"
REPO_PATH = f"enterprise-attack/enterprise-attack-{VERSION}.json"
RAW = ROOT / "data" / "raw" / "attack" / f"enterprise-attack-{VERSION}.json"
OUT = ROOT / "knowledge" / f"attack_enterprise_v{VERSION}_windows.json"


def download():
    meta = json.load(urllib.request.urlopen(urllib.request.Request(
        f"https://api.github.com/repos/mitre-attack/attack-stix-data/contents/{REPO_PATH}",
        headers={"User-Agent": "kb-builder", "Accept": "application/vnd.github+json"}), timeout=60))
    if RAW.exists() and RAW.stat().st_size == meta["size"]:
        content = RAW.read_bytes()
    else:
        url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{REPO_PATH}"
        content = urllib.request.urlopen(url, timeout=600).read()
    sha = hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()
    if sha != meta["sha"] or len(content) != meta["size"]:
        raise SystemExit(f"verification failed: sha {sha} vs {meta['sha']}")
    RAW.parent.mkdir(parents=True, exist_ok=True)
    RAW.write_bytes(content)
    return json.loads(content), meta["sha"]


def ext_id(obj):
    return next((r["external_id"] for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)


def main():
    bundle, sha = download()
    objs = {o["id"]: o for o in bundle["objects"]}
    live = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")
    tactics = {o["x_mitre_shortname"]: {"id": ext_id(o), "name": o["name"]} for o in objs.values()
               if o["type"] == "x-mitre-tactic" and live(o)}

    # detection strategy -> techniques it detects; analytic -> log sources (data components)
    detects = collections.defaultdict(list)
    for o in objs.values():
        if o["type"] == "relationship" and o.get("relationship_type") == "detects" and live(o):
            detects[o["target_ref"]].append(o["source_ref"])

    def log_sources(strategy):
        out = []
        for aref in strategy.get("x_mitre_analytic_refs", []):
            a = objs.get(aref, {})
            for ls in a.get("x_mitre_log_source_references", []):
                dc = objs.get(ls.get("x_mitre_data_component_ref"), {})
                out.append({"platforms": a.get("x_mitre_platforms"), "data_component": dc.get("name"),
                            "log_source": ls.get("name"), "channel": ls.get("channel")})
        return out

    techniques = []
    for o in objs.values():
        if o["type"] != "attack-pattern" or not live(o) or "Windows" not in o.get("x_mitre_platforms", []):
            continue
        strategies = [objs[s] for s in detects.get(o["id"], []) if s in objs]
        techniques.append({
            "id": ext_id(o), "name": o["name"], "is_subtechnique": o.get("x_mitre_is_subtechnique", False),
            "tactics": sorted(p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"),
            "description": re.sub(r"\s+", " ", re.sub(r"\(Citation:[^)]*\)", "", o.get("description", "")))[:600],
            "data_sources_legacy": o.get("x_mitre_data_sources", []),
            "detection_strategies": [{"id": ext_id(s), "name": s["name"],
                                      "log_sources": [x for x in log_sources(s) if not x["platforms"] or "Windows" in x["platforms"]]}
                                     for s in strategies],
        })
    techniques.sort(key=lambda t: t["id"])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "source": f"https://github.com/mitre-attack/attack-stix-data/blob/master/{REPO_PATH}",
        "attack_version": VERSION, "git_blob_sha1": sha,
        "copyright": "© 2026 The MITRE Corporation. Reproduced with the permission of The MITRE Corporation.",
        "tactics": tactics, "techniques": techniques}, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    ca = [t for t in techniques if "credential-access" in t["tactics"]]
    print(f"{len(techniques)} Windows techniques; credential-access: {len(ca)} "
          f"({sum(not t['is_subtechnique'] for t in ca)} techniques + {sum(t['is_subtechnique'] for t in ca)} sub-techniques); "
          f"with detection strategies: {sum(bool(t['detection_strategies']) for t in ca)}")


if __name__ == "__main__":
    main()
