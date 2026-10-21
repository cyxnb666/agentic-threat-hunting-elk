"""Download the OTRF Security-Datasets APT29 Day 1 files and verify them.

Source: https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/apt29/day1 (MIT licence)

Integrity check: the GitHub contents API returns each file's git blob SHA-1, which is
sha1(b"blob <size>\\0" + content). Every downloaded file is re-hashed the same way and must match.
A manifest (source URL, size, blob SHA, download time) is written next to the files.

Standard library only. Usage: py -3.13 scripts/download_apt29.py [--out data/raw/apt29_day1]
"""
import argparse
import hashlib
import json
import pathlib
import time
import urllib.request

API = "https://api.github.com/repos/OTRF/Security-Datasets/contents/{path}?ref=master"
# Host logs (Sysmon, Security, PowerShell, ...) and the per-type Zeek network logs
TARGETS = [
    "datasets/compound/apt29/day1/apt29_evals_day1_manual.zip",
    "datasets/compound/apt29/day1/zeek/individual_zeek_logs",
]


def get_json(url):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "apt29-downloader"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def list_files(path):
    """Return the file entries for a file or (non-recursive) directory path."""
    data = get_json(API.format(path=path))
    entries = data if isinstance(data, list) else [data]
    return [e for e in entries if e["type"] == "file"]


def git_blob_sha1(content: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/raw/apt29_day1")
    args = ap.parse_args()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    manifest = []
    for target in TARGETS:
        for e in list_files(target):
            rel = pathlib.PurePosixPath(e["path"]).relative_to("datasets/compound/apt29/day1")
            dest = out / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            with urllib.request.urlopen(e["download_url"], timeout=300) as r:
                content = r.read()
            sha = git_blob_sha1(content)
            ok = len(content) == e["size"] and sha == e["sha"]
            if not ok:
                raise SystemExit(f"VERIFY FAILED: {rel} size={len(content)}/{e['size']} sha={sha}/{e['sha']}")
            dest.write_bytes(content)
            manifest.append({"file": str(rel), "source": e["download_url"], "size": e["size"],
                             "git_blob_sha1": e["sha"], "verified": ok})
            print(f"ok  {e['size']:>10}  {rel}")

    meta = {"dataset": "OTRF Security-Datasets compound/apt29/day1", "license": "MIT",
            "repo": "https://github.com/OTRF/Security-Datasets",
            "downloaded_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "files": manifest}
    (out / "manifest.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"{len(manifest)} files verified; manifest at {out / 'manifest.json'}")


if __name__ == "__main__":
    main()
