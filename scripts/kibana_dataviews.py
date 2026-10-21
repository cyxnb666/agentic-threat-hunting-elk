"""Create Kibana data views for the parsed datasets so analysts can browse them in Discover.

Uses the Kibana data views API (POST /api/data_views/data_view, header kbn-xsrf) as the elastic user.
Idempotent: existing views (same id) are left alone.
Usage: .venv\\Scripts\\python scripts\\kibana_dataviews.py
"""
import base64
import json
import pathlib
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from hunt import config  # noqa: E402

VIEWS = [
    ("hunt-all", "logs-*,-logs-hunt.unparsed-*", "Hunt: all parsed logs"),
    ("hunt-windows-sysmon", "logs-windows.sysmon-*", "Hunt: Windows Sysmon"),
    ("hunt-windows-security", "logs-windows.security-*", "Hunt: Windows Security"),
    ("hunt-windows-powershell", "logs-windows.powershell-*", "Hunt: Windows PowerShell"),
    ("hunt-windows-other", "logs-windows.other-*", "Hunt: other Windows channels"),
    ("hunt-zeek", "logs-zeek-*", "Hunt: Zeek"),
    ("hunt-unparsed", "logs-hunt.unparsed-*", "Hunt: unparsed backlog"),
]


def main():
    auth = "Basic " + base64.b64encode(f"elastic:{config.env()['ELASTIC_PASSWORD']}".encode()).decode()
    for vid, pattern, name in VIEWS:
        body = json.dumps({"data_view": {"id": vid, "title": pattern, "name": name, "timeFieldName": "@timestamp"}}).encode()
        req = urllib.request.Request("http://localhost:5601/api/data_views/data_view", data=body, method="POST",
                                     headers={"kbn-xsrf": "true", "Content-Type": "application/json", "Authorization": auth})
        try:
            urllib.request.urlopen(req, timeout=30)
            print(f"created  {name} ({pattern})")
        except urllib.error.HTTPError as e:
            msg = e.read().decode()[:160]
            print(f"exists   {name}" if e.code in (400, 409) and "Duplicate" in msg or "already exists" in msg else f"ERROR {e.code} {name}: {msg}")


if __name__ == "__main__":
    main()
