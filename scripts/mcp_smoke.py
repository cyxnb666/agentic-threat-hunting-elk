"""Talk to the MCP server over stdio exactly like an AI client does, and exercise every tool once.

Usage: .venv\\Scripts\\python scripts\\mcp_smoke.py
"""
import asyncio
import json
import os
import pathlib
import sys

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = pathlib.Path(__file__).resolve().parent.parent


def data(res):
    d = getattr(res, "structured_content", None)
    return d if d else json.loads(res.content[0].text)


async def main():
    audit = ROOT / "runs" / "mcp_smoke_audit.jsonl"
    audit.unlink(missing_ok=True)
    params = StdioServerParameters(command=sys.executable, args=["-m", "hunt", "mcp"], cwd=str(ROOT),
                                   env=dict(os.environ, HUNT_AUDIT_FILE=str(audit)))
    ok = 0
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            init = await s.initialize()
            print("server:", init.server_info.name, "| protocol:", init.protocol_version)
            tools = (await s.list_tools()).tools
            print("tools:", [t.name for t in tools])
            calls = [
                ("list_data_sources", {}),
                ("get_fields", {"dataset": "windows.sysmon", "prefix": "process."}),
                ("search", {"dataset": "windows.sysmon", "query": "event.code:1", "size": 2}),
                ("count", {"dataset": "windows.security", "query": "event.code:4624"}),
                ("aggregate", {"dataset": "windows.sysmon", "field": "event.code", "size": 5}),
                ("timeline", {"dataset": "windows.powershell", "query": "event.code:4104", "interval": "5m"}),
                ("esql", {"query": "FROM logs-windows.sysmon-default METADATA _id | WHERE event.code == \"1\" | STATS n = COUNT(*) BY host.name | SORT n DESC"}),
                ("get_registry", {}),
                ("search", {"dataset": "windows.sysmon", "query": "event.code:(", "size": 1}),   # deliberate syntax error
            ]
            first_hit = None
            for name, args in calls:
                d = data(await s.call_tool(name, args))
                summary = {k: d[k] for k in ("total", "rows", "count", "returned") if k in d}
                if name == "list_data_sources":
                    summary = {"datasets": [x["dataset"] for x in d["datasets"]], "warnings": len(d["non_overlapping_time_windows"])}
                if name == "search" and d.get("hits"):
                    first_hit = d["hits"][0]
                print(f"  {name:18s} query_id={d.get('query_id')} {json.dumps(summary)} {('ERROR: ' + d['error'][:120]) if d.get('error') else ''}")
                ok += 1
            ev = data(await s.call_tool("get_event", {"index": first_hit["_index"], "id": first_hit["_id"]}))
            print(f"  get_event          found={ev['found']} has event.original={'original' in ev['source'].get('event', {})}")
    lines = audit.read_text(encoding="utf-8").splitlines()
    print(f"audit log: {len(lines)} entries in {audit.relative_to(ROOT)}")


if __name__ == "__main__":
    asyncio.run(main())
