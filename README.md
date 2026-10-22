# Agentic threat hunting on the Elastic Stack

A hunt capability that takes a hypothesis in plain language and returns an evidenced verdict.
Step-by-step record: the project log (a Google Doc, written in Chinese).

```
 sources                    Logstash 9.5.5                    Elasticsearch 9.5.5              agents
 ───────                    ──────────────                    ───────────────────              ──────
 dropzone/<id>/   ─pull──▶  file input  ┐                     logs-<dataset>-default  ◀──┐
 endpoint agent   ─push──▶  http :8080  ├─ route by source_id ──▶ (parsed by template)    │  onboarding agent
 syslog relay     ─stream▶  syslog :5514┘   (registry)          logs-hunt.unparsed  ─────┘  (DeepSeek, tools)
                                                                hunt-tpl-* ingest pipelines = parsing templates
                                                                        ▲
                                         MCP server (read-only) ────────┘ ◀── hunt agent (MCP client, DeepSeek)
                                                                              plan → query → verify → report
```

## What is where

| Path | What |
|---|---|
| `docker-compose.yml`, `elk/` | Elastic Stack: certs + setup one-shots, es01, kibana, logstash (pipelines per channel) |
| `hunt/ingest.py` | pull / push / stream senders, watcher, backfill, quality check |
| `hunt/onboarding.py`, `hunt/templates.py`, `hunt/registry.py` | onboarding agent, template library + validation contract, source registry |
| `templates/builtin`, `templates/generated` | parsing templates (written by hand / created by the agent) |
| `hunt/mcp_server.py` | MCP server: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry |
| `hunt/hunting.py`, `hunt/report.py` | hunt agent (scope, frame, plan, execute, investigate, verify, verdict) and report writer |
| `hunt/evaluate.py`, `hunt/compare.py` | scoring against the APT29 plan, run comparison |
| `knowledge/` | ATT&CK v20.0 Windows techniques with detection strategies (built by `scripts/build_attack_kb.py`) |
| `scripts/` | dataset download/preparation, ingest-all, MCP smoke test, env init, stack checks |
| `runs/` | everything the system produced: ingest logs, onboarding transcripts, hunt reports, comparisons |

## One command

After the one-time setup below: `.venv\Scripts\python scripts\rebuild_all.py` deletes all project data and
volumes, starts the stack, checks it, installs templates, ingests all six sources through the three channels
(onboarding agent included), checks that the agent onboarded every source, creates Kibana data views and runs the
full verification (`scripts\verify_all.py`). Every rebuild starts from nothing, whether the stack is running or
stopped (`--wipe` is still accepted and changes nothing). The containers do not restart by themselves: after a
restart of the computer or Docker Desktop, run `docker compose up -d`, then `scripts\verify_all.py`.

## Setup (Windows 11, Docker Desktop, Python 3.13)

1. Docker Desktop must run. Elasticsearch needs `vm.max_map_count = 1048576` in the docker-desktop VM
   (Elastic's Docker docs); run once in PowerShell:
   `wsl -d docker-desktop -u root sh -c "echo 'vm.max_map_count = 1048576' >> /etc/sysctl.conf && sysctl -w vm.max_map_count=1048576"`
2. `powershell -ExecutionPolicy Bypass -File scripts\init-env.ps1` creates `.env` with random passwords.
   Put your DeepSeek key into `.env` (`DEEPSEEK_API_KEY=`).
3. `docker compose up -d` (first start pulls ~6.6 GB of images), then copy the CA for the host clients:
   `docker compose cp es01:/usr/share/elasticsearch/config/certs/ca/ca.crt elk/certs/ca.crt`
4. `py -3.13 -m venv .venv` and `.venv\Scripts\python -m pip install -r requirements.txt`
5. `.venv\Scripts\python scripts\verify_stack.py` — TLS, auth, least privilege, health, ports.

Kibana: http://localhost:5601 (user `elastic`, password `ELASTIC_PASSWORD` from `.env`).

## Data

```
.venv\Scripts\python scripts\download_apt29.py      # OTRF APT29 Day 1, verified by git blob SHA-1
.venv\Scripts\python scripts\prepare_sources.py     # split by log type (gzip; see the Defender note in the record)
.venv\Scripts\python scripts\build_attack_kb.py     # MITRE ATT&CK v20.0 knowledge base
```

## Ingest ("point the system at a source")

```
.venv\Scripts\python -m hunt templates install
.venv\Scripts\python -m hunt ingest pull   data\sources\sysmon.ndjson.gz     --source-id apt29-sysmon
.venv\Scripts\python -m hunt ingest push   data\sources\security.ndjson.gz   --source-id apt29-security
.venv\Scripts\python -m hunt ingest stream data\sources\powershell.ndjson.gz --source-id apt29-powershell --eps 500
.venv\Scripts\python -m hunt ingest pull   data\sources\zeek\SCRANTON        --source-id zeek-scranton
.venv\Scripts\python -m hunt status
```
or all six sources at once: `.venv\Scripts\python scripts\ingest_all.py`. Each command delivers the source, lets the
onboarding agent pick or create a parsing template, backfills, and prints a full-data quality check.
Logstash deletes each file in `dropzone/` after reading it, so a Docker restart cannot make it read the file twice;
the originals stay in `data/sources/`. A file can also be dropped in by hand (copy it into `dropzone\.staging\`,
then move it into `dropzone\<source_id>\`) while `.venv\Scripts\python -m hunt watch` runs.
Start over: `.venv\Scripts\python -m hunt reset --yes` (add `--keep-generated` to keep agent-made templates).

## MCP server

`.venv\Scripts\python -m hunt mcp` speaks MCP over stdio (any MCP client can launch it; `scripts\mcp_smoke.py`
shows a client). Read-only Elasticsearch user `hunt_mcp`; every call is audited with a query_id.

## Hunt

```
.venv\Scripts\python -m hunt hunt "An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access)." --profile converged
.venv\Scripts\python -m hunt evaluate runs\hunts\<run>
.venv\Scripts\python -m hunt compare runs\hunts\<run A> runs\hunts\<run B>
.venv\Scripts\python scripts\evaluate_step8.py runs\hunts\<run>      # a lateral-movement hunt, scored on APT29 step 8
```
Each run writes `runs/hunts/<run>/report.md` (verdict, incidents, findings with evidence, per-technique conclusions,
coverage matrix, every query) plus the raw material: LLM transcript, MCP audit log, plan, results, verification.

- Frozen playbook: `--plan-from playbooks/credential-access-v1` re-uses a stored plan, so repeated runs execute the
  same queries (see the repeatability experiment in the record).
- `--profile baseline` is the unconstrained agent used as the experiment's reference.
- `python -m hunt render <run>` re-creates report.md from report.json.

## Tests

`.venv\Scripts\python -m pytest -q` (unit tests of the deterministic parts).
