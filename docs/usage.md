# Usage guide

This guide assumes a Windows 11 computer with Docker Desktop and Python 3.13 installed (`py -3.13` works), with the
project in `C:\Users\yaoxi\Downloads\project`. Run every command below in PowerShell, from the project folder:

```
cd C:\Users\yaoxi\Downloads\project
```

## 1. First-time setup (once only)

1. **Set the kernel parameter in the Docker VM** (required by Elasticsearch; without it Elasticsearch may not start):
   ```
   wsl -d docker-desktop -u root sh -c "echo 'vm.max_map_count = 1048576' >> /etc/sysctl.conf && sysctl -w vm.max_map_count=1048576"
   ```
   It worked if you see `vm.max_map_count = 1048576`.
2. **Create the configuration file .env (random passwords)**:
   ```
   powershell -ExecutionPolicy Bypass -File scripts\init-env.ps1
   ```
   Then open `.env` in Notepad, put your DeepSeek key after `DEEPSEEK_API_KEY=` and save it.
3. **Create the Python environment**:
   ```
   py -3.13 -m venv .venv
   .venv\Scripts\python -m pip install -r requirements.txt
   ```
4. **Download and prepare the data** (about 15 MB of dataset + 55 MB of ATT&CK knowledge base):
   ```
   .venv\Scripts\python scripts\download_apt29.py
   .venv\Scripts\python scripts\prepare_sources.py
   .venv\Scripts\python scripts\build_attack_kb.py
   ```

## One-command rebuild and self-check

After part 1, `.venv\Scripts\python scripts\rebuild_all.py` deletes the project data and the Docker volumes,
then starts ELK, runs the security checks, installs the templates, ingests all 6 sources, checks that the onboarding
agent onboarded every source, creates the Kibana data views, runs the full self-check and finally prints
`REBUILD OK` (about 6 minutes).
Every rebuild starts from nothing, whether ELK is running or stopped; `--wipe` is still accepted and changes nothing.
The containers do not restart by themselves. After a restart of the computer or Docker Desktop, first run
`docker compose up -d`, then `.venv\Scripts\python scripts\verify_all.py`, and check that everything passes.
Parts 2 and 3 below are what this command does internally; they can also be run on their own.

## 2. Start ELK

```
docker compose up -d
docker compose cp es01:/usr/share/elasticsearch/config/certs/ca/ca.crt elk/certs/ca.crt
.venv\Scripts\python scripts\verify_stack.py
```
The last command should show PASS for every check. Kibana: <http://localhost:5601>, user `elastic`, password
`ELASTIC_PASSWORD` from `.env`. `.venv\Scripts\python scripts\kibana_dataviews.py` creates a Kibana data view for
each dataset.

Stop: `docker compose stop`; start again: `docker compose start`.

## 3. Ingest logs ("point the system at a log source")

```
.venv\Scripts\python -m hunt templates install
.venv\Scripts\python scripts\ingest_all.py
```
`ingest_all.py` ingests the 6 sources one after another through the three channels (about 4 minutes). A single
source can also be ingested on its own:

```
.venv\Scripts\python -m hunt ingest pull   <file or folder>  --source-id <name>     # put into the drop folder
.venv\Scripts\python -m hunt ingest push   <file>            --source-id <name>     # pushed by an endpoint agent
.venv\Scripts\python -m hunt ingest stream <file>            --source-id <name> --eps 500   # continuous syslog stream
```
The system then does the rest by itself: deliver the logs → the onboarding agent inspects samples → pick or create a
parsing template → validate → register → backfill the backlog → full-data quality check.
Status: `.venv\Scripts\python -m hunt status`. Clear everything and start over: `.venv\Scripts\python -m hunt reset --yes`.

Pull channel: Logstash deletes each file in `dropzone` after reading it, so a Docker restart cannot make it read a
file twice; the original files stay in `data\sources\`.
A file can also be dropped in by hand: first run `.venv\Scripts\python -m hunt watch`, then copy the file into
`dropzone\.staging\` and move it into `dropzone\<source name>\`; the system ingests it automatically.

## 4. Threat hunt

```
.venv\Scripts\python -m hunt hunt "An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access)." --profile converged
```
It takes about 10 to 12 minutes. The terminal shows no output while it runs and prints one result line at the end.
The result is in `runs\hunts\<time>-converged\report.md`: the verdict, every finding with its evidence (event ID,
field values, ID of the query that produced it), the conclusion for each ATT&CK technique, the coverage matrix and
every query of the run.

- Re-use the frozen hunt playbook (two runs execute exactly the same queries): add
  `--plan-from playbooks/credential-access-v1` at the end of the command
- Score against the ground truth: `.venv\Scripts\python -m hunt evaluate runs\hunts\<run folder>`
- Compare two runs: `.venv\Scripts\python -m hunt compare runs\hunts\<A> runs\hunts\<B>`
- A run of the lateral-movement hypothesis, scored on APT29 step 8:
  `.venv\Scripts\python scripts\evaluate_step8.py runs\hunts\<run folder>`

## 5. MCP server

`.venv\Scripts\python -m hunt mcp` serves MCP over stdio; any MCP client can launch it as a subprocess.
`scripts\mcp_smoke.py` is a minimal client example that calls all 9 tools one by one.

## 6. Full self-check

```
.venv\Scripts\python scripts\verify_all.py
```
Checks ELK security and health, whether each source's document count matches its source file, the registry and
templates, every MCP tool, and the unit tests.
