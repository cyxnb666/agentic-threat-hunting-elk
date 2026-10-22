#!/bin/bash
# One-shot setup container, runs after Elasticsearch is healthy. Adapted from the official Elastic
# docker-compose example (https://github.com/elastic/elasticsearch/blob/main/docs/reference/setup/install/docker/docker-compose.yml):
#   - same kibana_system password step (certificate generation moved to certs.sh)
#   - added: least-privilege role + user for Logstash (privilege names from the Elasticsearch
#     security-privileges reference: create_doc, auto_configure; cluster monitor for connectivity checks)
set -euo pipefail
cd /usr/share/elasticsearch

for v in ELASTIC_PASSWORD KIBANA_PASSWORD LOGSTASH_WRITER_PASSWORD HUNT_AGENT_PASSWORD HUNT_MCP_PASSWORD; do
  if [ -z "${!v:-}" ]; then echo "Set $v in .env (run scripts/init-env.ps1)"; exit 1; fi
done

# Source registry (./registry, written by the onboarding agent, not in git). Logstash's translate filter refuses to
# start a pipeline whose dictionary file is missing ("File does not exist or cannot be opened", checked 2026-10-22
# with logstash 9.5.5), and Logstash starts only after this container. Missing files are created empty; existing
# ones are left as they are.
for f in sources.json sources_meta.json; do
  if [ ! -f "/registry/$f" ]; then echo '{}' > "/registry/$f"; echo "Created empty registry/$f"; fi
done

CA=config/certs/ca/ca.crt
ES=https://es01:9200

echo "Waiting for Elasticsearch availability"
until curl -s --cacert $CA $ES | grep -q "missing authentication credentials"; do sleep 10; done

echo "Setting kibana_system password"
until curl -s -X POST --cacert $CA -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json" \
  $ES/_security/user/kibana_system/_password -d "{\"password\":\"${KIBANA_PASSWORD}\"}" | grep -q "^{}"; do sleep 10; done

echo "Creating role logstash_writer"
until curl -s -X PUT --cacert $CA -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json" \
  $ES/_security/role/logstash_writer -d '{
    "cluster": ["monitor"],
    "indices": [{"names": ["logs-*"], "privileges": ["create_doc", "auto_configure"]}]
  }' | grep -q '"role"'; do sleep 10; done

echo "Creating user logstash_internal"
until curl -s -X PUT --cacert $CA -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json" \
  $ES/_security/user/logstash_internal -d "{
    \"password\": \"${LOGSTASH_WRITER_PASSWORD}\",
    \"roles\": [\"logstash_writer\"],
    \"full_name\": \"Logstash writer (logs-* only)\"
  }" | grep -q '"created"'; do sleep 10; done

# Onboarding agent: manages parsing templates (ingest pipelines), reads/backfills unparsed events.
#   manage_ingest_pipelines -> create/simulate templates; read + create_doc on logs-* -> reindex backlog into
#   the parsed data streams; maintenance -> refresh before counting; delete on logs-hunt.unparsed-* only ->
#   remove the backlog after it was re-ingested.
echo "Creating role hunt_ingest_agent and user hunt_agent"
until curl -s -X PUT --cacert $CA -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json" \
  $ES/_security/role/hunt_ingest_agent -d '{
    "cluster": ["monitor", "manage_ingest_pipelines"],
    "indices": [
      {"names": ["logs-*"], "privileges": ["read", "view_index_metadata", "create_doc", "auto_configure", "maintenance"]},
      {"names": ["logs-hunt.unparsed-*"], "privileges": ["delete"]}
    ]
  }' | grep -q '"role"'; do sleep 10; done
until curl -s -X PUT --cacert $CA -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json" \
  $ES/_security/user/hunt_agent -d "{\"password\": \"${HUNT_AGENT_PASSWORD}\", \"roles\": [\"hunt_ingest_agent\"],
    \"full_name\": \"Onboarding agent\"}" | grep -q '"created"'; do sleep 10; done

# MCP server: read-only. Search/aggregate/ES|QL need index "read"; read_pipeline lets it list templates.
echo "Creating role hunt_reader and user hunt_mcp"
until curl -s -X PUT --cacert $CA -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json" \
  $ES/_security/role/hunt_reader -d '{
    "cluster": ["monitor", "read_pipeline"],
    "indices": [{"names": ["logs-*"], "privileges": ["read", "view_index_metadata"]}]
  }' | grep -q '"role"'; do sleep 10; done
until curl -s -X PUT --cacert $CA -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json" \
  $ES/_security/user/hunt_mcp -d "{\"password\": \"${HUNT_MCP_PASSWORD}\", \"roles\": [\"hunt_reader\"],
    \"full_name\": \"MCP server (read-only)\"}" | grep -q '"created"'; do sleep 10; done

echo "logs@custom: no replicas (single node) + searchable long text fields"
# logs@custom is the hook the built-in logs-*-* template reserves for local changes; it is composed before
# ecs@mappings, so these dynamic templates win. Without them, long strings (PowerShell script blocks, full
# Windows event messages, Sysmon call traces) fall into ecs@mappings' keyword/ignore_above 1024 rule and are
# not searchable. wildcard has no length limit; the .text sub-field adds full-text search.
# event.code is pinned to keyword (its ECS type): Windows exports carry EventID as a JSON number, which dynamic
# mapping would turn into long, and the type would then differ between datasets.
until curl -s -X PUT --cacert $CA -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json"   $ES/_component_template/logs@custom -d '{
    "template": {
      "settings": {"index.number_of_replicas": 0},
      "mappings": {
        "properties": {"event": {"properties": {"code": {"type": "keyword"}}}},
        "dynamic_templates": [{"hunt_long_text": {
        "match_mapping_type": "string",
        "match": ["Message", "ScriptBlockText", "script_block_text", "CommandLine", "ParentCommandLine",
                  "CallTrace", "Payload", "ContextInfo", "Details", "Conditions", "TaskContentNew", "Properties"],
        "mapping": {"type": "wildcard", "fields": {"text": {"type": "match_only_text"}}}}}]}
    }}' | grep -q '"acknowledged":true'; do sleep 10; done

echo "All done!"
