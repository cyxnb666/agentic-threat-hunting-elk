#!/bin/bash
# One-shot: create the CA and the es01 certificate (same certutil calls as the official Elastic
# docker-compose example, reduced to one node). Runs before Elasticsearch starts; idempotent.
set -euo pipefail
cd /usr/share/elasticsearch

if [ ! -f config/certs/ca.zip ]; then
  echo "Creating CA"
  bin/elasticsearch-certutil ca --silent --pem -out config/certs/ca.zip
  unzip -q config/certs/ca.zip -d config/certs
fi
if [ ! -f config/certs/certs.zip ]; then
  echo "Creating certs"
  printf 'instances:\n  - name: es01\n    dns:\n      - es01\n      - localhost\n    ip:\n      - 127.0.0.1\n' > config/certs/instances.yml
  bin/elasticsearch-certutil cert --silent --pem -out config/certs/certs.zip --in config/certs/instances.yml \
    --ca-cert config/certs/ca/ca.crt --ca-key config/certs/ca/ca.key
  unzip -q config/certs/certs.zip -d config/certs
fi

echo "Setting file permissions"
chown -R root:root config/certs
find config/certs -type d -exec chmod 755 {} \;
find config/certs -type f -exec chmod 640 {} \;
# The CA certificate is public; the logstash user (uid/gid 1000, not in the root group) must read it.
chmod 644 config/certs/ca/ca.crt
echo "Certificates ready"
