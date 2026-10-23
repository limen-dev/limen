#!/usr/bin/env bash
# Creates the engine-side roles and users the example policy names, on the
# compose Elasticsearch and OpenSearch (dev passwords; see credentials.json).
# Idempotent. These are the engines' own controls, the second layer under
# Limen's policy (ADR-0036).
#
#   provision.sh ES_CONTAINER OS_CONTAINER
set -euo pipefail
es="$1" os="$2"

es_put() { docker exec "$es" curl -sf -u elastic:elastic-dev-only -H 'content-type: application/json' -X PUT "localhost:9200$1" -d "$2" >/dev/null; }
os_put() {
  docker exec "$os" curl -sf --cacert /usr/share/opensearch/config/root-ca.pem --resolve node-0.example.com:9200:127.0.0.1 \
    -u admin:Dev-only-Opensearch-1 -H 'content-type: application/json' -X PUT "https://node-0.example.com:9200$1" -d "$2" >/dev/null
}

# Elasticsearch: read-only on app-* and logs-*; read/write on app-*.
es_put /_security/role/limen_read '{"cluster":["monitor"],"indices":[{"names":["app-*","logs-*"],"privileges":["read","view_index_metadata"]}]}'
es_put /_security/role/limen_write '{"cluster":["monitor"],"indices":[{"names":["app-*"],"privileges":["read","write","create_index","view_index_metadata"]}]}'
es_put /_security/user/read '{"password":"read-dev-only-1","roles":["limen_read"]}'
es_put /_security/user/write '{"password":"write-dev-only-1","roles":["limen_write"]}'

# OpenSearch: the same shape through the security plugin.
os_put /_plugins/_security/api/roles/limen_read '{"cluster_permissions":["cluster_monitor"],"index_permissions":[{"index_patterns":["app-*","logs-*"],"allowed_actions":["read","indices:admin/get"]}]}'
os_put /_plugins/_security/api/roles/limen_write '{"cluster_permissions":["cluster_monitor","indices:data/write/bulk*"],"index_permissions":[{"index_patterns":["app-*"],"allowed_actions":["read","write","create_index","indices:admin/get"]}]}'
os_put /_plugins/_security/api/internalusers/read '{"password":"Read-dev-only-1","backend_roles":[]}'
os_put /_plugins/_security/api/internalusers/write '{"password":"Write-dev-only-1","backend_roles":[]}'
os_put /_plugins/_security/api/rolesmapping/limen_read '{"users":["read"]}'
os_put /_plugins/_security/api/rolesmapping/limen_write '{"users":["write"]}'
echo "provisioned"
