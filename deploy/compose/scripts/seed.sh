# shellcheck shell=bash disable=SC2154
# What setup.sh does for each target stack once it is running: wait until the
# target answers, then create its roles and sample data. Sourced by setup.sh,
# which provides $compose, $here, $LIMEN_ENV and wait_for/fail.

seed_db() {
  wait_for "postgres-target" "${compose[@]}" exec -T postgres-target pg_isready -U postgres
  wait_for "mysql-target" "${compose[@]}" exec -T mysql-target mysqladmin ping -h 127.0.0.1 -uroot -pmysql-target-dev-only --silent
  "${compose[@]}" run --rm db-bootstrap --db-bootstrap-once >/dev/null 2>&1 || fail "db bootstrap failed"
}

seed_redis() {
  local cli=(--user write --pass rw-dev-only --no-auth-warning)
  wait_for "redis" "${compose[@]}" exec -T redis-target redis-cli "${cli[@]}" ping
  wait_for "valkey" "${compose[@]}" exec -T valkey-target valkey-cli "${cli[@]}" ping
  "${compose[@]}" exec -T redis-target redis-cli "${cli[@]}" SET app:greeting hello >/dev/null
  "${compose[@]}" exec -T valkey-target valkey-cli "${cli[@]}" SET app:greeting hello-from-valkey >/dev/null
}

seed_mongo() {
  wait_for "mongodb" "${compose[@]}" exec -T mongo-target mongosh --quiet --tls --tlsCAFile /tls/ca.pem --host localhost -u read -p limen-read-dev-only --authenticationDatabase admin orders --eval 'db.customers.countDocuments()'
}

seed_search() {
  wait_for "elasticsearch" "${compose[@]}" exec -T elasticsearch-target curl -sf -u elastic:elastic-dev-only "localhost:9200/_cluster/health?wait_for_status=yellow&timeout=1s"
  wait_for "opensearch" "${compose[@]}" exec -T opensearch-target curl -sf --cacert /usr/share/opensearch/config/root-ca.pem --resolve node-0.example.com:9200:127.0.0.1 -u admin:Dev-only-Opensearch-1 "https://node-0.example.com:9200/_cluster/health?wait_for_status=yellow&timeout=1s"
  already_done search "elasticsearch-search-${LIMEN_ENV}" "opensearch-search-${LIMEN_ENV}" && return 0
  "$here/config/targets/search/provision.sh" "elasticsearch-search-${LIMEN_ENV}" "opensearch-search-${LIMEN_ENV}" >/dev/null || fail "search provisioning failed"
  mark_done search "elasticsearch-search-${LIMEN_ENV}" "opensearch-search-${LIMEN_ENV}"
}

seed_messaging() {
  wait_for "rabbitmq" "${compose[@]}" exec -T rabbitmq-target rabbitmq-diagnostics -q ping
  already_done kafka "kafka-1-messaging-${LIMEN_ENV}" "kafka-2-messaging-${LIMEN_ENV}" "kafka-3-messaging-${LIMEN_ENV}" && return 0
  "$here/config/targets/messaging/provision.sh" "kafka-1-messaging-${LIMEN_ENV}" >/dev/null || fail "Kafka provisioning failed"
  mark_done kafka "kafka-1-messaging-${LIMEN_ENV}" "kafka-2-messaging-${LIMEN_ENV}" "kafka-3-messaging-${LIMEN_ENV}"
}
