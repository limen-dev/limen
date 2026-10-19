#!/usr/bin/env bash
# Creates the Kafka topics, ACLs, and SCRAM users the example policy names, on the
# compose three-broker cluster (dev passwords; see credentials.json). Idempotent.
# These are the cluster's own controls, the second layer under Limen's policy
# (ADR-0037). RabbitMQ needs nothing: its users and vhosts come from
# rabbitmq-definitions.json.
#
#   provision.sh KAFKA_CONTAINER
set -euo pipefail
kafka="$1"

kx() { docker exec -i "$kafka" "$@"; }
bin=/opt/kafka/bin
bs=(--bootstrap-server kafka-1:9092 --command-config /tmp/admin.properties)

docker exec -i "$kafka" sh -c 'cat > /tmp/admin.properties' <<'PROPS'
security.protocol=SASL_PLAINTEXT
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="limen-admin" password="admin-dev-only";
PROPS

# The cluster takes a while to elect its controller.
for _ in $(seq 1 240); do
  kx "$bin/kafka-topics.sh" "${bs[@]}" --list >/dev/null 2>&1 && break
  sleep 0.5
done
kx "$bin/kafka-topics.sh" "${bs[@]}" --list >/dev/null

for t in "orders.new:6" "payments:3"; do
  kx "$bin/kafka-topics.sh" "${bs[@]}" --create --if-not-exists --topic "${t%%:*}" --partitions "${t##*:}" --replication-factor 3 >/dev/null
done
# The consumer reads orders.* and groups dev-* only.
kx "$bin/kafka-acls.sh" "${bs[@]}" --add --allow-principal User:limen-consumer --operation Read --operation Describe --topic orders. --resource-pattern-type prefixed >/dev/null 2>&1
kx "$bin/kafka-acls.sh" "${bs[@]}" --add --allow-principal User:limen-consumer --operation Read --group dev- --resource-pattern-type prefixed >/dev/null 2>&1
kx "$bin/kafka-configs.sh" "${bs[@]}" --alter --add-config 'SCRAM-SHA-512=[password=scram-admin-dev-only]' --entity-type users --entity-name limen-admin >/dev/null
kx "$bin/kafka-configs.sh" "${bs[@]}" --alter --add-config 'SCRAM-SHA-512=[password=scram-consumer-dev-only]' --entity-type users --entity-name limen-consumer >/dev/null
echo "provisioned"
