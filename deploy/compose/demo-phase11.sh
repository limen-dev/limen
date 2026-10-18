#!/usr/bin/env bash
# Phase 11 demo: RabbitMQ and Kafka through Limen. AMQP and Kafka clients
# connect to local listeners without a password; the worker logs in as the
# role's broker user, every operation is checked and audited, and message
# bodies and record values stay out of the audit trail. Kafka runs as a real
# three-broker cluster, which proves the advertised-address rewrite.
#
#   deploy/compose/demo-phase11.sh          # resets this demo's stack first (down -v)
#   deploy/compose/demo-phase11.sh --keep   # reuse the running stack
#
# Own compose project (limen-mq) on its own ports. The clients are pika
# (AMQP) and confluent-kafka (librdkafka, the library kcat is built on),
# installed into a throw-away virtualenv under .state/.
set -euo pipefail
keep=false
[ "${1:-}" = "--keep" ] && keep=true

root="$(cd "$(dirname "$0")/../.." && pwd)"
here="$root/deploy/compose"
# shellcheck source=dev-users.sh
source "$here/dev-users.sh"
project="${LIMEN_MQ_PROJECT:-limen-mq}"
state="$here/.state/$project"
mkdir -p "$state"
export LIMEN_MQ_PROXY_PORT="${LIMEN_MQ_PROXY_PORT:-39443}" LIMEN_MQ_HEALTH_PORT="${LIMEN_MQ_HEALTH_PORT:-39444}"
export LIMEN_MQ_DEX_PORT="${LIMEN_MQ_DEX_PORT:-39556}" LIMEN_MQ_CP_PORT="${LIMEN_MQ_CP_PORT:-39081}" LIMEN_MQ_S3_PORT="${LIMEN_MQ_S3_PORT:-39333}"
compose=(docker compose --progress=quiet -p "$project" -f "$here/docker-compose.messaging.yml")
export LIMEN_BIN="${LIMEN_BIN:-$root/target/release/limen}"
export LIMEN_PROXY="localhost:$LIMEN_MQ_PROXY_PORT" LIMEN_DEX_URL="http://localhost:$LIMEN_MQ_DEX_PORT"
export LIMEN_DEV_CA="$state/internal-ca.pem"
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
wait_for() { local what="$1"; shift; for _ in $(seq 1 240); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done; fail "timed out waiting for $what"; }

step "Build and start the stack ($project)"
# The image build caches cargo output across checkouts by file time; fresh times
# keep it from reusing another worktree's stale build of these crates.
[ -n "${LIMEN_NO_TOUCH:-}" ] || find "$root/crates" -name '*.rs' -exec touch {} +
(cd "$root" && cargo build --release -q -p limen-cli)
$keep || { echo "Resetting this demo's stack (project $project, down -v). Use --keep to skip."; "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1; }
"${compose[@]}" up -d --build --quiet-pull >/dev/null
wait_for "proxy readiness" curl -sf "http://localhost:$LIMEN_MQ_HEALTH_PORT/readyz"
"${compose[@]}" cp control-plane:/var/lib/limen/ca-public/internal-ca.pem "$state/internal-ca.pem" >/dev/null

# LIMEN_HOME is per person, so both stay logged in.
export HOME_ADMIN="$state/home-admin" HOME_DEV="$state/home-dev"
rm -rf "$HOME_ADMIN" "$HOME_DEV"
LIMEN_HOME="$HOME_ADMIN" "$here/dev-login.sh" "$ADMIN" >/dev/null
LIMEN_HOME="$HOME_ADMIN" "$LIMEN_BIN" admin apply "$root/examples/policy" --source-ref demo-phase11 >/dev/null
# Roles are mapped at login, so both sign in again now that the policy exists.
LIMEN_HOME="$HOME_ADMIN" "$here/dev-login.sh" "$ADMIN" >/dev/null
LIMEN_HOME="$HOME_DEV" "$here/dev-login.sh" "$DEVELOPER" >/dev/null
wait_for "worker tunnels" sh -c "curl -sf http://localhost:$LIMEN_MQ_HEALTH_PORT/tunnels | grep -q worker_id"
sleep 11   # proxy and worker pick up the new policy within their 10s refresh
pass "stack up, policy applied"

step "Kafka: topics, ACLs, SCRAM users"
kx() { "${compose[@]}" exec -T kafka-1 "$@"; }
cat > "$state/admin.properties" <<'PROPS'
security.protocol=SASL_PLAINTEXT
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="limen-admin" password="admin-dev-only";
PROPS
"${compose[@]}" cp "$state/admin.properties" kafka-1:/tmp/admin.properties >/dev/null
BIN=/opt/kafka/bin; BS="--bootstrap-server kafka-1:9092 --command-config /tmp/admin.properties"
wait_for "kafka cluster" kx $BIN/kafka-topics.sh $BS --list
for t in "orders.new:6" "payments:3"; do
  kx $BIN/kafka-topics.sh $BS --create --if-not-exists --topic "${t%%:*}" --partitions "${t##*:}" --replication-factor 3 >/dev/null
done
# The second layer, on the brokers: the consumer reads orders.* and groups dev-* only.
kx $BIN/kafka-acls.sh $BS --add --allow-principal User:limen-consumer --operation Read --operation Describe --topic orders. --resource-pattern-type prefixed >/dev/null 2>&1
kx $BIN/kafka-acls.sh $BS --add --allow-principal User:limen-consumer --operation Read --group dev- --resource-pattern-type prefixed >/dev/null 2>&1
kx $BIN/kafka-configs.sh $BS --alter --add-config 'SCRAM-SHA-512=[password=scram-admin-dev-only]' --entity-type users --entity-name limen-admin >/dev/null
kx $BIN/kafka-configs.sh $BS --alter --add-config 'SCRAM-SHA-512=[password=scram-consumer-dev-only]' --entity-type users --entity-name limen-consumer >/dev/null
pass "orders.new (6 partitions, RF 3) and payments exist; ACLs and SCRAM users set"

step "Python clients"
if [ ! -x "$state/venv/bin/python" ]; then
  python3 -m venv "$state/venv"
  "$state/venv/bin/pip" install -q pika confluent-kafka
fi
export LIMEN_MQ_STATE="$state" LIMEN_MQ_COMPOSE_PROJECT="$project" LIMEN_MQ_CP_AUDIT_CMD="${compose[*]}"
export LIMEN_COMPOSE_FILE="$here/docker-compose.messaging.yml"
"$state/venv/bin/python" -I "$here/targets/messaging/scenarios.py"
printf '\n\033[32mPhase 11 demo passed.\033[0m\n'
echo "Stop it with: docker compose -p $project -f deploy/compose/docker-compose.messaging.yml down -v"
