#!/usr/bin/env bash
# Phase 11 demo: RabbitMQ and Kafka through Limen. AMQP and Kafka clients
# connect to local listeners without a password; the worker logs in as the
# role's broker user, every operation is checked and audited, and message
# bodies and record values stay out of the audit trail. Kafka runs as a real
# three-broker cluster, which proves the advertised-address rewrite.
#
#   demos/demo-phase11.sh          # resets this demo's stack first (down -v)
#   demos/demo-phase11.sh --keep   # reuse the running stack
#
# Runs as its own compose project (limen-messaging) on its own ports, so it can
# sit next to the dev stack. Targets are real RabbitMQ 4 and a real three-broker
# Kafka 3.9 cluster (SASL, authorizer on). The clients are pika (AMQP) and
# confluent-kafka (librdkafka, the library kcat is built on), installed into a
# throw-away virtualenv under .state/. Amazon MQ and MSK are not covered here:
# no AWS account.
set -euo pipefail
keep=false
[ "${1:-}" = "--keep" ] && keep=true

root="$(cd "$(dirname "$0")/.." && pwd)"
here="$root/deploy/compose"
# shellcheck source=../deploy/compose/scripts/dev-users.sh
source "$here/scripts/dev-users.sh"
# LIMEN_MESSAGING_PROJECT and the *_PORT variables let a second copy run beside this one.
project="${LIMEN_MESSAGING_PROJECT:-limen-messaging}"
state="$here/.state/$project"
mkdir -p "$state"
export LIMEN_MESSAGING_PROXY_PORT="${LIMEN_MESSAGING_PROXY_PORT:-39443}" LIMEN_MESSAGING_HEALTH_PORT="${LIMEN_MESSAGING_HEALTH_PORT:-39444}"
export LIMEN_MESSAGING_DEX_PORT="${LIMEN_MESSAGING_DEX_PORT:-39556}" LIMEN_MESSAGING_CP_PORT="${LIMEN_MESSAGING_CP_PORT:-39081}" LIMEN_MESSAGING_S3_PORT="${LIMEN_MESSAGING_S3_PORT:-39333}"
export LIMEN_PROJECT="$project" LIMEN_STATE_DIR="$state" LIMEN_IMAGE_TAG=messaging
export LIMEN_PORT_PROXY="$LIMEN_MESSAGING_PROXY_PORT" LIMEN_PORT_HEALTH="$LIMEN_MESSAGING_HEALTH_PORT" LIMEN_PORT_DEX="$LIMEN_MESSAGING_DEX_PORT"
export LIMEN_PORT_CP="$LIMEN_MESSAGING_CP_PORT" LIMEN_PORT_S3="$LIMEN_MESSAGING_S3_PORT"
export LIMEN_PORT_POSTGRES="${LIMEN_MESSAGING_PG_PORT:-39432}" LIMEN_PORT_KMS="${LIMEN_MESSAGING_KMS_PORT:-39099}"
# shellcheck source=../deploy/compose/scripts/lib.sh
source "$here/scripts/lib.sh"
stack_setup messaging
export LIMEN_BIN="${LIMEN_BIN:-$root/target/release/limen}"
export LIMEN_PROXY="localhost:$LIMEN_MESSAGING_PROXY_PORT" LIMEN_DEX_URL="http://localhost:$LIMEN_MESSAGING_DEX_PORT"
export LIMEN_DEV_CA="$state/internal-ca.pem"
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
wait_for() { local what="$1"; shift; for _ in $(seq 1 720); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done; fail "timed out waiting for $what"; }

step "Build and start the stack ($project)"
# The image build caches cargo output across checkouts by file time; fresh times
# keep it from reusing another worktree's stale build of these crates.
find "$root/crates" -name '*.rs' -exec touch {} +
(cd "$root" && cargo build --release -q -p limen-cli)
$keep || { echo "Resetting this demo's stack (project $project, down -v). Use --keep to skip."; "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1; }
"${compose[@]}" up -d --build --quiet-pull >/dev/null
wait_for "proxy readiness" curl -sf "http://localhost:$LIMEN_MESSAGING_HEALTH_PORT/readyz"
"${compose[@]}" cp control-plane:/var/lib/limen/ca-public/internal-ca.pem "$state/internal-ca.pem" >/dev/null

# LIMEN_HOME is per person, so both stay logged in.
export HOME_ADMIN="$state/home-admin" HOME_DEV="$state/home-dev"
rm -rf "$HOME_ADMIN" "$HOME_DEV"
LIMEN_HOME="$HOME_ADMIN" "$here/scripts/dev-login.sh" "$ADMIN" >/dev/null
LIMEN_HOME="$HOME_ADMIN" "$LIMEN_BIN" admin apply "$root/examples/policy" --source-ref demo-phase11 >/dev/null
# Roles are mapped at login, so both sign in again now that the policy exists.
LIMEN_HOME="$HOME_ADMIN" "$here/scripts/dev-login.sh" "$ADMIN" >/dev/null
LIMEN_HOME="$HOME_DEV" "$here/scripts/dev-login.sh" "$DEVELOPER" >/dev/null
wait_for "worker tunnels" sh -c "curl -sf http://localhost:$LIMEN_MESSAGING_HEALTH_PORT/tunnels | grep -q worker_id"
sleep 11   # proxy and worker pick up the new policy within their 10s refresh
pass "stack up, policy applied"

step "Kafka: topics, ACLs, SCRAM users"
wait_for "rabbitmq" "${compose[@]}" exec -T rabbitmq-target rabbitmq-diagnostics -q ping
"$here/config/targets/messaging/provision.sh" "kafka-1-messaging-$LIMEN_ENV" >/dev/null
pass "orders.new (6 partitions, RF 3) and payments exist; ACLs and SCRAM users set"

step "Python clients"
if [ ! -x "$state/venv/bin/python" ]; then
  python3 -m venv "$state/venv"
  "$state/venv/bin/pip" install -q pika confluent-kafka
fi
export LIMEN_MQ_STATE="$state"
LIMEN_COMPOSE_JSON="$(python3 -I -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "${compose[@]}")"
export LIMEN_COMPOSE_JSON
"$state/venv/bin/python" -I "$here/config/targets/messaging/scenarios.py"
printf '\n\033[32mPhase 11 demo passed.\033[0m\n'
echo "Reset it by running this script without --keep"
