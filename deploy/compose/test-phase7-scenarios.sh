#!/usr/bin/env bash
# Phase 7 scenario tests: many ways to use, abuse, and break Redis access
# through Limen, against real Redis 7.4 and Valkey 8.0 (and a TLS Redis).
#
#   deploy/compose/test-phase7-scenarios.sh            # fresh stack, run, leave it up
#   deploy/compose/test-phase7-scenarios.sh --keep     # reuse the running stack
#   deploy/compose/test-phase7-scenarios.sh --down     # remove the stack afterwards
#
# Its own compose project, so it runs beside other stacks. Override
# LIMEN_REDIS_PROJECT and the LIMEN_REDIS_*_PORT variables if another copy
# of this stack is running (see docker-compose.redis.yml).
set -euo pipefail
args=("$@")
keep=false; down=false
for a in ${args[@]+"${args[@]}"}; do case "$a" in --keep) keep=true;; --down) down=true;; esac; done

root="$(cd "$(dirname "$0")/../.." && pwd)"
here="$root/deploy/compose"
# shellcheck source=dev-users.sh
source "$here/dev-users.sh"
export LIMEN_REDIS_PROJECT="${LIMEN_REDIS_PROJECT:-limen-redis-scn}"
export LIMEN_REDIS_PROXY_PORT="${LIMEN_REDIS_PROXY_PORT:-36443}" LIMEN_REDIS_HEALTH_PORT="${LIMEN_REDIS_HEALTH_PORT:-36444}"
export LIMEN_REDIS_DEX_PORT="${LIMEN_REDIS_DEX_PORT:-36556}" LIMEN_REDIS_CP_PORT="${LIMEN_REDIS_CP_PORT:-36081}" LIMEN_REDIS_S3_PORT="${LIMEN_REDIS_S3_PORT:-36333}"
state="$here/.state/$LIMEN_REDIS_PROJECT"
mkdir -p "$state/tls"
export LIMEN_REDIS_TLS_DIR="$state/tls"
files=(-f "$here/docker-compose.redis.yml" -f "$here/docker-compose.redis-tls.yml" --profile redis)
compose=(docker compose --progress=quiet -p "$LIMEN_REDIS_PROJECT" "${files[@]}")
export LIMEN_BIN="${LIMEN_BIN:-$root/target/release/limen}"
export LIMEN_PROXY="localhost:$LIMEN_REDIS_PROXY_PORT" LIMEN_DEX_URL="http://localhost:$LIMEN_REDIS_DEX_PORT"
export LIMEN_DEV_CA="$state/internal-ca.pem"
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
wait_for() { local what="$1"; shift; for _ in $(seq 1 120); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done; fail "timed out waiting for $what"; }

step "Certificates for the TLS Redis"
if [ ! -f "$state/tls/server.crt" ]; then
  (cd "$state/tls" \
    && openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 2 -subj "/CN=limen-scenario-ca" 2>/dev/null \
    && openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=redis-tls" 2>/dev/null \
    && printf 'subjectAltName=DNS:redis-tls\n' > san.cnf \
    && openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 2 -extfile san.cnf 2>/dev/null \
    && chmod 644 ./*.crt ./*.key)
fi

step "Build and start the stack ($LIMEN_REDIS_PROJECT)"
# The image build caches cargo output across checkouts by file time; fresh times
# keep it from reusing another worktree's stale build of these crates.
find "$root/crates" -name '*.rs' -exec touch {} +
(cd "$root" && cargo build --release -q -p limen-cli)
$keep || "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1
"${compose[@]}" up -d --build --quiet-pull >/dev/null
wait_for "proxy readiness" curl -sf "http://localhost:$LIMEN_REDIS_HEALTH_PORT/readyz"
"${compose[@]}" cp control-plane:/var/lib/limen/ca-public/internal-ca.pem "$state/internal-ca.pem" >/dev/null

# Two separate profiles: LIMEN_HOME is per person.
export HOME_ADMIN="$state/home-admin" HOME_DEV="$state/home-dev"
rm -rf "$HOME_ADMIN" "$HOME_DEV"
LIMEN_HOME="$HOME_ADMIN" "$here/dev-login.sh" "$ADMIN" >/dev/null
LIMEN_HOME="$HOME_ADMIN" "$LIMEN_BIN" admin apply "$root/examples/policy" "$here/targets/redis/scenario-policy.yaml" --source-ref scenarios >/dev/null
# Roles are fixed at login, so log in again now that policy maps groups to roles.
LIMEN_HOME="$HOME_ADMIN" "$here/dev-login.sh" "$ADMIN" >/dev/null
LIMEN_HOME="$HOME_DEV" "$here/dev-login.sh" "$DEVELOPER" >/dev/null
wait_for "worker tunnels" sh -c "curl -sf http://localhost:$LIMEN_REDIS_HEALTH_PORT/tunnels | grep -q worker_id"
sleep 11   # policy refresh
for svc in "redis-target redis-cli" "valkey-target valkey-cli" "redis-tls redis-cli"; do
  read -r name cli <<<"$svc"
  extra=(); [ "$name" = redis-tls ] && extra=(--tls --cacert /tls/ca.crt)
  wait_for "$name" "${compose[@]}" exec -T "$name" "$cli" ${extra[@]+"${extra[@]}"} --user limen-rw --pass rw-dev-only --no-auth-warning ping
done

step "Scenarios"
export SCN_STATE="$state" SCN_ROOT="$root" SCN_PROJECT="$LIMEN_REDIS_PROJECT" SCN_FILES="${files[*]}"
status=0
python3 -I "$here/targets/redis/scenarios.py" "$@" || status=$?
$down && "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1
exit $status
