#!/usr/bin/env bash
# Start Limen and the stacks you pick, for development.
#
#   deploy/compose/stack.sh up                    # Limen + every stack
#   deploy/compose/stack.sh up ssh redis          # Limen + only those
#   deploy/compose/stack.sh --scale up ssh db     # scaled Limen (3 of each component)
#   deploy/compose/stack.sh status | down [--scale]
#
# limen    postgres, dex, s3, kms, control plane, proxy, worker (always).
#          docker-compose.yml, or docker-compose.scale.yml with --scale.
# ssh      OpenSSH host that trusts Limen certificates
# db       PostgreSQL and MySQL with TLS; the limen_* roles are bootstrapped
# redis    Redis and Valkey with ACL users
# observability  fake Datadog Logs intake (an audit sink) plus Trino and Grafana
# bots     fake CI identity issuer (bot logins)
# `stack.sh up none` starts Limen alone. For prompts and prerequisite checks use setup.sh.
#
# `up` also pins the CA, signs in as the admin, applies examples/policy, and
# seeds the targets, so `limen ls` shows everything straight away.
# Development only. The per-phase demos (demo-phase*.sh) are separate.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
here="$root/deploy/compose"
# shellcheck source=dev-users.sh
source "$here/dev-users.sh"
# shellcheck source=stack-lib.sh
source "$here/stack-lib.sh"

scale=()
if [ "${1:-}" = --scale ]; then scale=(--scale); shift; fi
cmd="${1:-up}"
[ $# -gt 0 ] && shift
if [ "${1:-}" = --scale ]; then scale=(--scale); shift; fi
stacks=("$@")
[ ${#stacks[@]} -eq 0 ] && stacks=("${STACK_NAMES[@]}")
[ "${stacks[0]}" = none ] && stacks=()
[ "$cmd" = down ] && stacks=("${STACK_NAMES[@]}")
stack_setup ${scale[@]+"${scale[@]}"} ${stacks[@]+"${stacks[@]}"} || exit 2
has() { case " ${stacks[*]:-} " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
wait_for() {
  local what="$1"; shift
  for _ in $(seq 1 240); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out waiting for $what"
}

case "$cmd" in
  status) exec "${compose[@]}" ps ;;
  down) "${compose[@]}" down -v --remove-orphans; rm -f "$here/.state/stack.env"; exit 0 ;;
  up) ;;
  *) echo "usage: stack.sh [--scale] [up|down|status] [${STACK_NAMES[*]}]" >&2; exit 2 ;;
esac

state="$STACK_STATE"
export LIMEN_BIN="${LIMEN_BIN:-$root/target/release/limen}"
export LIMEN_PROXY="$STACK_PROXY" LIMEN_DEX_URL="$STACK_DEX" LIMEN_DEV_CA="$state/internal-ca.pem"
export LIMEN_HOME="$state/home-admin"

if [ -z "${LIMEN_PREFLIGHT_DONE:-}" ]; then
  step "Checking prerequisites"
  stack_preflight ${scale[@]+"${scale[@]}"} ${stacks[@]+"${stacks[@]}"} || fail "fix the items above and run again"
fi

step "Build and start: limen${scale[*]:+ (scaled)} + ${stacks[*]:-no extra stacks}"
(cd "$root" && cargo build --release -q -p limen-cli)
"${compose[@]}" up -d --build --quiet-pull >/dev/null
wait_for "proxy readiness" curl -sf "http://$STACK_HEALTH/readyz"
mkdir -p "$state"
"${compose[@]}" cp "$STACK_CP:/var/lib/limen/ca-public/internal-ca.pem" "$state/internal-ca.pem" >/dev/null
rm -rf "$LIMEN_HOME"
"$here/dev-login.sh" "$ADMIN" >/dev/null
"$LIMEN_BIN" admin apply "$root/examples/policy" --source-ref stack.sh >/dev/null
wait_for "worker tunnels" sh -c "curl -sf http://$STACK_HEALTH/tunnels | grep -q worker_id"
sleep 11 # proxy and worker refresh policy every 10s
"$here/dev-login.sh" "$ADMIN" >/dev/null # roles are fixed at login: sign in again to get the applied ones

if has db; then
  step "Database role bootstrap"
  wait_for "postgres-target" "${compose[@]}" exec -T postgres-target pg_isready -U postgres
  wait_for "mysql-target" "${compose[@]}" exec -T mysql-target mysqladmin ping -h 127.0.0.1 -uroot -pmysql-target-dev-only --silent
  "${compose[@]}" run --rm db-bootstrap --db-bootstrap-once >/dev/null 2>&1 || fail "db bootstrap failed"
fi
if has redis; then
  step "Seed Redis and Valkey"
  wait_for "redis" "${compose[@]}" exec -T redis-target redis-cli --user limen-rw --pass rw-dev-only --no-auth-warning ping
  wait_for "valkey" "${compose[@]}" exec -T valkey-target valkey-cli --user limen-rw --pass rw-dev-only --no-auth-warning ping
  "${compose[@]}" exec -T redis-target redis-cli --user limen-rw --pass rw-dev-only --no-auth-warning SET app:greeting hello >/dev/null
  "${compose[@]}" exec -T valkey-target valkey-cli --user limen-rw --pass rw-dev-only --no-auth-warning SET app:greeting hello-from-valkey >/dev/null
fi

step "Ready"
"$LIMEN_BIN" ls | sed 's/^/  /'
stack_summary ${scale[@]+"${scale[@]}"} ${stacks[@]+"${stacks[@]}"}
cat <<TRY

Try it (admin@example.com is signed in; developer@example.com has the day-to-day role)
  export PATH="$root/target/release:\$PATH" LIMEN_PROXY=$STACK_PROXY LIMEN_DEX_URL=$STACK_DEX
  export LIMEN_DEV_CA=$state/internal-ca.pem LIMEN_HOME=$state/home-dev
  $here/dev-login.sh developer@example.com
  limen ls
  Console: https://$STACK_PROXY/console/    Stop: deploy/compose/stack.sh${scale[*]:+ --scale} down
TRY
