#!/usr/bin/env bash
# Set up the Limen dev stack: checks what you need is installed, asks what to
# enable, starts it, and prints every port and how the services are connected.
#
#   deploy/compose/setup.sh                       # asks (same as `up`)
#   deploy/compose/setup.sh --yes                 # Limen + every stack, no questions
#   deploy/compose/setup.sh --yes --scale --stacks ssh,redis
#   deploy/compose/setup.sh --check               # only check the prerequisites
#   deploy/compose/setup.sh status | down [--scale]
#
# Limen    postgres, dex, s3, kms, control plane, proxy, worker (always).
#          docker-compose.yml, or stacks/scale.yml with --scale (3 of each component).
# ssh      OpenSSH host that trusts Limen certificates          stacks/ssh.yml
# db       PostgreSQL and MySQL with TLS, roles bootstrapped    stacks/db.yml
# redis    Redis and Valkey with ACL users                      stacks/redis.yml
# observability  fake Datadog intake, Trino and Grafana         stacks/observability.yml
# bots     fake CI identity issuer (bot logins)                 stacks/bots.yml
# kube     a kind cluster and a worker serving it (single Limen only)   stacks/kube.yml
#
# `--stacks none` starts Limen alone. After starting it pins the CA, signs in as
# the admin, applies examples/policy, and seeds the targets, so `limen ls` shows
# everything straight away. Development only: static tokens, Dex static
# passwords, file-backed CA keys. The per-phase demos are in demos/.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
# shellcheck source=scripts/lib.sh
source "$here/scripts/lib.sh"
# shellcheck source=scripts/dev-users.sh
source "$here/scripts/dev-users.sh"

cmd=up yes=false want_scale=false check=false picked=""
while [ $# -gt 0 ]; do
  case "$1" in
    up|down|status) cmd="$1" ;;
    --yes|-y) yes=true ;;
    --scale) want_scale=true ;;
    --check) check=true ;;
    --stacks) picked="${2:?--stacks needs a comma-separated list, or none}"; shift ;;
    -h|--help) sed -n 2,24p "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
wait_for() {
  local what="$1"; shift
  for _ in $(seq 1 240); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out waiting for $what"
}
ask() { # ask "question" default(y|n) -> 0 for yes
  local q="$1" def="$2" hint reply
  [ "$def" = y ] && hint="Y/n" || hint="y/N"
  $yes && { [ "$def" = y ]; return; }
  read -r -p "$q [$hint] " reply || reply=""
  reply="${reply:-$def}"
  case "$reply" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

scale_flag=()
$want_scale && scale_flag=(--scale)

# ---- down and status act on everything ------------------------------------------
if [ "$cmd" != up ]; then
  stack_setup ${scale_flag[@]+"${scale_flag[@]}"} "${STACK_NAMES[@]}"
  if [ "$cmd" = status ]; then exec "${compose[@]}" ps; fi
  "${compose[@]}" down -v --remove-orphans
  rm -f "$STACK_STATE/stack.env"
  if [ -n "${KUBE_CLUSTER:-}" ] && stack_kind get clusters 2>/dev/null | grep -qx "$KUBE_CLUSTER"; then
    stack_kind delete cluster --name "$KUBE_CLUSTER" >/dev/null 2>&1 && echo "Deleted the kind cluster $KUBE_CLUSTER."
  fi
  exit 0
fi

# ---- choose ---------------------------------------------------------------------
stacks=()
if [ -n "$picked" ]; then
  if [ "$picked" != none ]; then IFS=, read -r -a stacks <<<"$picked"; fi
elif $yes || [ ! -t 0 ]; then
  stacks=("${STACK_NAMES[@]}")
  [ -t 0 ] || echo "(no terminal: enabling everything; pass --stacks to choose)"
else
  bold "Limen"
  echo "  Always on: Postgres (state), S3 (audit batches and recordings), Dex (login),"
  echo "  the control plane, a proxy and a worker."
  if ask "  Scale it (3 control planes, 3 proxies, 3 workers)?" n; then want_scale=true; scale_flag=(--scale); fi
  echo
  bold "What should it connect to, and report to?"
  for s in "${STACK_NAMES[@]}"; do
    ask "  $(printf '%-14s' "$s") $(stack_describe "$s")" y && stacks+=("$s")
  done
fi

# ---- prerequisites --------------------------------------------------------------
echo
bold "Checking prerequisites"
if ! stack_preflight ${scale_flag[@]+"${scale_flag[@]}"} ${stacks[@]+"${stacks[@]}"}; then
  echo
  echo "Fix the items marked MISSING or BUSY above and run this again." >&2
  exit 1
fi
$check && exit 0

echo
bold "Starting Limen$($want_scale && echo ' (scaled)') with: ${stacks[*]:-no extra stacks}"
echo "The first run builds the images and the CLI, which takes several minutes."
if ! $yes && [ -t 0 ]; then ask "Go?" y || { echo "Cancelled."; exit 0; }; fi
has() { case " ${stacks[*]:-} " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# ---- start ----------------------------------------------------------------------
stack_setup ${scale_flag[@]+"${scale_flag[@]}"} ${stacks[@]+"${stacks[@]}"}
state="$STACK_STATE"
export LIMEN_BIN="${LIMEN_BIN:-$root/target/release/limen}"
export LIMEN_PROXY="$STACK_PROXY" LIMEN_DEX_URL="$STACK_DEX" LIMEN_DEV_CA="$state/internal-ca.pem"
export LIMEN_HOME="$state/home-admin"

step "Build and start"
(cd "$root" && cargo build --release -q -p limen-cli)
if has kube; then
  step "Kind cluster $KUBE_CLUSTER and the worker's service account"
  stack_kube_prepare
fi
"${compose[@]}" up -d --build --quiet-pull >/dev/null
wait_for "proxy readiness" curl -sf "http://$STACK_HEALTH/readyz"
"${compose[@]}" cp "$STACK_CP:/var/lib/limen/ca-public/internal-ca.pem" "$state/internal-ca.pem" >/dev/null
rm -rf "$LIMEN_HOME"
"$here/scripts/dev-login.sh" "$ADMIN" >/dev/null
"$LIMEN_BIN" admin apply "$root/examples/policy" --source-ref setup.sh >/dev/null
wait_for "worker tunnels" sh -c "curl -sf http://$STACK_HEALTH/tunnels | grep -q worker_id"
sleep 11 # proxy and worker refresh policy every 10s
"$here/scripts/dev-login.sh" "$ADMIN" >/dev/null # roles are fixed at login: sign in again to get the applied ones

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
stack_endpoints ${scale_flag[@]+"${scale_flag[@]}"} ${stacks[@]+"${stacks[@]}"}
stack_summary ${scale_flag[@]+"${scale_flag[@]}"} ${stacks[@]+"${stacks[@]}"}
