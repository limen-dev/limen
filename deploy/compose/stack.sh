#!/usr/bin/env bash
# Start the dev stack: the Limen core plus the target stacks you pick.
#
#   deploy/compose/stack.sh up                   # core + every target stack
#   deploy/compose/stack.sh up ssh redis         # core + only those
#   deploy/compose/stack.sh status
#   deploy/compose/stack.sh down                 # also removes volumes
#
# Core (docker-compose.yml): postgres, dex, kms, s3, control plane, proxy, worker.
# Target stacks, one compose file and profile each:
#   ssh            OpenSSH host that trusts Limen certificates
#   db             PostgreSQL and MySQL with TLS (roles bootstrapped here)
#   redis          Redis and Valkey with ACL users
#   observability  Trino and Grafana over the S3 audit batches
#
# `up` also pins the CA, signs in as the admin, applies examples/policy, and
# seeds the targets, so `limen ls` shows everything straight away.
# Development only. The per-phase demos (demo-phase*.sh) are unchanged.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
here="$root/deploy/compose"
# shellcheck source=dev-users.sh
source "$here/dev-users.sh"
state="$here/.state"
all=(ssh db redis observability)

cmd="${1:-up}"
[ $# -gt 0 ] && shift
profiles=("$@")
[ ${#profiles[@]} -eq 0 ] && profiles=("${all[@]}")
for p in ${profiles[@]+"${profiles[@]}"}; do
  case " ${all[*]} " in *" $p "*) ;; *) echo "unknown stack '$p' (choose from: ${all[*]})" >&2; exit 2 ;; esac
done
has() { case " ${profiles[*]} " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

flags=()
if [ "$cmd" = down ]; then
  for p in "${all[@]}" tools; do flags+=(--profile "$p"); done
else
  for p in ${profiles[@]+"${profiles[@]}"}; do flags+=(--profile "$p"); done
fi
compose=(docker compose --progress=quiet -f "$here/docker-compose.yml" "${flags[@]}")

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
wait_for() {
  local what="$1"; shift
  for _ in $(seq 1 240); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out waiting for $what"
}

case "$cmd" in
  status) exec "${compose[@]}" ps ;;
  down) exec "${compose[@]}" down -v --remove-orphans ;;
  up) ;;
  *) echo "usage: stack.sh [up|down|status] [${all[*]}]" >&2; exit 2 ;;
esac

export LIMEN_BIN="${LIMEN_BIN:-$root/target/release/limen}"
export LIMEN_PROXY=localhost:3443
export LIMEN_HOME="$state/home-admin"

step "Build and start: core + ${profiles[*]}"
(cd "$root" && cargo build --release -q -p limen-cli)
"${compose[@]}" up -d --build --quiet-pull >/dev/null
wait_for "proxy readiness" curl -sf http://localhost:3444/readyz
mkdir -p "$state"
"${compose[@]}" cp control-plane:/var/lib/limen/ca-public/internal-ca.pem "$state/internal-ca.pem" >/dev/null
rm -rf "$LIMEN_HOME"
"$here/dev-login.sh" "$ADMIN" >/dev/null
"$LIMEN_BIN" admin apply "$root/examples/policy" --source-ref stack.sh >/dev/null
wait_for "worker tunnels" sh -c "curl -sf http://localhost:3444/tunnels | grep -q worker_id"
sleep 11 # proxy and worker refresh policy every 10s

if has db; then
  step "Database role bootstrap"
  wait_for "postgres-target" "${compose[@]}" exec -T postgres-target pg_isready -U postgres
  wait_for "mysql-target" "${compose[@]}" exec -T mysql-target mysqladmin ping -h 127.0.0.1 -uroot -pmysql-target-dev-only --silent
  "${compose[@]}" --profile tools run --rm db-bootstrap --db-bootstrap-once >/dev/null 2>&1 || fail "db bootstrap failed"
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
cat <<EOF

  Console   https://localhost:3443/console/   (curl/browsers need --cacert $state/internal-ca.pem)
  Dex       http://localhost:5556              admin@example.com / password
$(has observability && echo "  Grafana   http://localhost:3000              admin / limen-dev-only")
  CLI       export LIMEN_PROXY=localhost:3443 LIMEN_HOME=$state/home-admin
  Stop      deploy/compose/stack.sh down
EOF
