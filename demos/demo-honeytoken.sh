#!/usr/bin/env bash
# Honeytoken demo (ADR-0052): a decoy resource that looks real. A developer
# lists it, tries to connect, request it and explain it; each is refused with
# the answer any unreachable name gets, and the proxy and control plane audit
# detect.honeytoken with the user, roles and address. A real resource beside
# it still works and raises nothing. Also runs the policy rules (no role
# reaches a decoy, validation, round trip) and the alert-rule generation.
# Needs docker and cargo.
#
#   demos/demo-honeytoken.sh          # runs the scenarios, removes its database after
#   demos/demo-honeytoken.sh --keep   # leaves the database container for another run
#
# It runs Limen (control plane, proxy, worker) in one process, the way the
# end-to-end tests do, with a real SSH target. Postgres is a throwaway
# container of its own on a RAM disk, so the dev stack is untouched.
#
# Verified against stand-ins. No SIEM, Datadog or Grafana evaluated the alerts.
set -euo pipefail
keep=false
for arg in "$@"; do
  case "$arg" in
    --keep) keep=true ;;
    *) echo "unknown option $arg" >&2; exit 2 ;;
  esac
done

root="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../deploy/compose/.env
set -a; source "$root/deploy/compose/.env"; set +a # image versions
name="${LIMEN_DEMO_PG:-limen-demo-honeytoken-postgres}"
port="${LIMEN_DEMO_PG_PORT:-39435}"
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
need() { command -v "$1" >/dev/null || fail "$1 is required"; }
need docker; need cargo

cleanup() { "$keep" || docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

step "a throwaway PostgreSQL on 127.0.0.1:$port (RAM-backed)"
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" -p "127.0.0.1:$port:5432" \
  --tmpfs /var/lib/postgresql:rw,size=1g \
  -e POSTGRES_USER=limen -e POSTGRES_PASSWORD=limen-demo -e POSTGRES_DB=limen \
  "$POSTGRES_IMAGE" -c fsync=off -c max_connections=300 >/dev/null
for _ in $(seq 1 60); do
  docker exec "$name" pg_isready -U limen >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$name" pg_isready -U limen >/dev/null || fail "postgres did not start"
pass "postgres is up"

export LIMEN_TEST_DATABASE_URL="postgres://limen:limen-demo@127.0.0.1:$port/limen"

run() { # run <what> <package> <test target>
  step "$1"
  out="$(cargo test -p "$2" --test "$3" -- --nocapture --test-threads=1 2>&1)" || { echo "$out" | tail -n 30; fail "$1"; }
  # A skipped test is not a pass.
  # A here-string, not a pipe: under pipefail, grep -q exiting early can
  # SIGPIPE the echo and turn a match into a miss.
  if grep -q SKIPPED <<<"$out"; then fail "$1 was skipped"; fi
  echo "$out" | tail -n 4
  pass "$1"
}

run "a decoy is listed, refused like any name, and every touch is audited" limen-e2e honeytoken

step "the policy rules and the alert rules"
cargo test -p limen-policy honeytoken 2>&1 | tail -n 3
cargo test -p limen-audit --lib ocsf 2>&1 | tail -n 3
python3 "$root/deploy/grafana/generate.py" >/dev/null
grep -q honeytoken "$root/deploy/grafana/alerting/trino/limen-audit-rules.json" || fail "the Grafana alert rule is missing"
pass "the alert rules are generated"

printf '\n\033[32mHoneytoken demo passed.\033[0m\n'
