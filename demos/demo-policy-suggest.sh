#!/usr/bin/env bash
# Policy suggest demo (ADR-0050): right-size roles from real use. A developer
# opens a real SSH session as one of two logins a role grants; `SuggestPolicy`
# reads the session history and proposes dropping the login nobody used, and
# nothing is applied. Also runs the control-plane checks: only admins may ask,
# the call is audited without names, short history and bad windows are
# refused, and roles that changed recently or opt out are left alone.
# Needs docker and cargo.
#
#   demos/demo-policy-suggest.sh          # runs the scenarios, removes its database after
#   demos/demo-policy-suggest.sh --keep   # leaves the database container for another run
#
# It runs Limen (control plane, proxy, worker) in one process, the way the
# end-to-end tests do, with a real SSH target. Postgres is a throwaway
# container of its own on a RAM disk, so the dev stack is untouched.
#
# Verified against stand-ins. Only SSH is checked end to end; the other
# protocols' session rows are read from the proxy code (see docs/design.md §14).
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
name="${LIMEN_DEMO_PG:-limen-demo-suggest-postgres}"
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

run "a real SSH session is the use that keeps its login; the unused one is proposed for removal" limen-e2e policy_suggest
run "the usage query, the audit event, admin-only access, short history, and exempt roles" limen-control-plane policy_suggest

step "the library: removals only, never a gain, and the result settles"
cargo test -p limen-policy suggest 2>&1 | tail -n 3

printf '\n\033[32mPolicy suggest demo passed.\033[0m\n'
