#!/usr/bin/env bash
# Policy replay demo (ADR-0049): recorded sessions replayed through a policy
# change. Sessions are written into a real control plane's database, then a
# dry-run apply with a replay window says which would have been refused: the
# person and the bot lose production SSH; replaying the policy against itself
# reports nothing; sessions that cannot be replayed are counted, not hidden;
# non-admins, real applies with a window and windows over 30 days are refused;
# replays are audited and rate limited. The policy crate's tests run here too,
# including the check that replay agrees with enforcement on 5,000 random
# requests. The console's "Check a change" with a replay is covered by the
# end-to-end console test, which needs the dev stack.
# Needs docker and cargo.
#
#   demos/demo-replay.sh          # runs the scenarios, removes its database after
#   demos/demo-replay.sh --keep   # leaves the database container for another run
#
# It runs the control plane in one process, the way the end-to-end tests do.
# Postgres is a throwaway container of its own on a RAM disk, so the dev stack
# is untouched. The test that a replay is refused while the audit trail is
# down needs an S3 endpoint (LIMEN_TEST_S3_ENDPOINT) and is skipped here.
#
# Verified against stand-ins: sessions are rows in the `sessions` table, not
# opened through a proxy and worker.
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
name="${LIMEN_DEMO_PG:-limen-demo-replay-postgres}"
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
  out="$(cargo test -p "$2" --test "$3" -- --nocapture --test-threads=1 --skip a_replay_that_cannot_be_audited 2>&1)" || { echo "$out" | tail -n 30; fail "$1"; }
  # A skipped test is not a pass.
  if echo "$out" | grep -q SKIPPED; then fail "$1 was skipped"; fi
  echo "$out" | tail -n 4
  pass "$1"
}

run "recorded sessions are replayed through a change; self-replay reports nothing; skips are counted; replays are admin-only, audited and rate limited" limen-control-plane policy_replay

step "the policy rules"
cargo test -p limen-policy replay 2>&1 | tail -n 3

printf '\n\033[32mReplay demo passed.\033[0m\n'
