#!/usr/bin/env bash
# Phase 13 demo: access requests and break-glass, search that lands on the
# recording, resources that find themselves, and a live session someone
# watches. Needs docker and cargo.
#
#   demos/demo-phase13.sh          # runs the scenarios, removes its database after
#   demos/demo-phase13.sh --keep   # leaves the database container for another run
#
# It runs Limen (control plane, proxy, worker, console) in one process, the way
# the end-to-end tests do, with a real SSH target and a stand-in for the AWS
# describe APIs (limen-testkit's fake_aws). Postgres is a throwaway container
# of its own on a RAM disk, so the dev stack is untouched.
#
# Verified against stand-ins. Not against real AWS: see docs/guides/discovery.md.
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
name="${LIMEN_DEMO_PG:-limen-demo13-postgres}"
port="${LIMEN_DEMO_PG_PORT:-39433}"
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
  --tmpfs /var/lib/postgresql/data:rw,size=1g \
  -e POSTGRES_USER=limen -e POSTGRES_PASSWORD=limen-demo -e POSTGRES_DB=limen \
  "$POSTGRES_IMAGE" -c fsync=off -c max_connections=300 >/dev/null
for _ in $(seq 1 60); do
  docker exec "$name" pg_isready -U limen >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$name" pg_isready -U limen >/dev/null || fail "postgres did not start"
pass "postgres is up"

export LIMEN_TEST_DATABASE_URL="postgres://limen:limen-demo@127.0.0.1:$port/limen"
export AWS_ACCESS_KEY_ID=demo AWS_SECRET_ACCESS_KEY=demo AWS_REGION=eu-west-1

run() { # run <what> <test name>
  step "$1"
  cargo test -p limen-e2e --test phase13 "$2" -- --nocapture --test-threads=1 2>&1 | tail -n 6
  [ "${PIPESTATUS[0]}" -eq 0 ] || fail "$1"
  pass "$1"
}

run "ask, approve, use, search, revoke: a developer is denied, asks with a ticket, an approver approves, the SSH session is recorded with its request id, an auditor finds the command, and revoking ends the open session" asked_for_approved_used_found_and_ended
run "break-glass: granted at once with a reason, audited, announced" break_glass_is_granted_at_once_and_loudly
run "a watcher sees the live session, and nothing is sent when nobody watches" watching_a_live_session_streams_what_the_user_sees
run "discovery: an EC2 instance appears as pending, is unreachable, and works after an admin accepts it" a_discovered_instance_is_reachable_only_once_an_admin_accepts_it
run "the console pages: request, approve, watch stream, search, simulator, reviews, evidence, discovered" the_console_pages_for_the_workflows

step "the policy tests and tooling"
cargo test -p limen-policy 2>&1 | tail -n 3
cargo run -q -p limen-cli -- policy test examples/policy examples/policy-workflows --coverage

printf '\n\033[32mPhase 13 demo passed.\033[0m\n'
