#!/usr/bin/env bash
# OCSF audit export demo (ADR-0048): the control plane writes an OCSF copy of
# the audit trail to a bucket of its own. Every event arrives with its native
# id, the audit bucket still verifies, a SIEM bucket that is down keeps its
# events and gets them when it returns, and one that holds the spool back is
# skipped and counted instead of filling the spool. Also runs the unit tests of
# the mapping (every event kind, secrets, the guide's generated table) and the
# configuration checks (the SIEM bucket and key may not be the audit ones).
# Needs docker and cargo.
#
#   demos/demo-ocsf.sh          # runs the scenarios, removes its containers after
#   demos/demo-ocsf.sh --keep   # leaves them for another run
#
# It runs the control plane in one process, the way the integration tests do.
# PostgreSQL (127.0.0.1:39435) and SeaweedFS (127.0.0.1:39436) are throwaway
# containers of their own, so the dev stack is untouched.
#
# Verified against stand-ins (SeaweedFS). No SIEM, Security Lake or AWS account
# has read the files.
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
pg="${LIMEN_DEMO_PG:-limen-demo-ocsf-postgres}"
pg_port="${LIMEN_DEMO_PG_PORT:-39435}"
s3="${LIMEN_DEMO_S3:-limen-demo-ocsf-s3}"
s3_port="${LIMEN_DEMO_S3_PORT:-39436}"
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
need() { command -v "$1" >/dev/null || fail "$1 is required"; }
need docker; need cargo

cleanup() { "$keep" || docker rm -f "$pg" "$s3" >/dev/null 2>&1 || true; }
trap cleanup EXIT

step "a throwaway PostgreSQL on 127.0.0.1:$pg_port and SeaweedFS on 127.0.0.1:$s3_port"
docker rm -f "$pg" "$s3" >/dev/null 2>&1 || true
docker run -d --name "$pg" -p "127.0.0.1:$pg_port:5432" \
  --tmpfs /var/lib/postgresql:rw,size=1g \
  -e POSTGRES_USER=limen -e POSTGRES_PASSWORD=limen-demo -e POSTGRES_DB=limen \
  "$POSTGRES_IMAGE" -c fsync=off -c max_connections=300 >/dev/null
docker run -d --name "$s3" -p "127.0.0.1:$s3_port:8333" \
  -v "$root/deploy/compose/config/s3/s3.json:/etc/seaweedfs/s3.json:ro" \
  "$SEAWEEDFS_IMAGE" server -s3 -s3.config=/etc/seaweedfs/s3.json -dir=/data >/dev/null
for _ in $(seq 1 60); do
  docker exec "$pg" pg_isready -U limen >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$pg" pg_isready -U limen >/dev/null || fail "postgres did not start"
for _ in $(seq 1 60); do
  curl -s -o /dev/null "http://127.0.0.1:$s3_port/" && break
  sleep 1
done
pass "postgres and s3 are up"

export LIMEN_TEST_DATABASE_URL="postgres://limen:limen-demo@127.0.0.1:$pg_port/limen"
export LIMEN_TEST_S3_ENDPOINT="http://127.0.0.1:$s3_port"
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1

run() { # run <what> <cargo test args...>
  local what="$1"; shift
  step "$what"
  out="$(cargo test "$@" -- --nocapture --test-threads=1 2>&1)" || { echo "$out" | tail -n 30; fail "$what"; }
  # A skipped test is not a pass.
  if echo "$out" | grep -q SKIPPED; then fail "$what was skipped"; fi
  echo "$out" | tail -n 4
  pass "$what"
}

run "every event kind maps to OCSF, secrets are redacted, and the guide's table matches the code" -p limen-audit --lib ocsf
run "the SIEM bucket and key cannot be the audit ones, and the lag bound must be below the spool size" -p limen-control-plane --lib ocsf
run "the lag decision: skip only when OCSF is the slowest sink and the spool is over the bound" -p limen-control-plane --lib ocsf_skips
run "every event reaches the OCSF bucket, an outage keeps events, a blocking outage is skipped" -p limen-control-plane --test ocsf_sink

printf '\n\033[32mOCSF export demo passed.\033[0m\n'
