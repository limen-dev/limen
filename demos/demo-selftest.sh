#!/usr/bin/env bash
# Scheduled self-test and controls report demo (ADR-0053). The control plane
# tests its own controls with a test principal no issuer will vouch for, signs
# a report, and writes an audit event with the report's hash first. This runs
# the checks and the report's tamper tests, runs a control plane against a
# real PostgreSQL (a run, the single-flight and rate limits, a failing policy
# test failing the run, the schedule running once across two replicas, the
# reserved `selftest:` name refused at login), and then checks one report with
# the CLI, offline, with only the CA certificate and the audit events.
# Needs docker and cargo.
#
#   demos/demo-selftest.sh          # runs the scenarios, removes its container after
#   demos/demo-selftest.sh --keep   # leaves it for another run
#
# It runs the control plane in one process, the way the integration tests do.
# PostgreSQL (127.0.0.1:39437) is a throwaway container of its own, so the dev
# stack is untouched.
#
# Verified against a local stand-in only: no AWS bucket, so the S3 manifest
# check is reported SKIPPED here (and a skipped check is not a pass).
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
pg="${LIMEN_DEMO_PG:-limen-demo-selftest-postgres}"
pg_port="${LIMEN_DEMO_PG_PORT:-39437}"
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
need() { command -v "$1" >/dev/null || fail "$1 is required"; }
need docker; need cargo

out_dir="$(mktemp -d)"
cleanup() { "$keep" || docker rm -f "$pg" >/dev/null 2>&1 || true; rm -rf "$out_dir"; }
trap cleanup EXIT

step "a throwaway PostgreSQL on 127.0.0.1:$pg_port"
docker rm -f "$pg" >/dev/null 2>&1 || true
docker run -d --name "$pg" -p "127.0.0.1:$pg_port:5432" \
  --tmpfs /var/lib/postgresql:rw,size=1g \
  -e POSTGRES_USER=limen -e POSTGRES_PASSWORD=limen-demo -e POSTGRES_DB=limen \
  "$POSTGRES_IMAGE" -c fsync=off -c max_connections=300 >/dev/null
for _ in $(seq 1 60); do
  docker exec "$pg" pg_isready -U limen >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$pg" pg_isready -U limen >/dev/null || fail "postgres did not start"
pass "postgres is up"

export LIMEN_TEST_DATABASE_URL="postgres://limen:limen-demo@127.0.0.1:$pg_port/limen"
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1
export LIMEN_TEST_REPORT_DIR="$out_dir"

run() { # run <what> <cargo test args...>
  local what="$1"; shift
  step "$what"
  out="$(cargo test "$@" -- --nocapture --test-threads=1 2>&1)" || { echo "$out" | tail -n 30; fail "$what"; }
  # A skipped test is not a pass.
  if echo "$out" | grep -q SKIPPED; then fail "$what was skipped"; fi
  echo "$out" | tail -n 4
  pass "$what"
}

run "the reserved name is refused by the CA and the verifier" -p limen-core -p limen-ca --lib self_test
run "the checks and the engine probe" -p limen-control-plane --lib selftest
run "the report: every manifest field and section is covered by the signature" -p limen-verify --lib controls
run "the control plane: a run, limits, a failure, the schedule, the reserved name at login" -p limen-control-plane --test selftest

step "check the report with the CLI, offline"
cargo build -q -p limen-cli
limen="$root/target/debug/limen"
[ -s "$out_dir/limen-controls.json" ] || fail "the test wrote no report"
"$limen" audit verify --controls "$out_dir/limen-controls.json" --ca-file "$out_dir/internal-ca.pem" \
  --audit-events "$out_dir/audit.jsonl" 2>&1 | tee "$out_dir/verify.txt" | tail -n 14
grep -q "OK: the report is signed" "$out_dir/verify.txt" || fail "the CLI did not accept the report"
grep -q "SKIPPED audit.manifest_tail" "$out_dir/verify.txt" || fail "the skipped check was hidden"
if "$limen" audit verify --controls "$out_dir/limen-controls.json" --ca-file "$out_dir/internal-ca.pem" --strict >/dev/null 2>&1; then
  fail "--strict accepted a report with skipped checks"
fi
pass "the CLI accepts the report, shows the skipped check, and --strict refuses it"

step "a tampered report is refused"
sed 's/"status": "passed"/"status": "failed"/' "$out_dir/limen-controls.json" > "$out_dir/tampered.json"
if "$limen" audit verify --controls "$out_dir/tampered.json" --ca-file "$out_dir/internal-ca.pem" >/dev/null 2>&1; then
  fail "a tampered report verified"
fi
pass "the tampered report did not verify"

printf '\n\033[32mSelf-test demo passed.\033[0m\n'
