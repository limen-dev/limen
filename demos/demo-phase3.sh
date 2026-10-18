#!/usr/bin/env bash
# Phase 3 demo: the audit pipeline. Every event reaches S3 (signed,
# hash-chained batches) and Datadog (the fake intake), survives a sink
# outage without loss, and shows up in the Grafana dashboards via Trino.
#
#   demos/demo-phase3.sh          # resets the dev stack first (down -v)
#   demos/demo-phase3.sh --keep   # reuse the running stack
set -euo pipefail
keep=false
[ "${1:-}" = "--keep" ] && keep=true

root="$(cd "$(dirname "$0")/.." && pwd)"
here="$root/deploy/compose"
# shellcheck source=../deploy/compose/scripts/dev-users.sh
source "$here/scripts/dev-users.sh"
state="$here/.state"
# shellcheck source=../deploy/compose/scripts/lib.sh
source "$here/scripts/lib.sh"
stack_setup ssh observability bots
export LIMEN_HOME="$state/home"
export LIMEN_BIN="${LIMEN_BIN:-$root/target/release/limen}"
export LIMEN_PROXY=localhost:3443
s3=http://localhost:8333/limen-audit
dd=http://localhost:8126
limen() { "$LIMEN_BIN" "$@"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
wait_for() {
  local what="$1"; shift
  for _ in $(seq 1 240); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out waiting for $what"
}
trino() { "${compose[@]}" exec -T trino trino --output-format CSV_UNQUOTED --execute "$1" 2>/dev/null; }
# The panel or alert query with this title, with Grafana's macros filled in.
query() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$root/deploy/grafana/queries.json" "$1"; }
verify() {
  "${compose[@]}" exec -T control-plane limen-audit-verify \
    --ca-file /var/lib/limen/ca-public/internal-ca.pem "$@" 2>&1
}
# Signed with the dev identity in s3/s3.json.
s3curl() { curl -sf --aws-sigv4 "aws:amz:us-east-1:s3" --user dev:dev-only-secret "$@"; }
s3_keys() { s3curl "$s3?list-type=2&prefix=$1" | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g'; }
command -v ssh >/dev/null || fail "OpenSSH client (ssh) is required"

step "Build and start the stack (with S3, fake Datadog, Trino, and Grafana)"
(cd "$root" && cargo build --release -q -p limen-cli)
if ! $keep; then
  echo "Resetting the dev stack (docker compose down -v). Use --keep to skip."
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1
fi
"${compose[@]}" up -d --build --quiet-pull >/dev/null
wait_for "proxy readiness" curl -sf http://localhost:3444/readyz
mkdir -p "$state"
"${compose[@]}" cp control-plane:/var/lib/limen/ca-public/internal-ca.pem "$state/internal-ca.pem" >/dev/null
rm -rf "$LIMEN_HOME"
"$here/scripts/dev-login.sh" "$ADMIN" >/dev/null
limen admin apply "$root/examples/policy" --source-ref demo-phase3 >/dev/null
wait_for "worker tunnels" sh -c "curl -sf http://localhost:3444/tunnels | grep -q worker_id"
sleep 11 # proxy and worker refresh policy every 10s
pass "stack up, policy applied"

step "Generate activity: sessions, a privileged command, denials"
"$here/scripts/dev-login.sh" "$DEVELOPER" >/dev/null
limen ssh web-staging-1 -- 'echo hello from $(hostname)'
limen ssh web-staging-1 -- 'sudo -n true 2>/dev/null; echo tried sudo'
limen ssh root@web-staging-1 -- id 2>/dev/null && fail "root must be denied"
pass "2 sessions and a denial"

step "Kill the Datadog sink; activity continues and piles up in the spool"
curl -sf -X POST "$dd/fake/fail?status=503" >/dev/null
before="$(curl -sf "$dd/fake/received" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"
for i in 1 2 3; do limen ssh web-staging-1 -- "echo during-outage-$i" >/dev/null; done
sleep 3
pending="$(curl -sf http://localhost:3081/metrics | awk '/^limen_audit_spool_pending\{consumer="datadog"\}/ {print $2}')"
echo "  datadog spool backlog: ${pending:-0} events; intake still has $before"
[ "${pending%.*}" -gt 0 ] 2>/dev/null || fail "events should be queued while Datadog is down"
pass "sessions still work; events wait in the spool"

step "Bring Datadog back: the backlog drains, nothing is lost"
curl -sf -X POST "$dd/fake/recover" >/dev/null
wait_for "datadog backlog to drain" sh -c "curl -sf http://localhost:3081/metrics | grep -q '^limen_audit_spool_pending{consumer=\"datadog\"} 0'"
"${compose[@]}" cp control-plane:/var/lib/limen/audit/control-plane.jsonl "$state/audit.jsonl" >/dev/null
curl -sf "$dd/fake/received" > "$state/datadog.json"
python3 - "$state/audit.jsonl" "$state/datadog.json" <<'PY'
import json, sys
local = {json.loads(l)["event_id"] for l in open(sys.argv[1])}
dd = {e["event_id"] for e in json.load(open(sys.argv[2]))}
missing = local - dd
print(f"  {len(local)} events in the audit log, {len(dd)} distinct in Datadog, {len(missing)} missing")
assert not missing, missing
PY
pass "every event reached Datadog after the outage"

step "S3: signed, hash-chained batches and recordings"
# The S3 consumer flushes every 10s; wait until S3 holds every event above.
want="$(wc -l < "$state/audit.jsonl" | tr -d ' ')"
for _ in $(seq 1 60); do
  have="$(verify | sed -n 's/.*events: \([0-9]*\).*/\1/p')"
  [ "${have:-0}" -ge "$want" ] && break
  sleep 1
done
[ "${have:-0}" -ge "$want" ] || fail "S3 has $have of $want events"
s3_keys events/ | head -3
s3_keys manifests/ | head -3
s3_keys recordings/ | grep -q '\.cast$' || fail "no recordings in S3"
echo "  $(s3_keys recordings/ | wc -l | tr -d ' ') recordings in S3"
verify | tee "$state/verify.txt"
grep -q '^OK' "$state/verify.txt" || fail "audit trail should verify"
pass "limen-audit-verify: chain intact"

step "Tamper with a batch: verification catches it"
# curl's SigV4 signs "=" in the path only when it's percent-encoded.
victim="$(s3_keys events/ | head -1 | sed 's/=/%3D/g')"
s3curl "$s3/$victim" -o "$state/original.jsonl.gz"
gunzip -c "$state/original.jsonl.gz" | sed 's/'"$DEVELOPER"'/eve@example.com/' | gzip -c > "$state/tampered.jsonl.gz"
s3curl -X PUT --data-binary @"$state/tampered.jsonl.gz" "$s3/$victim" >/dev/null
if verify > "$state/verify-tampered.txt" 2>&1; then cat "$state/verify-tampered.txt"; fail "tampering must be detected"; fi
grep -m1 'modified' "$state/verify-tampered.txt"
s3curl -X PUT --data-binary @"$state/original.jsonl.gz" "$s3/$victim" >/dev/null
verify >/dev/null || fail "restoring the original should verify again"
pass "a modified batch fails verification; restoring it passes"

step "Dashboards: the panels' SQL over the same S3 data (Trino stands in for Athena)"
trino "CALL audit.system.sync_partition_metadata('limen', 'events_raw', 'FULL')" >/dev/null
echo "  Who accessed what:"; trino "$(query 'Who accessed what')" | sed 's/^/    /'
trino "$(query 'Who accessed what')" | grep -q "$DEVELOPER,user,web-staging-1,ubuntu" || fail "who-accessed-what"
echo "  Privileged commands:"; trino "$(query 'Privileged commands')" | cut -d, -f2-5 | sed 's/^/    /'
trino "$(query 'Privileged commands')" | grep -q 'sudo' || fail "privileged commands panel"
echo "  Failed and denied attempts:"; trino "$(query 'Failed and denied attempts')" | cut -d, -f2-7 | sed 's/^/    /'
trino "$(query 'Failed and denied attempts')" | grep -q 'root' || fail "denied panel"
gaps="$(trino "$(query 'Limen: audit events missing')")"
echo "  missing events across all producers: $gaps"
[ "$gaps" = "0" ] || fail "sequence gaps"
pass "dashboard queries return the activity; no sequence gaps"

step "Grafana"
wait_for "grafana" curl -sf http://localhost:3000/api/health
health="$(curl -sf -u admin:limen-dev-only http://localhost:3000/api/datasources/uid/limen-trino/health)"
echo "  data source: $health"
grep -q '"status":"OK"' <<<"$health" || fail "Trino data source"
curl -sf -u admin:limen-dev-only http://localhost:3000/api/dashboards/uid/limen-audit | grep -q '"title":"Limen audit"' || fail "dashboard"
rules="$(curl -sf -u admin:limen-dev-only http://localhost:3000/api/v1/provisioning/alert-rules | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"
echo "  $rules alert rules provisioned"
[ "$rules" -ge 3 ] || fail "alert rules"
pass "open http://localhost:3000/d/limen-audit"

printf '\n\033[32mPhase 3 demo passed.\033[0m\n'
