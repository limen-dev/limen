#!/usr/bin/env bash
# Phase 1 demo. Brings up the dev stack and checks every Phase 1 exit
# criterion with the real CLI, Dex, and containers.
#
#   demos/demo-phase1.sh          # resets the dev stack first (down -v)
#   demos/demo-phase1.sh --keep   # reuse the running stack and its data
set -euo pipefail
keep=false
[ "${1:-}" = "--keep" ] && keep=true

root="$(cd "$(dirname "$0")/.." && pwd)"
here="$root/deploy/compose"
# shellcheck source=../deploy/compose/scripts/dev-users.sh
source "$here/scripts/dev-users.sh"
# shellcheck source=../deploy/compose/scripts/lib.sh
source "$here/scripts/lib.sh"
stack_setup ssh observability bots
export LIMEN_HOME="$here/.state/home"
export LIMEN_BIN="${LIMEN_BIN:-$root/target/release/limen}"
export LIMEN_PROXY=localhost:3443
limen() { "$LIMEN_BIN" "$@"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
wait_for() { # description, command...
  local what="$1"; shift
  for _ in $(seq 1 120); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out waiting for $what"
}
tunnels() { curl -sf http://localhost:3444/tunnels; }

step "Build the CLI and start the stack"
(cd "$root" && cargo build --release -q -p limen-cli)
if ! $keep; then
  echo "Resetting the dev stack (docker compose down -v). Use --keep to skip."
  docker rm -f limen-worker-2 limen-worker-3 >/dev/null 2>&1 || true
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1
fi
"${compose[@]}" up -d --build --quiet-pull >/dev/null
wait_for "proxy readiness" curl -sf http://localhost:3444/readyz
wait_for "control plane readiness" curl -sf http://localhost:3081/readyz
mkdir -p "$here/.state"
"${compose[@]}" cp control-plane:/var/lib/limen/ca-public/internal-ca.pem "$here/.state/internal-ca.pem" >/dev/null
rm -rf "$LIMEN_HOME"
pass "stack is up"

step "Worker tunnels (outbound only)"
wait_for "two worker tunnels" sh -c "curl -sf http://localhost:3444/tunnels | grep -o worker_id | wc -l | grep -q 2"
tunnels | python3 -m json.tool
pass "worker holds 2 reverse tunnels"

step "Admin logs in through Dex (PKCE) and applies policy"
"$here/scripts/dev-login.sh" "$ADMIN"
limen admin apply "$root/examples/policy" --source-ref demo | tee "$here/.state/apply.out"
$keep || grep -q "Applied policy version 1" "$here/.state/apply.out" || fail "policy should be applied as version 1"
pass "policy applied"

step "Roles come from IdP groups at login: admin logs in again to pick up 'sre'"
"$here/scripts/dev-login.sh" "$ADMIN"
limen ls
# Every resource document in examples/policy, so the number follows the policy instead of a constant.
expected="$(find "$root/examples/policy" -type f \( -name '*.yaml' -o -name '*.yml' \) -exec grep -h '^kind: resource' {} + | wc -l | tr -d ' ')"
[ "$(limen ls --json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')" = "$expected" ] || fail "admin should see all $expected resources of examples/policy"
pass "sre sees every resource"

filtered="$(limen ls --json --type ssh --label env=staging | python3 -c 'import json,sys; print(",".join(r["kind"] + ":" + r["labels"]["env"] for r in json.load(sys.stdin)))')"
[ -n "$filtered" ] && ! grep -qv '^ssh:staging$' <<<"${filtered//,/$'\n'}" || fail "limen ls --type ssh --label env=staging returned: $filtered"
pass "limen ls filters by type and label"

step "A developer sees only what policy allows"
"$here/scripts/dev-login.sh" "$DEVELOPER"
limen ls
names="$(limen ls --json | python3 -c 'import json,sys; print(",".join(r["name"] for r in json.load(sys.stdin)))')"
[ "$names" = "orders-staging,web-staging-1" ] || fail "developer saw: $names"
if limen admin apply "$root/examples/policy" --dry-run 2>/dev/null; then fail "developer must not be able to apply policy"; fi
pass "deny by default; developer can't administer"

step "A user with no mapped groups is denied"
if out="$("$here/scripts/dev-login.sh" $GUEST 2>&1)"; then fail "guest must be denied"; fi
grep -q "no roles are mapped" <<<"$out" || fail "unexpected error for guest: $out"
pass "guest denied: $(echo "$out" | grep -o 'login denied.*')"

step "Single-use join token enrolls a second worker; reuse is rejected"
"$here/scripts/dev-login.sh" "$ADMIN" >/dev/null
token="$(limen admin token create --kind worker --label pool=demo --ttl 10m 2>/dev/null)"
"${compose[@]}" rm -sf worker-2 worker-3 >/dev/null 2>&1 || true
docker rm -f limen-worker-2 limen-worker-3 >/dev/null 2>&1 || true
"${compose[@]}" run -d --name limen-worker-2 -e LIMEN_JOIN_TOKEN="$token" -e LIMEN_DATA_DIR=/var/lib/limen/worker-2 worker >/dev/null
wait_for "second worker tunnels" sh -c "curl -sf http://localhost:3444/tunnels | grep -o worker_id | wc -l | grep -q 4"
"${compose[@]}" run --name limen-worker-3 -e LIMEN_JOIN_TOKEN="$token" -e LIMEN_DATA_DIR=/var/lib/limen/worker-3 worker >"$here/.state/worker-3.log" 2>&1 || true
grep -q "invalid, expired, or already used join token" "$here/.state/worker-3.log" || fail "token reuse should be rejected"
pass "token reuse rejected"
limen admin components

step "Kill the proxy: workers reconnect with backoff and jitter"
"${compose[@]}" restart proxy >/dev/null
wait_for "tunnels after proxy restart" sh -c "curl -sf http://localhost:3444/tunnels | grep -o worker_id | wc -l | grep -q 4"
pass "all 4 tunnels back after proxy restart"

step "Audit trail (stub sink: JSONL in the control plane)"
"${compose[@]}" cp control-plane:/var/lib/limen/audit/control-plane.jsonl "$here/.state/audit.jsonl" >/dev/null
python3 - "$here/.state/audit.jsonl" <<'PY'
import collections, json, sys
events = [json.loads(l) for l in open(sys.argv[1])]
counts = collections.Counter(e["kind"] for e in events)
for kind, n in sorted(counts.items()):
    print(f"  {kind:20} {n}")
for kind in ["auth.login", "auth.denied", "policy.change", "join_token.create", "worker.enroll"]:
    assert counts[kind] > 0, f"missing {kind}"
seqs = [e["producer"]["seq"] for e in events if e["producer"]["instance_id"] == events[-1]["producer"]["instance_id"]]
assert seqs == list(range(seqs[0], seqs[0] + len(seqs))), "seq gap"
print("  no seq gaps for", events[-1]["producer"]["instance_id"])
PY
pass "every Phase 1 event kind present"

step "Logout"
limen logout
limen status
docker rm -f limen-worker-2 >/dev/null 2>&1 || true
printf '\n\033[32mPhase 1 demo passed.\033[0m\n'
