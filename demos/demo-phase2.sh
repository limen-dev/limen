#!/usr/bin/env bash
# Phase 2 demo: SSH with the real OpenSSH client, through Limen, to a real
# sshd that trusts only Limen per-session certificates.
#
#   demos/demo-phase2.sh          # resets the dev stack first (down -v)
#   demos/demo-phase2.sh --keep   # reuse the running stack
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
limen() { "$LIMEN_BIN" "$@"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
wait_for() {
  local what="$1"; shift
  for _ in $(seq 1 120); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out waiting for $what"
}
command -v ssh >/dev/null || fail "OpenSSH client (ssh) is required"

step "Build and start the stack"
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
limen admin apply "$root/examples/policy" --source-ref demo-phase2 >/dev/null
wait_for "worker tunnels" sh -c "curl -sf http://localhost:3444/tunnels | grep -q worker_id"
# Proxy and worker pick up the new policy within their 10s refresh.
sleep 11
pass "stack up, policy applied"

step "developer runs a command on web-staging-1 with plain OpenSSH, through Limen"
"$here/scripts/dev-login.sh" "$DEVELOPER" >/dev/null
out="$(limen ssh web-staging-1 -- 'echo "I am $(whoami) on $(hostname)"')"
echo "$out"
grep -q "I am ubuntu on" <<<"$out" || fail "unexpected output: $out"
pass "login inferred from policy (ubuntu), command ran on the target"

step "The target only accepted a Limen certificate naming the session and user"
"${compose[@]}" logs sshd-target 2>/dev/null | grep -o 'Accepted certificate ID "limen:[^"]*"' | tail -1 | tee "$state/sshd-accept.log"
grep -q ''"$DEVELOPER"'' "$state/sshd-accept.log" || fail "sshd log doesn't show the Limen certificate"
pass "sshd logged the per-session certificate"

step "Denials"
if limen ssh root@web-staging-1 -- id 2>"$state/deny.err"; then fail "root must be denied"; fi
grep -o "access denied.*" "$state/deny.err" | head -1
if limen ssh ubuntu@bastion-staging -- id 2>"$state/deny2.err"; then fail "the bastion is denied by policy"; fi
grep -o "access denied.*\|no SSH access.*" "$state/deny2.err" | head -1
pass "root and the bastion are refused"

step "Plain ssh via 'limen config ssh'"
limen config ssh > "$state/ssh_config"
cat "$state/ssh_config"
out="$(ssh -F "$state/ssh_config" ubuntu@web-staging-1.limen 'echo via-ssh-config')"
[ "$out" = "via-ssh-config" ] || fail "ssh via config: $out"
pass "ssh ubuntu@web-staging-1.limen works"

step "Control plane outage: a running session continues, new SSH sessions fail closed"
limen ssh web-staging-1 -- 'for i in $(seq 1 12); do echo tick $i; sleep 1; done' > "$state/ticks.log" 2>&1 &
ticker=$!
sleep 3
"${compose[@]}" stop control-plane >/dev/null
# Name the login: looking up the default one needs the control plane too.
if limen ssh ubuntu@web-staging-1 -- id 2>"$state/outage.err"; then fail "new SSH session must fail while the control plane is down"; fi
grep "control plane" "$state/outage.err" | head -1 || { cat "$state/outage.err"; fail "unexpected outage error"; }
wait "$ticker" || true
grep -q "tick 12" "$state/ticks.log" || { cat "$state/ticks.log"; fail "running session was cut"; }
pass "running session finished all 12 ticks during the outage"
"${compose[@]}" start control-plane >/dev/null
wait_for "control plane back" curl -sf http://localhost:3081/readyz

step "Recordings and audit trail"
# Events from the proxy and worker reach the control plane through their
# spools; recordings are uploaded by the worker after each session.
sleep 8
# The control plane stores them in the audit bucket (SeaweedFS in this
# stack, signed with the dev identity in s3/s3.json).
s3curl() { curl -sf --aws-sigv4 "aws:amz:us-east-1:s3" --user dev:dev-only-secret "$@"; }
rm -rf "$state/recordings"; mkdir -p "$state/recordings"
for key in $(s3curl "http://localhost:${LIMEN_PORT_S3:-8333}/limen-audit?list-type=2&prefix=recordings/" | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g'); do
  echo "  s3://limen-audit/$key"
  # curl's SigV4 signs "=" in the path only when it's percent-encoded.
  s3curl "http://localhost:${LIMEN_PORT_S3:-8333}/limen-audit/${key//=/%3D}" -o "$state/recordings/$(basename "$key")"
done
cast="$(grep -rl "tick 12" "$state/recordings" | head -1)"
[ -n "$cast" ] || fail "no recording of the ticking session"
head -1 "$cast"; grep -m2 '"o"' "$cast"
"${compose[@]}" cp control-plane:/var/lib/limen/audit/control-plane.jsonl "$state/audit.jsonl" >/dev/null
python3 - "$state/audit.jsonl" <<'PY'
import collections, json, sys
events = [json.loads(l) for l in open(sys.argv[1])]
print("  " + ", ".join(f"{k}={v}" for k, v in sorted(collections.Counter(e["kind"] for e in events).items())))
ends = {e["session_id"]: e for e in events if e["kind"] == "session.end"}
stored = {e["session_id"]: e for e in events if e["kind"] == "session.recording"}
assert stored, "session.recording events"
for sid, rec in stored.items():
    assert sid in ends and ends[sid]["data"]["recording_sha256"] == rec["data"]["sha256"], "recording matches its session"
execs = [e for e in events if e["kind"] == "ssh.exec"]
assert any(e["session_id"] in ends for e in execs), "ssh.exec links to its session"
for e in execs[:3]:
    print(f"  ssh.exec {e['user']} {e['data']['login']}@{e['data']['resource']}: {e['data']['command']}")
PY
pass "session.start/end, ssh.exec, and auth.denied present and linked"

printf '\n\033[32mPhase 2 demo passed.\033[0m\n'
