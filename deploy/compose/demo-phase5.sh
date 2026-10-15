#!/usr/bin/env bash
# Phase 5 demo: scale-out. Three control planes on one database serve SSH
# sessions while one is SIGKILLed and the other two are rolling-restarted,
# with no lost audit events and a verifying hash chain (design.md §13).
#
# Runs its own compose project (limen-scale, docker-compose.scale.yml) with
# its own volumes and host ports; the dev stack is never touched.
#
#   deploy/compose/demo-phase5.sh          # resets the scale stack first (down -v)
#   deploy/compose/demo-phase5.sh --keep   # reuse the running scale stack and leave it up
#
# One ephemeral replica is SIGTERMed while S3 is down, so its drain can't
# finish and it hands the rest of its spool to a peer; the other drains
# normally.
#
# Why the SIGKILL goes to control-plane-1: it runs in durable spool mode, so
# what it had acked but not shipped is still on its volume when it comes
# back. An ephemeral replica that is SIGKILLed loses that window (bounded by
# the S3 flush interval, and reported by limen-audit-verify as a seq gap);
# ephemeral replicas are only ever stopped with SIGTERM here, which drains
# and hands off. See ADR-0020.
set -euo pipefail
keep=false
[ "${1:-}" = "--keep" ] && keep=true

root="$(cd "$(dirname "$0")/../.." && pwd)"
here="$root/deploy/compose"
# shellcheck source=dev-users.sh
source "$here/dev-users.sh"
state="$here/.state-scale"
compose=(docker compose --progress=quiet -p limen-scale -f "$here/docker-compose.scale.yml")
export LIMEN_HOME="$state/home"
export LIMEN_BIN="${LIMEN_BIN:-$root/target/release/limen}"
export LIMEN_PROXY=localhost:23443
export LIMEN_DEV_CA="$state/internal-ca.pem"
export LIMEN_DEX_URL=http://localhost:25556
s3=http://localhost:28333/limen-audit
cp_health=(23081 23082 23083)   # control-plane-0..2 admin ports
proxy_health=(23444 23454 23464) # proxy-0..2 admin ports
ticks="${PHASE5_TICKS:-180}"     # seconds the long session runs
run="p5-$(date +%s)-$$"          # tags this run's commands in the audit trail
limen() { "$LIMEN_BIN" "$@"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
failures=0
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; failures=$((failures + 1)); }
die() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
wait_for() {
  local what="$1"; shift
  for _ in $(seq 1 240); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  die "timed out waiting for $what"
}
s3curl() { curl -sf --aws-sigv4 "aws:amz:us-east-1:s3" --user dev:dev-only-secret "$@"; }
verify() {
  "${compose[@]}" exec -T control-plane-0 limen-audit-verify \
    --ca-file /var/lib/limen/ca-public/internal-ca.pem 2>&1
}
# Sum of every audit spool backlog on the control planes and proxies.
pending() {
  local total=0 port v
  for port in "${cp_health[@]}" "${proxy_health[@]}"; do
    v="$(curl -sf "http://localhost:$port/metrics" | awk '/^limen_audit_spool_pending/ {s += $2} END {print s + 0}')" || return 1
    total=$((total + ${v%.*}))
  done
  echo "$total"
}
ready() { curl -sf "http://localhost:$1/readyz"; }
cp_ready() { ready "${cp_health[$1]}"; }
cleanup() {
  [ -n "${loop_pid:-}" ] && kill "$loop_pid" 2>/dev/null || true
  [ -n "${long_pid:-}" ] && kill "$long_pid" 2>/dev/null || true
  if ! $keep; then
    echo "Stopping the scale stack (docker compose -p limen-scale down). Use --keep to leave it up."
    "${compose[@]}" down --remove-orphans >/dev/null 2>&1 || true
  fi
}
command -v ssh >/dev/null || die "OpenSSH client (ssh) is required"

step "Build and start the scale stack: 3 control planes, 3 proxies, 3 workers"
(cd "$root" && cargo build --release -q -p limen-cli)
if ! $keep; then
  echo "Resetting the scale stack (docker compose -p limen-scale down -v). Use --keep to skip."
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1
fi
trap cleanup EXIT
"${compose[@]}" build --quiet >/dev/null
# Staged start: control-plane-1 first, and the proxies while it is the only
# replica, so every proxy's control plane connection (API calls, audit
# ingest) lands on it. Killing it later is the hardest case: all traffic
# fails over at once, with its acked events still unshipped.
if ! cp_ready 1 >/dev/null 2>&1; then
  "${compose[@]}" up -d --quiet-pull control-plane-1 >/dev/null
  wait_for "control-plane-1 readiness" cp_ready 1
  "${compose[@]}" up -d --no-deps proxy-0 proxy-1 proxy-2 >/dev/null
fi
"${compose[@]}" up -d --quiet-pull >/dev/null
for i in 0 1 2; do wait_for "control-plane-$i readiness" cp_ready "$i"; done
for p in "${proxy_health[@]}"; do wait_for "proxy on :$p" ready "$p"; done
mkdir -p "$state"
"${compose[@]}" cp control-plane-0:/var/lib/limen/ca-public/internal-ca.pem "$state/internal-ca.pem" >/dev/null
rm -rf "$LIMEN_HOME"
"$here/dev-login.sh" "$ADMIN" >/dev/null
limen admin apply "$root/examples/policy" --source-ref demo-phase5 >/dev/null
# Distinct workers with a tunnel to any proxy (each worker opens several).
workers_up() {
  local p
  for p in "${proxy_health[@]}"; do curl -sf "http://localhost:$p/tunnels"; done \
    | grep -o '"worker_id":"[^"]*"' | sort -u | wc -l | tr -d ' '
}
three_workers() { [ "$(workers_up)" -eq 3 ]; }
wait_for "3 workers connected" three_workers
sleep 11 # proxies and workers refresh policy every 10s
"${compose[@]}" exec -T postgres psql -U limen -d limen -At \
  -c "SELECT id || ' ' || spool_mode FROM control_plane_replicas ORDER BY id" | sed 's/^/  replica /'
for p in "${proxy_health[@]}"; do
  note "proxy :$p has tunnels from: $(curl -sf "http://localhost:$p/tunnels" | grep -o '"worker_id":"[^"]*"' | sort -u | cut -d'"' -f4 | tr '\n' ' ')"
done
pass "stack up, policy applied, 3 replicas registered"

step "A long SSH session that prints a line every second ($ticks s)"
"$here/dev-login.sh" "$DEVELOPER" >/dev/null
# Sessions that ran their command: the long one plus every new one that
# printed its line. Each must leave exactly one ssh.exec, session.start, and
# session.end in S3.
sessions_ran=0
rm -f "$state/long.status"
{ limen ssh web-staging-1 -- "for i in \$(seq 1 $ticks); do echo tick-$run-\$i; sleep 1; done" 2>"$state/long.err"; echo $? > "$state/long.status"; } \
  | while IFS= read -r line; do printf '%s %s\n' "$(date +%s)" "$line"; done > "$state/long.log" &
long_pid=$!
sessions_ran=$((sessions_ran + 1))
wait_for "the first tick" grep -q "tick-$run-1\$" "$state/long.log"
pass "session running"

step "New sessions, one after another, for the whole disruption"
rm -f "$state/loop.stop" "$state/loop.log"
(
  i=0
  while [ ! -e "$state/loop.stop" ]; do
    i=$((i + 1))
    # A watchdog fails a session that hangs instead of stalling the loop.
    limen ssh web-staging-1 -- "echo new-$run-$i" > "$state/loop.out" 2>&1 &
    pid=$!
    ( sleep 30; kill "$pid" 2>/dev/null ) &
    dog=$!
    status=0
    wait "$pid" || status=$?
    kill "$dog" 2>/dev/null || true
    wait "$dog" 2>/dev/null || true
    out="$(cat "$state/loop.out")"
    if [ "$status" -eq 0 ] && [ "$out" = "new-$run-$i" ]; then
      echo "$(date +%s) ok $i" >> "$state/loop.log"
    else
      echo "$(date +%s) FAILED $i (exit $status): $(tr '\n' ' ' <<<"$out")" >> "$state/loop.log"
    fi
    sleep 1
  done
) &
loop_pid=$!
wait_for "the first new session" grep -q ' ok 1$' "$state/loop.log"
pass "new sessions are being opened"

step "SIGKILL control-plane-1 (durable) while it holds unshipped events"
cp1_pending() {
  curl -sf "http://localhost:${cp_health[1]}/metrics" | awk '/^limen_audit_spool_pending\{consumer="s3"\}/ {print $2 + 0}'
}
for _ in $(seq 1 60); do
  [ "$(cp1_pending || echo 0)" -gt 0 ] 2>/dev/null && break
  sleep 0.5
done
note "control-plane-1 S3 backlog before the kill: $(cp1_pending || echo '?') events"
if [ "$(cp1_pending || echo 0)" -gt 0 ] 2>/dev/null; then
  pass "control-plane-1 holds acked, unshipped events: killing it mid-batch"
else
  fail "control-plane-1 never held a backlog, so this kill proves nothing (killing anyway)"
fi
# Disruption windows (epoch seconds), checked against loop.log at the end.
windows=()
w0=$(date +%s)
"${compose[@]}" kill -s KILL control-plane-1 >/dev/null
note "killed at $(date +%T)"
sleep 5
"${compose[@]}" start control-plane-1 >/dev/null
wait_for "control-plane-1 back" cp_ready 1
note "control-plane-1 ready again at $(date +%T)"
windows+=("control-plane-1 SIGKILL until ready again:$w0:$(date +%s)")

s3_pending() {
  curl -sf "http://localhost:${cp_health[$1]}/metrics" | awk '/^limen_audit_spool_pending\{consumer="s3"\}/ {print $2 + 0}'
}
# Rolling restart of the two ephemeral replicas. The first goes down while S3
# is unreachable, so its drain can't finish and it must hand what is left to
# a live peer; the second is a plain drain. The first is whichever holds an
# S3 backlog (the proxies spread over both after control-plane-1's kill).
step "S3 goes away; events pile up in the spools; sessions carry on"
"${compose[@]}" stop s3 >/dev/null
first=""
for _ in $(seq 1 60); do
  for n in 0 2; do
    if [ "$(s3_pending "$n" || echo 0)" -gt 0 ] 2>/dev/null; then first=$n; break 2; fi
  done
  sleep 0.5
done
if [ -n "$first" ]; then
  second=$((2 - first))
  pass "control-plane-$first holds $(s3_pending "$first") events it cannot ship"
else
  fail "neither ephemeral replica holds an S3 backlog, so the handoff is not exercised"
  first=0; second=2
fi
restart() { # <n> <what>
  local n="$1" since t0
  since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  t0=$(date +%s)
  "${compose[@]}" stop control-plane-"$n" >/dev/null
  note "stopped after $(( $(date +%s) - t0 )) s"
  "${compose[@]}" logs --no-log-prefix --since "$since" control-plane-"$n" 2>/dev/null \
    | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'shipped to every sink|remain in the spool|handed|lost with' \
    | cut -c1-220 | tee "$state/stop-$n.log" | sed 's/^/    /' || true
}

step "Rolling restart 1: SIGTERM control-plane-$first (ephemeral) while S3 is down"
w0=$(date +%s)
restart "$first"
if grep -q 'handed the rest of the audit spool to a peer' "$state/stop-$first.log"; then
  pass "control-plane-$first handed its unshipped events to a peer before exiting"
else
  fail "control-plane-$first did not hand off its unshipped events"
fi
"${compose[@]}" start s3 >/dev/null
note "S3 is back"
"${compose[@]}" start control-plane-"$first" >/dev/null
wait_for "control-plane-$first back" cp_ready "$first"
note "control-plane-$first ready again"
windows+=("restart 1 (control-plane-$first, S3 down) until ready again:$w0:$(date +%s)")
sleep 5

step "Rolling restart 2: SIGTERM control-plane-$second (ephemeral)"
w0=$(date +%s)
restart "$second"
"${compose[@]}" start control-plane-"$second" >/dev/null
wait_for "control-plane-$second back" cp_ready "$second"
note "control-plane-$second ready again"
windows+=("restart 2 (control-plane-$second) until ready again:$w0:$(date +%s)")
sleep 5

step "Settle: stop opening sessions, let the long session finish"
# The long session must outlast the disruption, or it proves nothing.
if kill -0 "$long_pid" 2>/dev/null; then long_outlasted=true; else long_outlasted=false; fi
touch "$state/loop.stop"
wait "$loop_pid" || true
loop_pid=
wait "$long_pid" || true
long_pid=
new_ok="$(grep -c ' ok ' "$state/loop.log" || true)"
new_failed="$(grep -c ' FAILED ' "$state/loop.log" || true)"
note "new sessions: $new_ok succeeded, $new_failed failed"
sessions_ran=$((sessions_ran + new_ok))

step "Assertions"
# 1. The long session never dropped and kept producing output.
got="$(grep -c "tick-$run-" "$state/long.log" || true)"
maxgap="$(awk 'NR > 1 { g = $1 - prev; if (g > m) m = g } { prev = $1 } END { print m + 0 }' "$state/long.log")"
long_status="$(cat "$state/long.status" 2>/dev/null || echo '?')"
if $long_outlasted && [ "$long_status" = "0" ] && [ "$got" -eq "$ticks" ] && grep -q "tick-$run-$ticks\$" "$state/long.log" && [ "$maxgap" -le 3 ]; then
  pass "long session: outlasted the disruption, all $ticks ticks, longest silence ${maxgap}s"
else
  fail "long session: outlasted=$long_outlasted, exit $long_status, $got of $ticks ticks, longest silence ${maxgap}s"; cat "$state/long.err" >&2
fi

# 2. Every new session during the disruption worked.
if [ "$new_failed" -eq 0 ] && [ "$new_ok" -gt 0 ]; then
  pass "new sessions during the disruption: $new_ok of $new_ok succeeded"
else
  fail "new sessions during the disruption: $new_failed of $((new_ok + new_failed)) failed"
  grep FAILED "$state/loop.log" | head -5 | sed 's/^/    /'
fi

# 3. Sessions really opened inside each disruption window, not only around it.
for w in "${windows[@]}"; do
  IFS=: read -r name from to <<<"$w"
  inside="$(awk -v a="$from" -v b="$to" '$2 == "ok" && $1 >= a && $1 <= b' "$state/loop.log" | wc -l | tr -d ' ')"
  if [ "$inside" -gt 0 ]; then
    pass "$inside new session(s) succeeded during $name ($((to - from)) s)"
  else
    fail "no new session succeeded during $name ($((to - from)) s)"
  fi
done

# Wait for every spool to drain and S3 to hold every session of this run.
for _ in $(seq 1 120); do [ "$(pending || echo 1)" = "0" ] && break; sleep 0.5; done
note "audit spool backlog reported by control planes and proxies: $(pending || echo '?') (informational; S3 is checked below)"
s3_events() {
  python3 - "$s3" "$run" <<'PY'
import gzip, json, subprocess, sys, re
base, run = sys.argv[1], sys.argv[2]
def get(url):
    return subprocess.run(["curl", "-sf", "--aws-sigv4", "aws:amz:us-east-1:s3",
                           "--user", "dev:dev-only-secret", url],
                          check=True, capture_output=True).stdout
keys, token = [], None
while True:
    url = f"{base}?list-type=2&prefix=events/" + (f"&continuation-token={token}" if token else "")
    body = get(url).decode()
    keys += re.findall(r"<Key>([^<]*)</Key>", body)
    m = re.search(r"<NextContinuationToken>([^<]*)</NextContinuationToken>", body)
    if not m:
        break
    token = m.group(1)
events = {}
for k in keys:
    for line in gzip.decompress(get(f"{base}/{k.replace('=', '%3D')}")).decode().splitlines():
        e = json.loads(line)
        events[e["event_id"]] = e
execs = [e for e in events.values() if e["kind"] == "ssh.exec" and run in e["data"].get("command", "")]
sids = {e["session_id"] for e in execs}
starts = [e for e in events.values() if e["kind"] == "session.start" and e.get("session_id") in sids]
ends = [e for e in events.values() if e["kind"] == "session.end" and e.get("session_id") in sids]
print(len(execs), len(sids), len(starts), len(ends))
PY
}
counts=""
for _ in $(seq 1 40); do
  counts="$(s3_events 2>/dev/null || true)"
  read -r execs sids starts ends <<<"${counts:-0 0 0 0}"
  [ "$execs" -ge "$sessions_ran" ] && [ "$starts" -ge "$sessions_ran" ] && [ "$ends" -ge "$sessions_ran" ] && break
  sleep 3
done
read -r execs sids starts ends <<<"${counts:-0 0 0 0}"

# 3. S3 holds exactly the sessions this run produced: one ssh.exec, one
#    session.start, and one session.end per session (distinct event ids).
if [ "$execs" -eq "$sessions_ran" ] && [ "$sids" -eq "$sessions_ran" ] \
   && [ "$starts" -eq "$sessions_ran" ] && [ "$ends" -eq "$sessions_ran" ]; then
  pass "S3 event count: $sessions_ran sessions -> $execs ssh.exec, $starts session.start, $ends session.end"
else
  fail "S3 event count: $sessions_ran sessions, but $execs ssh.exec ($sids sessions), $starts session.start, $ends session.end"
fi

# 4. The audit trail verifies: every writer's chain, and no producer seq gap.
# The verifier exits 2 on a problem; the checks below read its output.
verify > "$state/verify.txt" || true
sed 's/^/  /' "$state/verify.txt"
writers="$(sed -n 's/^writers: \([0-9]*\).*/\1/p' "$state/verify.txt")"
manifest_writers="$(s3curl "$s3?list-type=2&prefix=manifests/&delimiter=/" | grep -o '<Prefix>manifests/[^<]*</Prefix>' | sed 's/<[^>]*>//g; s#manifests/##; s#/$##' | grep . | sort | tr '\n' ' ')"
if grep -q '^OK: every batch' "$state/verify.txt"; then
  pass "limen-audit-verify: every chain intact"
else
  fail "limen-audit-verify: chain problems"
fi
if grep -q '^OK: no producer has a sequence gap' "$state/verify.txt" \
   && grep -q '^OK: no sequence number is used by two events' "$state/verify.txt"; then
  pass "limen-audit-verify: no sequence gap or conflict for any producer"
else
  fail "limen-audit-verify: sequence gaps (lost events) or conflicts"
fi
if [ "$writers" = "3" ] && [ "$manifest_writers" = "control-plane-0 control-plane-1 control-plane-2 " ]; then
  pass "writers: 3 (control-plane-0, -1, -2), one chain per replica id"
else
  fail "writers: ${writers:-?} ($manifest_writers), expected the 3 replica ids"
fi

echo
if [ "$failures" -eq 0 ]; then
  printf '\033[32mPhase 5 demo passed.\033[0m\n'
else
  printf '\033[31mPhase 5 demo: %d assertion(s) failed.\033[0m\n' "$failures"
  exit 1
fi
