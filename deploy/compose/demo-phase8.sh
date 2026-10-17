#!/usr/bin/env bash
# Phase 8 demo: kubectl through Limen, by impersonation, on a real cluster
# (kind). Needs docker, kind, kubectl, cargo, curl, and python3.
#
#   deploy/compose/demo-phase8.sh          # creates the kind cluster, removes it after
#   deploy/compose/demo-phase8.sh --keep   # leaves the cluster (and reuses it next time)
#
# It runs Limen (control plane, proxy, and a kube worker) in one process, the
# way the end-to-end tests do, because the dev compose stack is single-tenant
# on fixed host ports and has no cluster to talk to. Postgres is a throwaway
# container of its own. Nothing here touches the dev stack.
#
# Checked against kind, a real Kubernetes API server. Not checked against EKS
# (no AWS account): see docs/guides/kubernetes.md for what differs.
set -euo pipefail
keep=false
[ "${1:-}" = "--keep" ] && keep=true

root="$(cd "$(dirname "$0")/../.." && pwd)"
state="$root/deploy/compose/.state/phase8"
cluster="${LIMEN_DEMO_CLUSTER:-limen-demo8}"
ctx="kind-$cluster"
pg="${cluster}-postgres"
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
need() { command -v "$1" >/dev/null || fail "$1 is required"; }
# expect <what> <text it must contain> <command...>: run it, allow failure, check the output.
expect() {
  local what="$1" want="$2"; shift 2
  local got
  got="$("$@" 2>&1)" || true
  case "$got" in
    *"$want"*) pass "$what" ;;
    *) fail "$what: wanted \"$want\" in: $got" ;;
  esac
}
wait_for() {
  local what="$1"; shift
  for _ in $(seq 1 240); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out waiting for $what"
}
for tool in docker kubectl cargo curl python3; do need "$tool"; done
if command -v kind >/dev/null; then kind=(kind); else kind=(mise exec -- kind); fi

bridge_pid=""
cleanup() {
  [ -n "$bridge_pid" ] && { touch "$state/out/stop" 2>/dev/null || true; wait "$bridge_pid" 2>/dev/null || true; }
  docker rm -f "$pg" >/dev/null 2>&1 || true
  pkill -f "kubectl --kubeconfig $state/out" 2>/dev/null || true
  if ! $keep; then "${kind[@]}" delete cluster --name "$cluster" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

step "Build the limen CLI"
(cd "$root" && cargo build -q -p limen-cli)
limen="$root/target/debug/limen"
[ -x "$limen" ] || fail "no limen binary at $limen"

step "A kind cluster with the Limen worker's service account"
if ! "${kind[@]}" get clusters 2>/dev/null | grep -qx "$cluster"; then
  "${kind[@]}" create cluster --name "$cluster" --wait 180s >/dev/null 2>&1
fi
k() { kubectl --context "$ctx" "$@"; }
k apply -f "$root/deploy/kube/limen-kube-worker.yaml" -f "$root/deploy/kube/limen-groups.yaml" >/dev/null
# A non-expiring token for the demo. In a cluster, the worker uses its pod's projected token.
k apply -f - >/dev/null <<'YAML'
apiVersion: v1
kind: Secret
metadata:
  name: limen-kube-worker-token
  namespace: limen-system
  annotations: { kubernetes.io/service-account.name: limen-kube-worker }
type: kubernetes.io/service-account-token
YAML
rm -rf "$state"; mkdir -p "$state/out"
wait_for "the service account token" bash -c "kubectl --context $ctx -n limen-system get secret limen-kube-worker-token -o jsonpath='{.data.token}' | grep -q ."
k -n limen-system get secret limen-kube-worker-token -o jsonpath='{.data.token}' | base64 -d > "$state/token"
k config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > "$state/ca.pem"
api="$(k config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
pass "cluster $cluster at $api"

step "Start Limen in front of it (control plane, proxy, kube worker)"
docker rm -f "$pg" >/dev/null 2>&1 || true
docker run -d --name "$pg" -e POSTGRES_USER=limen -e POSTGRES_PASSWORD=limen-dev-only -e POSTGRES_DB=limen \
  -p 127.0.0.1::5432 postgres:18-alpine >/dev/null
pgport="$(docker port "$pg" 5432/tcp | head -1 | sed 's/.*://')"
# pg_isready also answers during the image's init-time server, which has no TCP listener. A TCP query does not.
wait_for "postgres" docker exec "$pg" psql -h 127.0.0.1 -U limen -d limen -c "select 1"
(
  cd "$root"
  KIND_API_SERVER="$api" KIND_CA_FILE="$state/ca.pem" KIND_TOKEN_FILE="$state/token" \
  KIND_CLUSTER="$cluster" KIND_OUT="$state/out" \
  LIMEN_TEST_DATABASE_URL="postgres://limen:limen-dev-only@127.0.0.1:$pgport/limen" \
  cargo test -q -p limen-e2e --test kind_bridge -- --ignored --nocapture >"$state/bridge.log" 2>&1
) &
bridge_pid=$!
wait_for "the Limen bridge" test -f "$state/out/ready"
out="$state/out"
for who in ops viewer; do
  LIMEN_HOME="$out/home-$who" "$limen" kube login kind-dev --kubeconfig "$out/kc-$who" >/dev/null
done
ops() { kubectl --kubeconfig "$out/kc-ops" "$@"; }
viewer() { kubectl --kubeconfig "$out/kc-viewer" "$@"; }
admin() { LIMEN_HOME="$out/home-admin" "$limen" admin "$@"; }
pass "Limen is up on $(cat "$out/ready")"

step "kubectl get, as someone Limen impersonates"
who="$(ops auth whoami)"
echo "$who" | grep -q "developer@example.com" || fail "whoami: $who"
echo "$who" | grep -q "limen:edit" || fail "no limen:edit group: $who"
echo "$who" | grep -q "limen-session" || fail "no session extra: $who"
pass "the API server sees developer@example.com in limen:edit, with the Limen session ID"
forged="$(ops --as=system:admin --as-group=system:masters auth whoami)"
echo "$forged" | grep -q "developer@example.com" || fail "a forged --as was honoured: $forged"
pass "a forged --as/--as-group is ignored"
ops get namespaces >/dev/null && pass "kubectl get namespaces"

step "RBAC in the cluster decides what the groups may do"
k delete pod web --ignore-not-found --wait=true >/dev/null
ops run web --image=busybox:1.37 --restart=Never --command -- sh -c 'httpd -f -p 8080 -h /etc' >/dev/null
ops wait --for=condition=Ready pod/web --timeout=180s >/dev/null
expect "the viewer (limen:view) can list pods" "web" viewer get pods
expect "the viewer cannot delete a pod" "Forbidden" viewer delete pod web
expect "the viewer cannot exec" "Forbidden" viewer exec web -- id
expect "the viewer cannot forge an admin" "Forbidden" viewer --as=system:admin get secrets -A
expect "the viewer is still the viewer" "guest@example.com" viewer --as=system:admin auth whoami

step "kubectl exec: WebSocket and SPDY, recorded"
set +e
ops exec web -- sh -c 'echo hello-from-ws; echo to-stderr >&2; exit 3' >"$out/ws.txt" 2>&1; rc=$?
set -e
if [ "$rc" != 3 ] || ! grep -q hello-from-ws "$out/ws.txt"; then fail "websocket exec: rc=$rc $(cat "$out/ws.txt")"; fi
pass "exec over WebSocket: output and exit code 3"
set +e
KUBECTL_REMOTE_COMMAND_WEBSOCKETS=false ops exec web -- sh -c 'echo hello-from-spdy; exit 4' >"$out/spdy.txt" 2>&1; rc=$?
set -e
if [ "$rc" != 4 ] || ! grep -q hello-from-spdy "$out/spdy.txt"; then fail "spdy exec: rc=$rc $(cat "$out/spdy.txt")"; fi
pass "exec over SPDY: output and exit code 4"
# The command (which is recorded, in the title) does not contain what is typed, and prints something else.
# shellcheck disable=SC2016 # ${#line} is for the container
typed="$(echo "$$-typed-secret" | ops exec -i web -- sh -c 'read line; echo "${#line} chars"; echo stdin-arrived')"
case "$typed" in *stdin-arrived*) pass "stdin reaches the container" ;; *) fail "stdin: $typed" ;; esac
rec="$(cat "$out/recordings-path")"
wait_for "recordings to upload" bash -c "grep -rl hello-from-spdy '$rec' && grep -rl hello-from-ws '$rec' && grep -rl stdin-arrived '$rec'"
if ! grep -rh '"x"' "$rec" | grep -q '"x","3"'; then fail "no exit code in the recordings"; fi
pass "recordings are on the control plane, with exit codes"
if grep -rq -e "-typed-secret" "$rec" 2>/dev/null; then fail "stdin was recorded"; fi
pass "stdin is not in the recordings"
if command -v asciinema >/dev/null; then echo "  play one with: asciinema play $(grep -rl hello-from-ws "$rec" | head -1)"; fi

step "kubectl port-forward: WebSocket-tunnelled SPDY and plain SPDY"
ops port-forward pod/web 18171:8080 >"$out/pf1.log" 2>&1 &
pf1=$!
KUBECTL_PORT_FORWARD_WEBSOCKETS=false ops port-forward pod/web 18172:8080 >"$out/pf2.log" 2>&1 &
pf2=$!
wait_for "port-forward 1" curl -sf -m 3 localhost:18171/hostname
wait_for "port-forward 2" curl -sf -m 3 localhost:18172/hostname
pass "traffic flows through both port-forwards"
kill "$pf1" "$pf2" 2>/dev/null || true; pkill -f "kubectl --kubeconfig $out/kc-ops port-forward" || true

step "A lock ends an open exec; a locked user is refused"
(set +e; ops exec web -- sleep 300 >"$out/lock.txt" 2>&1; echo "rc=$?" >>"$out/lock.txt") &
wait_for "the exec to start" bash -c "kubectl --context $ctx exec web -- true"
sleep 2
admin lock developer@example.com --reason "phase 8 demo" >/dev/null
wait_for "the exec to end" grep -q '^rc=' "$out/lock.txt"
pass "the open exec ended"
expect "new requests are refused" "user locked" ops get pods
admin unlock developer@example.com >/dev/null
wait_for "the unlock to reach the proxy" ops get pods

step "The audit trail"
audit="$(cat "$out/audit-path")"
wait_for "stream audit events" bash -c "grep -c '\"session.end\"' '$audit' | grep -qv '^[0-3]$'"
python3 - "$audit" <<'PY'
import json, sys
events = [json.loads(l) for l in open(sys.argv[1])]
req = [e for e in events if e["kind"] == "kube.request"]
assert any(e["data"]["verb"] == "list" and e["data"]["k8s_resource"] == "namespaces" for e in req), "kube.request for the list"
assert all(e["user"] for e in req), "every request names the user"
starts = {e["session_id"]: e["data"] for e in events if e["kind"] == "session.start" and e["data"].get("kind") == "kube"}
ends = {e["session_id"]: e["data"] for e in events if e["kind"] == "session.end" and e["data"].get("kind") == "kube"}
execs = [(starts[s], ends[s]) for s in starts if s in ends and starts[s]["login"] == "exec"]
assert any(e["exit_code"] == 3 and e.get("recording_sha256") for _, e in execs), "ws exec with exit code and recording"
assert any(e["exit_code"] == 4 and e.get("recording_sha256") for _, e in execs), "spdy exec with exit code and recording"
pfs = [e for s, e in ends.items() if e["login"] == "portforward"]
assert len(pfs) >= 2 and all(8080 in e["ports"] for e in pfs), f"port-forward ports: {pfs}"
assert any("locked" in e["reason"] for e in ends.values()), "the lock ended a stream"
print(f"  {len(req)} kube.request events, {len(starts)} streams (exec, port-forward), all linked to a user and a session")
PY
pass "kube.request, session.start/end, exit codes, ports, recordings, and the lock are in the trail"

step "Phase 8 demo passed"
