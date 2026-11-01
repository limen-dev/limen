#!/usr/bin/env bash
# Phase 14 demo: one management API (ADR-0042). A CI job logs in as a bot with
# a policy_writer grant and registers its own SSH host in Limen from a profile
# a person wrote, the way the Terraform provider does, and a developer reaches
# the host through Limen. Then the pipeline writes its own role and mapping:
# the access they give waits for a person, who approves it from the CLI. It
# runs in its own compose project and ports, so a dev stack already running is
# left alone.
#
#   demos/demo-phase14.sh          # resets this demo's own stack first
#   demos/demo-phase14.sh --keep   # reuse it
#
# The CI tokens come from a stand-in issuer: unverified against real GitHub.
set -euo pipefail
keep=false
[ "${1:-}" = "--keep" ] && keep=true

root="$(cd "$(dirname "$0")/.." && pwd)"
here="$root/deploy/compose"
# shellcheck source=../deploy/compose/scripts/dev-users.sh
source "$here/scripts/dev-users.sh"
project="${LIMEN_PHASE14_PROJECT:-limen-phase14}"
state="$here/.state/$project"
mkdir -p "$state"
export LIMEN_PROJECT="$project" LIMEN_STATE_DIR="$state" LIMEN_IMAGE_TAG=phase14 LIMEN_SUFFIX=-phase14
export LIMEN_PORT_PROXY="${LIMEN_PHASE14_PROXY_PORT:-38443}"
export LIMEN_PORT_HEALTH="${LIMEN_PHASE14_HEALTH_PORT:-38444}"
export LIMEN_PORT_DEX="${LIMEN_PHASE14_DEX_PORT:-38556}"
export LIMEN_PORT_CP="${LIMEN_PHASE14_CP_PORT:-38081}"
export LIMEN_PORT_S3="${LIMEN_PHASE14_S3_PORT:-38333}"
export LIMEN_PORT_POSTGRES="${LIMEN_PHASE14_PG_PORT:-38432}"
export LIMEN_PORT_KMS="${LIMEN_PHASE14_KMS_PORT:-38099}"
export LIMEN_PORT_CI_ISSUER="${LIMEN_PHASE14_ISSUER_PORT:-38130}"
# shellcheck source=../deploy/compose/scripts/lib.sh
source "$here/scripts/lib.sh"
stack_setup ssh bots

export LIMEN_BIN="${LIMEN_BIN:-$root/target/release/limen}"
export LIMEN_PROXY="localhost:$LIMEN_PORT_PROXY"
export LIMEN_DEX_URL="http://localhost:$LIMEN_PORT_DEX"
issuer_url="http://localhost:$LIMEN_PORT_CI_ISSUER"
ca="$state/internal-ca.pem"
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
wait_for() {
  local what="$1"; shift
  for _ in $(seq 1 240); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out waiting for $what"
}
as_admin() { LIMEN_HOME="$state/home-admin" "$LIMEN_BIN" "$@"; }
as_developer() { LIMEN_HOME="$state/home-developer" "$LIMEN_BIN" "$@"; }
as_bot() { LIMEN_HOME="$state/home-bot" "$LIMEN_BIN" "$@"; }
mint() { curl -sf "$issuer_url/github?repository=acme/demo-infra&ref=refs/heads/main&environment=staging&run_id=$1&actor=octocat"; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
command -v ssh >/dev/null || fail "OpenSSH client (ssh) is required"

step "Build and start the demo's own stack ($project)"
(cd "$root" && cargo build --release -q -p limen-cli)
$keep || { echo "Resetting this demo's stack (project $project, down -v). Use --keep to skip."; "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1; }
"${compose[@]}" up -d --build --quiet-pull >/dev/null
wait_for "proxy readiness" curl -sf "http://localhost:$LIMEN_PORT_HEALTH/readyz"
wait_for "the fake CI issuer" curl -sf "$issuer_url/.well-known/openid-configuration"
"${compose[@]}" cp control-plane:/var/lib/limen/ca-public/internal-ca.pem "$ca" >/dev/null
export LIMEN_DEV_CA="$ca"
rm -rf "$state/home-admin" "$state/home-developer" "$state/home-bot" "$state/home-oncall" "$state/work"
mkdir -p "$state/work"
LIMEN_HOME="$state/home-admin" "$here/scripts/dev-login.sh" "$ADMIN" >/dev/null

# People write the profile (what's fixed) and the grant (who may complete it).
cat > "$state/work/delegation.yaml" <<'YAML'
kind: role
version: v1
metadata: { name: demo-ci }
spec:
  cert_ttl: 15m
  allow:
    - resources: { kind: [ssh], labels: { team: [demo], env: [staging] } }
      ssh: { logins: [ubuntu] }
---
kind: bot
version: v1
metadata: { name: demo-terraform }
spec:
  join:
    method: github_actions
    issuer: http://fake-ci-issuer:8130
    match: { repository: acme/demo-infra, ref: refs/heads/main, environment: staging }
  roles: [demo-ci]
  max_ttl: 1h
---
kind: resource_profile
version: v1
metadata: { name: demo-ssh, description: An SSH host of the demo team. }
spec:
  template:
    ssh: {}
    worker_selector: { pool: dev }
  settable:
    ssh.address: { hosts: [sshd-target], ports: [22] }
    ssh.host_key: {}
  labels:
    fixed: { team: demo }
    allowed: { env: [staging] }
---
kind: policy_writer
version: v1
metadata: { name: demo-terraform }
spec:
  bot: demo-terraform
  namespace: demo-team
  names: ["demo-*"]
  kinds: [resource, role, role_mapping, policy_test]
  profiles: [demo-ssh]
  max_documents: 10
  approvers: { groups: [sre-oncall] }
YAML
apply_files() { as_admin admin apply "$root/examples/policy" "$state/work/delegation.yaml" --source-ref demo-phase14 >/dev/null; }
apply_files
# Signing in maps groups to roles, so the developer signs in after the policy exists.
LIMEN_HOME="$state/home-developer" "$here/scripts/dev-login.sh" "$DEVELOPER" >/dev/null
wait_for "worker tunnels" sh -c "curl -sf http://localhost:$LIMEN_PORT_HEALTH/tunnels | grep -q worker_id"
pass "stack up; the profile and the writer grant are in policy"

step "The CI job logs in as the bot: no secret, and no limen:admin"
mint 1 > "$state/work/token-1.jwt"
as_bot --proxy "$LIMEN_PROXY" login --bot github_actions --token-file "$state/work/token-1.jwt" --ca-file "$ca" >/dev/null
rm -f "$state/work/token-1.jwt"
as_bot manage whoami > "$state/work/whoami.json"
[ "$(json 'd["grant"]["namespace"]' < "$state/work/whoami.json")" = demo-team ] || fail "the bot's grant isn't demo-team"
[ "$(json 'd["admin"]' < "$state/work/whoami.json")" = False ] || fail "the bot is an admin"
pass "bot:demo-terraform writes in namespace demo-team, from profile demo-ssh only"

step "It registers its host from the profile, as terraform apply would"
host_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAkWE808+SBJ5tbkLTrbcpmj4Qg2UvqRG/CYJgBwP1S"
spec="{\"ssh\":{\"address\":\"sshd-target:22\",\"host_key\":\"$host_key\"}}"
as_bot manage put-resource demo-web --profile demo-ssh --spec "$spec" --label env=staging \
  --source terraform/demo --request-id 6f1c2b7a-3d4e-4f50-8a9b-0c1d2e3f4a5b > "$state/work/created.json"
[ "$(json 'd["outcome"]' < "$state/work/created.json")" = applied ] || fail "the resource wasn't applied"
[ "$(json 'd["documents"][0]["effective_labels"]["team"]' < "$state/work/created.json")" = demo ] || fail "the profile's fixed label is missing"
json '"\n".join("  " + c for c in d["access_changes"])' < "$state/work/created.json"
again="$(as_bot manage put-resource demo-web --profile demo-ssh --spec "$spec" --label env=staging \
  --source terraform/demo --request-id 6f1c2b7a-3d4e-4f50-8a9b-0c1d2e3f4a5b | json 'd["policy_version"]')"
[ "$again" = "$(json 'd["policy_version"]' < "$state/work/created.json")" ] || fail "a retry wrote again"
pass "demo-web registered; a retry with the same request id returned the first result"

step "Outside its grant, it's refused, and the refusals are audited"
refuse() {
  local why="$1"; shift
  if as_bot manage "$@" >/dev/null 2>"$state/work/refused.err"; then fail "accepted: $*"; fi
  grep -q "$why" "$state/work/refused.err" || { cat "$state/work/refused.err"; fail "refused for the wrong reason (wanted: $why)"; }
  echo "  refused: $why"
}
refuse "doesn't match" put-resource other-web --profile demo-ssh --spec "$spec" --source terraform/demo
refuse "doesn't match the allowed hosts" put-resource demo-evil --profile demo-ssh \
  --spec '{"ssh":{"address":"control-plane:22"}}' --source terraform/demo
refuse "always refuses" put-resource demo-meta --profile demo-ssh \
  --spec '{"ssh":{"address":"169.254.169.254:22"}}' --source terraform/demo
refuse "isn't allowed" put-resource demo-prod --profile demo-ssh --spec "$spec" --label env=prod --source terraform/demo
refuse "isn't settable" put-resource demo-other-worker --profile demo-ssh \
  --spec '{"ssh":{"address":"sshd-target:22"},"worker_selector":{"pool":"elsewhere"}}' --source terraform/demo
pass "names, hosts, metadata addresses, labels, and the worker are out of the writer's reach"

step "Policy applied from files leaves the writer's resource alone"
apply_files
owner="$(as_admin manage get resource demo-web | json 'd["owner"]["source"]')" \
  || fail "a file apply dropped the writer's resource"
[ "$owner" = terraform/demo ] || fail "the resource changed owner: $owner"
pass "limen admin apply replaced its own source only"

step "A developer reaches the host through Limen"
sleep 11 # proxy and worker refresh policy every 10s
# shellcheck disable=SC2016 # expands on the target, not here
as_developer ssh demo-web -- 'echo "hello from $(hostname), registered by a pipeline"' || fail "the developer couldn't reach demo-web"
pass "a resource a pipeline registered works like any other"

step "terraform destroy: the bot deletes it, and it's gone"
etag="$(as_bot manage get resource demo-web | json 'd["etag"]')"
as_bot manage delete-resource demo-web --source terraform/demo --etag "$etag" | json 'd["outcome"]' | grep -q applied || fail "delete"
as_bot manage delete-resource demo-web --source terraform/demo --if-exists | json 'd["outcome"]' | grep -q unchanged || fail "a repeated delete"
sleep 11
if as_developer ssh demo-web -- true >/dev/null 2>&1; then fail "the deleted resource is still reachable"; fi
pass "deleted; a second delete is a no-op; the host is no longer reachable"

step "The pipeline writes its own role and mapping; the access they give waits for a person"
as_bot manage put role demo-web-readers --source terraform/demo \
  --spec '{"allow":[{"resources":{"kind":["ssh"],"labels":{"team":["demo"]}},"ssh":{"logins":["ubuntu"]}}]}' \
  | json 'd["outcome"]' | grep -q applied || fail "the writer's role"
as_bot manage put role_mapping demo-viewers --source terraform/demo \
  --spec '[{"idp_group":"viewers","roles":["demo-web-readers"]}]' \
  | json 'd["outcome"]' | grep -q applied || fail "the writer's mapping (it reaches nothing yet)"
refuse "built-in role" put role_mapping demo-admins --source terraform/demo \
  --spec '[{"idp_group":"viewers","roles":["limen:admin"]}]'
refuse "requestable" put role demo-ask --source terraform/demo \
  --spec '{"allow":[],"request":{"who":{"groups":["viewers"]},"approvers":{"groups":["viewers"]},"max_duration":"1h"}}'
refuse "can't write bot" put bot demo-sneaky --source terraform/demo --spec '{}'
as_bot manage put-resource demo-api --profile demo-ssh --spec "$spec" --label env=staging \
  --source terraform/demo > "$state/work/held.json"
[ "$(json 'd["outcome"]' < "$state/work/held.json")" = pending_approval ] \
  || { cat "$state/work/held.json"; fail "access from the writer's own mapping went through"; }
change="$(json 'd["pending_change"]["id"]' < "$state/work/held.json")"
json '"\n".join("  waits: " + c for c in d["pending_change"]["access_changes"] if "viewers" in c)' < "$state/work/held.json"
if as_admin manage get resource demo-api >/dev/null 2>&1; then fail "a held resource exists"; fi
if as_bot manage changes approve "$change" >/dev/null 2>"$state/work/refused.err"; then fail "the bot approved its own change"; fi
grep -q "bots never do" "$state/work/refused.err" || { cat "$state/work/refused.err"; fail "the bot was refused for the wrong reason"; }
pass "held as change $change; bots never decide"

step "Someone on call reviews it in the CLI and approves it"
LIMEN_HOME="$state/home-oncall" "$here/scripts/dev-login.sh" "$ONCALL" >/dev/null
as_oncall() { LIMEN_HOME="$state/home-oncall" "$LIMEN_BIN" "$@"; }
as_oncall manage changes ls | json '"\n".join("  pending: " + c["id"] + " by " + c["author"] + " (run by " + c["author_ci"].get("actor", "?") + ")" for c in d)'
as_oncall manage changes approve "$change" --note "viewers may read the demo hosts" > "$state/work/approved.json"
[ "$(json 'd["state"]' < "$state/work/approved.json")" = applied ] || { cat "$state/work/approved.json"; fail "approval"; }
[ "$(as_admin manage get resource demo-api | json 'd["updated_by"]')" = bot:demo-terraform ] || fail "not written as its author"
pass "approved by $ONCALL; demo-api is in policy, written as the bot"

step "Admins write the people-only kinds through the API too"
as_admin manage put role demo-auditors --source console/demo \
  --spec '{"allow":[{"resources":{"kind":["ssh"],"labels":{"team":["demo"]}},"ssh":{"logins":["ubuntu"]}}]}' \
  | json 'd["outcome"]' | grep -q applied || fail "an admin's role"
etag="$(as_admin manage get bot demo-terraform | json 'd["etag"]')"
if as_admin manage delete bot demo-terraform --source console/demo --etag "$etag" >/dev/null 2>"$state/work/refused.err"; then
  fail "the API deleted a bot that files own"
fi
grep -q 'managed by git source "default"' "$state/work/refused.err" || { cat "$state/work/refused.err"; fail "wrong refusal for a bot files own"; }
pass "an admin's role went through; what files own stays theirs"

step "The audit trail tells the story"
"${compose[@]}" cp control-plane:/var/lib/limen/audit/control-plane.jsonl "$state/work/audit.jsonl" >/dev/null
python3 - "$state/work/audit.jsonl" <<'PY'
import json, sys
events = [json.loads(line) for line in open(sys.argv[1])]
kinds = [e["kind"] for e in events]
denied = [e for e in events if e["kind"] == "policy.write_denied"]
assert len(denied) >= 5, f"expected the refusals in the trail, found {len(denied)}"
changes = [e for e in events if e["kind"] == "policy.change" and e.get("user") == "bot:demo-terraform"]
assert len(changes) >= 2, "the bot's create and delete are policy changes"
owners = changes[0]["data"]["owners"][0]
assert owners == {"channel": "api", "source": "terraform/demo", "namespace": "demo-team"}, owners
pending = [e for e in events if e["kind"] == "policy.change_pending"]
decided = [e for e in events if e["kind"] == "policy.change_decided" and e["data"]["state"] == "applied"]
assert pending and decided, "the held change and its approval are in the trail"
approved = [e for e in changes if (e["data"].get("approval") or {}).get("approved_by")]
assert approved, "the applied change names its approver"
print(f"  {len(changes)} policy changes by the bot, {len(denied)} refused writes, all attributed;")
print(f"  {len(pending)} held, approved by {approved[0]['data']['approval']['approved_by']}")
PY
pass "every write and refusal is in the trail, with its owner"

printf '\n\033[32mPhase 14 demo passed.\033[0m\n'
echo "This stack: project $project, proxy $LIMEN_PROXY. Stop it: LIMEN_PROJECT=$project docker compose -p $project down -v"
