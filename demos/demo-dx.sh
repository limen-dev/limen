#!/usr/bin/env bash
# First-five-minutes demo (epic #121, ADR-0041): `limen doctor`, plain ssh
# through `limen config ssh --install`, and `limen kube config`.
#
#   demos/demo-dx.sh          # starts its own stack (project limen-dxdemo) and removes it after
#   demos/demo-dx.sh --keep   # leaves that stack running, and reuses it next time
#
# It runs beside the dev stack on its own ports and never touches your real
# ~/.ssh/config or kubeconfig: the CLI's home and the OpenSSH config it edits
# live in the demo's state directory.
set -euo pipefail
keep=false
[ "${1:-}" = "--keep" ] && keep=true

root="$(cd "$(dirname "$0")/.." && pwd)"
here="$root/deploy/compose"
# shellcheck source=../deploy/compose/scripts/dev-users.sh
source "$here/scripts/dev-users.sh"
export LIMEN_PROJECT="${LIMEN_PROJECT:-limen-dxdemo}" LIMEN_IMAGE_TAG="${LIMEN_IMAGE_TAG:-dxdemo}"
export LIMEN_STATE_DIR="${LIMEN_STATE_DIR:-$here/.state/dxdemo}"
export LIMEN_PORT_PROXY="${LIMEN_PORT_PROXY:-33443}" LIMEN_PORT_HEALTH="${LIMEN_PORT_HEALTH:-33444}"
export LIMEN_PORT_DEX="${LIMEN_PORT_DEX:-35556}" LIMEN_PORT_CP="${LIMEN_PORT_CP:-33081}"
export LIMEN_PORT_POSTGRES="${LIMEN_PORT_POSTGRES:-35432}" LIMEN_PORT_S3="${LIMEN_PORT_S3:-38333}"
export LIMEN_PORT_KMS="${LIMEN_PORT_KMS:-38099}"
state="$LIMEN_STATE_DIR"
export LIMEN_BIN="${LIMEN_BIN:-$root/target/release/limen}"
export LIMEN_PROXY="localhost:$LIMEN_PORT_PROXY" LIMEN_DEX_URL="http://localhost:$LIMEN_PORT_DEX"
export LIMEN_DEV_CA="$state/internal-ca.pem"
export LIMEN_HOME="$state/home"
unset KUBECONFIG
limen() { "$LIMEN_BIN" "$@"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
login() { "$here/scripts/dev-login.sh" "$1" >/dev/null; }
for tool in ssh curl python3 cargo; do command -v "$tool" >/dev/null || fail "$tool is required"; done
cleanup() { $keep || "$here/setup.sh" down >/dev/null 2>&1 || true; }
trap cleanup EXIT

step "Build the CLI and start the stack (ssh and kube)"
(cd "$root" && cargo build --release -q -p limen-cli)
if $keep && curl -sf "http://localhost:$LIMEN_PORT_HEALTH/readyz" >/dev/null; then
  echo "Reusing the running $LIMEN_PROJECT stack."
else
  "$here/setup.sh" --yes --stacks ssh,kube >"$state.setup.log" 2>&1 || { tail -30 "$state.setup.log"; fail "setup.sh"; }
fi
rm -rf "$LIMEN_HOME"
pass "stack up on $LIMEN_PROXY"

step "doctor before any login: says what is missing, and how to fix it"
out="$(limen doctor 2>&1)" && fail "doctor passed with no login"
echo "$out"
grep -q "no CA is pinned" <<<"$out" || fail "the missing CA isn't named"
grep -q "skipped" <<<"$out" || fail "dependent checks aren't skipped"
pass "no CA, no login: doctor fails with fixes"

step "doctor on a proxy that isn't there"
limen login --proxy localhost:1 --ca-file "$LIMEN_DEV_CA" >/dev/null 2>&1 || true
out="$(limen --proxy localhost:1 doctor 2>&1)" && fail "doctor passed for a dead proxy"
grep -q "✖ network" <<<"$out" || fail "unreachable proxy not reported: $out"
grep -q "– tls" <<<"$out" || fail "tls should be skipped: $out"
pass "unreachable proxy reported as a network problem; TLS skipped"

step "developer logs in; doctor passes"
login "$DEVELOPER"
limen doctor || fail "doctor after login"
pass "all checks pass"

step "doctor with a resource: one you have, one you don't"
limen doctor web-staging-1 >/dev/null || fail "web-staging-1 should be reachable"
out="$(limen doctor bastion-staging 2>&1)" && fail "the bastion is denied by policy"
grep -A1 "✖ access" <<<"$out"
pass "access is checked against policy"

step "doctor --json holds no secret"
limen doctor --json >"$state/doctor.json" || fail "doctor --json"
python3 - "$state/doctor.json" "$LIMEN_HOME" <<'PY'
import json, pathlib, sys
report = json.load(open(sys.argv[1]))
assert report["ok"] is True, report
names = [c["name"] for c in report["checks"]]
assert names[:7] == ["proxy", "ca", "network", "tls", "clock", "login", "session"], names
text = open(sys.argv[1]).read()
key = next(pathlib.Path(sys.argv[2]).glob("profiles/*/key.pem")).read_text()
cert = next(pathlib.Path(sys.argv[2]).glob("profiles/*/cert.pem")).read_text()
for secret in ("PRIVATE KEY", "CERTIFICATE", key.splitlines()[1], cert.splitlines()[1]):
    assert secret not in text, secret
PY
pass "JSON report: checks in order, no key or certificate"

step "config ssh --install: plain ssh"
sshcfg="$state/user-ssh-config"
printf 'Host example-not-limen\n    User someone\n' >"$sshcfg"
limen config ssh --install --file "$sshcfg"
head -4 "$sshcfg"
grep -q "^Include $LIMEN_HOME/ssh_config$" "$sshcfg" || fail "Include line missing"
grep -q "^Host example-not-limen" "$sshcfg" || fail "existing entries must be kept"
out="$(ssh -F "$sshcfg" web-staging-1 'echo "plain ssh as $(whoami)"')"
echo "$out"
[ "$out" = "plain ssh as ubuntu" ] || fail "plain ssh: $out"
# The stand-in target has no scp, sftp-server, rsync or git, so this checks
# the transport they all ride on: bytes through stdin and stdout, both ways.
head -c 65536 /dev/urandom >"$state/payload.bin"
ssh -F "$sshcfg" web-staging-1 'cat > /tmp/limen-payload.bin' <"$state/payload.bin"
ssh -F "$sshcfg" web-staging-1 'cat /tmp/limen-payload.bin' >"$state/payload-back.bin"
cmp -s "$state/payload.bin" "$state/payload-back.bin" || fail "binary round trip"
pass "ssh web-staging-1 runs commands and carries 64 KiB of binary both ways, with no wrapper"

step "Installing twice keeps one block"
limen config ssh --install --file "$sshcfg" >/dev/null
[ "$(grep -c '>>> limen >>>' "$sshcfg")" = 1 ] || fail "duplicate block"
pass "idempotent"

step "Login refreshes the generated file to the new roles"
grep -q "^Host bastion-staging" "$LIMEN_HOME/ssh_config" && fail "developer must not see the bastion"
login "$ADMIN"
grep -q "^Host bastion-staging" "$LIMEN_HOME/ssh_config" || fail "admin login didn't refresh the hosts"
pass "admin's login added bastion-staging"

step "kube config: one kubeconfig, a context per cluster"
limen kube config
python3 - "$LIMEN_HOME/kubeconfig" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
names = [c["name"] for c in cfg["contexts"]]
assert names and all(n.startswith("limen-") for n in names), names
assert "current-context" not in cfg
assert "client-key-data" not in open(sys.argv[1]).read()
print("contexts:", ", ".join(names))
PY
if command -v kubectl >/dev/null; then
  ctx="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["contexts"][0]["name"])' "$LIMEN_HOME/kubeconfig")"
  KUBECONFIG="$LIMEN_HOME/kubeconfig" kubectl --context "$ctx" get namespaces >/dev/null || fail "kubectl through the generated kubeconfig"
  pass "kubectl --context $ctx works"
else
  echo "(kubectl not installed: skipping the kubectl call)"
fi
out="$(limen doctor 2>&1)" || true
grep -q "! kubeconfig" <<<"$out" || fail "doctor should point out KUBECONFIG"
KUBECONFIG="$LIMEN_HOME/kubeconfig" limen doctor >/dev/null || fail "doctor with KUBECONFIG set"
pass "doctor notices when KUBECONFIG doesn't include it"

step "Uninstall"
limen config ssh --uninstall --file "$sshcfg"
limen kube config --uninstall
grep -q ">>> limen" "$sshcfg" && fail "block left behind"
[ -e "$LIMEN_HOME/ssh_config" ] && fail "generated ssh_config left behind"
[ -e "$LIMEN_HOME/kubeconfig" ] && fail "generated kubeconfig left behind"
[ "$(cat "$sshcfg")" = "$(printf 'Host example-not-limen\n    User someone')" ] || fail "user's own entries changed"
pass "everything Limen added is gone; the rest is untouched"

printf '\n\033[32mAll first-five-minutes checks passed.\033[0m\n'
