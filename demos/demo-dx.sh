#!/usr/bin/env bash
# First-five-minutes demo (epic #121, ADR-0041): `limen doctor`, plain ssh,
# scp, rsync, and git through `limen config ssh --install`, denial hints,
# and `limen kube config`.
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
login() { local out; out="$("$here/scripts/dev-login.sh" "$1" 2>&1)" || { echo "$out"; fail "login as $1"; }; }
# Fail instead of waiting forever (macOS has no `timeout`).
within() { local secs="$1"; shift; perl -e 'alarm shift; exec @ARGV' "$secs" "$@"; }
for tool in ssh scp rsync git curl python3 perl cargo docker; do command -v "$tool" >/dev/null || fail "$tool is required"; done
cleanup() { $keep || "$here/setup.sh" down >/dev/null 2>&1 || true; }
trap cleanup EXIT

step "Build the CLI and start the stack (ssh and kube)"
(cd "$root" && cargo build --release -q -p limen-cli)
if $keep && curl -sf "http://localhost:$LIMEN_PORT_HEALTH/readyz" >/dev/null; then
  echo "Reusing the running $LIMEN_PROJECT stack."
else
  "$here/setup.sh" --yes --stacks ssh,kube || fail "setup.sh"
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
limen doctor web-staging-1 | grep -E "access|worker|client"
out="$(limen doctor bastion-staging 2>&1)" && fail "the bastion is denied by policy"
grep -A6 "✖ access" <<<"$out"
grep -q "Your role \`dev-readonly\` allows" <<<"$out" || fail "doctor should give explain's reason: $out"
pass "access is checked against policy, with the server's reason"

step "doctor notices when no worker serves the resource"
# Wait with `explain` (authenticated): doctor's clock check uses the
# unauthenticated API, which is rate limited per address.
worker_down() { limen explain web-staging-1 | grep -q "No worker that can reach"; }
docker stop limen-worker-dxdemo >/dev/null
for _ in $(seq 1 30); do worker_down && break; sleep 1; done
out="$(limen doctor web-staging-1 2>&1)" && fail "doctor passed with the worker stopped"
grep "✖ worker" <<<"$out" || fail "a stopped worker should fail the worker check: $out"
docker start limen-worker-dxdemo >/dev/null
for _ in $(seq 1 60); do worker_down || break; sleep 1; done
limen doctor web-staging-1 >/dev/null || fail "the worker didn't come back"
pass "worker down: doctor says so; back up: it passes"

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
pass "ssh web-staging-1 runs commands, with no wrapper"

step "scp, rsync, and git use the same names"
head -c 65536 /dev/urandom >"$state/payload.bin"
rm -f "$state/payload-back.bin"
# scp speaks SFTP (OpenSSH 9 and later), so this exercises the subsystem path.
within 60 scp -F "$sshcfg" -q "$state/payload.bin" web-staging-1:/tmp/limen-payload.bin || fail "scp up"
within 60 scp -F "$sshcfg" -q web-staging-1:/tmp/limen-payload.bin "$state/payload-back.bin" || fail "scp down"
cmp -s "$state/payload.bin" "$state/payload-back.bin" || fail "scp round trip"
pass "scp carries 64 KiB both ways"
rm -rf "$state/rsync-src" "$state/rsync-back"; mkdir -p "$state/rsync-src/sub"
echo one >"$state/rsync-src/a.txt"; echo two >"$state/rsync-src/sub/b.txt"
within 60 rsync -a -e "ssh -F $sshcfg" "$state/rsync-src/" web-staging-1:/tmp/limen-rsync/ || fail "rsync up"
within 60 rsync -a -e "ssh -F $sshcfg" web-staging-1:/tmp/limen-rsync/ "$state/rsync-back/" || fail "rsync down"
diff -r "$state/rsync-src" "$state/rsync-back" || fail "rsync round trip"
pass "rsync copies a tree both ways"
rm -rf "$state/git-src" "$state/git-back"
ssh -F "$sshcfg" web-staging-1 'rm -rf /tmp/limen-demo.git && git init -q --bare /tmp/limen-demo.git'
git init -q "$state/git-src"
git -C "$state/git-src" -c user.name=demo -c user.email=demo@example.com commit -q --allow-empty -m "through limen"
export GIT_SSH_COMMAND="ssh -F $sshcfg"
within 60 git -C "$state/git-src" push -q web-staging-1:/tmp/limen-demo.git HEAD:refs/heads/main || fail "git push"
within 60 git clone -q -b main web-staging-1:/tmp/limen-demo.git "$state/git-back" || fail "git clone"
unset GIT_SSH_COMMAND
[ "$(git -C "$state/git-back" log -1 --format=%s)" = "through limen" ] || fail "git round trip"
pass "git push and clone over SSH"
# A subsystem the target doesn't have fails at once (it used to hang).
out="$(within 20 ssh -F "$sshcfg" -s web-staging-1 no-such-subsystem 2>&1 </dev/null)" && fail "an unknown subsystem was accepted"
grep -qi "subsystem request failed" <<<"$out" || fail "unknown subsystem: $out"
pass "an unknown subsystem is refused, not left hanging"

step "Denied: the error says why and how to get access"
out="$(ssh -F "$sshcfg" ubuntu@bastion-staging.limen true 2>&1)" && fail "the bastion is denied by policy"
echo "$out" | head -8
grep -q "access denied" <<<"$out" || fail "no refusal: $out"
grep -q "No role you hold grants access to \`bastion-staging\`" <<<"$out" || fail "no explanation under the refusal: $out"
pass "plain ssh shows explain's answer under the refusal"

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
