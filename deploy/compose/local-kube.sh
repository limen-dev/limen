#!/usr/bin/env bash
# The whole local Limen with Kubernetes, to use by hand: the dev stack
# (control plane, proxy, workers, Dex, S3 audit) plus a kind cluster and a
# worker that serves it. You sign in with the real `limen login` (a browser,
# or `--no-browser`) against Dex, and open the console in a browser.
#
#   deploy/compose/local-kube.sh up       # build, start, and print what to do
#   deploy/compose/local-kube.sh down     # stop it (keeps data)
#   deploy/compose/local-kube.sh reset    # stop it and delete data and the cluster
#
# It is the dev stack, so it uses its fixed ports (3443, 3444, 3081, 5556)
# and stops if one is taken. It runs as the Compose project
# `limen-kube`, so it never touches another stack's containers or volumes.
# Dev only: Dex static users all have password "password".
#
# Checked against kind, a real Kubernetes API server. Not checked against EKS
# (no AWS account): see docs/guides/kubernetes.md.
set -euo pipefail
# env.sh from the demo points KUBECONFIG at Limen's kubeconfig; this talks to kind.
unset KUBECONFIG

cmd="${1:-up}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
state="$here/.state/kube"
cluster="${LIMEN_LOCAL_CLUSTER:-limen-local}"
project="limen-kube"
export LIMEN_KIND_NODE="${cluster}-control-plane"
export LIMEN_KUBE_DIR="$state/kube"
export LIMEN_BUILD_CACHE="limen-target-kube"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || fail "$1 is required"; }
wait_for() {
  local what="$1"; shift
  for _ in $(seq 1 240); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out waiting for $what"
}
# The core reads .state/stack.env (stack.sh writes it); this stack has no extra stacks.
mkdir -p "$here/.state" && : > "$here/.state/stack.env"
compose() {
  docker compose -p "$project" -f "$here/docker-compose.yml" -f "$here/docker-compose.kube.yml" "$@"
}
if command -v kind >/dev/null; then kind=(kind); else kind=(mise exec -- kind); fi
limen="$root/target/release/limen"

case "$cmd" in
  down)
    compose down
    echo "Stopped. Data is kept; \`$0 up\` starts it again. The kind cluster $cluster is still running."
    exit 0
    ;;
  reset)
    compose down -v
    "${kind[@]}" delete cluster --name "$cluster" >/dev/null 2>&1 || true
    rm -rf "$state"
    echo "Deleted the stack's data and the kind cluster $cluster."
    exit 0
    ;;
  up) ;;
  *) fail "usage: $0 up|down|reset" ;;
esac

for tool in docker kubectl cargo curl; do need "$tool"; done

step "Ports"
busy=""
for port in 3443 3444 3081 5556; do
  # Our own stack already holding a port is fine: compose reuses it.
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 \
     && ! compose ps --format '{{.Ports}}' 2>/dev/null | grep -q ":$port->"; then
    busy="$busy $port"
  fi
done
[ -z "$busy" ] || fail "port(s)$busy are in use by something else (another Limen stack?). Stop it first."
echo "free"

step "The limen CLI"
(cd "$root" && cargo build --release -q -p limen-cli)
[ -x "$limen" ] || fail "no limen binary at $limen"
echo "$limen"

step "A kind cluster with the Limen worker's service account"
if ! "${kind[@]}" get clusters 2>/dev/null | grep -qx "$cluster"; then
  "${kind[@]}" create cluster --name "$cluster" --wait 180s >/dev/null 2>&1
fi
ctx="kind-$cluster"
k() { kubectl --context "$ctx" "$@"; }
k apply -f "$root/deploy/kube/limen-kube-worker.yaml" -f "$root/deploy/kube/limen-groups.yaml" >/dev/null
k apply -f - >/dev/null <<'YAML'
apiVersion: v1
kind: Secret
metadata:
  name: limen-kube-worker-token
  namespace: limen-system
  annotations: { kubernetes.io/service-account.name: limen-kube-worker }
type: kubernetes.io/service-account-token
YAML
wait_for "the service account token" bash -c "kubectl --context $ctx -n limen-system get secret limen-kube-worker-token -o jsonpath='{.data.token}' | grep -q ."
mkdir -p "$LIMEN_KUBE_DIR"
k -n limen-system get secret limen-kube-worker-token -o jsonpath='{.data.token}' | base64 -d > "$LIMEN_KUBE_DIR/token"
k config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > "$LIMEN_KUBE_DIR/ca.pem"
# The worker runs as a different user in a container.
chmod 755 "$LIMEN_KUBE_DIR"; chmod 644 "$LIMEN_KUBE_DIR/token" "$LIMEN_KUBE_DIR/ca.pem"
docker network inspect kind >/dev/null 2>&1 || fail "no Docker network named kind"
echo "cluster $cluster (the worker reaches it as $LIMEN_KIND_NODE:6443)"

step "Build and start Limen (the first build takes several minutes)"
compose up -d --build control-plane proxy worker kube-worker
wait_for "the control plane" curl -sf http://localhost:3081/readyz
wait_for "the proxy" curl -sf http://localhost:3444/readyz
mkdir -p "$here/.state"
compose cp control-plane:/var/lib/limen/ca-public/internal-ca.pem "$here/.state/internal-ca.pem" >/dev/null
echo "CA pinned at $here/.state/internal-ca.pem"

step "Policy (examples/policy) and the workers"
# Applying policy needs an admin login. It uses its own profile directory, so
# yours is never touched.
boot="$state/bootstrap-home"
mkdir -p "$boot"
LIMEN_HOME="$boot" LIMEN_BIN="$limen" "$here/dev-login.sh" admin@example.com >/dev/null
LIMEN_HOME="$boot" "$limen" admin apply "$root/examples/policy" --source-ref local-kube >/dev/null
wait_for "both workers' tunnels" bash -c "[ \$(curl -sf http://localhost:3444/tunnels | grep -o worker_id | wc -l) -ge 2 ]"
echo "policy applied; workers connected"

cat <<EOF

Limen is running, with real sign-in. Nothing below is shared with other stacks.

  export PATH="$root/target/release:\$PATH"
  limen --proxy localhost:3443 login --ca-file $here/.state/internal-ca.pem
      # A browser opens on Dex. Sign in as admin@example.com / password
      # (or add --no-browser and open the URL it prints).
  limen ls                                # eks-staging is the Kubernetes cluster
  limen kube login eks-staging --kubeconfig /tmp/eks-staging.json
  export KUBECONFIG=/tmp/eks-staging.json
  kubectl get pods -A
  kubectl exec -it <pod> -- sh            # recorded
  limen logout                            # ends this login at the proxy

Console: https://localhost:3443/console/   (sign in with Dex: admin@example.com / password)
  The certificate is signed by Limen's dev CA: $here/.state/internal-ca.pem
  Import it into your browser only if you choose to.
  Sessions → your kubectl session and exec recordings. Audit trail → Kubernetes → every request.

Other dev users (password "password"): developer@example.com (read-only roles, no Kubernetes),
guest@example.com (denied: no mapped role). The \`sre\` group, which admin is in, gets limen:edit.

Stop: $0 down    Delete everything: $0 reset
EOF
