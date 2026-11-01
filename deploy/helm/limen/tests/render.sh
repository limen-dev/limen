#!/usr/bin/env bash
# Renders the chart with values that exercise what `helm lint` cannot see: a
# group that sets a zero value over a non-zero default, a workers-only or
# proxy-only install, and budgets that depend on the replica count.
#
#   deploy/helm/limen/tests/render.sh        (needs helm)
set -euo pipefail
chart="$(cd "$(dirname "$0")/.." && pwd)"
failures=0
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }
render() { helm template limen "$chart" "$@"; }
# One document of the rendered output: doc <Kind> <name>, reading the render on stdin.
doc() { awk -v kind="kind: $1" -v name="  name: $2" 'BEGIN{RS="\n---\n"} index($0, kind "\n") && index($0, "\n" name "\n") {print}'; }

base=(-f "$chart/ci-values.yaml")

# 1. A zero value in a group beats a non-zero default.
out="$(render "${base[@]}" --set workerDefaults.discovery=true --set workers.prod-db.discovery=false)"
doc Deployment worker-prod-db <<<"$out" | grep -q LIMEN_DISCOVERY && fail "discovery: false on a group did not override the default"
doc Deployment worker-partner <<<"$out" | grep -q LIMEN_DISCOVERY || fail "discovery: true from the defaults did not reach a group that does not set it"

out="$(render "${base[@]}" --set workers.staging.replicas=0)"
doc Deployment worker-staging <<<"$out" | grep -q 'replicas: 0' || fail "replicas: 0 on a group was ignored"

# 2. Workers only, with the proxy named by address (no proxy group defined).
out="$(render --set image.tag=t --set controlPlanes=null --set proxies=null \
  --set workers.w.namePrefix=w --set workers.w.proxyAddr=px.example.com:443 --set workers.w.proxyName=px.example.com)" \
  || fail "a workers-only install with proxyAddr and proxyName does not render"
grep -q 'px.example.com:443' <<<"$out" || fail "workers-only: the proxy address is missing"

# 3. Proxies only, dialling a control plane elsewhere.
out="$(render --set image.tag=t --set controlPlanes=null --set workers=null \
  --set proxies.p.namePrefix=p --set proxies.p.dnsNames=limen.example.com --set proxies.p.controlPlaneAddr=cp.other.example.com:3080)" \
  || fail "a proxy-only install with controlPlaneAddr does not render"
grep -q 'cp.other.example.com:3080' <<<"$out" || fail "proxy-only: the control plane address is missing"

# 4. The PodDisruptionBudget never requires every replica.
out="$(render "${base[@]}" --set proxies.public.replicas=1 --set proxies.partner.replicas=2)"
doc PodDisruptionBudget proxy-public <<<"$out" | grep -q 'minAvailable: 0' || fail "one replica: minAvailable should be 0"
doc PodDisruptionBudget proxy-partner <<<"$out" | grep -q 'minAvailable: 1' || fail "two replicas: minAvailable should be 1"
doc PodDisruptionBudget control-plane-core <<<"$out" | grep -q 'minAvailable: 2' || fail "three replicas: minAvailable should stay 2"

if [ "$failures" -ne 0 ]; then echo "$failures check(s) failed" >&2; exit 1; fi
echo "chart render checks ok"
