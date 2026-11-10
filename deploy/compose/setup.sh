#!/usr/bin/env bash
# Set up the Limen dev stack: checks what you need is installed, asks what to
# enable, starts it, and prints every port and how the services are connected.
#
#   deploy/compose/setup.sh                       # asks (same as `up`)
#   deploy/compose/setup.sh --yes                 # Limen + every stack, no questions
#   deploy/compose/setup.sh --yes --scale --stacks ssh,redis
#   deploy/compose/setup.sh --check               # only check the prerequisites
#   deploy/compose/setup.sh status | down [--scale]
#
# Limen    postgres, dex (on its own PostgreSQL), s3, kms, control plane, proxy, worker (always).
#          Logins are checked against Dex every 15 seconds (offboarding, ADR-0047).
#          docker-compose.yml, or stacks/scale.yml with --scale (3 of each component).
# ssh      OpenSSH host that trusts Limen certificates          stacks/ssh.yml
# db       PostgreSQL and MySQL with TLS, roles bootstrapped    stacks/db.yml
# redis    Redis and Valkey with ACL users                      stacks/redis.yml
# mongo    MongoDB with TLS, SCRAM and X.509                    stacks/mongo.yml
# search   Elasticsearch 8 and OpenSearch 2 (security on)        stacks/search.yml
# messaging  RabbitMQ and a three-broker Kafka cluster          stacks/messaging.yml
# observability  fake Datadog intake, Trino and Grafana         stacks/observability.yml
# tracing  Jaeger, receiving OTLP traces from every component   stacks/tracing.yml
# bots     fake CI identity issuer (bot logins)                 stacks/bots.yml
# kube     a Kubernetes cluster (k3s) and a worker serving it   stacks/kube.yml
# tcp      a raw TCP echo target for `limen tcp`                 stacks/tcp.yml
# web      an HTTP app target for browser SSO                    stacks/web.yml
#
# `--stacks none` starts Limen alone. After starting it pins the CA, signs in as
# the admin, applies shared policy plus the selected stack policies, and
# seeds the targets. Development only: static tokens, Dex static passwords,
# file-backed CA keys. The per-phase demos are in demos/.
set -eEuo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
# shellcheck source=scripts/lib.sh
source "$here/scripts/lib.sh"
# shellcheck source=scripts/dev-users.sh
source "$here/scripts/dev-users.sh"
# shellcheck source=scripts/seed.sh
source "$here/scripts/seed.sh"

ui_init

# ---- helpers --------------------------------------------------------------------
current_step="" locked=false stack_is_up=false
step() { current_step="$*"; ui_section "$*"; }
fail() { ui_bad FAILED "$*"; exit 1; }
has() { case " ${stacks[*]:-} " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
wait_for() { # wait_for WHAT COMMAND...: retry for up to two minutes
  local what="$1"; shift
  for _ in $(seq 1 240); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out waiting for $what"
}
ask() { # ask QUESTION y|n: asks, returns 0 for yes. --yes takes the default.
  local question="$1" default="$2" reply
  $yes && { [ "$default" = y ]; return; }
  printf '%s?%s %s %s[%s]%s ' "$C_CYAN$C_BOLD" "$C_RESET" "$question" "$C_DIM" "$([ "$default" = y ] && echo Y/n || echo y/N)" "$C_RESET"
  read -r reply || reply=""
  case "${reply:-$default}" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# Runs on every exit. If something failed, say where, and once the stack is up
# still show how to use it.
on_exit() {
  local code=$?
  $locked && stack_unlock
  if [ "$code" -ne 0 ] && [ -n "$current_step" ]; then
    ui_warn "Stopped during: $current_step (exit $code). Fix it and run this again."
    $stack_is_up && print_help
  fi
}
on_error() { # the failed command's own status; ignore subshells like $(...), they report to their caller
  local code=$?
  [ "$BASH_SUBSHELL" = 0 ] && ui_bad FAILED "'$BASH_COMMAND' exited with $code" >&2
  return 0
}
trap on_error ERR
trap on_exit EXIT

# ---- arguments ------------------------------------------------------------------
cmd=up yes=false want_scale=false check=false picked=""
while [ $# -gt 0 ]; do
  case "$1" in
    up|down|status) cmd="$1" ;;
    --yes|-y) yes=true ;;
    --scale) want_scale=true ;;
    --check) check=true ;;
    --stacks) picked="${2:?--stacks needs a comma-separated list, or none}"; shift ;;
    -h|--help) sed -n 2,25p "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

# ---- the steps of `up` ----------------------------------------------------------
# Which target stacks to start: --stacks, everything (--yes or no terminal), or ask.
choose_stacks() {
  stacks=()
  if [ -n "$picked" ]; then
    if [ "$picked" != none ]; then IFS=, read -r -a stacks <<<"$picked"; fi
  elif $yes || [ ! -t 0 ]; then
    stacks=("${STACK_NAMES[@]}")
    [ -t 0 ] || ui_note "(no terminal: enabling everything; pass --stacks to choose)"
  else
    ui_section "Limen"
    ui_note "Always on: Postgres (state), S3 (audit batches and recordings), Dex (login),"
    ui_note "the control plane, a proxy and a worker."
    ask "Scale it (3 control planes, 3 proxies, 3 workers)?" n && want_scale=true
    ui_section "What should it connect to, and report to?"
    for s in "${STACK_NAMES[@]}"; do
      if ask "$(printf '%-14s' "$s") $(stack_describe "$s")" y; then stacks+=("$s"); fi
    done
  fi
  scale_flag=()
  ! $want_scale || scale_flag=(--scale)
}

check_prerequisites() {
  step "Checking prerequisites"
  stack_autoport ${scale_flag[@]+"${scale_flag[@]}"}
  stack_preflight ${scale_flag[@]+"${scale_flag[@]}"} ${stacks[@]+"${stacks[@]}"} || {
    printf '\n  %sFix the items marked MISSING or BUSY above and run this again.%s\n' "$C_YELLOW" "$C_RESET" >&2
    current_step="" # already explained
    exit 1
  }
}

# Build, then bring everything up. Containers whose certificate expired are
# recreated so they enroll again; the rest of the running stack is kept.
start_stack() {
  stack_setup ${scale_flag[@]+"${scale_flag[@]}"} ${stacks[@]+"${stacks[@]}"}
  stack_policy_files "$root" "${stacks[@]}" || fail "could not select policy examples"
  stack_lock
  locked=true
  state="$STACK_STATE"
  export LIMEN_BIN="${LIMEN_BIN:-$root/target/release/limen}"
  export LIMEN_PROXY="$STACK_PROXY" LIMEN_DEX_URL="$STACK_DEX" LIMEN_DEV_CA="$state/internal-ca.pem"
  export LIMEN_HOME="$state/home-admin"

  step "Build and start"
  (cd "$root" && cargo build --release -q -p limen-cli)
  stack_renew_expired_identities
  if has kube; then
    step "Kubernetes cluster $KUBE_CLUSTER and the worker's service account"
    stack_kube_prepare
    current_step="Build and start"
  fi
  "${compose[@]}" up -d --build --quiet-pull >/dev/null
  stack_is_up=true
  wait_for "proxy readiness" curl -sf "http://$STACK_HEALTH/readyz"
}

# Trust the dev CA, sign in as the admin and load the policy for the chosen stacks.
sign_in_and_apply_policy() {
  step "Sign in and apply policy"
  local applied
  "${compose[@]}" cp "$STACK_CP:/var/lib/limen/ca-public/internal-ca.pem" "$state/internal-ca.pem" >/dev/null
  rm -rf "$LIMEN_HOME"
  "$here/scripts/dev-login.sh" "$ADMIN" >/dev/null
  applied="$("$LIMEN_BIN" admin apply "${POLICY_FILES[@]}" --source-ref setup.sh)"
  wait_for "worker tunnels" sh -c "curl -sf http://$STACK_HEALTH/tunnels | grep -q worker_id"
  case "$applied" in *"No changes"*) return 0 ;; esac
  sleep 11 # the proxy and worker refresh policy every 10s
  "$here/scripts/dev-login.sh" "$ADMIN" >/dev/null # roles are fixed at login: sign in again to get the new ones
}

# Create roles and sample data in each target (see scripts/seed.sh).
seed_targets() {
  local s
  for s in db redis mongo search messaging; do
    has "$s" || continue
    step "Seed $s"
    "seed_$s"
  done
}

print_help() {
  stack_summary ${scale_flag[@]+"${scale_flag[@]}"} ${stacks[@]+"${stacks[@]}"}
  stack_endpoints ${scale_flag[@]+"${scale_flag[@]}"} ${stacks[@]+"${stacks[@]}"}
}

# ---- run ------------------------------------------------------------------------
if [ "$cmd" != up ]; then # down and status act on every stack
  scale_flag=()
  ! $want_scale || scale_flag=(--scale)
  stack_setup ${scale_flag[@]+"${scale_flag[@]}"} "${STACK_NAMES[@]}"
  if [ "$cmd" = status ]; then exec "${compose[@]}" ps; fi
  stack_lock
  locked=true
  "${compose[@]}" down -v --remove-orphans
  rm -f "$STACK_STATE/stack.env"
  exit 0
fi

ui_banner "Limen" "local development stack"
choose_stacks
check_prerequisites
$check && exit 0

ui_section "Starting Limen$($want_scale && echo ' (scaled)') with: ${stacks[*]:-no extra stacks}"
ui_note "The first run builds the images and the CLI, which takes several minutes."
if ! $yes && [ -t 0 ]; then echo; ask "Go?" y || { ui_note "Cancelled."; exit 0; }; fi

start_stack
sign_in_and_apply_policy
seed_targets

current_step=""
ui_done "Limen is ready"
print_help
