# shellcheck shell=bash disable=SC2154,SC2034
# Builds the `docker compose` command for the Limen stack plus the target
# stacks you pick. Sourced by setup.sh and by the demos (needs $here, the deploy/compose directory, set).
#
#   stack_setup [--scale] STACK...
#
# Another copy beside a running one: set LIMEN_PROJECT, LIMEN_STATE_DIR, LIMEN_IMAGE_TAG
# and the LIMEN_PORT_* variables (see docker-compose.yml) before calling it.
# Sets: compose (the command array), STACK_FLAGS, and for the CLI: STACK_PROXY, STACK_HEALTH,
# STACK_DEX, STACK_CP (a control plane service), STACK_STATE. Writes
# .state/stack.env, the settings some stacks need on a Limen service.
#
# Limen: docker-compose.yml (one of each component) or, with --scale,
# stacks/scale.yml (3 control planes, 3 proxies, 3 workers).
# Stacks (each a compose file and a profile of the same name):
STACK_NAMES=(ssh db redis observability bots kube)
compose=() STACK_FLAGS=() # set by stack_setup

# ---- terminal output -----------------------------------------------------------
# Colours and symbols; plain text when stdout is not a terminal or NO_COLOR is set.
ui_init() {
  [ -n "${UI_READY:-}" ] && return 0
  UI_READY=1
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then
    C_RESET=$'\033[0m' C_BOLD=$'\033[1m' C_DIM=$'\033[2m' C_RED=$'\033[31m' C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m' C_BLUE=$'\033[34m' C_CYAN=$'\033[36m'
  else
    C_RESET='' C_BOLD='' C_DIM='' C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_CYAN=''
  fi
  case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
    *UTF-8*|*utf8*|*UTF8*) G_OK='✓' G_BAD='✗' G_ARROW='▸' G_HINT='→' G_RULE='─' ;;
    *) G_OK='+' G_BAD='x' G_ARROW='>' G_HINT='->' G_RULE='-' ;;
  esac
}
ui_banner() { # ui_banner TITLE SUBTITLE
  ui_init
  local rule='' i
  for i in $(seq 1 $((${#1} + ${#2} + 3))); do rule="$rule$G_RULE"; done
  printf '\n  %s%s%s %s·%s %s\n  %s%s%s\n' "$C_BOLD$C_CYAN" "$1" "$C_RESET" "$C_DIM" "$C_RESET" "$2" "$C_DIM" "$rule" "$C_RESET"
}
ui_section() { ui_init; printf '\n%s%s %s%s\n' "$C_BOLD$C_BLUE" "$G_ARROW" "$*" "$C_RESET"; }
ui_ok() { ui_init; printf '  %s%s%s %s\n' "$C_GREEN" "$G_OK" "$C_RESET" "$*"; }
ui_note() { ui_init; printf '  %s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }
ui_bad() { # ui_bad LABEL MESSAGE HINT
  ui_init; printf '  %s%s %s%s %s\n' "$C_RED" "$G_BAD" "$1" "$C_RESET" "$2"
  [ -n "${3:-}" ] && printf '      %s%s %s%s\n' "$C_DIM" "$G_HINT" "$3" "$C_RESET"
  return 0
}
ui_done() { ui_init; printf '\n%s%s %s%s\n' "$C_BOLD$C_GREEN" "$G_OK" "$*" "$C_RESET"; }

stack_setup() {
  local scale=false
  if [ "${1:-}" = --scale ]; then scale=true; shift; fi
  local s files=() env=()
  if $scale; then
    files=(-f "$here/stacks/scale.yml")
    STACK_PROXY=localhost:23443 STACK_HEALTH=localhost:23444 STACK_DEX=http://localhost:25556
    STACK_CP=control-plane-0 STACK_STATE="$here/.state/scale"
  else
    files=(-f "$here/docker-compose.yml")
    STACK_PROXY=localhost:${LIMEN_PORT_PROXY:-3443} STACK_HEALTH=localhost:${LIMEN_PORT_HEALTH:-3444}
    STACK_DEX=http://localhost:${LIMEN_PORT_DEX:-5556}
    STACK_CP=control-plane STACK_STATE="${LIMEN_STATE_DIR:-$here/.state}"
  fi
  local profiles=()
  for s in "$@"; do
    case "$s" in
      ssh) files+=(-f "$here/stacks/ssh.yml") ;;
      db) files+=(-f "$here/stacks/db.yml"); profiles+=(--profile tools) ;;
      redis) files+=(-f "$here/stacks/redis.yml")
             env+=(LIMEN_REDIS_CREDENTIALS_FILE=/etc/limen/redis-credentials.json) ;;
      observability) files+=(-f "$here/stacks/observability.yml")
               env+=(LIMEN_DATADOG_LOGS_URL=http://fake-datadog:8126/api/v2/logs DD_API_KEY=dev-only-datadog-key) ;;
      bots) files+=(-f "$here/stacks/bots.yml")
            env+=(LIMEN_BOT_ALLOW_INSECURE_ISSUERS=true) ;;
      kube) files+=(-f "$here/stacks/kube.yml")
            KUBE_CLUSTER="${LIMEN_KIND_CLUSTER:-limen-dev}"
            export LIMEN_KIND_NODE="$KUBE_CLUSTER-control-plane" LIMEN_KUBE_DIR="$STACK_STATE/kube"
            export LIMEN_EXTRA_JOIN_TOKENS=",worker:dev-only-kube-worker-join-token-9d4b7e1a6c3f2058:pool=kube" ;;
      *) echo "unknown stack '$s' (choose from: ${STACK_NAMES[*]})" >&2; return 2 ;;
    esac
    profiles+=(--profile "$s")
  done
  mkdir -p "$STACK_STATE"
  export LIMEN_STACK_ENV="$STACK_STATE/stack.env"
  printf '%s\n' ${env[@]+"${env[@]}"} >"$LIMEN_STACK_ENV"
  # STACK_FLAGS: everything after `docker compose`, for tools that run it themselves.
  local project_flag=()
  [ -n "${LIMEN_PROJECT:-}" ] && project_flag=(-p "$LIMEN_PROJECT")
  STACK_FLAGS=(--project-directory "$here" ${project_flag[@]+"${project_flag[@]}"} "${files[@]}" ${profiles[@]+"${profiles[@]}"})
  compose=(docker compose --progress=quiet "${STACK_FLAGS[@]}")
}

# One line per stack, for the setup questions.
stack_describe() {
  case "$1" in
    ssh) echo "an OpenSSH host that trusts only Limen certificates (limen ssh)" ;;
    db) echo "PostgreSQL and MySQL with TLS, roles bootstrapped (limen db connect)" ;;
    redis) echo "Redis and Valkey with ACL users (limen redis connect)" ;;
    observability) echo "fake Datadog intake, plus Trino and Grafana over the audit log" ;;
    bots) echo "a fake CI identity issuer, to log in as a bot" ;;
    kube) echo "a kind cluster and a worker that serves it (limen kube login)" ;;
  esac
}

_hint() { # _hint docker|cargo|curl|ssh: how to install it on this OS
  local os; os="$(uname -s)"
  case "$1:$os" in
    docker:Darwin) echo "install OrbStack (brew install --cask orbstack, https://orbstack.dev) or Docker Desktop, and start it" ;;
    docker:Linux) echo "install Docker Engine with the Compose plugin: https://docs.docker.com/engine/install/" ;;
    docker:*) echo "install Docker (WSL 2 with Docker Desktop on Windows): https://docs.docker.com/get-docker/" ;;
    cargo:*) echo "install the toolchain in mise.toml with 'mise install' (https://mise.jdx.dev) or rustup (https://rustup.rs); or set LIMEN_BIN to an existing limen binary" ;;
    curl:Darwin) echo "brew install curl" ;;
    curl:*) echo "install it with your package manager (apt install curl, dnf install curl, ...)" ;;
    kind:*) echo "install it with 'mise install' (kind is pinned in mise.toml) or https://kind.sigs.k8s.io/docs/user/quick-start/#installation" ;;
    kubectl:*) echo "install it with 'mise install' (kubectl is pinned in mise.toml) or https://kubernetes.io/docs/tasks/tools/" ;;
    ssh:Darwin) echo "OpenSSH ships with macOS; check that 'ssh' is on PATH" ;;
    ssh:*) echo "install the OpenSSH client (apt install openssh-client, dnf install openssh-clients, ...)" ;;
  esac
}

# Host ports a selection publishes, as "port|service|what it is".
stack_ports() {
  local scale=false s
  if [ "${1:-}" = --scale ]; then scale=true; shift; fi
  if $scale; then
    cat <<'PORTS'
23443|proxy-0 API|CLI, console and tunnels enter here (mTLS)
23444|proxy-0 health|/readyz, /tunnels (admin and debug)
23453|proxy-1 API|second proxy
23454|proxy-1 health|
23463|proxy-2 API|third proxy
23464|proxy-2 health|
23081|control-plane-0 health|
23082|control-plane-1 health|
23083|control-plane-2 health|
25556|Dex|OIDC login (admin@example.com / password)
28333|S3 (SeaweedFS)|audit batches and recordings
PORTS
  else
    printf '%s\n' \
      "${LIMEN_PORT_PROXY:-3443}|proxy API|CLI, console and tunnels enter here (mTLS)|LIMEN_PORT_PROXY" \
      "${LIMEN_PORT_HEALTH:-3444}|proxy health|/readyz, /tunnels (admin and debug)|LIMEN_PORT_HEALTH" \
      "${LIMEN_PORT_CP:-3081}|control plane health||LIMEN_PORT_CP" \
      "${LIMEN_PORT_DEX:-5556}|Dex|OIDC login (admin@example.com / password)|LIMEN_PORT_DEX" \
      "${LIMEN_PORT_POSTGRES:-5432}|Postgres|control plane state|LIMEN_PORT_POSTGRES" \
      "${LIMEN_PORT_S3:-8333}|S3 (SeaweedFS)|audit batches and recordings|LIMEN_PORT_S3" \
      "${LIMEN_PORT_KMS:-8099}|KMS emulator|used by tests|LIMEN_PORT_KMS"
  fi
  for s in "$@"; do
    case "$s" in
      observability) printf '%s\n' '8126|fake Datadog|GET /fake/received shows the audit events' '3000|Grafana|audit dashboards (admin / limen-dev-only)' ;;
      bots) printf '%s\n' '8130|fake CI issuer|mints identity tokens for bot logins' ;;
    esac
  done
}

# Checks what the selection needs. Prints one line per check, returns 1 if any failed.
stack_preflight() {
  ui_init
  local scale=() s bad=0 want_ssh=false want_kube=false
  if [ "${1:-}" = --scale ]; then scale=(--scale); shift; fi
  for s in "$@"; do
    [ "$s" = ssh ] && want_ssh=true
    [ "$s" = kube ] && want_kube=true
  done
  ok() { ui_ok "$*"; }
  miss() { ui_bad "${3:-MISSING}" "$1" "$2"; bad=1; }

  if ! command -v docker >/dev/null 2>&1; then
    miss "docker" "$(_hint docker)"
  else
    local v; v="$(docker compose version --short 2>/dev/null || true)"
    if [ -z "$v" ]; then
      miss "docker compose (the v2 plugin)" "$(_hint docker)"
    elif [ "$(printf '%s\n2.24.0\n' "${v#v}" | sort -V | head -1)" != 2.24.0 ]; then
      miss "docker compose $v is older than 2.24" "update Docker: $(_hint docker)"
    elif ! docker info >/dev/null 2>&1; then
      miss "the Docker daemon is not running" "start OrbStack / Docker Desktop, or 'sudo systemctl start docker'"
    else
      ok "docker, compose $v, daemon running"
    fi
  fi
  if [ -x "${LIMEN_BIN:-}" ]; then ok "limen CLI at $LIMEN_BIN"
  elif command -v cargo >/dev/null 2>&1; then ok "cargo (builds the limen CLI)"
  else miss "cargo (needed to build the limen CLI)" "$(_hint cargo)"; fi
  if command -v curl >/dev/null 2>&1; then ok curl; else miss curl "$(_hint curl)"; fi
  if $want_ssh; then
    if command -v ssh >/dev/null 2>&1; then ok "ssh client"; else miss "ssh client (for the ssh stack)" "$(_hint ssh)"; fi
  fi

  if $want_kube; then
    if command -v kind >/dev/null 2>&1 || command -v mise >/dev/null 2>&1 && mise exec -- kind version >/dev/null 2>&1; then ok kind
    else miss kind "$(_hint kind)"; fi
    if command -v kubectl >/dev/null 2>&1; then ok kubectl; else miss kubectl "$(_hint kubectl)"; fi
  fi

  local project=limen port name what holder proj row hint
  [ ${#scale[@]} -gt 0 ] && project=limen-scale
  local var
  while IFS='|' read -r port name what var; do
    [ -z "$port" ] && continue
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      holder=""; proj=""
      if command -v docker >/dev/null 2>&1; then
        row="$(docker ps --format '{{.Label "com.docker.compose.project"}}|{{.Names}}|{{.Ports}}' 2>/dev/null | grep -E ":$port->" | head -1 || true)"
        proj="${row%%|*}"; holder="${row#*|}"; holder="${holder%%|*}"
        [ -n "$row" ] && holder="container $holder"
      fi
      if [ -z "$holder" ] && command -v lsof >/dev/null 2>&1; then
        holder="process $(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR==2{print $1" (pid "$2")"}')"
      fi
      if [ "$proj" = "$project" ]; then
        ok "port $port ($name) is in use by this stack; it will be updated"
      else
        hint="stop what holds it, then run this again"
        [ -n "$var" ] && hint="$hint, or move this port: export $var=<a free port>"
        case "$holder" in
          *OrbStack*) hint="$hint. OrbStack forwards ports listening inside its Linux machines (see: orb list; orb -m <machine> sudo docker ps)" ;;
        esac
        miss "port $port ($name) is in use${holder:+ by $holder}" "$hint" BUSY
      fi
    fi
  done < <(stack_ports ${scale[@]+"${scale[@]}"} "$@")
  [ "$bad" = 0 ]
}

# Ports, and how the services connect, for what is running.
stack_summary() {
  ui_init
  local scale=() port name what proxy s has_ssh=false has_db=false has_redis=false has_obs=false has_bots=false
  if [ "${1:-}" = --scale ]; then scale=(--scale); shift; fi
  for s in "$@"; do
    case "$s" in ssh) has_ssh=true ;; db) has_db=true ;; redis) has_redis=true ;; observability) has_obs=true ;; bots) has_bots=true ;; esac
  done
  proxy="${LIMEN_PORT_PROXY:-3443}"
  [ ${#scale[@]} -gt 0 ] && proxy=23443
  ui_section "Ports (all on 127.0.0.1)"
  while IFS='|' read -r port name what _; do
    [ -n "$port" ] && printf "  ${C_BOLD}%-6s${C_RESET} %-24s ${C_DIM}%s${C_RESET}\n" "$port" "$name" "$what"
  done < <(stack_ports ${scale[@]+"${scale[@]}"} "$@")
  ui_note "(databases, Redis, the SSH host, Trino and the Datadog intake are reached through Limen, not published)"

  ui_section "How it is connected"
  cat <<SUMMARY
  you (limen CLI, browser) --mTLS--> proxy :$proxy --> worker --> target
  1. Login: the CLI sends you to Dex (OIDC). The control plane checks the token, maps your
     groups to roles with examples/policy, and its CA signs a short-lived certificate for you.
  2. The proxy and the worker enrol with the control plane using join tokens and get their own
     certificates. The control plane keeps state in Postgres and writes audit events to S3.
  3. The worker dials OUT to the proxy and holds a reverse tunnel, so targets need no inbound
     path from you. For each session the proxy picks a worker, and the worker connects to the
     target. Every session is audited (and recorded for SSH).
SUMMARY
  if [ ${#scale[@]} -gt 0 ]; then
    echo "  Scaled: three control planes share one Postgres and one CA key volume (any can serve any"
    echo "     call); three proxies share the name 'proxy' and three workers dial whichever answers."
  fi
  if $has_ssh; then echo "  ssh:   worker -> sshd-target:22, which trusts only Limen's SSH user CA. limen ssh web-staging-1"; fi
  if $has_db; then echo "  db:    worker -> postgres-target / mysql-target over TLS, as limen_* roles whose passwords only the worker holds. limen db connect orders-staging"; fi
  if $has_redis; then echo "  redis: worker -> redis-target / valkey-target as ACL users from the worker's credentials file. limen redis connect cache-staging"; fi
  if $has_obs; then echo "  observability: the control plane also sends audit events to the fake Datadog intake; Trino reads the S3 audit batches and Grafana queries Trino."; fi
  if $has_bots; then echo "  bots:  the fake CI issuer mints identity tokens; policy (bots.yaml) maps them to roles, no human login."; fi
  return 0
}

# kind, from PATH or from mise.
stack_kind() { if command -v kind >/dev/null 2>&1; then kind "$@"; else mise exec -- kind "$@"; fi; }

# Creates the kind cluster, the worker's service account, and the files the kube worker
# mounts ($LIMEN_KUBE_DIR). Needs stack_setup kube to have run, and $root.
stack_kube_prepare() {
  # The kind cluster's kubeconfig lives in the stack's state directory: the one
  # in $KUBECONFIG or ~/.kube/config is never read or written.
  unset KUBECONFIG
  mkdir -p "$LIMEN_KUBE_DIR"
  KIND_KUBECONFIG="$STACK_STATE/kind.kubeconfig"
  if ! stack_kind get clusters 2>/dev/null | grep -qx "$KUBE_CLUSTER"; then
    stack_kind create cluster --name "$KUBE_CLUSTER" --kubeconfig "$KIND_KUBECONFIG" --wait 180s >/dev/null 2>&1 \
      || fail "could not create the kind cluster $KUBE_CLUSTER"
  fi
  stack_kind export kubeconfig --name "$KUBE_CLUSTER" --kubeconfig "$KIND_KUBECONFIG" >/dev/null 2>&1 \
    || fail "could not read the kubeconfig of the kind cluster $KUBE_CLUSTER"
  local k=(kubectl --kubeconfig "$KIND_KUBECONFIG")
  "${k[@]}" apply -f "$root/deploy/kubernetes/access/limen-kube-worker.yaml" -f "$root/deploy/kubernetes/access/limen-groups.yaml" >/dev/null
  "${k[@]}" apply -f - >/dev/null <<'YAML'
apiVersion: v1
kind: Secret
metadata:
  name: limen-kube-worker-token
  namespace: limen-system
  annotations: { kubernetes.io/service-account.name: limen-kube-worker }
type: kubernetes.io/service-account-token
YAML
  wait_for "the service account token" bash -c "kubectl --kubeconfig '$KIND_KUBECONFIG' -n limen-system get secret limen-kube-worker-token -o jsonpath='{.data.token}' | grep -q ."
  "${k[@]}" -n limen-system get secret limen-kube-worker-token -o jsonpath='{.data.token}' | base64 -d >"$LIMEN_KUBE_DIR/token"
  "${k[@]}" config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d >"$LIMEN_KUBE_DIR/ca.pem"
  # The worker runs as a different user in a container.
  chmod 755 "$LIMEN_KUBE_DIR"; chmod 644 "$LIMEN_KUBE_DIR/token" "$LIMEN_KUBE_DIR/ca.pem"
  docker network inspect kind >/dev/null 2>&1 || fail "no Docker network named kind"
}

# What to connect to, once it is running. Needs stack_setup to have run.
stack_endpoints() {
  ui_init
  local scale=() s has_ssh=false has_db=false has_redis=false has_obs=false has_bots=false has_kube=false
  if [ "${1:-}" = --scale ]; then scale=(--scale); shift; fi
  for s in "$@"; do
    case "$s" in ssh) has_ssh=true ;; db) has_db=true ;; redis) has_redis=true ;; observability) has_obs=true ;; bots) has_bots=true ;; kube) has_kube=true ;; esac
  done
  local ca="$STACK_STATE/internal-ca.pem"
  ui_section "Connect"
  printf "  ${C_CYAN}%-18s${C_RESET} %s\n" "CA certificate" "$ca" \
    "Limen proxy" "$STACK_PROXY" \
    "Console" "https://$STACK_PROXY/console/" \
    "Sign-in (OIDC)" "$STACK_DEX   admin@example.com / password (developer@example.com, guest@example.com)"
  ui_note "The proxy's certificate is signed by Limen's dev CA. Pass the file to the CLI; import it into a browser only if you choose to."
  echo "  CLI sign-in:  limen --proxy $STACK_PROXY login --ca-file $ca"
  echo "  Then:         limen ls"
  if $has_ssh || $has_db || $has_redis || $has_kube; then
    ui_section "Resources (reached through the proxy; the listeners below are local)"
  fi
  $has_ssh && printf "  ${C_CYAN}%-18s${C_RESET} %s\n" "SSH" "limen ssh web-staging-1  (target sshd-target:22)"
  if $has_db; then
    printf "  ${C_CYAN}%-18s${C_RESET} %s\n" "PostgreSQL" "limen db connect orders-staging  (prints the psql command and its local port; target postgres-target:5432)" \
      "MySQL" "limen db connect orders-mysql-staging  (prints the mysql command; target mysql-target:3306)"
  fi
  if $has_redis; then
    printf "  ${C_CYAN}%-18s${C_RESET} %s\n" "Redis" "limen redis connect cache-staging  (prints the redis-cli command; target redis-target:6379)" \
      "Valkey" "limen redis connect cache-valkey  (prints the redis-cli command; target valkey-target:6379)"
  fi
  if $has_kube; then
    printf "  ${C_CYAN}%-18s${C_RESET} %s\n" "Kubernetes" "limen kube login eks-staging --kubeconfig $STACK_STATE/kubeconfig.json" \
      "" "export KUBECONFIG=$STACK_STATE/kubeconfig.json; kubectl get pods -A" \
      "" "API server behind the worker: https://$LIMEN_KIND_NODE:6443 (kind cluster $KUBE_CLUSTER, reached only through Limen)"
  fi
  if $has_obs || $has_bots; then ui_section "Other"; fi
  $has_obs && printf "  ${C_CYAN}%-18s${C_RESET} %s\n" "Grafana" "http://localhost:3000   admin / limen-dev-only" \
    "Fake Datadog" "http://localhost:8126/fake/received"
  $has_bots && printf "  ${C_CYAN}%-18s${C_RESET} %s\n" "Fake CI issuer" "http://localhost:8130"
  printf '\n  %sStop it:%s deploy/compose/setup.sh%s down\n' "$C_BOLD" "$C_RESET" "${scale[*]:+ --scale}"
  return 0
}
