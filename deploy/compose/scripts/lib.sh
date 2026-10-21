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
STACK_NAMES=(ssh db redis mongo search messaging observability bots kube)
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
ui_warn() { ui_init; printf '  %s! %s%s\n' "$C_YELLOW" "$*" "$C_RESET"; }
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
  # The environment name ends the name of every stand-in target: postgres-orders-dev, redis-cache-dev, ...
  # A demo's own project (limen-dbdemo) gives dbdemo; the scaled variant is `scale`.
  if $scale; then LIMEN_ENV="${LIMEN_ENV:-scale}"
  else LIMEN_ENV="${LIMEN_ENV:-${LIMEN_PROJECT:+${LIMEN_PROJECT#limen-}}}"; fi
  export LIMEN_ENV="${LIMEN_ENV:-dev}"
  # Limen itself is not an environment: its containers only get a suffix when a second copy
  # (the scaled stack, a demo) runs beside the dev one.
  if [ "$LIMEN_ENV" = dev ]; then export LIMEN_SUFFIX=""; else export LIMEN_SUFFIX="-$LIMEN_ENV"; fi
  local profiles=()
  for s in "$@"; do
    case "$s" in
      ssh) files+=(-f "$here/stacks/ssh.yml") ;;
      db) files+=(-f "$here/stacks/db.yml"); profiles+=(--profile tools) ;;
      redis) files+=(-f "$here/stacks/redis.yml")
             env+=(LIMEN_REDIS_CREDENTIALS_FILE=/etc/limen/redis-credentials.json) ;;
      mongo) files+=(-f "$here/stacks/mongo.yml") ;;
      search) files+=(-f "$here/stacks/search.yml")
              env+=(LIMEN_SEARCH_CREDENTIALS_FILE=/etc/limen/search-credentials.json LIMEN_SEARCH_CA_FILE=/etc/limen/search/opensearch-root-ca.pem) ;;
      messaging) files+=(-f "$here/stacks/messaging.yml")
                 env+=(LIMEN_BROKER_CREDENTIALS_FILE=/etc/limen/broker-credentials.json) ;;
      observability) files+=(-f "$here/stacks/observability.yml")
               env+=(LIMEN_DATADOG_LOGS_URL=http://fake-datadog:8126/api/v2/logs DD_API_KEY=dev-only-datadog-key) ;;
      bots) files+=(-f "$here/stacks/bots.yml")
            env+=(LIMEN_BOT_ALLOW_INSECURE_ISSUERS=true) ;;
      kube) files+=(-f "$here/stacks/kube.yml")
            KUBE_CLUSTER="kubernetes-$LIMEN_ENV"
            export LIMEN_KUBE_DIR="$STACK_STATE/kube"
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
    mongo) echo "MongoDB with TLS, SCRAM and X.509 (limen mongo connect)" ;;
    search) echo "Elasticsearch 8 and OpenSearch 2 with security on (limen search connect)" ;;
    messaging) echo "RabbitMQ and a three-broker Kafka cluster (limen mq connect, limen kafka connect)" ;;
    observability) echo "fake Datadog intake, plus Trino and Grafana over the audit log" ;;
    bots) echo "a fake CI identity issuer, to log in as a bot" ;;
    kube) echo "a Kubernetes cluster (k3s) and a worker that serves it (limen kube login)" ;;
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

# Is something listening on this host port? Which compose project publishes it (empty if none)?
_port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
# Prints "project|container|ports" of the first running container that publishes host port $1.
# Docker prints consecutive ports as a range (127.0.0.1:3443-3444->3443-3444/tcp), so a range
# counts too.
_port_row() {
  command -v docker >/dev/null 2>&1 || return 0
  local port="$1" row spec lo hi
  while IFS= read -r row; do
    for spec in $(printf '%s' "${row##*|}" | grep -oE ':[0-9]+(-[0-9]+)?->' | sed -E 's/^://; s/->$//'); do
      lo="${spec%-*}"; hi="${spec#*-}"
      if [ "$port" -ge "$lo" ] && [ "$port" -le "$hi" ]; then printf '%s\n' "$row"; return 0; fi
    done
  done < <(docker ps --format '{{.Label "com.docker.compose.project"}}|{{.Names}}|{{.Ports}}' 2>/dev/null)
  return 0
}
_port_project() { _port_row "$1" | cut -d'|' -f1; }

# Moves the host ports that only tests and health checks use (Postgres, S3, KMS, control plane
# health) to a free port when the default is taken, unless you set the variable yourself.
# A port held by this stack's own containers counts as free, so a re-run keeps its ports.
stack_autoport() {
  ui_init
  [ "${1:-}" = --scale ] && return 0
  local project="${LIMEN_PROJECT:-limen}" pair var def n
  for pair in LIMEN_PORT_POSTGRES:5432 LIMEN_PORT_S3:8333 LIMEN_PORT_KMS:8099 LIMEN_PORT_CP:3081; do
    var="${pair%%:*}"; def="${pair##*:}"
    [ -n "${!var:-}" ] && continue
    _port_busy "$def" || continue
    [ "$(_port_project "$def")" = "$project" ] && continue
    n=$((def + 40000))
    while _port_busy "$n" && [ "$(_port_project "$n")" != "$project" ]; do n=$((n + 1)); done
    export "$var=$n"
    ui_note "port $def is busy: using $n for ${var#LIMEN_PORT_} (set $var to choose another)"
  done
  return 0
}

# One setup.sh at a time per stack. Two runs on the same Compose project recreate each other's
# containers and fail with "connection refused" half way. The lock is a directory in the stack's
# state directory (mkdir is atomic); a lock left by a run that is gone is replaced.
stack_lock() {
  local lock="$STACK_STATE/setup.lock" pid
  mkdir -p "$STACK_STATE"
  if ! mkdir "$lock" 2>/dev/null; then
    pid="$(cat "$lock/pid" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      fail "another setup.sh (pid $pid) is already working on this stack ($STACK_STATE). Wait for it, or stop it first."
    fi
    rm -rf "$lock"
    mkdir "$lock"
  fi
  printf '%s\n' "$$" >"$lock/pid"
  # shellcheck disable=SC2064 # expand $lock now
  trap "rm -rf '$lock'" EXIT
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
    if command -v kubectl >/dev/null 2>&1; then ok kubectl
    else ui_warn "kubectl not found: setup works without it, but you need it to use the cluster ($(_hint kubectl))"; fi
  fi

  local project=limen port name what holder proj row hint
  [ ${#scale[@]} -gt 0 ] && project=limen-scale
  local var
  while IFS='|' read -r port name what var; do
    [ -z "$port" ] && continue
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      holder=""; proj=""
      if command -v docker >/dev/null 2>&1; then
        row="$(_port_row "$port")"
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

# The ports in use, for what is running.
stack_summary() {
  ui_init
  local scale=() port name what
  if [ "${1:-}" = --scale ]; then scale=(--scale); shift; fi
  ui_section "Ports (127.0.0.1)"
  while IFS='|' read -r port name what _; do
    [ -n "$port" ] && printf "  ${C_BOLD}%-6s${C_RESET} %-24s ${C_DIM}%s${C_RESET}\n" "$port" "$name" "$what"
  done < <(stack_ports ${scale[@]+"${scale[@]}"} "$@")
  ui_note "Databases, Redis, MongoDB, the SSH host and the Kubernetes cluster are reached through Limen, not published."
  return 0
}

# Starts the cluster, applies the worker's service account, and writes the token and CA the
# kube worker mounts ($LIMEN_KUBE_DIR). Needs stack_setup kube to have run, and $root. Uses
# the kubectl inside the cluster container, so the host needs none.
stack_kube_prepare() {
  local k=("${compose[@]}" exec -T kubernetes kubectl) tok
  mkdir -p "$LIMEN_KUBE_DIR"
  "${compose[@]}" up -d --wait kubernetes >/dev/null 2>&1 || fail "the Kubernetes cluster did not become ready"
  "${k[@]}" apply -f - <"$root/deploy/kubernetes/access/limen-kube-worker.yaml" >/dev/null
  "${k[@]}" apply -f - <"$root/deploy/kubernetes/access/limen-groups.yaml" >/dev/null
  "${k[@]}" apply -f - >/dev/null <<'YAML'
apiVersion: v1
kind: Secret
metadata:
  name: limen-kube-worker-token
  namespace: limen-system
  annotations: { kubernetes.io/service-account.name: limen-kube-worker }
type: kubernetes.io/service-account-token
YAML
  for _ in $(seq 1 120); do
    tok="$("${k[@]}" -n limen-system get secret limen-kube-worker-token -o jsonpath='{.data.token}' 2>/dev/null || true)"
    [ -n "$tok" ] && break
    sleep 0.5
  done
  [ -n "$tok" ] || fail "no service account token for the Limen kube worker"
  printf '%s' "$tok" | base64 -d >"$LIMEN_KUBE_DIR/token"
  "${k[@]}" -n limen-system get secret limen-kube-worker-token -o jsonpath='{.data.ca\.crt}' | base64 -d >"$LIMEN_KUBE_DIR/ca.pem"
  # The worker runs as a different user in a container.
  chmod 755 "$LIMEN_KUBE_DIR"; chmod 644 "$LIMEN_KUBE_DIR/token" "$LIMEN_KUBE_DIR/ca.pem"
}

# Commands for what is running, ending with how to sign in. Needs stack_setup to have run.
stack_endpoints() {
  ui_init
  local scale=() s has_ssh=false has_db=false has_redis=false has_mongo=false has_search=false has_messaging=false has_obs=false has_bots=false has_kube=false
  if [ "${1:-}" = --scale ]; then scale=(--scale); shift; fi
  for s in "$@"; do
    case "$s" in ssh) has_ssh=true ;; db) has_db=true ;; redis) has_redis=true ;; mongo) has_mongo=true ;; search) has_search=true ;; messaging) has_messaging=true ;; observability) has_obs=true ;; bots) has_bots=true ;; kube) has_kube=true ;; esac
  done
  local ca="$STACK_STATE/internal-ca.pem" kc="$STACK_STATE/kubeconfig.json" row="  ${C_CYAN}%-12s${C_RESET} %s\n"
  if $has_ssh || $has_db || $has_redis || $has_mongo || $has_search || $has_messaging || $has_kube; then
    ui_section "Resources"
    $has_ssh && printf "$row" "SSH" "limen ssh web-staging-1"
    $has_db && printf "$row" "PostgreSQL" "limen db connect orders-staging" "MySQL" "limen db connect orders-mysql-staging"
    $has_redis && printf "$row" "Redis" "limen redis connect cache-staging" "Valkey" "limen redis connect cache-valkey"
    $has_mongo && printf "$row" "MongoDB" "limen mongo connect catalog-staging" "MongoDB (X.509)" "limen mongo connect catalog-x509"
    $has_search && printf "$row" "Elasticsearch" "limen search connect search-staging" "OpenSearch" "limen search connect search-opensearch"
    $has_messaging && printf "$row" "RabbitMQ" "limen mq connect events-rabbit-staging" "Kafka" "limen kafka connect events-kafka-staging"
    $has_kube && printf "$row" "Kubernetes" "limen kube login eks-staging --kubeconfig $kc && kubectl --kubeconfig $kc get pods -A"
  fi
  if $has_obs || $has_bots; then
    ui_section "Other"
    $has_obs && printf "$row" "Grafana" "http://localhost:3000   admin / limen-dev-only" "Datadog stub" "http://localhost:8126/fake/received"
    $has_bots && printf "$row" "CI issuer" "http://localhost:8130"
  fi
  ui_section "Connect"
  printf "$row" "CLI" "limen --proxy $STACK_PROXY login --ca-file $ca" "" "limen ls"
  printf "$row" "Console" "https://$STACK_PROXY/console/" "Sign in" "admin@example.com / password"
  ui_note "Browsers warn about the dev CA; that is expected. Stop it with: deploy/compose/setup.sh${scale[*]:+ --scale} down"
  return 0
}
