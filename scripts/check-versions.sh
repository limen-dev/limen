#!/usr/bin/env bash
# Checks that container image versions are defined once, in deploy/compose/.env.
#
#   scripts/check-versions.sh
#
# 1. No compose file pins an image literally: every `image:` is a ${VARIABLE} or a locally
#    built limen image.
# 2. No script, demo or compose file contains one of the .env image references as a literal
#    (the places that cannot read .env are listed below and checked in step 3).
# 3. The Dockerfiles take their base images as build args with no default, every build of them
#    passes the args, and the places that cannot read .env agree with it (the CI service
#    containers).
# 4. The Rust version agrees across RUST_IMAGE, rust-toolchain.toml and mise.toml.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
envfile=deploy/compose/.env
bad=0
fail() { echo "FAIL $*" >&2; bad=1; }

set -a
# shellcheck source=../deploy/compose/.env
source "$envfile"
set +a

# 1. compose files
while IFS= read -r line; do
  file="${line%%:*}"; rest="${line#*:}"
  value="$(printf '%s' "$rest" | sed -E 's/^[0-9]+:[[:space:]]*(-[[:space:]]*)?image:[[:space:]]*//; s/[[:space:]]*#.*$//; s/^"//; s/"$//')"
  case "$value" in
    '${'*'}') ;;                                   # a variable
    limen-*:*|limen-*) ;;                           # built from this repository
    *) fail "$file: image is pinned in the compose file (use a variable from $envfile): $value" ;;
  esac
done < <(grep -rnE '^[[:space:]]*(-[[:space:]]*)?image:' deploy/compose/docker-compose.yml deploy/compose/stacks deploy/compose/config/targets/redis/tls-overlay.yml)

# 2. literals elsewhere
allowed_re='^(deploy/compose/\.env|\.github/workflows/ci-rust\.yml|scripts/check-versions\.sh)$'
for var in POSTGRES_IMAGE DEX_IMAGE SEAWEEDFS_IMAGE KMS_IMAGE MYSQL_IMAGE MONGO_IMAGE ELASTICSEARCH_IMAGE OPENSEARCH_IMAGE REDIS_IMAGE VALKEY_IMAGE RABBITMQ_IMAGE KAFKA_IMAGE K3S_IMAGE TRINO_IMAGE GRAFANA_IMAGE JAEGER_IMAGE ALPINE_IMAGE PYTHON_IMAGE SSHD_BASE_IMAGE RUST_IMAGE DISTROLESS_IMAGE; do
  ref="${!var}"
  while IFS= read -r file; do
    [[ "$file" =~ $allowed_re ]] && continue
    case "$file" in *.md|docs/adr/*) continue ;; esac
    fail "$file: contains $var ($ref) literally; read it from $envfile"
  done < <(git grep -lF -- "$ref" -- . ':!docs/adr' 2>/dev/null || true)
done

# 3. places that cannot read .env
# No image in a Dockerfile: its base images are build args with no default.
for df in deploy/docker/Dockerfile deploy/compose/config/targets/sshd/Dockerfile; do
  if grep -qE '^ARG (RUST_IMAGE|DISTROLESS_IMAGE|BASE_IMAGE)=' "$df"; then fail "$df: a base image ARG has a default (it comes from $envfile)"; fi
  # a stage name has no ':', '/' or '@'; an image reference has at least one
  if grep -qE '^FROM [^$ ]*[:/@]' "$df"; then fail "$df: FROM names an image (use a build arg from $envfile)"; fi
done
# Every build of deploy/docker/Dockerfile passes both args; the sshd build passes its own.
while IFS= read -r file; do
  case "$file" in docs/*|*.md|scripts/check-versions.sh|deploy/compose/.env) continue ;; esac
  for arg in RUST_IMAGE DISTROLESS_IMAGE; do
    case "$file" in
      deploy/compose/*) pat="^[[:space:]]+$arg:" ;;            # a compose build.args entry
      *) pat="--build-arg[ =]$arg" ;;                          # docker build / buildx build
    esac
    grep -qE -- "$pat" "$file" || fail "$file: builds deploy/docker/Dockerfile without passing $arg"
  done
done < <(git grep -lF 'deploy/docker/Dockerfile' -- . ':!docs' ':!*.md' ':!scripts/check-versions.sh' ':!deploy/compose/.env' 2>/dev/null)
grep -q 'SSHD_BASE_IMAGE' deploy/compose/stacks/ssh.yml || fail "deploy/compose/stacks/ssh.yml: the sshd build does not pass SSHD_BASE_IMAGE"
# CI service containers cannot read a file: their image strings must equal the ones here.
for var in POSTGRES_IMAGE KMS_IMAGE JAEGER_IMAGE; do
  grep -qE "^[[:space:]]+image: ${!var}$" .github/workflows/ci-rust.yml || fail ".github/workflows/ci-rust.yml: the service image for $var is not ${!var}"
done

# 4. Rust
rust="${RUST_IMAGE#rust:}"; rust="${rust%%-*}"
toolchain="$(sed -nE 's/^channel *= *"([^"]+)".*/\1/p' rust-toolchain.toml)"
mise_rust="$(sed -nE 's/^rust *= *\{ *version *= *"([^"]+)".*/\1/p' mise.toml)"
[ "$toolchain" = "$rust" ] || fail "rust-toolchain.toml channel is $toolchain, $envfile says $rust"
[ "$mise_rust" = "$rust" ] || fail "mise.toml rust is $mise_rust, $envfile says $rust"

if [ "$bad" = 0 ]; then echo "ok: image versions agree ($envfile)"; else exit 1; fi
