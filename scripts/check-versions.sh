#!/usr/bin/env bash
# Checks that container image versions are defined once, in deploy/compose/.env.
#
#   scripts/check-versions.sh
#
# 1. No compose file pins an image literally: every `image:` is a ${VARIABLE} or a locally
#    built limen image.
# 2. No script, demo or compose file contains one of the .env image references as a literal
#    (the places that cannot read .env are listed below and checked in step 3).
# 3. The places that cannot read .env agree with it: the default build args of the
#    Dockerfiles, and the CI service containers.
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
allowed_re='^(deploy/compose/\.env|deploy/docker/Dockerfile|deploy/compose/config/targets/sshd/Dockerfile|\.github/workflows/ci\.yml|scripts/check-versions\.sh)$'
for var in POSTGRES_IMAGE DEX_IMAGE SEAWEEDFS_IMAGE KMS_IMAGE MYSQL_IMAGE REDIS_IMAGE VALKEY_IMAGE K3S_IMAGE TRINO_IMAGE GRAFANA_IMAGE ALPINE_IMAGE SSHD_BASE_IMAGE RUST_IMAGE DISTROLESS_IMAGE; do
  ref="${!var}"
  while IFS= read -r file; do
    [[ "$file" =~ $allowed_re ]] && continue
    case "$file" in *.md|docs/adr/*) continue ;; esac
    fail "$file: contains $var ($ref) literally; read it from $envfile"
  done < <(git grep -lF -- "$ref" -- . ':!docs/adr' 2>/dev/null || true)
done

# 3. places that cannot read .env
arg_default() { sed -nE "s/^ARG $2=(.*)$/\\1/p" "$1" | head -1; }
[ "$(arg_default deploy/docker/Dockerfile RUST_IMAGE)" = "$RUST_IMAGE" ] || fail "deploy/docker/Dockerfile: ARG RUST_IMAGE default differs from $envfile ($RUST_IMAGE)"
[ "$(arg_default deploy/docker/Dockerfile DISTROLESS_IMAGE)" = "$DISTROLESS_IMAGE" ] || fail "deploy/docker/Dockerfile: ARG DISTROLESS_IMAGE default differs from $envfile ($DISTROLESS_IMAGE)"
[ "$(arg_default deploy/compose/config/targets/sshd/Dockerfile BASE_IMAGE)" = "$SSHD_BASE_IMAGE" ] || fail "sshd Dockerfile: ARG BASE_IMAGE default differs from $envfile ($SSHD_BASE_IMAGE)"
# CI service containers cannot read a file: their image strings must equal the ones here.
for var in POSTGRES_IMAGE KMS_IMAGE; do
  grep -qE "^[[:space:]]+image: ${!var}$" .github/workflows/ci.yml || fail ".github/workflows/ci.yml: the service image for $var is not ${!var}"
done

# 4. Rust
rust="${RUST_IMAGE#rust:}"; rust="${rust%%-*}"
toolchain="$(sed -nE 's/^channel *= *"([^"]+)".*/\1/p' rust-toolchain.toml)"
mise_rust="$(sed -nE 's/^rust *= *\{ *version *= *"([^"]+)".*/\1/p' mise.toml)"
[ "$toolchain" = "$rust" ] || fail "rust-toolchain.toml channel is $toolchain, $envfile says $rust"
[ "$mise_rust" = "$rust" ] || fail "mise.toml rust is $mise_rust, $envfile says $rust"

if [ "$bad" = 0 ]; then echo "ok: image versions agree ($envfile)"; else exit 1; fi
