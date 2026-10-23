# syntax=docker/dockerfile:1.7
#
# One Dockerfile for all Limen server images. Pick one with --target:
#   . deploy/compose/.env    # RUST_IMAGE and DISTROLESS_IMAGE, which the Dockerfile has no default for
#   docker build -f deploy/docker/Dockerfile --target control-plane -t limen-control-plane \
#     --build-arg RUST_IMAGE --build-arg DISTROLESS_IMAGE .
#
# The builder stage is shared, so building all three compiles once.

# The base images come from deploy/compose/.env (RUST_IMAGE, DISTROLESS_IMAGE) and have no
# default here: Compose passes them, and so do CI and the release (--build-arg), so there is
# one place to change them. rust-toolchain.toml pins the same Rust version (scripts/check-versions.sh
# checks it).
ARG RUST_IMAGE
ARG DISTROLESS_IMAGE

FROM ${RUST_IMAGE} AS builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends protobuf-compiler cmake \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# Compose setup assigns a target cache per checkout. For manual builds that
# share a Docker host, pass a distinct LIMEN_BUILD_CACHE for each checkout.
ARG LIMEN_BUILD_CACHE=limen-target
# rust-toolchain.toml pins the same version as the base image.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=${LIMEN_BUILD_CACHE} \
    cargo build --release --locked \
      --bin limen-control-plane --bin limen-audit-verify --bin limen-spool-adopt --bin limen-proxy --bin limen-worker --bin limen --bin fake-datadog --bin fake-ci-issuer \
 && mkdir -p /out /state/ca /state/ca-public /state/audit /state/spool /state/recordings /state/proxy /state/worker /state/db-secrets /state/db-tls \
 && cp target/release/limen-control-plane target/release/limen-audit-verify target/release/limen-spool-adopt target/release/limen-proxy target/release/limen-worker target/release/limen target/release/fake-datadog target/release/fake-ci-issuer /out/

# Distroless: no shell, no package manager, runs as uid 65532.
FROM ${DISTROLESS_IMAGE} AS runtime-base
# State directories owned by the runtime user, so named volumes mounted
# here inherit that ownership.
COPY --from=builder --chown=nonroot:nonroot /state /var/lib/limen
WORKDIR /var/lib/limen
USER nonroot:nonroot

FROM runtime-base AS control-plane
COPY --from=builder /out/limen-control-plane /usr/local/bin/limen-control-plane
COPY --from=builder /out/limen-audit-verify /usr/local/bin/limen-audit-verify
COPY --from=builder /out/limen-spool-adopt /usr/local/bin/limen-spool-adopt
EXPOSE 3080 3081
ENTRYPOINT ["/usr/local/bin/limen-control-plane"]

FROM runtime-base AS proxy
COPY --from=builder /out/limen-proxy /usr/local/bin/limen-proxy
EXPOSE 3443 3444
ENTRYPOINT ["/usr/local/bin/limen-proxy"]

FROM runtime-base AS worker
COPY --from=builder /out/limen-worker /usr/local/bin/limen-worker
EXPOSE 3090
ENTRYPOINT ["/usr/local/bin/limen-worker"]

# The CLI, for running in CI or in the compose network.
FROM runtime-base AS cli
COPY --from=builder /out/limen /usr/local/bin/limen
ENTRYPOINT ["/usr/local/bin/limen"]

# Development only: a stand-in for a CI platform's OIDC issuer (ADR-0019). It
# mints any token on request.
FROM runtime-base AS fake-ci-issuer
COPY --from=builder /out/fake-ci-issuer /usr/local/bin/fake-ci-issuer
EXPOSE 8130
ENTRYPOINT ["/usr/local/bin/fake-ci-issuer"]

# Development only: a fake Datadog Logs intake for the local stack.
FROM runtime-base AS fake-datadog
COPY --from=builder /out/fake-datadog /usr/local/bin/fake-datadog
EXPOSE 8126
ENTRYPOINT ["/usr/local/bin/fake-datadog"]
