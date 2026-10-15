# syntax=docker/dockerfile:1.7
#
# One Dockerfile for all Limen server images. Pick one with --target:
#   docker build -f deploy/docker/Dockerfile --target control-plane -t limen-control-plane .
#   docker build -f deploy/docker/Dockerfile --target proxy -t limen-proxy .
#   docker build -f deploy/docker/Dockerfile --target worker -t limen-worker .
#
# The builder stage is shared, so building all three compiles once.

FROM rust:1.99.0-trixie AS builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends protobuf-compiler cmake \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# The cargo cache below is shared by every build on this machine, whatever
# checkout it came from, and COPY keeps each file's own modification time. Cargo
# decides what is stale by comparing those times, so a build from one worktree
# can leave artifacts that look newer than another worktree's sources, and the
# next build silently reuses them. Making every workspace file "new" forces
# Cargo to rebuild the workspace crates (the registry dependencies stay cached).
RUN find /src/crates /src/proto /src/Cargo.toml /src/Cargo.lock -exec touch {} +
# rust-toolchain.toml pins the same version as the base image.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
      --bin limen-control-plane --bin limen-audit-verify --bin limen-proxy --bin limen-worker --bin limen --bin fake-datadog --bin fake-ci-issuer \
 && mkdir -p /out /state/ca /state/ca-public /state/audit /state/spool /state/recordings /state/proxy /state/worker \
 && cp target/release/limen-control-plane target/release/limen-audit-verify target/release/limen-proxy target/release/limen-worker target/release/limen target/release/fake-datadog target/release/fake-ci-issuer /out/

# Distroless: no shell, no package manager, runs as uid 65532.
FROM gcr.io/distroless/cc-debian13:nonroot AS runtime-base
# State directories owned by the runtime user, so named volumes mounted
# here inherit that ownership.
COPY --from=builder --chown=nonroot:nonroot /state /var/lib/limen
WORKDIR /var/lib/limen
USER nonroot:nonroot

FROM runtime-base AS control-plane
COPY --from=builder /out/limen-control-plane /usr/local/bin/limen-control-plane
COPY --from=builder /out/limen-audit-verify /usr/local/bin/limen-audit-verify
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
