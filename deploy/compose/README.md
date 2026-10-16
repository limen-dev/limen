<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="../../assets/logo-dark.svg"><img src="../../assets/logo.svg" alt="Limen" width="240"></picture></p>

# Local development stack

Runs a complete Limen deployment on your machine. Nothing here is fit for real use: Dex has static users whose password is `password`, join tokens are static, and CA keys sit on a Docker volume.

| Service | What it is | Host port |
|---|---|---|
| `postgres` | Control plane state | 5432 |
| `dex` | OIDC provider standing in for Okta | 5556 |
| `kms` | KMS emulator ([local-kms](https://github.com/nsmithuk/local-kms)), used by tests | 8099 |
| `control-plane` | API, CA, policy, registry. Health on 3081 | 3081 |
| `proxy` | Public entry point (3443) and admin/debug endpoints (3444) | 3443, 3444 |
| `worker` | Enrolls through the proxy (labels `pool=dev`) and holds two reverse tunnels | none (outbound only) |
| `sshd-target` | OpenSSH host that trusts only Limen per-session certificates (`web-staging-1` in the example policy) | none |

## Quick start

You need Docker (OrbStack on macOS) and the Rust toolchain from `mise.toml`.

```sh
deploy/compose/demo-phase1.sh        # builds everything, resets the stack, checks every Phase 1 criterion
```

Or step by step:

```sh
docker compose -f deploy/compose/docker-compose.yml up -d --build
cargo build --release -p limen-cli && export PATH="$PWD/target/release:$PATH"

# The proxy's certificate comes from the Limen internal CA. Pin it once.
mkdir -p deploy/compose/.state
docker compose -f deploy/compose/docker-compose.yml cp \
  control-plane:/var/lib/limen/ca-public/internal-ca.pem deploy/compose/.state/internal-ca.pem

limen --proxy localhost:3443 login --ca-file deploy/compose/.state/internal-ca.pem
# A browser opens on Dex. Log in as admin@example.com / password.

limen admin apply examples/policy      # admin is a bootstrap admin (group limen-admins)
limen login                            # log in again: roles are fixed at login
limen ls
limen admin components                 # the proxy, the worker, and its tunnels
```

### Dev users

<!-- BEGIN dev-users (generated from dev-users.toml) -->
| User | Groups | Roles with `examples/policy` |
|---|---|---|
| `admin@example.com` | `limen-admins`, `sre` | `limen:admin`, `sre` |
| `developer@example.com` | `developers` | `dev-readonly` |
| `guest@example.com` | `marketing` | none, so login is denied |
<!-- END dev-users -->

### Logging in without a browser

- `limen login --device` uses the device flow. Open the printed URL anywhere and enter the code.
- `deploy/compose/dev-login.sh developer@example.com` automates Dex's password form. It's for scripts and tests only.

## SSH (Phase 2)

```sh
deploy/compose/demo-phase2.sh          # end to end with OpenSSH, including a control plane outage
deploy/compose/demo-phase3.sh          # audit to S3 and Datadog, sink outage, tamper check, Grafana
deploy/compose/demo-phase35.sh         # web console, locking a user, ending a session
```

By hand, after `limen admin apply examples/policy`:

```sh
limen login                                   # as developer@example.com (developers -> dev-readonly)
limen ssh web-staging-1                       # interactive shell as ubuntu (the only login policy allows)
limen ssh web-staging-1 -- uptime             # one command
limen ssh root@web-staging-1                  # denied, and audited
limen config ssh >> ~/.ssh/config && ssh ubuntu@web-staging-1.limen

docker compose -f deploy/compose/docker-compose.yml logs sshd-target | grep 'Accepted certificate'
docker compose -f deploy/compose/docker-compose.yml cp worker:/var/lib/limen/worker/recordings ./recordings
asciinema play recordings/<session-id>.cast   # if you have asciinema 3.x
```

Audit events are in `proxy:/var/lib/limen/proxy/audit/proxy.jsonl` (`session.start`, `session.end`, `auth.denied`) and `worker:/var/lib/limen/worker/audit/worker.jsonl` (`ssh.exec`). Phase 3 ships them to S3 and Datadog.

## Things to try

```sh
# Enroll another worker with a single-use token (as admin):
TOKEN=$(limen admin token create --kind worker --label pool=demo)
docker compose -f deploy/compose/docker-compose.yml run -d -e LIMEN_JOIN_TOKEN=$TOKEN \
  -e LIMEN_DATA_DIR=/var/lib/limen/worker-2 worker
# Using the same token again fails: "invalid, expired, or already used join token".

# Kill the proxy and watch workers reconnect with backoff and jitter:
docker compose -f deploy/compose/docker-compose.yml restart proxy
curl -s localhost:3444/tunnels

# Read the audit trail (stub sink in Phase 1):
docker compose -f deploy/compose/docker-compose.yml cp \
  control-plane:/var/lib/limen/audit/control-plane.jsonl - | tar -xO | tail -5
```

## Integration tests against this stack

```sh
docker compose -f deploy/compose/docker-compose.yml up -d postgres kms
export LIMEN_TEST_DATABASE_URL=postgres://limen:limen-dev-only@localhost:5432/limen
export LIMEN_TEST_KMS_ENDPOINT=http://localhost:8099
cargo test --workspace --all-features
```

Each test creates its own database named `limen_test_*` or `limen_e2e_*`. Drop them whenever you like, or reset everything with `docker compose ... down -v`.

## Web console (Phase 3.5)

`https://localhost:3443/console/`, served by the proxy. Sign in through Dex as `admin@example.com` (admin) or `developer@example.com` (sees only his own resources and sessions). The proxy's certificate comes from the Limen internal CA, so your browser will warn about it. That's expected here: don't add the dev CA to your system trust store. Use `limen --ca-file` for the CLI, and `curl --cacert deploy/compose/.state/internal-ca.pem` for scripts. `demo-phase35.sh` does the Dex login with curl, locks and unlocks a user, ends a live session, and plays back the recording check.

The console's OIDC client (`limen-console`) and its dev secret are in `dex/config.yaml` and `docker-compose.yml`.

## Scale-out (Phase 5)

`docker-compose.scale.yml` is a separate compose project, `limen-scale`, with its own volumes and host ports, so it runs next to the dev stack without touching it:

```sh
docker compose -f deploy/compose/docker-compose.scale.yml up -d --build
deploy/compose/demo-phase5.sh          # resets the scale stack, runs the exit test, stops it
deploy/compose/demo-phase5.sh --keep   # reuse the running scale stack and leave it up
```

What is in it:

- `control-plane-0`, `-1`, `-2` on one PostgreSQL. Each has its own `--id` (`LIMEN_ID`, also its S3 manifest writer), its own spool volume, and `--advertise-url https://control-plane-N:3080` (where peers hand off to). All three share the network alias `control-plane`, so DNS returns all three. Spool modes: `-1` is `durable`, `-0` and `-2` are `ephemeral`; override with `LIMEN_SCALE_SPOOL_MODE_0/1/2`. `stop_grace_period` (40 s) is longer than the drain timeout (20 s), so `docker compose stop` drains and hands off rather than being cut short.
- Connection age: each control plane closes every API connection gracefully (HTTP/2 GOAWAY) after `LIMEN_MAX_CONNECTION_AGE_SECS` ±10 %, then gives in-flight calls `LIMEN_CONNECTION_AGE_GRACE_SECS` (30 s) before cutting it. The default is 300 s; this stack uses 60 s (`LIMEN_SCALE_MAX_CONNECTION_AGE_SECS` overrides it, 0 disables), so the proxies, which all start on `control-plane-1`, move onto the other replicas during the demo. Proxies resolve `control-plane` again on every reconnect and try the addresses in random order.
- Worker load: each worker accepts at most `LIMEN_MAX_SESSIONS` sessions at once (default 200, 0 for no cap) and reports its load in every ping; proxies send each session to the less loaded of two eligible workers and answer `no capacity` (audited as `auth.denied`, `data.reason` `capacity`) when every eligible worker is full. Proxies learn the load from their pings (`LIMEN_PING_INTERVAL_SECS`, default 15) and share it with peers through the registry (`LIMEN_REPORT_INTERVAL_SECS`, default 15); a full worker that the figures missed refuses, and the proxy tries another (up to 3). This stack keeps the defaults; the cap is exercised by the end-to-end tests (`crates/limen-e2e/tests/scale.rs`).
- Worker drain: on `docker compose stop worker-N` (SIGTERM) a worker takes no new sessions (a proxy that hasn't seen its `draining` ping yet is refused before anything is read and tries another worker), lets open sessions finish for `LIMEN_DRAIN_TIMEOUT_SECS` (default 20), then ends the rest (`session.end` with `data.reason` `worker_drain`), uploads their recordings, and exits; an idle worker exits at once. `stop_grace_period` (40 s) covers the timeout plus the 15 s the worker needs after it.
- The CA: the CA certificates are in the database, and with the file backend the keys are on one volume (`cp-ca`) every replica mounts. Whichever replica starts first creates them; the others read the same files (creation is race-free). Separate key volumes per replica do not work: a replica whose key does not match the stored certificate refuses to start. With the KMS backend, every replica gets the same KMS key ids instead.
- `proxy-0`, `-1`, `-2` reach the control plane through the `control-plane` alias, and share the alias `proxy`; `worker-0`, `-1`, `-2` dial `proxy` and so land on any of them (sessions reach a worker on another proxy by peering). They enroll with the same multi-use static dev tokens as the dev stack.
- The dev stack's `sshd-target`, SeaweedFS, PostgreSQL, and Dex (the same `dex/config.yaml`, rewritten at start for this stack's ports). No KMS, Datadog, Trino, or Grafana.

Host ports (127.0.0.1): proxies `23443` / `23453` / `23463` (admin `23444` / `23454` / `23464`), control plane admin `23081` / `23082` / `23083`, Dex `25556`, S3 `28333`. To use the CLI against it:

```sh
docker compose -p limen-scale cp control-plane-0:/var/lib/limen/ca-public/internal-ca.pem deploy/compose/.state-scale/internal-ca.pem
LIMEN_PROXY=localhost:23443 LIMEN_DEV_CA=deploy/compose/.state-scale/internal-ca.pem \
  LIMEN_DEX_URL=http://localhost:25556 deploy/compose/dev-login.sh developer@example.com
```

`demo-phase5.sh` starts `control-plane-1` first and the proxies while it is the only replica, so all their traffic lands on it. It then opens a long SSH session and new sessions one after another, and while they run:

1. SIGKILLs `control-plane-1` (durable) while it holds acked, unshipped events, and starts it again: its spool ships from the same volume.
2. Stops S3, waits until an ephemeral replica holds events it cannot ship, and SIGTERMs it: it drains what it can, then hands the rest to a live peer (`handed the rest of the audit spool to a peer` in its log). S3 comes back and the replica is started again.
3. SIGTERMs the other ephemeral replica (a plain drain) and starts it again.

It asserts that the long session outlasted all of this without a stall, every new session worked, `limen-audit-verify` finds every chain intact and no producer sequence gap, there is one chain per replica id, and S3 holds exactly one `ssh.exec`, `session.start`, and `session.end` per session the demo ran. It never SIGKILLs an ephemeral replica: that loses what it had acked but not shipped (ADR-0020), which `limen-audit-verify` would report as a gap. `LIMEN_SCALE_PROXY_LOG` sets the proxies' `RUST_LOG` (for example `info,h2=debug`).
