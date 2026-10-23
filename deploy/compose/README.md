<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="../../assets/logo-dark.svg"><img src="../../assets/logo.svg" alt="Limen" width="240"></picture></p>

# Local development stack

Runs a complete Limen deployment on your machine. Nothing here is fit for real use: Dex has static users whose password is `password`, join tokens are static, and CA keys sit on a Docker volume.

## Quick start

### Requirements

`setup.sh` checks these first and stops with install instructions for anything missing.

| Needed | Why | Install |
|---|---|---|
| Docker with Compose v2.24 or newer, and a running daemon | runs every service | macOS: [OrbStack](https://orbstack.dev) (`brew install --cask orbstack`) or Docker Desktop. Linux: [Docker Engine](https://docs.docker.com/engine/install/) with the Compose plugin |
| Rust toolchain from `mise.toml` (and `protoc`) | builds the `limen` CLI | `mise install` ([mise](https://mise.jdx.dev)), or [rustup](https://rustup.rs). Skip it by setting `LIMEN_BIN` to an existing `limen` binary |
| `curl` | health checks and the scripted logins | your package manager |
| OpenSSH client | only if you enable the `ssh` stack (`limen ssh`) | your package manager |
| Free host ports | see the port table `setup.sh` prints, or the [Stacks](#stacks); `setup.sh` reports any that are taken, and by what | stop the other stack |

The scripts are plain bash, written for macOS (tested) and Linux (untested). On Windows, run them inside WSL 2 (untested). The first build takes several minutes.

### Run it

```sh
deploy/compose/setup.sh
```

It asks whether to scale Limen and which stacks to enable, starts everything, applies `examples/policy`, and ends with the ports in use, the command for each enabled resource (SSH, PostgreSQL, MySQL, Redis, MongoDB, Kubernetes), and the CLI sign-in and console URL.

Then log in as the developer and try a resource:

```sh
export PATH="$PWD/target/release:$PATH" LIMEN_PROXY=localhost:3443 LIMEN_HOME=deploy/compose/.state/home-dev
LIMEN_DEV_CA=deploy/compose/.state/internal-ca.pem deploy/compose/scripts/dev-login.sh developer@example.com
limen ls
limen ssh web-staging-1 -- uptime
```

To check a phase's exit criteria instead, run its demo, which builds and resets its own stack: `demos/demo-phase1.sh`.

### By hand

```sh
deploy/compose/setup.sh --yes --stacks ssh        # or any other stacks; it starts Limen and applies the policy
# Without setup.sh: docker compose -f deploy/compose/docker-compose.yml up -d --build
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

### Kubernetes (Phase 8)

`deploy/compose/setup.sh --stacks kube` adds a Kubernetes cluster (k3s, a Compose service of this stack) and a Kubernetes worker (`stacks/kube.yml`) and prints how to sign in and use `kubectl` through Limen. See the [Kubernetes guide](../../docs/guides/kubernetes.md).

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
- `deploy/compose/scripts/dev-login.sh developer@example.com` automates Dex's password form. It's for scripts and tests only.

## Versions

Every container image the stack, the demos and the image builds use is listed in one file, [`.env`](.env) (Compose loads it by itself from this directory, and the demos and `scripts/ci-db-targets.sh` source it). Tool versions are in `mise.toml`. To change a version, edit `.env`, then run `scripts/check-versions.sh`. It fails when something drifts: a compose file that pins an image itself, a script that names one, a Dockerfile that has a default for a base image instead of taking it as a build arg, a build of it that does not pass the arg, or one of the few places that cannot read `.env` (the CI service containers, the Rust toolchain pins) disagreeing with it. CI runs it in the lint job.

## Layout

```
deploy/compose/
  setup.sh                  the entry point: checks prerequisites, asks what to enable, starts it
  docker-compose.yml        Limen: postgres, dex, s3, kms, control plane, proxy, worker
  stacks/                   one compose file per stack, layered on Limen with -f
    scale.yml                 Limen scaled: 3 control planes, 3 proxies, 3 workers (replaces docker-compose.yml)
    ssh.yml  db.yml  redis.yml  mongo.yml  search.yml  messaging.yml  observability.yml  bots.yml  kube.yml
  config/                   what the services mount: dex, s3, trino, grafana, targets/, dev-users.toml
  scripts/                  lib.sh (builds the compose command), dev-login.sh, console-login.sh,
                            dev-users.sh and gen-dev-users.py (generated user lists)
demos/                      one demo per phase (exit criteria) and the Redis scenarios test
scripts/                    smoke-release.sh, ci-db-targets.sh
deploy/                     cli/ (installer), compose/, docker/, grafana/, kubernetes/, terraform/
```

Compose resolves relative paths against the first `-f` file's directory, so list `docker-compose.yml` first, or pass `--project-directory deploy/compose` when you start from a file in `stacks/`.

## Stacks

Limen is one stack and everything it connects to or reports to is another, each its own compose file layered on with `-f` (and a profile of the same name):

| Stack | File | Adds |
|---|---|---|
| limen | `docker-compose.yml` | `postgres`, `dex`, `s3`, `kms`, `control-plane`, `proxy`, `worker`. Postgres holds state, S3 the audit batches and recordings |
| limen, scaled | `stacks/scale.yml` | the same with 3 control planes, 3 proxies, 3 workers (ports 23xxx; replaces the line above) |
| `ssh` | `stacks/ssh.yml` | `sshd-target` |
| `db` | `stacks/db.yml` | `postgres-target`, `mysql-target` (TLS, seeded `orders`), the role bootstrap |
| `redis` | `stacks/redis.yml` | `redis-target`, `valkey-target` (ACL users) |
| `search` | `stacks/search.yml` | `elasticsearch-target` (Elasticsearch 8, security on) and `opensearch-target` (OpenSearch 2, security plugin, TLS with its demo certificate), the engine roles `provision.sh` creates, and the logins and CA the worker holds |
| `messaging` | `stacks/messaging.yml` | `rabbitmq-target` (RabbitMQ 4) and `kafka-1`..`kafka-3` (a real three-broker Kafka 3.9 cluster, KRaft, SASL and the authorizer on); `provision.sh` creates the topics, ACLs and SCRAM users, and the worker holds the broker logins |
| `mongo` | `stacks/mongo.yml` | `mongo-target` (MongoDB 8 with TLS, SCRAM and X.509, seeded `orders` and `billing`) and the credentials the worker holds |
| `observability` | `stacks/observability.yml` | `fake-datadog` (the control plane sends audit events to it), `trino`, `grafana` (http://localhost:3000) over the S3 audit batches |
| `bots` | `stacks/bots.yml` | `fake-ci-issuer`, and the control plane trusts its plain-http issuer |
| `kube` | `stacks/kube.yml` | `kubernetes` (a k3s cluster in one privileged container, so it belongs to the project and `down -v` removes it) and `kube-worker`, which serves it as `eks-staging`; works with the single and the scaled Limen |

**Container names.** Limen itself is not an environment (one Limen is deployed to reach all of them), so its containers have plain names: `limen-control-plane`, `limen-proxy`, `limen-worker`, `limen-postgres`, `limen-dex`, `limen-s3`, `limen-kms`. The stand-in targets and tools carry the environment they represent, `-dev` here: `postgres-orders-dev`, `mysql-orders-dev`, `redis-cache-dev`, `valkey-cache-dev`, `ssh-web-dev`, `kubernetes-dev` (the k3s cluster), `datadog-fake-dev`, `trino-dev`, `grafana-dev`, `ci-issuer-fake-dev`. A second copy beside the dev stack (the scaled stack, or a demo) uses its own environment name for both, for example `limen-proxy-scale`, `postgres-orders-dbdemo`.

`setup.sh` picks the files and profiles, writes the settings a stack needs on a Limen service to `.state/stack.env` (the core reads it if present), then pins the CA, signs in as the admin, applies `examples/policy`, bootstraps the database roles, and seeds Redis, so `limen ls` shows every resource:

```sh
deploy/compose/setup.sh --yes               # limen + every stack, no questions
deploy/compose/setup.sh --stacks ssh,redis   # limen + SSH + Redis
deploy/compose/setup.sh --scale --stacks ssh,db   # scaled limen + SSH + databases
deploy/compose/setup.sh status
deploy/compose/setup.sh down                # removes the volumes too (add --scale for the scaled one)
```

The demos in `demos/` use the same helper (`scripts/lib.sh`). The Phase 5, 6 and 7 demos run their own copy (project, images and host ports set through `LIMEN_PROJECT`, `LIMEN_IMAGE_TAG` and `LIMEN_PORT_*`, see `docker-compose.yml`), so each can run beside this one.

Every phase is checked against the running stack, not only by unit tests: Phase 2 covers SSH with recording, Phase 3 the audit pipeline and dashboards, Phase 3.5 the web console, Phase 4 bots (a CI job logging in with an identity token), Phase 5 scale-out (killing and restarting control planes during a live session without losing audit events), and Phase 6 databases (`psql` and `mysql` through `limen db connect`). The exit criteria for each phase are in [`docs/design.md`](../../docs/design.md#13-phases-and-exit-criteria).

## SSH (Phase 2)

```sh
demos/demo-phase2.sh          # end to end with OpenSSH, including a control plane outage
demos/demo-phase3.sh          # audit to S3 and Datadog, sink outage, tamper check, Grafana
demos/demo-phase35.sh         # web console, locking a user, ending a session
demos/demo-phase7.sh          # Redis and Valkey through limen redis connect (own project and ports)
demos/demo-phase9.sh          # MongoDB through limen mongo connect and mongosh (own project and ports)
demos/demo-phase10.sh         # Elasticsearch and OpenSearch through limen search connect (own project and ports; pulls two ~1 GB images)
demos/demo-phase11.sh         # RabbitMQ and a three-broker Kafka cluster through limen mq connect and limen kafka connect (own project and ports)
```

By hand, after `limen admin apply examples/policy`:

```sh
limen login                                   # as developer@example.com (developers -> dev-readonly)
limen ssh web-staging-1                       # interactive shell as ubuntu (the only login policy allows)
limen ssh web-staging-1 -- uptime             # one command
limen ssh root@web-staging-1                  # denied, and audited
limen config ssh >> ~/.ssh/config && ssh ubuntu@web-staging-1.limen

docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/stacks/ssh.yml --profile ssh logs sshd-target | grep 'Accepted certificate'
docker compose -f deploy/compose/docker-compose.yml cp worker:/var/lib/limen/worker/recordings ./recordings
asciinema play recordings/<session-id>.cast   # if you have asciinema 3.x
```

Audit events are in `proxy:/var/lib/limen/proxy/audit/proxy.jsonl` (`session.start`, `session.end`, `auth.denied`) and `worker:/var/lib/limen/worker/audit/worker.jsonl` (`ssh.exec`). Phase 3 ships them to S3 and Datadog.

## Databases (Phase 6)

PostgreSQL 18 and MySQL 8.4 targets with TLS, a `limen_admin` login, and a seeded `orders` database are in `stacks/db.yml` (profile `db`, with the role bootstrap):

```sh
demos/demo-phase6.sh          # psql and mysql through `limen db connect`, bootstrap, audit, cancel, lock
db=(-f deploy/compose/docker-compose.yml -f deploy/compose/stacks/db.yml --profile db)
docker compose "${db[@]}" up -d postgres-target mysql-target db-secrets-init
docker compose "${db[@]}" --profile tools run --rm db-bootstrap --db-bootstrap-once   # create the limen_* roles
```

The demo runs its own project (`limen-dbdemo`, the core plus `stacks/db.yml`) on other host ports, so it can run next to the dev stack. The roles and resources come from `examples/policy`; the worker reads role passwords from the `db-secrets` volume and verifies the databases against the `db-tls` CA. Guide: [`docs/guides/databases.md`](../../docs/guides/databases.md). Runbook: [`docs/runbooks/database-onboarding.md`](../../docs/runbooks/database-onboarding.md).

For the integration tests of the database relay (they print SKIPPED without these), get the CA out of the `db-tls` volume and point the tests at the targets:

```sh
docker run --rm -v limen-db_db-tls:/tls alpine cat /tls/ca.pem > /tmp/limen-db-ca.pem   # volume name: <project>_db-tls
export LIMEN_TEST_PG_CA_FILE=/tmp/limen-db-ca.pem
export LIMEN_TEST_PG_TARGET=localhost:5433        # host:port of postgres-target, as your machine reaches it
export LIMEN_TEST_MYSQL_TARGET=localhost:3307     # host:port of mysql-target
cargo test -p limen-worker --test db_pg --test db_bootstrap --test db_mysql
cargo test -p limen-e2e --test phase6             # also needs LIMEN_TEST_DATABASE_URL
```

The targets publish no host ports; on OrbStack use their container hostnames (`<project>-postgres-target-1.orb.local:5432`), or add `ports:` in an override file.

## Things to try

```sh
# Enroll another worker with a single-use token (as admin):
TOKEN=$(limen admin token create --kind worker --label pool=demo)
docker compose -f deploy/compose/docker-compose.yml run -d -e LIMEN_JOIN_TOKEN=$TOKEN \
  -e LIMEN_DATA_DIR=/var/lib/limen/worker-2 worker
# Using the same token again fails: "invalid, expired, or already used join token".

# A named worker: the token approves the name (exactly, or a pattern with one *),
# and the worker asks for it with LIMEN_NAME (an exact name is given even without).
TOKEN=$(limen admin token create --kind worker --label pool=demo --name 'demo-worker-*')
docker compose -f deploy/compose/docker-compose.yml run -d -e LIMEN_JOIN_TOKEN=$TOKEN \
  -e LIMEN_NAME=demo-worker-1 -e LIMEN_DATA_DIR=/var/lib/limen/worker-3 worker
limen admin components   # the name column; the console shows it beside the id

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

The console's OIDC client (`limen-console`) and its dev secret are in `config/dex/config.yaml` and `docker-compose.yml`.

## Scale-out (Phase 5)

`stacks/scale.yml` is a separate compose project, `limen-scale`, with its own volumes and host ports, so it runs next to the dev stack without touching it:

```sh
docker compose --project-directory deploy/compose -f deploy/compose/stacks/scale.yml up -d --build
demos/demo-phase5.sh          # resets the scale stack, runs the exit test, stops it
demos/demo-phase5.sh --keep   # reuse the running scale stack and leave it up
```

What is in it:

- `control-plane-0`, `-1`, `-2` on one PostgreSQL. Each has its own `--id` (`LIMEN_ID`, also its S3 manifest writer), its own spool volume, and `--advertise-url https://control-plane-N:3080` (where peers hand off to). All three share the network alias `control-plane`, so DNS returns all three. Spool modes: `-1` is `durable`, `-0` and `-2` are `ephemeral`; override with `LIMEN_SCALE_SPOOL_MODE_0/1/2`. `stop_grace_period` (40 s) is longer than the drain timeout (20 s), so `docker compose stop` drains and hands off rather than being cut short.
- Connection age: each control plane closes every API connection gracefully (HTTP/2 GOAWAY) after `LIMEN_MAX_CONNECTION_AGE_SECS` ±10 %, then gives in-flight calls `LIMEN_CONNECTION_AGE_GRACE_SECS` (30 s) before cutting it. The default is 300 s; this stack uses 60 s (`LIMEN_SCALE_MAX_CONNECTION_AGE_SECS` overrides it, 0 disables), so the proxies, which all start on `control-plane-1`, move onto the other replicas during the demo. Proxies resolve `control-plane` again on every reconnect and try the addresses in random order.
- Worker load: each worker accepts at most `LIMEN_MAX_SESSIONS` sessions at once (default 200, 0 for no cap) and reports its load in every ping; proxies send each session to the less loaded of two eligible workers and answer `no capacity` (audited as `auth.denied`, `data.reason` `capacity`) when every eligible worker is full. Proxies learn the load from their pings (`LIMEN_PING_INTERVAL_SECS`, default 15) and share it with peers through the registry (`LIMEN_REPORT_INTERVAL_SECS`, default 15); a full worker that the figures missed refuses, and the proxy tries another (up to 3). This stack keeps the defaults; the cap is exercised by the end-to-end tests (`crates/limen-e2e/tests/scale.rs`).
- Worker drain: on `docker compose stop worker-N` (SIGTERM) a worker takes no new sessions (a proxy that hasn't seen its `draining` ping yet is refused before anything is read and tries another worker), lets open sessions finish for `LIMEN_DRAIN_TIMEOUT_SECS`, then ends the rest (`session.end` with `data.reason` `worker_drain`), uploads their recordings, and exits; an idle worker exits at once. The default timeout is 600 s; this stack sets 20 s, and its `stop_grace_period` (40 s) covers that plus the 18 s the worker may need after it. Worker stops are exercised by the end-to-end tests (`crates/limen-e2e/tests/scale.rs`), not by `demo-phase5.sh`.
- The CA: the CA certificates are in the database, and with the file backend the keys are on one volume (`cp-ca`) every replica mounts. Whichever replica starts first creates them; the others read the same files (creation is race-free). Separate key volumes per replica do not work: a replica whose key does not match the stored certificate refuses to start. With the KMS backend, every replica gets the same KMS key ids instead.
- `proxy-0`, `-1`, `-2` reach the control plane through the `control-plane` alias, and share the alias `proxy`; `worker-0`, `-1`, `-2` dial `proxy` and so land on any of them (sessions reach a worker on another proxy by peering). They enroll with the same multi-use static dev tokens as the dev stack, which here also approve names: `limen.io/name=proxy-*` and `limen.io/name=worker-*` in `LIMEN_STATIC_JOIN_TOKENS`, and each proxy and worker asks for its own with `LIMEN_NAME` (`proxy-0`..`proxy-2`, `worker-0`..`worker-2`).
- Names: optional, for people. They show beside the id in the console, `limen admin components`, the proxies' `/tunnels`, logs, and audit data (`worker_name` and `proxy_name` on `session.start`, `worker_name` on `session.end` and `session.recording`, `component_name` on `worker.enroll` and `component.revoke`), only for components that have one. The id stays the identity: certificates, policy, and revocation use it. A name is `a-z`, `0-9` and `-`, 1 to 63 characters, not starting or ending with `-`, and must be approved by the join token: exactly (`--name prod-a-worker-1`, given even if the component asks for none) or by a pattern with one `*`, which matches zero or more of those characters (`prod-a-*` accepts `prod-a-1`, not `prod-b-1` or `prod-a`). Static tokens are reusable, so they take patterns only. Anything else is refused (`permission_denied`, audited as `auth.denied`). Names are unique among enrolled, unrevoked proxies and workers together: a second component asking for a live name gets `already_exists` (audited as `auth.denied`, reason `name already in use`), and a single-use token is not used up by that. Revoking a component frees its name. The name is sent only at first enrollment and is fixed after that (also as the certificate label `limen.io/name`; policy can't select on it: a `worker_selector` on that key is refused, because a name is for people and whoever holds a pattern token picks its value, so select workers by the labels on their join token); a different `LIMEN_NAME` later is ignored with a warning. A component that loses its data directory and enrolls again under its old name is refused until the old one is revoked, so give autoscaled, ephemeral components unique names (for example with the instance id), or none.
- SeaweedFS, PostgreSQL, and Dex (the same `config/dex/config.yaml`, rewritten at start for this stack's ports). The SSH target and the other targets come from their stacks (`setup.sh --scale`); there is no KMS here.

Host ports (127.0.0.1): proxies `23443` / `23453` / `23463` (admin `23444` / `23454` / `23464`), control plane admin `23081` / `23082` / `23083`, Dex `25556`, S3 `28333`. To use the CLI against it:

```sh
docker compose -p limen-scale cp control-plane-0:/var/lib/limen/ca-public/internal-ca.pem deploy/compose/.state/scale/internal-ca.pem
LIMEN_PROXY=localhost:23443 LIMEN_DEV_CA=deploy/compose/.state/scale/internal-ca.pem \
  LIMEN_DEX_URL=http://localhost:25556 deploy/compose/scripts/dev-login.sh developer@example.com
```

`demos/demo-phase5.sh` starts `control-plane-1` first and the proxies while it is the only replica, so all their traffic lands on it. It then opens a long SSH session and new sessions one after another, and while they run:

1. SIGKILLs `control-plane-1` (durable) while it holds acked, unshipped events, and starts it again: its spool ships from the same volume.
2. Stops S3, waits until an ephemeral replica holds events it cannot ship, and SIGTERMs it: it drains what it can, then hands the rest to a live peer (`handed the rest of the audit spool to a peer` in its log). S3 comes back and the replica is started again.
3. SIGTERMs the other ephemeral replica (a plain drain) and starts it again.

It asserts that the long session outlasted all of this without a stall, every new session worked, `limen-audit-verify` finds every chain intact and no producer sequence gap, there is one chain per replica id, and S3 holds exactly one `ssh.exec`, `session.start`, and `session.end` per session the demo ran. It never SIGKILLs an ephemeral replica: that loses what it had acked but not shipped (ADR-0020), which `limen-audit-verify` would report as a gap. `LIMEN_SCALE_PROXY_LOG` sets the proxies' `RUST_LOG` (for example `info,h2=debug`).

**If an image build looks stale.** The Dockerfile keeps Cargo's `target` directory in a BuildKit cache that all checkouts and worktrees on the machine share, and Cargo decides what to rebuild from file times. Building two different branches one after the other can link old code into the new image (a build fails, or a fix seems to have no effect). If that happens, rebuild with `--no-cache`, or clear the builder's cache (`docker builder prune`); either makes the next build compile from scratch.

## Redis and Valkey (Phase 7)

The demo runs its own project (`limen-redis`, the core plus `stacks/redis.yml`) with its own volumes and host ports (proxy 33443/33444, Dex 35556, control plane health 33081, S3 38333), so it runs next to the dev stack. The stack adds a Redis 7.4 and a Valkey 8.0 target with the ACL in `config/targets/redis/users.acl`, and gives the worker the matching passwords from `config/targets/redis/credentials.json` (dev only). `demos/demo-phase7.sh` builds and starts it, seeds keys, and checks the exit criteria with `redis-cli` (or `config/targets/redis/resp-client.py` when `redis-cli` isn't installed). Stop it with `docker compose -p limen-redis down -v`. `scripts/dev-login.sh` takes `LIMEN_DEX_URL` (default `http://localhost:5556`) for a stack whose Dex has another port.

`demos/demo-phase7.sh --scenarios` runs 26 more scenarios on the same stack, after the walkthrough, against the same targets plus a TLS-only Redis (RESP3, 20 MiB values, 60,000-command pipelines, refusals inside pipelines and `MULTI`, Pub/Sub, key-limit escapes, malformed input, 16 parallel sessions, a target dying mid-session, locking a user, a control plane outage with audit catching up, unix sockets, the idle timeout, secrets in logs and audit). Give scenario names after `--scenarios` to run only those whose name contains them; add `--down` to remove the stack afterwards. It is the same project (`limen-redis`) and ports as the demo; set `LIMEN_REDIS_PROJECT` and the `LIMEN_REDIS_*_PORT` variables to run another copy beside it.

## MongoDB (Phase 9)

`stacks/mongo.yml` (profile `mongo`) adds a MongoDB 8 target with TLS from a throwaway CA, SCRAM-SHA-256/SHA-1 and X.509 enabled, seeded by `config/targets/mongo/init.js` with `orders` and `billing`, the users `read` and `write`, and an X.509 user for the worker's client certificate. `gen-tls.sh` makes the certificates and `worker-creds.sh` gives the worker only what it needs (the CA, a password file per role, the client certificate, in the `mongo-worker` volume the Limen worker mounts at `/etc/limen/mongo`): the server's key stays in its own volume. Try it with `deploy/compose/setup.sh --stacks mongo`, then `limen mongo connect catalog-staging`.

```sh
demos/demo-phase9.sh          # mongosh through `limen mongo connect`, SCRAM, X.509, refusals, redacted audit, console list, lock
```

The demo needs `mongosh` on the PATH (mise installs it) and runs its own project (`limen-mongo`) on ports 37xxx, so it can run next to the dev stack. The same server runs in CI and for the tests: `scripts/ci-db-targets.sh start` starts it next to PostgreSQL and MySQL on `127.0.0.1:17017` and exports `LIMEN_TEST_MONGO_TARGET`, `LIMEN_TEST_MONGO_CA_FILE`, and `LIMEN_TEST_MONGO_CLIENT_PEM`.

## Search (Phase 10)

`stacks/search.yml` (profile `search`) adds real **Elasticsearch 8** (security on, plain HTTP) and **OpenSearch 2** (security plugin on, TLS with the image's demo certificate, which the worker verifies in full through the `node-0.example.com` network alias). `config/targets/search/provision.sh` creates the engine-side roles (`limen_read` on `app-*` and `logs-*`; `limen_write` on `app-*`) and users that `config/targets/search/credentials.json` gives the worker; `setup.sh search` runs it. The engines publish no host port.

```sh
demos/demo-phase10.sh         # curl through `limen search connect`: refusals, bulk, engine second layer, TLS to OpenSearch, lock, audit, console
```

The demo runs its own project (`limen-search`) on ports 34xxx. It pulls about 2.4 GB of images and the engines take a minute or two to start; it is not run in CI. Amazon OpenSearch Service, OpenSearch Serverless, and Elastic Cloud are unverified.

## Messaging (Phase 11)

`stacks/messaging.yml` (profile `messaging`) adds real **RabbitMQ 4** (two users and three vhosts from a definitions file) and a real **three-broker Kafka 3.9 cluster** (KRaft, SASL `PLAIN` with SCRAM added, the authorizer on). `config/targets/messaging/provision.sh` creates the topics, ACLs and SCRAM users, and the worker holds the broker logins (`config/targets/messaging/credentials.json`). Kafka clients are told to reach each broker at `kafka-N:9092`, which only exists on the Docker network: through Limen they use the loopback listeners `limen kafka connect` opens, which is what the demo proves.

```sh
deploy/compose/setup.sh --stacks messaging
limen mq connect events-rabbit-staging         # an amqp:// URL with no real password
limen kafka connect events-kafka-staging       # prints a bootstrap address for kcat and the clients
demos/demo-phase11.sh         # pika and librdkafka: refusals, a consumer group across brokers, a broker down, audit, one console row per run
```

The demo runs its own project (`limen-messaging`) on ports 39xxx and needs `python3` (it installs `pika` and `confluent-kafka` into a virtualenv under `.state/`). The first image build takes several minutes; it is not run in CI. Amazon MQ, Amazon MSK, and the `AWS_MSK_IAM` login are unverified.
