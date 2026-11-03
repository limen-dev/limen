<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="../../assets/logo-dark.svg"><img src="../../assets/logo.svg" alt="Limen" width="240"></picture></p>

# Local development stack

Runs a complete Limen deployment on your machine. **Nothing here is fit for real use**: Dex has static users whose password is `password`, join tokens are static, and CA keys sit on a Docker volume.

## Quick start

`setup.sh` checks these first and stops with install instructions for anything missing.

| Needed | Why | Install |
|---|---|---|
| Docker with Compose v2.24+, daemon running | runs every service | macOS: [OrbStack](https://orbstack.dev) (`brew install --cask orbstack`) or Docker Desktop. Linux: [Docker Engine](https://docs.docker.com/engine/install/) with the Compose plugin |
| Rust toolchain from `mise.toml` (and `protoc`) | builds the `limen` CLI | `mise install` ([mise](https://mise.jdx.dev)) or [rustup](https://rustup.rs). Skip by setting `LIMEN_BIN` to an existing `limen` binary |
| `curl` | health checks, scripted logins | your package manager |
| OpenSSH client | only for the `ssh` stack | your package manager |
| Free host ports | the table `setup.sh` prints, or [Stacks](#stacks); it reports what holds any taken port | stop the other stack |

The scripts are plain bash, tested on macOS and untested on Linux. On Windows use WSL 2 (untested). The first build takes several minutes.

```sh
deploy/compose/setup.sh
```

It asks whether to scale Limen and which stacks to enable, starts everything, applies the shared policy plus only the selected stacks' policies, and prints the ports, a command per enabled resource, how to sign in, and the console URL. For example, with the TCP and web fixtures:

```sh
deploy/compose/setup.sh --stacks tcp,web
export PATH="$PWD/target/release:$PATH" LIMEN_PROXY=localhost:3443
limen login --ca-file deploy/compose/.state/internal-ca.pem
limen ls
limen tcp tcp-echo                       # prints a local port: nc 127.0.0.1 <port>
limen web open --no-browser web-demo     # prints the app URL
```

Sign in as `developer@example.com` / `password` so the grants apply. To load the web app, resolve `app.apps.test` to `127.0.0.1`; its certificate is signed by the dev CA, which must not be added to the system trust store.

To check a phase's exit criteria instead, run its demo, which builds and resets its own stack (`demos/demo-phase1.sh`).

### By hand

```sh
deploy/compose/setup.sh --yes --stacks ssh        # starts Limen and applies the policy
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

### Dev users

<!-- BEGIN dev-users (generated from dev-users.toml) -->
| User | Groups | Roles with `examples/policy` |
|---|---|---|
| `admin@example.com` | `limen-admins`, `sre` | `limen:admin`, `sre` |
| `developer@example.com` | `developers` | `dev-readonly` |
| `guest@example.com` | `marketing` | none, so login is denied |
| `auditor@example.com` | `auditors` | `auditor` |
| `viewer@example.com` | `viewers` | `viewer` |
| `oncall@example.com` | `sre-oncall` | `sre-oncall` |
| `contractor@example.com` | `contractors` | `contractor` |
<!-- END dev-users -->

Without a browser: `limen login --device` prints a URL and code to open anywhere. `deploy/compose/scripts/dev-login.sh developer@example.com` automates Dex's password form (scripts and tests only; `LIMEN_DEX_URL` points it at a stack whose Dex has another port).

## Versions

Every container image used by the stack, the demos and the image builds is listed in one file, [`.env`](.env). Compose loads it itself; the demos and `scripts/ci-db-targets.sh` source it. Tool versions are in `mise.toml`. To change a version, edit `.env` and run `scripts/check-versions.sh`. It fails on drift: a compose file or script that pins an image itself, a Dockerfile that defaults a base image instead of taking a build arg, a build that doesn't pass the arg, or a place that can't read `.env` (CI service containers, Rust toolchain pins) disagreeing with it. CI runs it in the lint job.

A weekly workflow ([`image-bumps.yml`](../../.github/workflows/image-bumps.yml), which runs `scripts/bump-images.py`) looks for newer tags and opens one draft pull request with the patch and minor bumps; mark it ready for review to run CI and the demos. Major versions and new release lines (for example `redis:7.4` to `8.x`), images pinned by digest, and the variables the script is told to hold (`MONGO_IMAGE`, with the reason) are only listed. Run `scripts/bump-images.py` yourself for the report (add `--apply` to edit the files). Not run end to end yet: the report and the file edits were run locally, the workflow itself only linted (`unverified` until its first scheduled or manual run).

## Layout

```
deploy/compose/
  setup.sh                  entry point: checks prerequisites, asks what to enable, starts it
  docker-compose.yml        Limen: postgres, dex, s3, kms, control plane, proxy, worker
  stacks/                   one compose file per stack, layered on Limen with -f
    scale.yml                 3 control planes, 3 proxies, 3 workers (replaces docker-compose.yml)
    ssh.yml  db.yml  redis.yml  mongo.yml  search.yml  messaging.yml  observability.yml  tracing.yml  bots.yml  kube.yml  tcp.yml  web.yml
  config/                   what the services mount: dex, s3, trino, grafana, targets/, dev-users.toml
  scripts/                  lib.sh (builds the compose command), dev-login.sh, console-login.sh,
                            dev-users.sh and gen-dev-users.py (generated user lists), test-policy-selection.sh
```

Other top-level directories: [CONTRIBUTING.md](../../CONTRIBUTING.md#repository-layout). Compose resolves relative paths against the first `-f` file's directory, so list `docker-compose.yml` first, or pass `--project-directory deploy/compose` when starting from a file in `stacks/`.

## Stacks

Limen is one stack, and everything it connects to or reports to is another: a compose file layered on with `-f`, with a profile of the same name. `setup.sh` picks files and profiles, writes the settings a stack needs on a Limen service to `.state/stack.env`, pins the CA, signs in as admin, applies shared policy plus only the selected stacks' policies, bootstraps database roles and seeds Redis. So `limen ls` shows resources for the enabled stacks only.

| Stack | File | Containers (names carry `-dev`) |
|---|---|---|
| limen | `docker-compose.yml` | `limen-postgres` (state), `limen-dex` (dev OIDC), `limen-s3` (SeaweedFS: audit batches and recordings), `limen-kms` (local KMS stand-in), `limen-control-plane`, `limen-proxy`, `limen-worker` |
| limen, scaled | `stacks/scale.yml` | the same ×3 as `limen-control-plane-{0,1,2}` etc. (ports 23xxx; replaces the line above) |
| `ssh` | `stacks/ssh.yml` | `ssh-web-dev` (OpenSSH) |
| `db` | `stacks/db.yml` | `postgres-orders-dev`, `mysql-orders-dev` (TLS, seeded `orders`); *once*: `db-tls`, `db-secrets-init`, `db-bootstrap` (profile `tools`; creates the roles the policy names) |
| `redis` | `stacks/redis.yml` | `redis-cache-dev`, `valkey-cache-dev` (ACL users) |
| `mongo` | `stacks/mongo.yml` | `mongo-catalog-dev` (MongoDB 8: TLS, SCRAM, X.509; seeded `orders`, `billing`); *once*: `mongo-tls`, `mongo-creds` |
| `search` | `stacks/search.yml` | `elasticsearch-search-dev` (8, security on), `opensearch-search-dev` (2, security plugin, TLS with its demo certificate); *once*: `search-ca-dir` |
| `messaging` | `stacks/messaging.yml` | `rabbitmq-messaging-dev` (4), `kafka-{1,2,3}-messaging-dev` (three-broker 3.9, KRaft, SASL, authorizer on) |
| `kube` | `stacks/kube.yml` | `kubernetes-dev` (k3s in a privileged container, removed by `down -v`), `limen-kube-worker` (serves it as `eks-staging`); works with single and scaled Limen |
| `tcp` | `stacks/tcp.yml` | `tcp-target-dev` (echo fixture) |
| `web` | `stacks/web.yml` + the single/scale worker opt-in overlay | `web-target-dev` (HTTP fixture for browser SSO, request policy, audit) |
| `observability` | `stacks/observability.yml` | `datadog-fake-dev` (receives the audit events), `trino-dev` + `trino-init-dev` (SQL over the S3 batches, as Athena does), `grafana-dev` (http://localhost:3000) |
| `tracing` | `stacks/tracing.yml` | `jaeger-dev` (http://localhost:16686, memory storage); components export via `LIMEN_OTLP_ENDPOINT` |
| `bots` | `stacks/bots.yml` | `ci-issuer-fake-dev`; the control plane trusts its plain-http issuer |

Limen itself isn't an environment (one deployment reaches all of them), so its containers have plain names. Stand-in targets carry the environment they represent, `-dev` here. A second copy beside the dev stack (scaled, or a demo) uses its own environment name: `limen-proxy-scale`, `postgres-orders-dbdemo`. `limen-*` images are built from this repository (`deploy/docker/Dockerfile`); others take their version from `.env`.

```sh
deploy/compose/setup.sh --yes                     # limen + every stack, no questions
deploy/compose/setup.sh --stacks ssh,redis        # limen + SSH + Redis
deploy/compose/setup.sh --scale --stacks ssh,db   # scaled limen + SSH + databases
deploy/compose/setup.sh status
deploy/compose/setup.sh down                      # removes volumes too (add --scale for the scaled one)
```

The demos in `demos/` share `scripts/lib.sh`. The Phase 5, 6, 7, 9, 10 and 11 demos run their own project, images and host ports (`LIMEN_PROJECT`, `LIMEN_IMAGE_TAG`, `LIMEN_PORT_*`; see `docker-compose.yml`), so each runs beside the dev stack. Each demo checks its phase's exit criteria ([design §13](../../docs/design.md#13-phases-and-exit-criteria)).

## SSH

```sh
demos/demo-phase2.sh          # end to end with OpenSSH, including a control plane outage
demos/demo-phase3.sh          # audit to S3 and Datadog, sink outage, tamper check, Grafana
demos/demo-phase35.sh         # web console, locking a user, ending a session
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
asciinema play recordings/<session-id>.cast   # needs asciinema 3.x
```

Audit events are in `proxy:/var/lib/limen/proxy/audit/proxy.jsonl` (`session.start`, `session.end`, `auth.denied`) and `worker:/var/lib/limen/worker/audit/worker.jsonl` (`ssh.exec`).

## Databases

`stacks/db.yml` (profile `db`) has PostgreSQL 18 and MySQL 8.4 with TLS, a `limen_admin` login and a seeded `orders` database. Guide: [databases](../../docs/guides/databases.md). Runbook: [onboarding](../../docs/runbooks/database-onboarding.md).

```sh
demos/demo-phase6.sh          # psql and mysql through `limen db connect`, bootstrap, audit, cancel, lock
db=(-f deploy/compose/docker-compose.yml -f deploy/compose/stacks/db.yml --profile db)
docker compose "${db[@]}" up -d postgres-target mysql-target db-secrets-init
docker compose "${db[@]}" --profile tools run --rm db-bootstrap --db-bootstrap-once   # create the limen_* roles
```

The demo's project is `limen-dbdemo`. Roles and resources come from `examples/policy`; the worker reads role passwords from the `db-secrets` volume and verifies databases against the `db-tls` CA.

For the relay's integration tests (they print SKIPPED without these), extract the CA from the `db-tls` volume and point the tests at the targets:

```sh
docker run --rm -v limen-db_db-tls:/tls alpine cat /tls/ca.pem > /tmp/limen-db-ca.pem   # volume: <project>_db-tls
export LIMEN_TEST_PG_CA_FILE=/tmp/limen-db-ca.pem
export LIMEN_TEST_PG_TARGET=localhost:5433        # host:port of postgres-target as your machine reaches it
export LIMEN_TEST_MYSQL_TARGET=localhost:3307     # host:port of mysql-target
cargo test -p limen-worker --test db_pg --test db_bootstrap --test db_mysql
cargo test -p limen-e2e --test phase6             # also needs LIMEN_TEST_DATABASE_URL
```

The targets publish no host ports. On OrbStack use `<project>-postgres-target-1.orb.local:5432`, or add `ports:` in an override file.

## Things to try

```sh
# Enroll another worker with a single-use token (as admin):
TOKEN=$(limen admin token create --kind worker --label pool=demo)
docker compose -f deploy/compose/docker-compose.yml run -d -e LIMEN_JOIN_TOKEN=$TOKEN \
  -e LIMEN_DATA_DIR=/var/lib/limen/worker-2 worker
# Reusing the token fails: "invalid, expired, or already used join token".

# A named worker: the token approves the name (exact, or a pattern with one *); the worker asks with LIMEN_NAME.
TOKEN=$(limen admin token create --kind worker --label pool=demo --name 'demo-worker-*')
docker compose -f deploy/compose/docker-compose.yml run -d -e LIMEN_JOIN_TOKEN=$TOKEN \
  -e LIMEN_NAME=demo-worker-1 -e LIMEN_DATA_DIR=/var/lib/limen/worker-3 worker
limen admin components   # the name column; the console shows it beside the id

# Kill the proxy and watch workers reconnect with backoff and jitter:
docker compose -f deploy/compose/docker-compose.yml restart proxy
curl -s localhost:3444/tunnels

# Read the control plane's audit file:
docker compose -f deploy/compose/docker-compose.yml cp \
  control-plane:/var/lib/limen/audit/control-plane.jsonl - | tar -xO | tail -5
```

## Integration tests

```sh
docker compose -f deploy/compose/docker-compose.yml up -d postgres kms
export LIMEN_TEST_DATABASE_URL=postgres://limen:limen-dev-only@localhost:5432/limen
export LIMEN_TEST_KMS_ENDPOINT=http://localhost:8099
cargo test --workspace --all-features
```

Each test creates its own database named `limen_test_*` or `limen_e2e_*`. Drop them whenever, or reset everything with `docker compose ... down -v`.

## Web console

`https://localhost:3443/console/`, served by the proxy. Sign in through Dex as `admin@example.com` (admin) or `developer@example.com` (own resources and sessions only). The certificate warning and dev CA are covered in the [README quickstart](../../README.md#quickstart). `demos/demo-phase35.sh` logs in with curl, locks and unlocks a user, ends a live session and checks recording playback. The console's OIDC client (`limen-console`) and its dev secret are in `config/dex/config.yaml` and `docker-compose.yml`.

## Scale-out

`stacks/scale.yml` is a separate compose project, `limen-scale`, with its own volumes and host ports, so it runs beside the dev stack:

```sh
docker compose --project-directory deploy/compose -f deploy/compose/stacks/scale.yml up -d --build
demos/demo-phase5.sh          # resets the scale stack, runs the exit test, stops it
demos/demo-phase5.sh --keep   # reuse the running scale stack and leave it up
```

Behaviour (identity, spool modes, connection age, worker load and drain, names, the shared CA) is in the [scale-out guide](../../docs/guides/scale-out.md). In this stack:

- `control-plane-0/-1/-2` share one PostgreSQL and the network alias `control-plane`. Spool modes: `-1` `durable`, `-0` and `-2` `ephemeral` (override with `LIMEN_SCALE_SPOOL_MODE_0/1/2`). `stop_grace_period` (40 s) exceeds the drain timeout (20 s), so `docker compose stop` drains and hands off.
- `proxy-0/-1/-2` (alias `proxy`) and `worker-0/-1/-2` dial `proxy` and land on any of them. They enroll with the dev stack's multi-use static tokens, which here also approve the names `proxy-N` and `worker-N` (`LIMEN_STATIC_JOIN_TOKENS`).
- Timers are shorter for speed: connection age 60 s (`LIMEN_SCALE_MAX_CONNECTION_AGE_SECS`, 0 disables) and worker drain 20 s. The per-worker session cap and drain are exercised by `crates/limen-e2e/tests/scale.rs`, not `demo-phase5.sh`.
- File-backed CA keys live on one volume (`cp-ca`) every replica mounts; there is no KMS.
- SeaweedFS, PostgreSQL and Dex (same config, rewritten for these ports). Targets come from their stacks (`setup.sh --scale`).

Host ports (127.0.0.1): proxies `23443` / `23453` / `23463` (admin `23444` / `23454` / `23464`), control plane admin `23081` / `23082` / `23083`, Dex `25556`, S3 `28333`. To use the CLI against it:

```sh
docker compose -p limen-scale cp control-plane-0:/var/lib/limen/ca-public/internal-ca.pem deploy/compose/.state/scale/internal-ca.pem
LIMEN_PROXY=localhost:23443 LIMEN_DEV_CA=deploy/compose/.state/scale/internal-ca.pem \
  LIMEN_DEX_URL=http://localhost:25556 deploy/compose/scripts/dev-login.sh developer@example.com
```

`demo-phase5.sh` starts `control-plane-1` first, and the proxies while it is the only replica, so all traffic lands on it. It opens a long SSH session and then new ones in sequence, and meanwhile:

1. SIGKILLs `control-plane-1` (durable) while it holds acked, unshipped events, and restarts it: its spool ships from the same volume.
2. Stops S3, waits until an ephemeral replica holds events it can't ship, and SIGTERMs it: it drains what it can and hands the rest to a live peer (`handed the rest of the audit spool to a peer` in its log). S3 returns and the replica restarts.
3. SIGTERMs the other ephemeral replica (a plain drain) and restarts it.

It asserts that the long session outlasted all this without a stall, every new session worked, `limen-audit-verify` finds every chain intact with no producer sequence gap, there is one chain per replica id, and S3 holds exactly one `ssh.exec`, `session.start` and `session.end` per session. It never SIGKILLs an ephemeral replica: that loses acked but unshipped events (ADR-0020), which the verifier would report as a gap. `LIMEN_SCALE_PROXY_LOG` sets the proxies' `RUST_LOG` (such as `info,h2=debug`).

**If an image build looks stale.** The Dockerfile keeps Cargo's `target` directory in a BuildKit cache shared by every checkout and worktree on the machine, and Cargo decides what to rebuild from file times. Building two branches in turn can link old code into the new image (a build fails, or a fix has no effect). Rebuild with `--no-cache` or run `docker builder prune`.

## Redis and Valkey

The demo runs its own project (`limen-redis`, ports proxy 33443/33444, Dex 35556, control plane health 33081, S3 38333). The stack adds Redis 7.4 and Valkey 8.0 targets with the ACL in `config/targets/redis/users.acl`, and gives the worker the matching passwords from `config/targets/redis/credentials.json` (dev only). `demos/demo-phase7.sh` builds and starts it, seeds keys, and checks the exit criteria with `redis-cli` (or `config/targets/redis/resp-client.py` without it). Stop it with `docker compose -p limen-redis down -v`.

`demos/demo-phase7.sh --scenarios` runs 26 more scenarios on the same stack plus a TLS-only Redis: RESP3, 20 MiB values, 60,000-command pipelines, refusals inside pipelines and `MULTI`, Pub/Sub, key-limit escapes, malformed input, 16 parallel sessions, a target dying mid-session, locking a user, a control plane outage with audit catching up, unix sockets, the idle timeout, and secrets in logs and audit. Name scenarios after `--scenarios` to run only those matching; `--down` removes the stack afterwards. `LIMEN_REDIS_PROJECT` and the `LIMEN_REDIS_*_PORT` variables run another copy beside it.

## MongoDB

`stacks/mongo.yml` (profile `mongo`) adds a MongoDB 8 target with TLS from a throwaway CA, SCRAM-SHA-256/SHA-1 and X.509, seeded by `config/targets/mongo/init.js` with `orders` and `billing`, the users `read` and `write`, and an X.509 user for the worker's client certificate. `gen-tls.sh` makes the certificates and `worker-creds.sh` gives the worker only what it needs (the CA, a password file per role and the client certificate, in the `mongo-worker` volume mounted at `/etc/limen/mongo`); the server's key stays in its own volume. Try it: `deploy/compose/setup.sh --stacks mongo`, then `limen mongo connect catalog-staging`.

```sh
demos/demo-phase9.sh          # mongosh through `limen mongo connect`: SCRAM, X.509, refusals, redacted audit, console list, lock
```

The demo needs `mongosh` on the PATH (mise installs it) and runs project `limen-mongo` on ports 37xxx. CI and the tests use the same server: `scripts/ci-db-targets.sh start` starts it beside PostgreSQL and MySQL on `127.0.0.1:17017` and exports `LIMEN_TEST_MONGO_TARGET`, `LIMEN_TEST_MONGO_CA_FILE` and `LIMEN_TEST_MONGO_CLIENT_PEM`.

## Search

`stacks/search.yml` (profile `search`) adds real **Elasticsearch 8** (security on, plain HTTP) and **OpenSearch 2** (security plugin on, TLS with the image's demo certificate, verified in full through the `node-0.example.com` alias). `config/targets/search/provision.sh` (run by `setup.sh search`) creates the engine roles (`limen_read` on `app-*` and `logs-*`; `limen_write` on `app-*`) and the users that `config/targets/search/credentials.json` gives the worker. The engines publish no host port.

```sh
demos/demo-phase10.sh         # curl through `limen search connect`: refusals, bulk, engine second layer, TLS to OpenSearch, lock, audit, console
```

The demo runs project `limen-search` on ports 34xxx. It pulls about 2.4 GB of images, the engines take a minute or two to start, and it isn't run in CI. Amazon OpenSearch Service, OpenSearch Serverless and Elastic Cloud are **unverified**.

## Messaging

`stacks/messaging.yml` (profile `messaging`) adds real **RabbitMQ 4** (two users and three vhosts from a definitions file) and a **three-broker Kafka 3.9 cluster** (KRaft, SASL `PLAIN` plus SCRAM, authorizer on). `config/targets/messaging/provision.sh` creates topics, ACLs and SCRAM users; the worker holds the broker logins (`config/targets/messaging/credentials.json`). Kafka tells clients to reach brokers at `kafka-N:9092`, which exists only on the Docker network; through Limen they use the loopback listeners `limen kafka connect` opens, which the demo proves.

```sh
deploy/compose/setup.sh --stacks messaging
limen mq connect events-rabbit-staging         # an amqp:// URL with no real password
limen kafka connect events-kafka-staging       # prints a bootstrap address
demos/demo-phase11.sh         # pika and librdkafka: refusals, a consumer group across brokers, a broker down, audit, one console row per run
```

The demo runs project `limen-messaging` on ports 39xxx and needs `python3` (it installs `pika` and `confluent-kafka` into a virtualenv under `.state/`). The first image build takes several minutes, and it isn't run in CI. Amazon MQ, Amazon MSK and `AWS_MSK_IAM` are **unverified**.

## Kubernetes

`deploy/compose/setup.sh --stacks kube` adds a k3s cluster and a Kubernetes worker (`stacks/kube.yml`) and prints how to use `kubectl` through Limen. See the [Kubernetes guide](../../docs/guides/kubernetes.md).
