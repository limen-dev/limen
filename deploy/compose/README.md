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
# A browser opens on Dex. Log in as alice@example.com / password.

limen admin apply examples/policy      # alice is a bootstrap admin (group limen-admins)
limen login                            # log in again: roles are fixed at login
limen ls
limen admin components                 # the proxy, the worker, and its tunnels
```

### Dev users

| User | Groups | Roles with `examples/policy` |
|---|---|---|
| `alice@example.com` | `limen-admins`, `sre` | `limen:admin`, `sre` |
| `bob@example.com` | `developers` | `dev-readonly` |
| `carol@example.com` | `marketing` | none, so login is denied |

### Logging in without a browser

- `limen login --device` uses the device flow. Open the printed URL anywhere and enter the code.
- `deploy/compose/dev-login.sh bob@example.com` automates Dex's password form. It's for scripts and tests only.

## SSH (Phase 2)

```sh
deploy/compose/demo-phase2.sh          # end to end with OpenSSH, including a control plane outage
```

By hand, after `limen admin apply examples/policy`:

```sh
limen login                                   # as bob@example.com (developers -> dev-readonly)
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
# Enroll another worker with a single-use token (as alice):
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
