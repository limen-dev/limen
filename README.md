<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo.svg" alt="Limen" width="320">
  </picture>
</p>

<p align="center"><b>Identity-aware access to your infrastructure. Short-lived, audited, self-hosted.</b></p>

<p align="center">
  <a href="https://github.com/jfcmartins/limen/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/jfcmartins/limen/ci.yml?branch=main&label=CI&logo=githubactions&logoColor=white"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-14B8A6"></a>
  <img alt="Written in Rust" src="https://img.shields.io/badge/written%20in-Rust-DEA584?logo=rust&logoColor=white">
  <a href="https://github.com/jfcmartins/limen/milestones"><img alt="Roadmap" src="https://img.shields.io/badge/roadmap-milestones-5319e7"></a>
</p>

# Limen

Limen is a self-hosted, open-source platform for identity-aware access to infrastructure. Engineers, and the bots that act for them, log in through their identity provider and get short-lived, audited access to SSH hosts, databases, caches, search and message brokers, Kubernetes, and internal web apps. There are no static SSH keys, shared database passwords, or hand-made users.

> **Status: Phase 3.5 complete.** OIDC login, policy, proxies with peering, workers, SSH with session recording, the audit pipeline (S3, Datadog, Grafana), and a web console work end to end against local stand-ins. Everything else below is planned: see the [roadmap](#roadmap).

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/console-overview-dark.jpg">
    <img src="docs/images/console-overview-light.jpg" alt="The Limen web console, showing resources, sessions, and workers" width="860">
  </picture>
</p>

Try it locally: [`deploy/compose/README.md`](deploy/compose/README.md), or run `deploy/compose/demo-phase2.sh` (SSH), `deploy/compose/demo-phase3.sh` (audit pipeline and dashboards), or `deploy/compose/demo-phase35.sh` (web console, locks, session kill).

## Features

<table>
  <tr>
    <td width="50%" valign="top">
      <h3>🖥️ Web console</h3>
      <ul>
        <li><b>Resources:</b> everything Limen can reach, searchable, with who has access and whether a worker can serve it</li>
        <li><b>Sessions:</b> live and past, with <b>in-browser replay</b> of SSH recordings and one-click <b>end session</b></li>
        <li><b>Users:</b> who signed in, their roles, <b>lock and unlock</b> with a reason</li>
        <li><b>Workers:</b> enrolled components, <b>join tokens</b>, <b>revoke</b></li>
        <li><b>Policy:</b> the active YAML and a <b>dry-run diff</b> before you apply</li>
        <li>Light and dark themes, SSO sign-in, CSRF and CSP hardening</li>
        <li>People only see their own resources and sessions</li>
      </ul>
    </td>
    <td width="50%" valign="top">
      <h3>⌨️ Command line</h3>
      <ul>
        <li><b><code>limen login</code></b> through your identity provider (browser or device code), credentials last minutes</li>
        <li><b><code>limen ls</code></b> shows exactly what you can reach, as a table or JSON</li>
        <li><b><code>limen ssh</code></b> opens recorded SSH sessions; plain <code>ssh</code> works too through <code>limen config ssh</code></li>
        <li><b><code>limen admin</code></b> applies policy, creates join tokens, locks users, ends sessions, revokes workers</li>
        <li>Colour, glyphs, and a spinner on a terminal; plain text when piped or with <code>NO_COLOR</code></li>
        <li>Helpful errors that say what to do next</li>
      </ul>
    </td>
  </tr>
</table>

Behind both: short-lived certificates instead of keys and passwords, deny-by-default YAML policy, an audit trail that cannot silently lose events (S3 with a signed hash chain, Datadog, Grafana), and reverse tunnels so targets never need an open inbound port.

## Quickstart

You need Docker (OrbStack on macOS) and the Rust toolchain from `mise.toml`. Everything below runs on your machine against local stand-ins.

```sh
# 1. Start the stack: control plane, proxy, worker, Postgres, Dex (the identity provider), a test SSH host
docker compose -f deploy/compose/docker-compose.yml up -d --build

# 2. Build the CLI and trust the dev stack's CA once
cargo build --release -p limen-cli && export PATH="$PWD/target/release:$PATH"
mkdir -p deploy/compose/.state
docker compose -f deploy/compose/docker-compose.yml cp control-plane:/var/lib/limen/ca-public/internal-ca.pem deploy/compose/.state/internal-ca.pem

# 3. Sign in as the dev admin, admin@example.com (password: "password"), then load the example policy
limen --proxy localhost:3443 login --ca-file deploy/compose/.state/internal-ca.pem   # opens your browser on Dex
limen admin apply examples/policy
limen login                                       # roles are fixed at login: sign in again to pick them up

# 4. Use it
limen ls                                          # what can I reach?
limen ssh web-staging-1                           # a recorded SSH session

# 5. Open the console in your browser (sign in with the same user)
open https://localhost:3443/console/              # macOS; elsewhere just paste the URL
```

> [!NOTE]
> The proxy's certificate comes from the Limen dev CA, so a browser warns about it. That is expected here. Don't add the CA to your system trust store; click through the warning on localhost, or use `curl --cacert deploy/compose/.state/internal-ca.pem`. The dev users and their passwords are in [`deploy/compose/README.md`](deploy/compose/README.md). Want it scripted instead? `deploy/compose/demo-phase35.sh` does all of this, including the console, and checks the results.

## Using the console

Open **`https://<your proxy>/console/`** (locally `https://localhost:3443/console/`) and choose *Continue with single sign-on*. You sign in with the same identity provider as the CLI. What you see depends on your roles.

| Page | What you can do | Who |
|---|---|---|
| **Overview** | See your identity and roles, what you can reach (with a copy-paste `limen ssh` command), and recent sessions. Admins also get live counts: active sessions, users, locks, workers, policy version | everyone |
| **Resources** | Search and filter by kind. Open a resource to see its labels and, for admins, its target, **which roles grant access**, **which live workers can serve it** (a red *none* means sessions will fail), and its sessions | everyone sees their own; admins see all |
| **Sessions** | Browse live and past sessions. Open one to **replay the recording** (the control plane verifies its hash first) and, as an admin, **end it** with a reason | everyone sees their own; admins see all |
| **Users** | See who has signed in and their roles. **Lock** a user (they are signed out, can't log in, and their open sessions end within seconds) or **unlock** them, always with an audited reason | admins |
| **Workers** | See enrolled proxies and workers and their tunnels. **Create single-use join tokens** (shown once) and **revoke** a component | admins |
| **Policy** | Browse roles, mappings, and resources as the YAML behind them, and **check a change**: paste YAML, see the diff, nothing is applied | admins |

A few things worth knowing:
- **Policy stays in Git.** The console shows and checks policy but doesn't edit it. Apply with `limen admin apply`.
- **Everything you change is audited** as you, marked as coming from the console.
- **Switch theme** with the sun/moon buttons at the bottom of the sidebar (it follows your system by default).
- **Sessions last as long as your login certificate** (10 minutes by default). Sign in again when it ends.
- Setup for your own deployment (OIDC client, public URL): [`docs/runbooks/console.md`](docs/runbooks/console.md).

## Using the CLI

```sh
limen login                  # sign in (opens a browser). On a machine without one: limen login --device
limen status                 # who am I, which roles, when does it expire?
limen ls                     # what can I reach?   add --json for scripts
limen ssh web-staging-1      # connect; the login is picked from policy when there's only one
limen ssh ubuntu@web-staging-1 -- uptime   # explicit login, run a command
limen logout                 # delete local credentials
```

What `limen ls` looks like:

```text
NAME             KIND        ACCESS AS                 LABELS
bastion-staging  ● ssh       ec2-user, ubuntu          env=staging tier=bastion
orders-staging   ● postgres  limen_readonly, limen_rw  env=staging team=payments
web-staging-1    ● ssh       ec2-user, ubuntu          env=staging
  3 resources · connect with `limen ssh <name>`
```

<details>
<summary><b>All commands</b></summary>

| Command | What it does |
|---|---|
| `limen login [--device] [--no-browser] [--ca-file PEM]` | Sign in through the identity provider and get short-lived credentials. `--ca-file` pins the proxy's CA for later commands |
| `limen logout` | Delete the local credentials |
| `limen status` | Show your identity, roles, and the time left on your credentials |
| `limen ls [--json]` | List the resources you can access |
| `limen ssh [login@]resource [command…]` | Open an SSH session through Limen (recorded and audited) |
| `limen config ssh` | Print an `~/.ssh/config` block so plain `ssh <login>@web-staging-1.limen` works |
| `limen admin apply <files or dirs> [--dry-run] [--source-ref SHA]` | Validate and apply policy YAML; shows a coloured diff |
| `limen admin policy` | Show the active policy version, digest, and author |
| `limen admin components` | List enrolled proxies and workers and their tunnels |
| `limen admin token create [--kind worker\|proxy] [--label k=v] [--ttl 15m]` | Create a single-use join token |
| `limen admin lock <user> --reason …` / `unlock <user>` / `locks` | Lock or unlock a user; list locks |
| `limen admin kill-session <id> --reason …` | End one live session |
| `limen admin revoke <component> --reason …` | Stop honouring a proxy's or worker's certificate |
| `limen db`, `limen redis`, `limen kube` | Planned ([roadmap](#roadmap)); they say so when run |

Global options: `--proxy HOST:PORT` (or `LIMEN_PROXY`; remembered after the first login), `--color auto|always|never`, `--help`, `--version`.
</details>

**Good to know**
- **Credentials are short-lived on purpose.** They live in `~/.limen/` (override with `LIMEN_HOME`) and expire in minutes. When they do, the CLI tells you to run `limen login`.
- **Plain `ssh` works too.** Run `limen config ssh >> ~/.ssh/config`, then `ssh <login>@<resource>.limen`.
- **Scripting.** Output is plain text when piped; `limen ls --json` is stable for tools; `NO_COLOR=1` or `--color never` turns colour off everywhere.
- **Admin commands need the `limen:admin` role** and are audited like everything else.

## What it connects to

<table>
  <tr>
    <td align="center" valign="top" width="25%"><br><img src="assets/icons/terminal.svg" height="48" alt="SSH"><br><br><b>SSH</b><br><sub>EC2 and any SSH host<br>per-session certificates, recorded</sub><br><sub>✅ Working</sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/postgresql" height="48" alt="PostgreSQL"><br><br><b>PostgreSQL</b><br><sub>RDS · Aurora · Amazon Redshift<br>IAM auth, every statement audited</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/9">Phase 6</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/mysql" height="48" alt="MySQL"><br><br><b>MySQL</b><br><sub>RDS · Aurora<br>IAM auth, every statement audited</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/9">Phase 6</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/redis" height="48" alt="Redis / Valkey"><br><br><b>Redis / Valkey</b><br><sub>ElastiCache<br>values redacted in audit</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/10">Phase 7</a></sub><br><br></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/kubernetes" height="48" alt="Kubernetes"><br><br><b>Kubernetes</b><br><sub>Amazon EKS<br>impersonation, recorded exec</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/11">Phase 8</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/mongodb" height="48" alt="MongoDB"><br><br><b>MongoDB</b><br><sub>any server · Atlas · DocumentDB<br>SCRAM, X.509, IAM</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/12">Phase 9</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/opensearch" height="48" alt="OpenSearch"><br><br><b>OpenSearch</b><br><sub>Amazon OpenSearch Service<br>index-aware policy</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/13">Phase 10</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><picture><source media="(prefers-color-scheme: dark)" srcset="https://cdn.simpleicons.org/elasticsearch/white"><img src="https://cdn.simpleicons.org/elasticsearch" height="48" alt="Elasticsearch"></picture><br><br><b>Elasticsearch</b><br><sub>self-hosted and Elastic Cloud<br>index-aware policy</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/13">Phase 10</a></sub><br><br></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/rabbitmq" height="48" alt="RabbitMQ"><br><br><b>RabbitMQ</b><br><sub>any broker · Amazon MQ<br>no message bodies in audit</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/14">Phase 11</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><picture><source media="(prefers-color-scheme: dark)" srcset="https://cdn.simpleicons.org/apachekafka/white"><img src="https://cdn.simpleicons.org/apachekafka" height="48" alt="Kafka"></picture><br><br><b>Kafka</b><br><sub>any cluster · Amazon MSK<br>IAM, SCRAM, mTLS</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/14">Phase 11</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="assets/icons/globe.svg" height="48" alt="Internal web apps"><br><br><b>Internal web apps</b><br><sub>SSO in front of any web UI<br>every request audited</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/15">Phase 12</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="assets/icons/network.svg" height="48" alt="TCP services"><br><br><b>TCP services</b><br><sub>anything else, through a local port<br>same policy, same audit</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/15">Phase 12</a></sub><br><br></td>
  </tr>
</table>

Each target works with the managed AWS service **and** any compatible self-hosted server. ✅ working and tested, ⏳ planned (the link goes to its milestone). Everything is tested against local stand-ins. Nothing has been verified against real AWS, Okta, or Datadog yet.

## Who and what can log in

<table>
  <tr>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/okta" height="48" alt="Okta"><br><br><b>Okta</b><br><sub>OIDC login, groups to roles</sub><br><sub>✅ Tested with Dex<br>⚠️ not yet with Okta</sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/openid" height="48" alt="Any OIDC provider"><br><br><b>Any OIDC provider</b><br><sub>Keycloak, Entra ID, Auth0, Dex</sub><br><sub>✅ Working with Dex</sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="assets/icons/bot.svg" height="48" alt="Bots and automation"><br><br><b>Bots and automation</b><br><sub>CI jobs as audited principals<br>no long-lived secrets</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/6">Phase 4</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/githubactions" height="48" alt="GitHub Actions"><br><br><b>GitHub Actions</b><br><sub>OIDC tokens become bot logins</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/6">Phase 4</a></sub><br><br></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/gitlab" height="48" alt="GitLab CI"><br><br><b>GitLab CI</b><br><sub>ID tokens become bot logins</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/6">Phase 4</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="assets/icons/key-round.svg" height="48" alt="AWS IAM and Kubernetes"><br><br><b>AWS IAM and Kubernetes</b><br><sub>workload identity for bots</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/6">Phase 4</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><picture><source media="(prefers-color-scheme: dark)" srcset="https://cdn.simpleicons.org/datadog/white"><img src="https://cdn.simpleicons.org/datadog" height="48" alt="Datadog"></picture><br><br><b>Datadog</b><br><sub>logs and monitors as Terraform</sub><br><sub>✅ Working (fake intake)</sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/grafana" height="48" alt="Grafana"><br><br><b>Grafana</b><br><sub>audit dashboards over S3 and Athena</sub><br><sub>✅ Working (Trino locally)</sub><br><br></td>
  </tr>
</table>

## Where it runs

<table>
  <tr>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/kubernetes" height="48" alt="Kubernetes"><br><br><b>Kubernetes</b><br><sub>StatefulSet or Deployment</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/7">Phase 5</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="assets/icons/hard-drive.svg" height="48" alt="Amazon ECS and EC2"><br><br><b>Amazon ECS and EC2</b><br><sub>Fargate tasks or an Auto Scaling group</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/7">Phase 5</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/terraform" height="48" alt="Terraform"><br><br><b>Terraform</b><br><sub>audit store and monitors today</sub><br><sub>✅ Working (audit module)</sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/docker" height="48" alt="Docker Compose"><br><br><b>Docker Compose</b><br><sub>the full local stack</sub><br><sub>✅ Working</sub><br><br></td>
  </tr>
</table>

## Roadmap

The roadmap lives in [GitHub milestones](https://github.com/jfcmartins/limen/milestones): one per phase, with the checklist in its epic issue and the exit criteria in its description. [`docs/design.md`](docs/design.md#13-phases-and-exit-criteria) holds the technical definition of "done" ([ADR-0023](docs/adr/0023-roadmap-in-github.md)).

| Phase | What | Status |
|---|---|---|
| 0 – 3.5 | Foundations, control plane, SSH, audit pipeline, web console | ✅ Done: [0](https://github.com/jfcmartins/limen/milestone/1), [1](https://github.com/jfcmartins/limen/milestone/2), [2](https://github.com/jfcmartins/limen/milestone/3), [3](https://github.com/jfcmartins/limen/milestone/4), [3.5](https://github.com/jfcmartins/limen/milestone/5) |
| 4 | Machine identities (bots) | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/6) |
| 5 | Scale-out: many control planes, proxies, workers | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/7) |
| Docs | Documentation site and homepage | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/8) |
| 6 | PostgreSQL, MySQL, Aurora, Redshift | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/9) |
| 7 | Redis and Valkey | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/10) |
| 8 | Kubernetes (EKS) | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/11) |
| 9 | MongoDB, Atlas, DocumentDB | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/12) |
| 10 | OpenSearch and Elasticsearch | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/13) |
| 11 | RabbitMQ and Kafka | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/14) |
| 12 | Internal web apps and TCP services | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/15) |
| 13 | Hardening and production readiness | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/16) |

## Why "Limen"
Limen is Latin for "threshold", the root of the English word *liminal*. A threshold is the point you cross once you are allowed in. That is what Limen does: you prove who you are through your identity provider, Limen lets you across into infrastructure for a short, audited window, and then closes the door behind you.

The name is short enough to type as a command (`limen login`, `limen ssh`). Both "LIE-men" and "LEE-men" are in common use.

## Documentation
- [Design](docs/design.md): architecture, data paths, failure semantics
- [ADRs](docs/adr/README.md): key decisions and their trade-offs
- [Threat model](docs/threat-model.md)
- [Policy reference](docs/policy.md)
- [Runbooks](docs/runbooks/README.md)
- A public documentation site and homepage are planned ([ADR-0021](docs/adr/0021-docs-site-and-homepage.md))

## Repository layout
| Path | Contents |
|---|---|
| `crates/` | Rust workspace: `limen-control-plane`, `limen-proxy`, `limen-worker`, `limen-cli` (binary `limen`), and the libraries they share |
| `proto/` | Protobuf definitions for the control plane API and the worker tunnel |
| `deploy/` | Dockerfiles, docker-compose dev stack, Terraform (audit store, Datadog monitors) |
| `dashboards/` | Grafana dashboards and alert rules, generated for Athena and Trino |
| `docs/` | Design, ADRs, threat model, runbooks |

## Development
Tools are pinned in `mise.toml`: Rust, protoc, cargo-deny, cargo-audit, actionlint, Terraform.

```sh
mise install
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check && cargo audit

# Integration tests need PostgreSQL, a KMS emulator, and an S3-compatible store:
docker compose -f deploy/compose/docker-compose.yml up -d postgres kms s3
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1 \
LIMEN_TEST_S3_ENDPOINT=http://localhost:8333 \
LIMEN_TEST_DATABASE_URL=postgres://limen:limen-dev-only@localhost:5432/limen \
LIMEN_TEST_KMS_ENDPOINT=http://localhost:8099 cargo test --workspace --all-features
```

The local dev stack needs a Docker-compatible runtime. OrbStack is recommended on macOS. To put the CLI on your PATH: `cargo install --locked --path crates/limen-cli`. Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md).

## License
[Apache-2.0](LICENSE). Icons are from [Simple Icons](https://simpleicons.org) (CC0) and [Lucide](https://lucide.dev) (ISC). Product names and logos belong to their owners and appear here only to say what Limen works with.
