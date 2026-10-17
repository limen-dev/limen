<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo.svg" alt="Limen" width="320">
  </picture>
</p>

<p align="center"><b>Identity-aware access to your infrastructure. Short-lived, audited, self-hosted.</b></p>

<p align="center">
  <a href="https://github.com/jfcmartins/limen/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/jfcmartins/limen/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-14B8A6"></a>
  <img alt="Written in Rust" src="https://img.shields.io/badge/written%20in-Rust-DEA584?logo=rust&logoColor=white">
  <a href="https://github.com/jfcmartins/limen/milestones"><img alt="Roadmap" src="https://img.shields.io/badge/roadmap-milestones-5319e7"></a>
</p>

# Limen

Limen is a self-hosted, open-source platform for identity-aware access to infrastructure. Engineers, and the bots that act for them, log in through their identity provider and get short-lived, audited access to SSH hosts, databases, caches, search and message brokers, Kubernetes, and internal web apps. There are no static SSH keys, shared database passwords, or hand-made users.

## What it connects to

<table>
  <tr>
    <td align="center" valign="top" width="25%"><br><img src="assets/icons/terminal.svg" height="48" alt="SSH"><br><br><b>SSH</b><br><sub>EC2 and any SSH host<br>per-session certificates, recorded</sub><br><sub>✅ Working</sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/postgresql" height="48" alt="PostgreSQL"><br><br><b>PostgreSQL</b><br><sub>RDS · Aurora · Amazon Redshift<br>IAM auth, every statement audited</sub><br><sub>✅ Working (IAM and Redshift unverified on AWS)</sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/mysql" height="48" alt="MySQL"><br><br><b>MySQL</b><br><sub>RDS · Aurora<br>IAM auth, every statement audited</sub><br><sub>✅ Working (IAM unverified on AWS)</sub><br><br></td>
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
    <td align="center" valign="top" width="25%"><br><img src="assets/icons/bot.svg" height="48" alt="Bots and automation"><br><br><b>Bots and automation</b><br><sub>CI jobs as audited principals<br>no long-lived secrets</sub><br><sub>✅ Working<br>⚠️ tested with a stand-in issuer</sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/githubactions" height="48" alt="GitHub Actions"><br><br><b>GitHub Actions</b><br><sub>OIDC tokens become bot logins</sub><br><sub>✅ Working with a stand-in<br>⚠️ not yet with real tokens</sub><br><br></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/gitlab" height="48" alt="GitLab CI"><br><br><b>GitLab CI</b><br><sub>ID tokens become bot logins</sub><br><sub>✅ Working with a stand-in<br>⚠️ not yet with real tokens</sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="assets/icons/key-round.svg" height="48" alt="AWS IAM and Kubernetes"><br><br><b>AWS IAM and Kubernetes</b><br><sub>workload identity for bots<br>Kubernetes tokens via generic OIDC</sub><br><sub>⏳ AWS IAM: <a href="https://github.com/jfcmartins/limen/milestone/16">Phase 13</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><picture><source media="(prefers-color-scheme: dark)" srcset="https://cdn.simpleicons.org/datadog/white"><img src="https://cdn.simpleicons.org/datadog" height="48" alt="Datadog"></picture><br><br><b>Datadog</b><br><sub>logs and monitors as Terraform</sub><br><sub>✅ Working (fake intake)</sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/grafana" height="48" alt="Grafana"><br><br><b>Grafana</b><br><sub>optional dashboards over S3 and Athena</sub><br><sub>✅ Working (Trino locally)</sub><br><br></td>
  </tr>
</table>

## Where it runs

<table>
  <tr>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/kubernetes" height="48" alt="Kubernetes"><br><br><b>Kubernetes</b><br><sub>StatefulSet or Deployment</sub><br><sub>scale-out example, unverified on a cluster<br>EKS: ⏳ <a href="https://github.com/jfcmartins/limen/milestone/11">Phase 8</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="assets/icons/hard-drive.svg" height="48" alt="Amazon ECS and EC2"><br><br><b>Amazon ECS and EC2</b><br><sub>Fargate tasks or an Auto Scaling group</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/16">Phase 13</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/terraform" height="48" alt="Terraform"><br><br><b>Terraform</b><br><sub>audit store and monitors today</sub><br><sub>✅ Working (audit module)</sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/docker" height="48" alt="Docker Compose"><br><br><b>Docker Compose</b><br><sub>the full local stack</sub><br><sub>✅ Working</sub><br><br></td>
  </tr>
</table>

## Two ways in: the console and the CLI

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

**Guides:** [using the console](docs/guides/console.md) · [using the CLI](docs/guides/cli.md)

Behind both: short-lived certificates instead of keys and passwords, deny-by-default YAML policy, an audit trail that cannot silently lose events (S3 with a signed hash chain, Datadog, Grafana), and reverse tunnels so targets never need an open inbound port.

## Quickstart

You need Docker (OrbStack on macOS) and the Rust toolchain from `mise.toml`. Everything below runs on your machine against local stand-ins.

```sh
# 1. Start the stack: control plane, proxy, worker, Postgres, Dex (the identity provider), a test SSH host
docker compose -f deploy/compose/docker-compose.yml up -d --build

# 2. Install the CLI (once; re-run after pulling to upgrade) and trust the dev stack's CA
scripts/install-cli.sh
mkdir -p deploy/compose/.state
docker compose -f deploy/compose/docker-compose.yml cp control-plane:/var/lib/limen/ca-public/internal-ca.pem deploy/compose/.state/internal-ca.pem

# 3. Sign in as the dev admin, admin@example.com (password: "password"), then load the example policy
limen --proxy localhost:3443 login --ca-file deploy/compose/.state/internal-ca.pem   # opens your browser on Dex
limen admin apply examples/policy
limen login                                       # roles are fixed at login: sign in again to pick them up

# 4. Use it
limen ls                                          # what can I reach?
limen ssh web-staging-1                           # a recorded SSH session
# databases: see docs/guides/databases.md, or run deploy/compose/demo-phase6.sh

# 5. Open the console in your browser (sign in with the same user)
open https://localhost:3443/console/              # macOS; elsewhere just paste the URL
```

> [!NOTE]
> The proxy's certificate comes from the Limen dev CA, so a browser warns about it. That is expected here. Don't add the CA to your system trust store; click through the warning on localhost, or use `curl --cacert deploy/compose/.state/internal-ca.pem`. The dev users and their passwords are in [`deploy/compose/README.md`](deploy/compose/README.md).

## Roadmap

The roadmap lives in [GitHub milestones](https://github.com/jfcmartins/limen/milestones): one per phase, with the checklist in its epic issue and the exit criteria in its description. [`docs/design.md`](docs/design.md#13-phases-and-exit-criteria) holds the technical definition of "done" ([ADR-0023](docs/adr/0023-roadmap-in-github.md)).

| Phase | What | Status |
|---|---|---|
| 0 – 3.5 | Foundations, control plane, SSH, audit pipeline, web console | ✅ Done: [0](https://github.com/jfcmartins/limen/milestone/1), [1](https://github.com/jfcmartins/limen/milestone/2), [2](https://github.com/jfcmartins/limen/milestone/3), [3](https://github.com/jfcmartins/limen/milestone/4), [3.5](https://github.com/jfcmartins/limen/milestone/5) |
| 4 | Machine identities (bots) | ✅ [milestone](https://github.com/jfcmartins/limen/milestone/6) |
| 5 | Scale-out: many control planes, proxies, workers | ✅ [milestone](https://github.com/jfcmartins/limen/milestone/7) |
| 6 | PostgreSQL, MySQL, Aurora, Redshift | ✅ [milestone](https://github.com/jfcmartins/limen/milestone/9) (IAM and Redshift unverified on AWS) |
| 6.5 | Access requests and approvals, audit and recording search, resource discovery, policy tooling, access reviews | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/18) |
| 7 | Redis and Valkey | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/10) |
| 8 | Kubernetes (EKS) | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/11) |
| 9 | MongoDB, Atlas, DocumentDB | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/12) |
| 10 | OpenSearch and Elasticsearch | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/13) |
| 11 | RabbitMQ and Kafka | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/14) |
| 12 | Internal web apps and TCP services | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/15) |
| 13 | Hardening and production readiness | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/16) |
| Docs | Documentation site and homepage | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/8) |

## Why "Limen"
Limen is Latin for "threshold", the root of the English word *liminal*. A threshold is the point you cross once you are allowed in. That is what Limen does: you prove who you are through your identity provider, Limen lets you across into infrastructure for a short, audited window, and then closes the door behind you.

The name is short enough to type as a command (`limen login`, `limen ssh`). Both "LIE-men" and "LEE-men" are in common use.

## Documentation
- [Using the console](docs/guides/console.md), [using the CLI](docs/guides/cli.md), [databases](docs/guides/databases.md), and [bots for CI](docs/guides/bots.md)
- [The three server programs](docs/components.md): what the control plane, proxy and worker each do
- [Design](docs/design.md): architecture, data paths, failure semantics
- [ADRs](docs/adr/README.md): key decisions and their trade-offs
- [Threat model](docs/threat-model.md)
- [Policy reference](docs/policy.md)
- [Runbooks](docs/runbooks/README.md)
- A public documentation site and homepage are planned ([ADR-0021](docs/adr/0021-docs-site-and-homepage.md))

## Contributing and development
See [CONTRIBUTING.md](CONTRIBUTING.md) for the repository layout, how to build and test, and the conventions. Coding agents: [AGENTS.md](AGENTS.md).

## License
[Apache-2.0](LICENSE). Icons are from [Simple Icons](https://simpleicons.org) (CC0) and [Lucide](https://lucide.dev) (ISC). Product names and logos belong to their owners and appear here only to say what Limen works with.
