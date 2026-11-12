# Roll out Limen to your organisation

This is the order to do things in when you deploy Limen for a team: from an empty AWS account to developers running `limen login --server limen.example.com`. It links to the detailed guides for each step and says how to check that a step worked before you start the next.

**Unverified.** It is assembled from the other guides, the Terraform modules and the Helm chart. Nobody has applied the Terraform or installed the chart on a real cluster yet (issues #80 and #85), and nothing here has been run against a real public CA or a real identity provider. Do the first rollout in a staging environment and correct this page where it is wrong.

## What you end with

- A control plane, one or more proxies behind a public name, and workers next to the things people need to reach.
- Developers who install the CLI and run one command. No certificate files, no keys, no VPN.
- Short-lived access: every login is a certificate that lasts an hour by default (an operator can set a lower or higher ceiling with `--max-cert-ttl`), and every session is in the audit trail.

## Decide four things first

| Decision | Options | Recommendation |
|---|---|---|
| **Where it runs** | Kubernetes (Helm chart) or ECS and EC2 (Terraform) | Kubernetes. It can mount the public certificate, keeps the audit spool on a volume, and has the more complete guide. The ECS/EC2 example cannot mount the certificate yet, so users there must pin the internal CA ([below](#3-the-public-name-and-certificate)). |
| **Identity provider** | Anything that speaks OpenID Connect and puts the user's email and groups in the ID token | Whatever your people already sign in with ([Okta guide](okta.md) as the worked example). |
| **The public name** | For example `limen.example.com` | One name per proxy group. Console and web apps need more names; see step 3. |
| **Who the first admins are** | A group in the identity provider | A small group, for example `limen-admins`. |

## 1. The identity provider

Create the OIDC client for the CLI (a native or public app with PKCE) and, if you want the console, a second web client. The [Okta guide](okta.md) lists exactly what Limen needs: the issuer, the client id, a `groups` claim in the ID token, and a verified email.

**Check:** you have an issuer URL and a client id, and a test user's ID token contains `email`, `email_verified: true` and `groups`.

## 2. The infrastructure and the control plane

Follow [Deploying Limen on AWS](deploy.md): Terraform creates the database, the KMS signing keys, the audit store and the join tokens; the chart or the ECS example installs Limen itself.

Things people miss:
- **Install the control plane first.** It creates the internal CA, which proxies and workers must have before they enroll. The Kubernetes steps in the guide cover publishing it.
- **Name the first admins.** Set `LIMEN_BOOTSTRAP_ADMIN_GROUPS` on the control plane (with the chart: `controlPlanes.<key>.extraEnv`) to the identity-provider group of your first admins, so one of them can log in and apply policy.
- **Keep the admin ports private.** `/metrics` and `/healthz` (3081, 3444, 3090) are unauthenticated.

**Check:** the control plane replicas are ready, and `kubectl -n limen rollout status statefulset/control-plane-core` returns.

## 3. The public name and certificate

Point the proxy's public name at its load balancer. The load balancer must pass TCP through (a Network Load Balancer, not an HTTP one): users present client certificates, and the proxy has to see them.

Then decide how users will trust the proxy. The CLI checks the proxy's certificate before it sends anything, so it has to know who to trust. There are three ways:

| | You do | Developers do | Choose it when |
|---|---|---|---|
| **A. A certificate from a public CA** | Get a certificate for the name (Let's Encrypt, a commercial CA, or an exported ACM certificate) and give it to the proxy | Nothing | You can get a public certificate for the name. **The best default.** |
| **B. A certificate from your company CA** | The same, using your internal CA | Nothing, if IT already puts the company root CA on laptops (the CLI uses the operating system's trust store) | You have a company CA that is already on every laptop |
| **C. No certificate of yours** | Send developers the internal CA file, `internal-ca.pem` (public information, not a secret). On Kubernetes it is the file you published into the `limen-internal-ca` ConfigMap in the [deploy steps](deploy.md#on-kubernetes); on ECS and EC2 it is in the `.../internal-ca` Secrets Manager secret that Terraform fills | `limen login --server limen.example.com --ca-file internal-ca.pem`, once | You cannot get a certificate yet, or you are on the ECS/EC2 example |

Limen never trusts a server automatically the first time it sees it, because that would let anyone on the network in the middle of a first login capture the identity-provider token.

### Giving the proxy its certificate (A and B), with the Helm chart

The chart takes a `kubernetes.io/tls` Secret with the keys `tls.crt` (the chain, leaf first, with any intermediates) and `tls.key`:

```yaml
proxies:
  public:
    dnsNames: limen.example.com
    joinSecret: limen-proxy-public
    publicCertSecret: limen-public-tls
```

With cert-manager the Secret is produced and renewed for you. This is an example, not something tested here:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: limen-public, namespace: limen }
spec:
  secretName: limen-public-tls
  dnsNames: [limen.example.com]
  issuerRef: { name: letsencrypt-dns, kind: ClusterIssuer }
```

Use a DNS-01 challenge (or any issuer that does not need an HTTP endpoint). The proxy listens on one TCP port with no web server on port 80, so an HTTP-01 challenge has nothing to answer it.

The proxy reads the files again every minute, so renewals need no restart. How it behaves when a file is bad, what to alert on, and what to tell existing users are in [the proxy's public certificate](deploy.md#the-proxys-public-certificate). Workers and peer proxies keep using the internal CA and need nothing.

For the console and web apps, the certificate must also cover their names (a wildcard such as `*.apps.example.com`).

**Check, before telling anyone:**
```sh
# The certificate the CLI and browsers will see, and who issued it
openssl s_client -connect limen.example.com:443 -servername limen.example.com -alpn h2 </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```
The issuer should be your public or company CA, not "Limen Internal CA". Then, from a machine that is not yours, `limen doctor --server limen.example.com` should pass the TLS check without any CA file.

## 4. The first admin and policy

Log in as someone in the bootstrap admin group, then check who you are:

```sh
limen login --server limen.example.com
limen status        # your name and roles: limen:admin should be there
```

If `limen status` shows no roles, the ID token has no `groups` claim or nothing matches it; the [Okta guide](okta.md#7-check-it) explains how to look.

Access starts at nothing. Write policy as YAML (roles, a `role_mapping` from identity-provider groups to roles, and the resources) and apply it. `examples/policy/` in the repository has working sets to start from, and the [policy reference](../policy.md) lists the document kinds:

```sh
limen admin apply policy/ --dry-run     # see what would change
limen admin apply policy/ --require-tests
```

Keep the policy in Git and apply it from CI with [a bot](bots.md) or [the management API](management-api.md), so changes are reviewed. [Policy tooling](policy-tooling.md) shows how to test a change before it is applied.

**Check:** `limen policy who-can <resource>` lists the people you expect, and `limen explain <resource>` gives a test user the answer you intended.

## 5. Workers and resources

A worker sits next to what you want to reach (an SSH host, a database, a Kubernetes cluster) and only ever connects **out** to the proxy on 443. With the chart, workers are entries under `workers:`. To add one by hand, the [worker enrollment runbook](../runbooks/worker-enrollment.md) covers single-use tokens.

**Check:**
```sh
limen admin components      # each worker appears, with its tunnels up
```

Then declare the resources and guide each team through theirs: [SSH](../runbooks/ssh-target-onboarding.md), [SQL databases](databases.md), [Kubernetes](kubernetes.md), [web apps](web-apps.md), and the others in the [CLI guide](cli.md). [Discovery](discovery.md) can find resources in AWS for an admin to accept.

## 6. Onboard developers

Developers need the `limen` binary. Releases publish it as a tarball for each platform, `limen-vX.Y.Z-<target>.tar.gz`, with a `SHA256SUMS` file; the targets are Linux (x86_64 and arm64) and macOS (Apple Silicon and Intel). There is no Windows build, no Homebrew tap and no hosted install script yet ([ADR-0024](../adr/0024-release-strategy.md)). Until there is, give them these steps (or put the binary on your own package mirror or device-management system):

```sh
gh release download vX.Y.Z --repo limen-dev/limen --pattern 'limen-*-aarch64-apple-darwin.tar.gz' --pattern SHA256SUMS
shasum -a 256 --check --ignore-missing SHA256SUMS
tar -xzf limen-vX.Y.Z-aarch64-apple-darwin.tar.gz
install limen-vX.Y.Z-aarch64-apple-darwin/limen ~/.local/bin/    # or anywhere on PATH
```

(`scripts/install-cli.sh` builds the CLI from a checkout and needs a Rust toolchain; it is for contributors, not for your developers. The download commands above are untested here, and they need access to the repository while it is private.)

Then send them this:

> ```sh
> limen login --server limen.example.com    # a browser opens on our identity provider
> limen ls                                  # what you can reach
> limen doctor                              # if something is wrong, it says what
> ```

With certificate option C, add `--ca-file internal-ca.pem` to the login and attach the file.

A developer needs nothing else: no keys to create, no certificate files (with option A or B), no extra tools for SSH (`limen config ssh --install` lets plain `ssh`, `scp`, `rsync` and `git` work). The [CLI guide](cli.md) has the rest.

## 7. Run it

- **Alerts.** [Metrics](metrics.md) lists what to watch and `deploy/prometheus/alerts.yml` has the rules, including certificate expiry.
- **Upgrades.** One `helm upgrade` or `terraform apply`, in the right order; read the [upgrading runbook](../runbooks/upgrading.md) first.
- **Leavers and lost devices.** [Offboarding](offboarding.md) and [locking a user](../runbooks/lock-user.md).
- **The audit trail.** [Verify it](../runbooks/audit-verify.md) regularly, and [search it](audit-search.md).

## When something goes wrong

| What you see | Cause | Fix |
|---|---|---|
| `the server's certificate isn't trusted`, first login, no CA file | The proxy shows the internal CA's certificate (option C), or a company-CA certificate on a laptop that does not have the root | Give the proxy a certificate the laptop trusts, or pass `--ca-file` |
| The same, for someone who used Limen before the public certificate | An old pinned CA is checked first, and logout keeps it | `limen login --server limen.example.com --system-roots`, once |
| `BadSignature` or `UnknownIssuer` with a CA pinned, after the stack was rebuilt (dev) | The internal CA changed and the pin is the old one | `limen login --ca-file <the new internal-ca.pem>` |
| `certificate expired` from the server | The proxy's own certificate was not renewed. The proxy log says why, for example `renewal: unknown component (PermissionDenied)` after the database was recreated | Re-enroll the proxy: delete its data directory and start it with a new join token ([runbook](../runbooks/worker-enrollment.md#symptoms-and-fixes)) |
| `certificate in … expired at …` from a worker | It was offline longer than its certificate lasts | Delete its data directory and enroll again with a new token |
| `limen status` shows no roles | No `groups` claim in the ID token, or no `role_mapping` matches | [Okta guide, step 7](okta.md#7-check-it) |
| `no server selected` | `--server` or `LIMEN_SERVER` is missing and there is no earlier login | `limen login --server limen.example.com` |
| `limen audit verify` asks for a CA | It checks signatures against Limen's own CA, never the system's | Pass `--ca-file internal-ca.pem` |

## What has not been checked

- The Terraform modules, the chart and the ECS example against real AWS and a real cluster.
- A certificate from a real public CA, an exported ACM certificate, a company CA, and cert-manager. The proxy's handling of the files was tested with a stand-in CA, and the operating-system trust path was exercised on macOS (which refused an unknown CA) and on Linux (which accepted a trusted one).
- A real identity provider.
