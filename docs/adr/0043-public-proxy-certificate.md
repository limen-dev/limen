# ADR-0043: A publicly trusted certificate for the proxy's public listener

- Status: **Proposed**, for the owner's decision. Nothing here is built. Tracks the "ACM or operator-supplied proxy certificate" item of #16 and the open assumption in design §4 ("verify in Phase 15").
- Date: 2026-11-04

## Context
The proxy has one TLS listener (ADR-0005). Today it presents the certificate the control plane's internal CA issued to it at enrollment, with the names from `--dns-name`. Three kinds of client reach that listener:

| Client | How it decides to trust the proxy |
|---|---|
| Workers (tunnel) and peer proxies | Pinned to the internal CA (ALPN `limen-tunnel`, `limen-peer`) |
| The CLI (`limen login`, `ssh`, `db`, `kube`, …) | Pinned to the CA given once with `--ca-file`; **it refuses to connect without one** (`api::connect`: "no CA is pinned") |
| Browsers (the console, web apps) | The system trust store |

So the console and web apps can only work in a browser if the people using it have been given the internal CA, and the CLI always needs a file. Design §4 assumed a publicly trusted certificate for the public side and left it open whether it comes from an ACM exportable certificate or one the operator supplies. The deploy guide lists this as not covered: nothing provisions the certificate, and it blocks real browser and CLI trust.

Constraints that rule out the simple answers:
- **TLS can't end at a load balancer.** Users present client certificates (mTLS) and the design requires TCP passthrough. An ALB or an ACM certificate attached to a load balancer is not an option; only a certificate the proxy itself holds works.
- **Swapping the certificate for everyone breaks workers and peers**, which verify the proxy against the internal CA.

## Decision (proposed)
1. **Operator-supplied certificate first.** The proxy takes `--public-cert-file` and `--public-key-file` (`LIMEN_PUBLIC_CERT_FILE`, `LIMEN_PUBLIC_KEY_FILE`): a PEM chain and key, for example from Secrets Manager mounted by the platform, or an exported ACM certificate (ACM can export a public certificate and its key under a passphrase; the operator decrypts it into the mount). ACM export is a way to *produce* the files, not a separate code path.
2. **Pick the certificate per connection by ALPN.** A `ResolvesServerCert` returns the internal-CA certificate when the client offers only `limen-tunnel` or `limen-peer`, and the public certificate otherwise. Workers and peers see no change. If the flags are not set, nothing changes at all.
3. **Reload without a restart.** The files are re-read every minute (and on `SIGHUP`); a file that fails to parse or whose key doesn't match is rejected and the last good certificate stays in use, with a warning and a metric. Public certificates renew every 60-90 days, so a restart-only design would be an outage generator.
4. **The CLI trusts the system roots when no CA is pinned.** `--ca-file` keeps working and wins when present (the dev stack and private deployments are unchanged). With no pinned CA the CLI verifies the proxy against the platform's trust store, with normal host-name checking. There is no trust-on-first-use.
5. **The private key is a secret.** It is held as `Secret`, never logged, read from a file the operator mounts read-only with mode 0600, and the threat model gets a row for it (a new secret on the proxy host, and the effect of its loss: impersonating the proxy to browsers and the CLI, but not to workers, which pin the internal CA).

Not in this ADR: ACME inside the proxy (needs port 80 or DNS credentials in a component we want to keep small), and certificates per name (one certificate may carry several names).

## Alternatives considered
- **Terminate TLS at the load balancer with ACM.** Rejected: breaks client certificates and the passthrough requirement.
- **Use the public certificate for every connection.** Rejected: workers and peers would have to trust a public CA, which widens what can impersonate the proxy to them.
- **Keep requiring the internal CA everywhere and document distribution.** Possible and what exists. It leaves browsers needing a private CA installed, and it is the gap this item is about.
- **ACME (Let's Encrypt) in the proxy.** Deferred: more moving parts and credentials in the proxy; the operator-supplied path doesn't prevent adding it later.

## Consequences
- \+ Browsers and the CLI work with no CA distribution for a deployment that has a normal public certificate.
- \+ Workers and peers are unaffected, and the change is off unless both flags are set.
- − Two certificates to know about; the proxy's certificate list is a new thing to monitor (expiry of the public certificate should be a metric and an alert).
- − The CLI gains a dependency on the platform trust store (for example `rustls-platform-verifier`); it needs an ADR-0012 row after a maintenance and advisory check.
- − Six CLI call sites build TLS configs from the pinned CA today (`api.rs`, `kube.rs`, `ssh.rs`, `tools.rs`, `doctor.rs`, `db.rs`); they need one shared helper.

## What it needs to be accepted
- Owner decision: operator-supplied first (this ADR) versus anything else.
- Tests: a test CA stands in for the public CA; the CLI connects with no pinned CA by pointing its trust store at it; workers still enroll and tunnel through the same listener; reload with a valid, an invalid, and a mismatched key.
- Not verifiable without a real domain and a real public CA: browser trust, ACM export, and the platform verifier on each OS. Those would be labelled `unverified`.
