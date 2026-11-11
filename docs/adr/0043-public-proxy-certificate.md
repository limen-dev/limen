# ADR-0043: A publicly trusted certificate for the proxy's public listener

- Status: **Accepted** by the owner on 2026-11-11, with the amendments marked *Amended* below. Tracks the "ACM or operator-supplied proxy certificate" item of #16 and the open assumption in design §4 ("verify in Phase 15").
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

## Decision
1. **Operator-supplied certificate first.** The proxy takes `--public-cert-file` and `--public-key-file` (`LIMEN_PUBLIC_CERT_FILE`, `LIMEN_PUBLIC_KEY_FILE`): a PEM chain and key, for example from Secrets Manager mounted by the platform, or an exported ACM certificate (ACM can export a public certificate and its key under a passphrase; the operator decrypts it into the mount). ACM export is a way to *produce* the files, not a separate code path.
2. **Pick the certificate per connection by ALPN.** A `ResolvesServerCert` returns the internal-CA certificate when the client offers any protocol only Limen's own components speak (`limen-tunnel/1`, `limen-peer/1`, `limen-worker-api/1`), and the public certificate otherwise. If the flags are not set, nothing changes at all.
   - *Amended.* The first draft keyed on `limen-tunnel` and `limen-peer` alone. Reading the workers showed that was not enough: a worker's enrollment, renewal and relayed control-plane calls are plain `h2` to the proxy, pinned to the internal CA, so they would have been handed the public certificate and failed. Workers now offer `limen-worker-api/1, h2` for those calls. The proxy serves that protocol exactly like `h2`. Offering `h2` as well keeps a new worker working against a proxy from before this change (it negotiates `h2`). The CLI and browsers never offer the internal protocols.
   - *Rollout order.* A worker from before this change offers only `h2` and cannot be told from the CLI, so once a proxy has a public certificate it would get the public one and refuse it. Upgrade the workers first, then set the flags.
3. **Reload without a restart.** The files are re-read every minute (and on `SIGHUP`); a file that fails to parse or whose key doesn't match is rejected and the last good certificate stays in use, with a warning and a metric. Public certificates renew every 60-90 days, so a restart-only design would be an outage generator.
4. **The CLI trusts the system roots when no CA is pinned.** `--ca-file` keeps working and wins when present (the dev stack and private deployments are unchanged). With no pinned CA the CLI verifies the proxy against the platform's trust store (`rustls-platform-verifier`), with normal host-name checking. There is no trust-on-first-use.
   - *Amended.* The CLI's flag for the address is now `--server` (`LIMEN_SERVER`), with port 443 by default, so `limen login --server limen.example.com` is the whole command for a deployment with a public certificate. `--proxy` is removed.
   - `limen audit verify` is unchanged in kind: it checks signatures against Limen's own CA, which is not a TLS question, so it never falls back to system roots. A login that pinned no CA has none to use, and the command says to pass `--ca-file`.
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
- − The CLI gains a dependency on the platform trust store (`rustls-platform-verifier`, ADR-0012 row added).
- − The CLI's TLS call sites (`api.rs`, `ssh.rs`, `db.rs`, `doctor.rs`) now share one helper, `api::tls_config`. `kube.rs` and `tools.rs` only write the CA into a kubeconfig and already left it out when none is pinned.
- − Workers must be upgraded before a public certificate is switched on (see decision 2).

## What it needs to be accepted
- Owner decision: operator-supplied first (this ADR) versus anything else. **Done, 2026-11-11.**
- Tests: a test CA stands in for the public CA; the CLI connects with no pinned CA by pointing its trust store at it; workers still enroll and tunnel through the same listener; reload with a valid, an invalid, and a mismatched key.
- Not verifiable without a real domain and a real public CA: browser trust, ACM export, and the platform verifier on each OS. Those would be labelled `unverified`.

## What was verified
Run in this change, against a throwaway CA standing in for the public one (`demos/demo-public-cert.sh`, `stacks/public-cert.yml`): the certificate each ALPN set receives, on the wire; a worker enrolling and tunnelling through the same listener; the CLI pinned to the stand-in CA; the CLI in a Linux container trusting only `SSL_CERT_FILE`; the same without it, refused; reload on `SIGHUP`; a broken key refused with the last certificate kept. Unit tests cover the resolver with real handshakes, and valid, garbage, mismatched, expired and empty files.

`unverified`: browser trust, the macOS Keychain and Windows verifiers, a certificate from a real public CA, and an exported ACM certificate.
