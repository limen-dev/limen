# Demos

Each phase ships a runnable demo. Every script starts with a header that says
what it needs, which ports and project name it uses, and what it checks.
Most take `--keep` to leave their stack running. Read the header before
running one: they build the CLI and start containers.

| Script | What it shows |
| --- | --- |
| `demo-phase1.sh` | Dev stack and every Phase 1 exit criterion |
| `demo-phase2.sh` | SSH with the OpenSSH client, per-session certificates |
| `demo-phase3.sh` | Audit pipeline: signed, hash-chained batches to S3 and Datadog |
| `demo-phase35.sh` | Locking users, ending sessions, the web console (the full-stack check) |
| `demo-phase4.sh` | Machine identities: CI logs in with a workload token |
| `demo-phase5.sh` | Scale-out: three control planes, one killed, rolling restart |
| `demo-phase6.sh` | `psql` and `mysql` through `limen db connect` |
| `demo-phase7.sh` | Redis and Valkey |
| `demo-phase8.sh` | `kubectl` by impersonation, on a kind cluster |
| `demo-phase9.sh` | MongoDB |
| `demo-phase10.sh` | Elasticsearch and OpenSearch |
| `demo-phase11.sh` | RabbitMQ and Kafka |
| `demo-phase12.sh` | Browser SSO, web requests, WebSockets, TCP |
| `demo-phase13.sh` | Access requests and break-glass, search, discovery, live watch |
| `demo-phase14.sh` | The management API (ADR-0042) |
| `demo-shadow.sh` | Shadow mode for deny rules (ADR-0046) |
| `demo-honeytoken.sh` | Honeytoken resources: a decoy that is listed, refused like any name, and audited (ADR-0053) |
| `demo-policy-suggest.sh` | `limen policy suggest`: removals proposed from real sessions (ADR-0050) |
| `demo-replay.sh` | Replay recorded sessions against a policy change (ADR-0051) |
| `demo-idp-offboarding.sh` | IdP-driven onboarding (groups become roles) and offboarding against a real Dex (ADR-0047) |
| `demo-ocsf.sh` | OCSF export of the audit trail for SIEMs (ADR-0049) |
| `demo-public-cert.sh` | A public certificate on the proxy: the CLI needs no CA file, workers are unaffected, reload on SIGHUP (ADR-0043) |
| `demo-dx.sh` | First five minutes: `limen doctor`, ssh, scp, rsync, git, `limen kube config` |
| `demo-website.sh` | Builds and checks the documentation site |
