# Phase 5: Scale-out Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run several control planes, proxies, and workers at once without losing audit events, and prove it with a three-replica demo.

**Architecture:** A `control_plane_replicas` table gives writer-ID safety and peer discovery. Shutdown drains the audit spool to every sink and, in ephemeral mode, hands the remainder to a live peer over a new `AuditHandoff` gRPC. Balancing is by connection max-age on the control plane and load-aware (power of two choices) worker selection.

**Tech Stack:** Rust, tonic/prost, sqlx (literal SQL only), Postgres, SeaweedFS, docker compose, kind (if available).

**Spec:** `docs/superpowers/specs/2026-10-15-phase-5-scale-out-design.md`

## Global Constraints

- Work only in `.claude/worktrees/phase-5-scale-out` (branch `phase-5-scale-out`). Don't push or tag.
- `cargo fmt && cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` clean before every commit (pedantic).
- sqlx wants literal SQL: shared fragments through `macro_rules!` + `concat!`, never `format!`.
- Secrets use `limen_core::secret::Secret`; audit fails closed; mTLS everywhere.
- A new dependency needs an ADR-0012 row and an advisory check first. Plan assumes none.
- A new entry point or data store updates `docs/threat-model.md` (Task 10).
- Nothing is called working unless it was run. Anything only run against a local stand-in is labelled `unverified`.
- Conventional commits, small; stage specific files. No `timeout` or `sleep`-polling on macOS; run long commands in the background.
- Spool modes: `durable` (default) and `ephemeral`. Registry heartbeat 5 s; a row is live if heartbeat is younger than 15 s. Max connection age 5 min ±10 % jitter, 30 s grace. Worker `--max-sessions` default 200.

## Review Focus

- Two replicas started with the same id: second must refuse to start (Task 1).
- SIGTERM with a sink down (S3 unreachable): drain must hit the deadline, not hang, and in ephemeral mode hand off rather than drop (Tasks 2, 3).
- Handoff interrupted halfway (receiver dies, sender retries): no loss, duplicates tolerated via `event_id` (Task 3).
- A caller that holds a control-plane certificate but has no live registry row, or a proxy certificate, calls `Handoff`: refused (Task 3).
- Every eligible worker at its cap: user gets a capacity error and an audit event, not a hang (Task 7).

---

### Task 1: Replica registry and writer-ID safety

**Files:**
- Create: `crates/limen-control-plane/migrations/0006_replicas.sql`, `crates/limen-control-plane/src/replicas.rs`
- Modify: `crates/limen-control-plane/src/{config.rs,db.rs,lib.rs,jobs.rs,main.rs}`
- Test: `crates/limen-control-plane/src/replicas.rs` (unit + DB integration, SKIPPED without `LIMEN_TEST_DATABASE_URL`)

**Interfaces:**
- Produces: `replicas::register(db: &Db, id: &str, ingest_url: &str, mode: SpoolMode) -> Result<(), RegisterError>` (fails `RegisterError::IdInUse` if a live row has this id; takes over a stale one), `replicas::heartbeat(db, id) -> Result<(), sqlx::Error>`, `replicas::live_peers(db, except_id: &str) -> Result<Vec<Replica>, sqlx::Error>`, `replicas::deregister(db, id)`, `struct Replica { id: String, ingest_url: String }`, `enum SpoolMode { Durable, Ephemeral }` (clap `ValueEnum`, `--spool-mode`, env `LIMEN_SPOOL_MODE`, default `durable`), `jobs::replica_heartbeat(state, shutdown)`.
- `--id` default becomes the hostname (`hostname` crate already in tree? if not, read `HOSTNAME` env then `/etc/hostname`; no new dependency).

- [ ] **Step 1: Write failing tests** in `replicas.rs`: `second_register_with_live_id_is_refused`, `stale_row_is_taken_over` (set `heartbeat_at` 1 minute back), `live_peers_excludes_self_and_stale`, `deregister_removes_row`.
- [ ] **Step 2: Run** `cargo test -p limen-control-plane replicas` (with the integration env vars from AGENTS.md). Expected: FAIL, module missing.
- [ ] **Step 3: Migration** `control_plane_replicas(id text primary key, ingest_url text not null, spool_mode text not null, started_at timestamptz not null default now(), heartbeat_at timestamptz not null default now())`. Implement the functions with one literal SQL `INSERT ... ON CONFLICT (id) DO UPDATE ... WHERE control_plane_replicas.heartbeat_at < now() - interval '15 seconds'` and check `rows_affected`.
- [ ] **Step 4: Wire** register in `build_state` (before the pipeline opens, so a duplicate never touches the spool), the heartbeat job in `run`, deregister at the end of shutdown. Extend the existing `db::cleanup` to delete rows older than 1 day.
- [ ] **Step 5: Run** the tests. Expected: PASS. Run clippy.
- [ ] **Step 6: Commit** `feat(control-plane): replica registry and refusal of duplicate ids`.

### Task 2: Drain the spool on shutdown

**Files:**
- Modify: `crates/limen-audit/src/ship.rs`, `crates/limen-control-plane/src/{lib.rs,pipeline.rs,server.rs}`
- Test: `crates/limen-audit/src/ship.rs` tests

**Interfaces:**
- Produces: `ship::run_consumer` gains a `drain: watch::Receiver<bool>`-style stop: on `shutdown` it keeps shipping until `spool.pending(name) == 0` or a separate `deadline: watch::Receiver<bool>` flips, then returns. Signature: `run_consumer(spool, config, send, shutdown, deadline)`. `Pipeline::drain(&self, deadline: Duration) -> DrainReport { pending: BTreeMap<String, u64> }` waits for all consumers.
- Consumes: Task 1 (`SpoolMode` in config).

- [ ] **Step 1: Write failing tests** `drains_to_zero_after_shutdown` (25 records, shutdown flipped immediately, all shipped) and `gives_up_at_deadline_with_records_left` (send always `Retry`; returns shortly after deadline, `pending > 0`).
- [ ] **Step 2: Run** `cargo test -p limen-audit ship`. Expected: FAIL.
- [ ] **Step 3: Implement** the change; update existing callers and the existing test.
- [ ] **Step 4: Shutdown order** in `run`: flip readiness false and reject new `Ingest` with `unavailable` → `serve_api` finishes in-flight calls → `Pipeline::drain(drain_timeout - handoff_reserve)`. `handoff_reserve` = 20 % of the drain timeout.
- [ ] **Step 5: Run** all `limen-audit` and control-plane tests. Expected: PASS. Commit `feat(audit): drain the spool to every sink on shutdown`.

### Task 3: Handoff to a peer

**Files:**
- Modify: `proto/limen/v1/audit.proto`, `crates/limen-control-plane/src/{services/mod.rs,server.rs,lib.rs,pipeline.rs}`, `crates/limen-audit/src/spool.rs`
- Create: `crates/limen-control-plane/src/services/handoff.rs`, `crates/limen-control-plane/src/handoff_client.rs`
- Test: `crates/limen-control-plane/tests/handoff.rs`

**Interfaces:**
- Proto: `service AuditHandoff { rpc Handoff(stream HandoffBatch) returns (stream HandoffAck); }` with `HandoffBatch { repeated bytes events = 1; uint64 last_index = 2; }` and `HandoffAck { uint64 durable_upto = 1; }`.
- Produces: `handoff_client::send_remaining(state: &AppState, deadline: Duration) -> Result<u64 /* records sent */, HandoffError>` (tries peers from `replicas::live_peers` in random order; commits the spool's consumers only after each ack). `Spool::read_all_unshipped(&self) -> Vec<(u64, Vec<u8>)>` helper if needed, else reuse `read`.
- Server: caller must be a `ComponentKind::ControlPlane` **and** present in `live_peers`; otherwise `permission_denied`. Appends to its own spool, acks after fsync.
- Ephemeral flow in the shutdown sequence after `Pipeline::drain`: if `pending` non-empty and mode is ephemeral, call `send_remaining`. Durable mode logs the leftover and exits.

- [ ] **Step 1: Write failing tests** (two in-process replicas on one DB, A with S3 sink pointed at a dead address): `ephemeral_replica_hands_unshipped_events_to_peer` (all event ids appear in B's spool), `handoff_retry_after_receiver_restart_loses_nothing`, `unregistered_control_plane_cert_is_refused`, `proxy_cert_is_refused`, `durable_mode_does_not_hand_off`.
- [ ] **Step 2: Run** `cargo test -p limen-control-plane --test handoff`. Expected: FAIL.
- [ ] **Step 3: Implement** proto, service, client, shutdown wiring. Commit offsets only after `HandoffAck.durable_upto` covers them.
- [ ] **Step 4: Run** tests with compose services up. Expected: PASS. Clippy. Commit `feat(audit): hand unshipped events to a peer replica on shutdown`.

### Task 4: Adopt an orphaned spool

**Files:**
- Create: `crates/limen-control-plane/src/bin/limen-spool-adopt.rs` (follows `limen-audit-verify.rs`)
- Test: `crates/limen-control-plane/tests/handoff.rs`

**Interfaces:** Consumes Task 3's `send_remaining` core, refactored to take a `Spool` and a peer list: `handoff_client::send_spool(spool: &Spool, peers: &[Replica], tls: ...) -> Result<u64, HandoffError>`. CLI: `limen-spool-adopt --dir <path> --database-url … --ca-file … --cert …` (mirrors existing flags).

- [ ] **Step 1: Test** `adopt_pushes_a_leftover_spool_to_a_live_peer` (copy a populated spool dir, adopt, events in the peer's spool).
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). Document in the runbook (Task 10).
- [ ] **Step 5: Commit** `feat(control-plane): limen-spool-adopt for leftover spools`.

### Task 5: Verifier reports sequence gaps; the scale compose profile and demo

**Files:**
- Modify: `crates/limen-control-plane/src/verify.rs` (gap report), `crates/limen-control-plane/src/bin/limen-audit-verify.rs`, `deploy/compose/docker-compose.yml`
- Create: `deploy/compose/demo-phase5.sh`, `deploy/compose/README.md` section

**Interfaces:** `verify::VerifyReport` gains `seq_gaps: Vec<SeqGap { component, instance_id, missing_from: u64, missing_to: u64 }>` and `events: u64`; the CLI exits non-zero if the chain breaks **or** a gap exists.

- [ ] **Step 1: Failing test** in `verify.rs`: a bucket fixture with seq 1,2,4 for one producer reports one gap (3..=3).
- [ ] **Step 2–3:** run (FAIL), implement, run (PASS), commit `feat(audit): verifier reports producer sequence gaps`.
- [ ] **Step 4: Compose profile `scale`**: `control-plane-0..2` each with own named volume, `LIMEN_ID`, `LIMEN_SPOOL_MODE`, and network alias `control-plane`; three proxies and three workers; reuse existing sshd target. Existing profiles unchanged (run `demo-phase4.sh` to confirm).
- [ ] **Step 5: `demo-phase5.sh`**: start stack; open a long SSH session; `docker kill` `control-plane-1` (durable) mid-batch and start it; SIGTERM-restart `control-plane-0` and `-2` one at a time (ephemeral for these two via env); assert the session survived, a new session worked throughout, verifier clean, S3 event count equals count produced. Support `--keep` like the other demos.
- [ ] **Step 6: Run the demo for real.** Expected: ends with PASS lines. If it fails, fix the cause (Tasks 1–3), never the assertion. Commit `feat(deploy): scale profile and Phase 5 demo`.

### Task 6: Connection max-age and re-resolve

**Files:**
- Modify: `crates/limen-control-plane/src/{server.rs,config.rs}`, `crates/limen-tunnel/src/connect.rs`, `crates/limen-proxy/src/lib.rs`, `crates/limen-worker/src/lib.rs`
- Test: `crates/limen-e2e/tests/scale.rs` (new)

**Interfaces:** Config `--max-connection-age-secs` (default 300), jitter ±10 %, grace 30 s, set on the tonic `Server` (HTTP/2 GOAWAY). `connect::dial` already resolves per call via `TcpStream::connect(addr)`; proxy and worker reconnect loops must treat a GOAWAY close as `info`, not `error`, and reconnect immediately without backoff.

- [ ] **Step 1: Failing test** `new_replica_receives_connections_within_one_age_period` (age set to 2 s in the test; start with one control plane, add a second behind a resolver stub that returns both, expect the second to accept a proxy connection).
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). Commit `feat(control-plane): maximum connection age so connections rebalance`.

### Task 7: Load-aware worker selection and per-worker cap

**Files:**
- Modify: `proto/limen/v1/tunnel.proto` (`PingResponse` gains `uint32 active_sessions = 3; uint32 max_sessions = 4;`), `crates/limen-worker/src/{lib.rs,main.rs,session.rs}`, `crates/limen-proxy/src/{tunnels.rs,peer.rs,ssh.rs,lib.rs}`
- Test: unit tests in `tunnels.rs`; `crates/limen-e2e/tests/scale.rs`

**Interfaces:**
- Worker `--max-sessions` (`LIMEN_MAX_SESSIONS`, default 200); refuses `OpenSession` over the cap with `resource_exhausted`.
- `Tunnels::pick` and the peer pick use `fn p2c<'a, T>(candidates: &'a [T], load: impl Fn(&T) -> f64, rng: &mut impl rand::Rng) -> Option<&'a T>` that excludes full workers (`active >= max`) and picks the less loaded of two random candidates. Load is the last value from the periodic ping.
- When no eligible worker has room: SSH user sees `no capacity` and the proxy emits an audit event `session.denied` data `{reason:"capacity"}` using existing `auth.denied` kind with `data.reason = "capacity"` (no new event kind; schema stays v1).

- [ ] **Step 1: Failing tests:** `p2c_prefers_the_less_loaded` (statistical, fixed seed: worker at 10 % gets over 70 % of 1000 picks against one at 90 %), `full_workers_are_never_picked`, `all_full_returns_none`, `worker_refuses_over_cap` (e2e), `capacity_error_is_audited` (e2e).
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). Commit `feat(proxy,worker): least-loaded worker choice and a per-worker session cap`.

### Task 8: Worker drain on scale-in

**Files:** Modify `crates/limen-worker/src/{lib.rs,main.rs}`; test in `crates/limen-e2e/tests/scale.rs`.

**Interfaces:** On SIGTERM the worker sets `draining` (already in `PingResponse`), the proxy stops picking it (existing), the worker waits for open sessions up to `--drain-timeout-secs`, then ends the rest and emits `session.end` with `data.reason = "worker_drain"`.

- [ ] **Step 1: Failing tests:** `draining_worker_gets_no_new_sessions`, `open_session_finishes_during_drain`, `session_over_deadline_is_ended_and_audited`.
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). Commit `feat(worker): drain open sessions on scale-in`.

### Task 9: Scale metrics

**Files:** Modify `crates/limen-proxy/src/{lib.rs,tunnels.rs}`, `crates/limen-worker/src/lib.rs`, `crates/limen-control-plane/src/{replicas.rs,server.rs}`, `dashboards/grafana/generate.py` (then regenerate).

**Interfaces:** gauges `limen_sessions_active{component}`, `limen_tunnels_active`, `limen_control_plane_replicas`; histogram `limen_api_request_seconds{method}`. `limen_audit_spool_pending` exists.

- [ ] **Step 1: Failing test** that scrapes the admin `/metrics` of an in-process component and finds each name.
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS); `python3 dashboards/grafana/generate.py` and commit the generated output. Commit `feat: scale metrics and a Grafana row`.

### Task 10: Load test, Kubernetes example, docs

**Files:**
- Create: `crates/limen-e2e/tests/load.rs` (ignored by default, enabled by `LIMEN_LOAD_TEST=1`), `deploy/kubernetes/{README.md,control-plane-statefulset.yaml,proxy-deployment.yaml,worker-deployment.yaml}`, `docs/runbooks/scale-out.md`, `docs/scale-out.md`
- Modify: `docs/adr/0020-scale-out.md` (Status Accepted; correction on SIGKILL of an ephemeral replica; ECS to Phase 13), `docs/threat-model.md` (handoff entry point; replica registry data store), `docs/design.md` §13 (Phase 5 ✅ only after the demo passes), `docs/adr/0012-*.md` only if a dependency was added.

**Interfaces:** Load test: 500 users log in (mock IdP), 100 hold sessions for 30 s on compose; prints p50/p95/p99 and error count; fails over 1 % errors. Docs cover pool sizing (`max_connections × replicas` vs Aurora limits, RDS Proxy, 500-user worked example), rate limits (per replica, effective limit `limit × replicas`), spool modes and the SIGKILL loss window, scale signals, and the adopt runbook.

- [ ] **Step 1:** Write the load test; run it against the `scale` profile and record the real numbers in `docs/scale-out.md`.
- [ ] **Step 2:** Write the Kubernetes manifests (`terminationGracePeriodSeconds` greater than the drain timeout, PVC per control plane pod). If `kind` is available, apply and run `demo-phase5.sh`-equivalent checks; if not, label `unverified` in the README.
- [ ] **Step 3:** Docs and ADR edits as listed. Run `mise exec -- actionlint`, `cargo deny --locked check && cargo audit`.
- [ ] **Step 4:** Full verification: fmt, clippy, full test suite with env vars, `demo-phase5.sh --keep`, `demo-phase4.sh`, `demo-phase35.sh`. Mark Phase 5 done in design.md only if all pass.
- [ ] **Step 5: Commit** `docs: Phase 5 scale-out guide, runbook, Kubernetes example; ADR-0020 accepted`.
