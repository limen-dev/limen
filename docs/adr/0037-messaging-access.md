# ADR-0037: RabbitMQ, Amazon MQ, Kafka, and MSK access

- Status: Accepted (the owner asked for the implementation on 2026-10-18; the open questions were settled as the recommendations below, see "As built")
- Date: 2026-10-18

## Context
`docs/design.md` §13 lists Phase 11 as "RabbitMQ and Amazon MQ, then Kafka and MSK (ADR-0018): an AMQP client and `kcat` work through Limen against compose brokers; connection and topic/exchange audit with no message bodies; the Kafka multi-broker design from the spike is proven". ADR-0018 fixed the shape per target: AMQP 0-9-1 for RabbitMQ, the Kafka binary protocol for Kafka, the worker holds the credential, message bodies are never logged, and Kafka is the hard one because a client connects to *every broker* at the address the cluster advertises.

The data side already exists as stubs: policy accepts `rabbitmq` and `kafka` targets (`BrokerTarget`) and `mq: { users }` and `kafka: { users }` grants, the proxy knows the principals `MqUser` and `KafkaUser`, the console lists the kinds with their brand marks, and `limen mq connect` and `limen kafka connect` parse their options and answer "planned for Phase 11". No wire protocol is implemented.

The pattern from ADR-0002, ADR-0015, ADR-0034 holds: the **worker terminates the protocol next to the target and holds the credential**; the proxy only authorizes and routes; the CLI opens loopback listeners so the user's own clients work unchanged and never see a credential. The user asked that these sessions are **recorded**, "like the databases and redis": not video, but a durable, ordered, per-session record. See "Session record".

## Decision

### Common
1. **Wire is ours.** Both codecs are written in the worker (ADR-0012: no AMQP or Kafka client library is a dependency). Each is small for what a policy point needs: AMQP framing and about thirty method argument layouts; Kafka's size-prefixed requests, a header, and a hand-written reader for the fields policy needs of about twenty API keys at pinned versions. They are fuzz-friendly pure functions and are unit-tested with fixtures captured from real clients and servers.
2. **ALPN and CLI.** `limen-mq/1` and `limen-kafka/1` through the proxy exactly like `limen-redis/1` (one local connection is one Limen session, with the same grant, lock, kill, and drain machinery). `limen mq connect` and `limen kafka connect` print a ready-to-use URL or `--bootstrap` line with no password (clients that insist on credentials get a placeholder the worker discards).
3. **Client authentication is discarded.** The outer hop is mTLS plus the grant. SASL and AMQP `PLAIN` offered by the local client are accepted with any value and dropped; the worker never forwards them.
4. **Credentials are the worker's** and never logged (`limen_core::secret::Secret`): a JSON file `--broker-credentials-file` of `{"<resource>": {"<broker user>": "<password>" | {password, client_cert_file, client_key_file}}}`, and `--broker-ca-file` for TLS roots. TLS toward the target is on by default with `verify-full`; `tls: false` is for local brokers and is shown as a warning in the console.
5. **Policy is checked in the worker for every operation**, default deny, with the broker's own ACLs as the second layer. A denial is an `auth.denied` event (`action: mq` or `kafka`) and an error the client's library understands (below). **Audit fails closed**: an operation whose event can't be written isn't forwarded.
6. **Message bodies, message properties and headers, and record keys and values are never read into an event**, whatever the setting. There is no `log_values` equivalent. Names (exchange, queue, routing key, topic, group, client ID) are logged: they are what makes the trail useful.

### RabbitMQ and Amazon MQ (AMQP 0-9-1)
7. **Targets.** RabbitMQ 3.x and 4.x speaking AMQP 0-9-1 (including the 0-9-1 listener on Amazon MQ for RabbitMQ, `amqps` on 5671). Not in scope: AMQP 1.0, the Streams protocol, MQTT, STOMP (a client that offers another protocol header gets the supported one back and is closed), Amazon MQ for ActiveMQ, and the management API (a web resource, ADR-0022, Phase 12).
8. **The worker is a frame-aware relay.** It plays the server toward the client (`Start`, `Tune` with frame-max 131072 and the client's heartbeat, `Open`), then connects to the broker as the broker user the role names (`PLAIN`), and relays frames in both directions. Only the **client-to-broker method frames** are decoded: those that name an exchange, queue, vhost, or routing key, and a few channel-lifecycle methods. Content headers and bodies are relayed as opaque frames (header size is read for the event). Broker-to-client frames pass untouched. A frame over the negotiated maximum, a bad end byte, or an unknown frame type ends the session (`501 frame-error`).
9. **Where the vhost comes from.** From the client's `Connection.Open`, checked against the grant; the worker opens the broker connection only after that, so the broker sees exactly the allowed vhost. A vhost the grant doesn't name is `Connection.Close 530 not-allowed`.
10. **Policy, in the shape RabbitMQ experts know** (configure, write, read):
    ```yaml
    mq:
      users: [limen-app]            # broker user (credential selector)
      vhosts: ["/", "orders-*"]     # default ["/"]
      classes: [read, write]        # read | write | configure. Default [read, write]
      names: ["orders.*", "events"] # exchange and queue name patterns, `*` only. Default: any non-reserved name
    ```
    - *write*: `Basic.publish`, `Tx.*`, `Confirm.select`. The target is the exchange; for the default exchange (`""`) it is the **routing key**, because that is the queue it delivers to.
    - *read*: `Basic.consume`, `Basic.get`, `Basic.ack/nack/reject/recover/qos/cancel`. The target is the queue.
    - *configure*: `Exchange.declare/delete/bind/unbind`, `Queue.declare/delete/bind/unbind/purge`. A server-named queue (`Queue.declare` with an empty name) is allowed when `configure` is granted.
    - *Reserved names* (`amq.*`) match only a pattern that itself starts with `amq.`, so `*` never opens `amq.rabbitmq.trace`. Anything that isn't a known method is refused.
    - A refused method **closes that channel** with `403 access-refused` (the broker's own behaviour for permission errors, which clients handle): the worker answers `Channel.Close` itself, closes the broker-side channel, and discards the frames of the refused message. Other channels are unaffected. A refusal on channel 0 closes the connection.
11. **Heartbeats.** The worker keeps both sides alive with its own heartbeat frames and consumes theirs.
12. **Audit.** One `mq.operation` event per decoded operation, written before the method is forwarded: action (`publish`, `consume`, `get`, `declare_queue`, …), vhost, exchange, queue, routing key, channel, and for a publish the **body size** (taken from the content header, so the method frame is held until it arrives). Deliveries are not audited one by one (a consumer receives them by the million); the session's totals are in `session.end` and the delivery count in a closing `mq.summary` event. `Basic.get` is audited per call.
13. **Credentials.** The broker user's password from the credentials file. **Amazon MQ IAM** (the STS-JWT exchange on RabbitMQ 3.13 and 4.2+) is *not built*: the AWS documentation describes it, but it can't be tested here and brokers older than that need a password anyway. Amazon MQ works with a broker user whose password is in the file (the operator keeps it in Secrets Manager and renders the file).

### Kafka and MSK
14. **Targets.** Apache Kafka 2.8 to 4.x (KRaft or ZooKeeper), Amazon MSK provisioned (IAM, SCRAM, mTLS), Confluent-compatible brokers. MSK Serverless is the same protocol with IAM and is unverified. `tls: true` is the default.
15. **The multi-broker design (the spike).** A Kafka client dials the bootstrap address, reads `Metadata`, then dials *each broker at the address in the answer*. Limen resolves this without the client noticing:
    - `limen kafka connect` binds **one loopback listener for bootstrap and one per broker slot** (`--brokers N`, default 8; ports are chosen by the OS and printed). Every accepted connection is a Limen session; the session request names the **slot** and carries the **port table** (`database = "slot=2;ports=41001,41002,…"`, validated).
    - A session for slot 0 connects to the target's `endpoint`. A session for slot *s* connects to the broker that has rank *s* among the cluster's node IDs, sorted ascending (the worker asks the bootstrap for `Metadata` and caches the answer for 10 s).
    - In every `Metadata`, `FindCoordinator`, and `DescribeCluster` answer, the worker **rewrites each broker's host and port to `127.0.0.1:<port of that broker's slot>`** and keeps the node IDs, so partition leadership, `NOT_LEADER` retries, and coordinator lookups keep their meaning. A cluster with more brokers than slots fails the rewrite with a clear error on the session (`reconnect with --brokers N`) instead of handing out an address that doesn't exist.
    - Rank is stable while the membership is. If a broker is added or removed while connected, the client's next `Metadata` refresh yields the new mapping and its connections re-resolve; the worst case is a few `NOT_LEADER_OR_FOLLOWER` retries, which Kafka clients are built for.
    - Clients use `security.protocol=PLAINTEXT` toward the loopback listeners: the outer hop is mTLS and the loopback hop is local to the user, as for Redis. `advertised.listeners` on the cluster is never changed.
16. **The worker parses every request** header and the body fields policy needs, and **pins the API versions** it can read. It answers `ApiVersions` itself with the intersection of its own table and what the broker supports, so clients negotiate down to versions the worker understands. Pinned (non-flexible encodings, which keeps the hand-written readers small): `Produce` 3–8, `Fetch` 4–11, `ListOffsets` 1–5, `Metadata` 1–8, `OffsetCommit` 2–7, `OffsetFetch` 1–5, `FindCoordinator` 0–2, `JoinGroup` 0–5, `Heartbeat` 0–3, `LeaveGroup` 0–3, `SyncGroup` 0–3, `DescribeGroups` 0–4, `ListGroups` 0–2, `CreateTopics` 0–4, `DeleteTopics` 0–3, `InitProducerId` 0–1, `ApiVersions` 0–3. Any API key or version outside the table is **not advertised and is refused**: transactions, ACL and quota changes, config alteration, partition reassignment, and the broker-to-broker APIs cannot be used through Limen.
17. **Policy**, in the shape of Kafka ACLs:
    ```yaml
    kafka:
      users: [consumer]       # broker user (credential selector)
      classes: [read]               # read | write | admin. Default [read]
      topics: ["orders.*"]          # `*` only. Default: any non-internal topic
      groups: ["reports-*"]         # consumer groups. Default: any
    ```
    - *read*: `Fetch`, `ListOffsets`, `OffsetFetch`, group membership (`JoinGroup`, `SyncGroup`, `Heartbeat`, `LeaveGroup`, `OffsetCommit`, `DescribeGroups`), `Metadata`, `FindCoordinator`. *write*: `Produce`, `InitProducerId`. *admin*: `CreateTopics`, `DeleteTopics`.
    - Every topic named in a request must be covered by a pattern (as text: `orders.a*` is covered by `orders.*`); every group by a group pattern. A refused request gets the protocol's error (`TOPIC_AUTHORIZATION_FAILED` or `GROUP_AUTHORIZATION_FAILED`) *for that topic*, the others in the request are still served, like a broker's ACLs.
    - *Internal topics* (names starting with `_`, such as `__consumer_offsets`) match only a pattern that starts with `_`.
    - **`Metadata` answers are filtered** to the topics the grant covers (a request for all topics is answered with the covered ones), so topic names the user may not touch aren't disclosed.
18. **Authentication to the cluster**, in the worker, per target `sasl:` — `plain`, `scram-sha-256`, `scram-sha-512`, `aws-msk-iam`, or `none` (mTLS or an open listener), reusing the Phase 6 SCRAM and SigV4 code. `aws-msk-iam` signs the `AWS_MSK_IAM` payload (SigV4, `kafka-cluster:Connect`, 15 minutes) with the worker's AWS credentials and re-authenticates before the broker's `session_lifetime_ms`, never mid-request. `OAUTHBEARER` and `GSSAPI` are not built.
19. **Audit.** `kafka.request` events, written before the request is forwarded: API, client ID, topic(s), partition count, group, and for `Produce` the **record batch bytes** (never contents). `Produce` and `Fetch` polls arrive hundreds of times a second, so they are audited at **first contact with each (API, topic) in a session and once per 60 s after**, and each event carries the counts of requests and bytes since the last (a `kafka.summary` event closes the session with the totals). Group, admin, and coordinator operations are audited every time; `Heartbeat` and `ApiVersions` are counted, not logged. Denials are `auth.denied` every time.

### Session record
20. **What "recorded" means for these kinds** (as for databases and Redis): the audit events above are the record; they are hash-chained, shipped to S3 and Datadog, and carry the session ID. The control plane **projects them into the existing `db_statements` table** (`mq.operation`, `kafka.request`, and the broker-kind `auth.denied`, status `allowed` or `denied`), and the console's session page lists a messaging session's operations in order, with the refused ones marked, like a Redis session's commands. No new table, no terminal recording, no message content.
21. **Exit criteria demonstrated in the demo and tests** are listed below; the session page showing each protocol's operations is part of the demo.

## Tests and demo
- Unit: AMQP frame and method codec (round-trips, truncation, malformed lengths, oversize), policy matrices for both grants, the Kafka request readers and the `Metadata` rewrite and filter against fixtures captured from real clients, SCRAM and `AWS_MSK_IAM` payload fixtures, the dedupe window, audit fail-closed with a dead sink.
- Session tests against an in-process fake broker (as for Redis), including the refused-channel path and the slot table.
- Compose: RabbitMQ 4 (with a second vhost and permissions), a **3-broker KRaft Kafka cluster** with SASL (`PLAIN` and `SCRAM`) listeners. Scenarios drive real clients: `pika` (AMQP) and `librdkafka`, the library `kcat` is built on, through `limen mq connect` and `limen kafka connect`; the **multi-broker proof** creates a 6-partition topic with replication factor 3 and checks that the partition leaders are on all three brokers, every partition is produced to and consumed through Limen, a consumer group rebalances across two clients, and killing one broker's leadership (controlled shutdown) does not break the session after a metadata refresh.
- Demo: `demos/demo-phase11.sh`.

## Dependencies
None new in the workspace: the codecs are ours, HMAC and SHA-2 come from `aws-lc-rs` and `sha2`, SigV4 and SCRAM are the Phase 6 modules. The demo scripts install `pika` and `confluent-kafka` into a throw-away virtualenv; they are not Rust dependencies and not in the product.

## Open questions (decided as recommended)
1. **Fetch and Produce audit sampling.** Per-request events for a polling consumer would drown the trail and the control plane. The recommendation (item 19) is first contact plus one event per minute with counts. The alternative is an event per request with a per-resource opt-out.
2. **Kafka API version pinning.** Capping versions means a client library newer than the pinned set negotiates down (Java 3.x and librdkafka do this transparently), and some features need the missing APIs (transactions, exactly-once, share groups). Is that acceptable for Phase 11? The alternative is flexible-version readers for all of them, which is most of the work again.
3. **Slot count default (8).** MSK clusters are three to six brokers per AZ set; bigger clusters need `--brokers`. Alternatively the CLI could bind lazily on demand, which needs a control channel from the worker; not built.
4. **AMQP publish auditing at volume.** One event per publish, grouped per read of the socket so one fsync covers a batch. A producer that sends one message at a time pays one fsync (measured in Phase 7 at about 9 ms in the dev stack). Is a per-exchange sampling mode wanted?
5. **Management plane.** The RabbitMQ management API and Kafka REST proxies/UIs are web resources (Phase 12), not part of this phase.

## Consequences
- \+ AMQP and Kafka clients work unchanged and never see a credential; the same session, audit, lock, and kill machinery as SSH applies.
- \+ Policy reads like the brokers' own permission models.
- \+ The multi-broker design needs no change on the cluster and no wildcard DNS.
- − Two more wire codecs to own. Kafka's version pinning is a deliberate limit that must be documented.
- − A Kafka client that caches broker addresses across a Limen reconnect (a new CLI invocation prints new ports) must be restarted.
- − Producing one message at a time is slower through Limen than directly (audit before forward).
- Threat model: no new entry point beyond the loopback listeners already listed, and two new data-store connections; `docs/threat-model.md` gets the rows when the code lands.
- *Unverified against real services:* Amazon MQ, MSK (IAM payload acceptance, session re-authentication, TLS with the AWS CA bundle), and MSK Serverless. Locally the SigV4 inputs are tested against fixtures.

## As built (2026-10-18)
Where this section and the text above differ, this section is right.

1. **Credentials and TLS** are one pair of worker flags for both protocols: `--broker-credentials-file` (`LIMEN_BROKER_CREDENTIALS_FILE`) and `--broker-ca-file`. A broker user's entry is a password, or an object with a password and a client certificate and key for mutual TLS. A TLS target without a CA file is refused.
2. **RabbitMQ names.** The reserved prefix is `amq.rabbitmq.` (the firehose tracer, direct reply-to handled separately), not all of `amq.*`: the standard exchanges (`amq.topic`, ...) are ordinary names, as in RabbitMQ's own permissions. A queue the broker names for the session (`amq.gen-...`) is the session's own and usable whatever the patterns say. The worker offers frame-max 131072 to the client and refuses a broker that allows less; the vhost is opened at the broker only after the client's `Connection.Open`.
3. **RabbitMQ audit** has `connect`, `publish` (exchange, routing key, size), `consume`, `get`, and the declare, bind, purge, and delete operations. A publish is held until its content header gives the size. Acknowledgements, `Basic.qos`, and channel housekeeping are checked but not logged. `mq.summary` holds the publish and delivery counts and bytes.
4. **Kafka table.** `DescribeGroups` and `ListGroups` were left out (they return other members' data and need response filtering); `SaslHandshake` v1 and `SaslAuthenticate` v0-1 were added, answered locally so a client configured for SASL still connects (its login is discarded). `Metadata` rewrites the request to switch off automatic topic creation unless the role has `admin`.
5. **Kafka audit.** Dedupe is per (API, topic) with a 60 s window kept in memory per session; a window rollover logs the counts since. `Metadata` is deduped on its topic list. Fetch bytes are not counted (only Produce's, as the span size of the request); the session's `session.end` has the byte totals. An audit outage answers with `REQUEST_TIMED_OUT` (retriable), and ends the connection for `Metadata`.
6. **Broker slots.** The slot table travels in the session request's `database` field and is validated by the proxy and the worker. A cluster with more brokers than listeners makes the worker end the session and write `auth.denied` with the `--brokers N` hint; the CLI prints it on the next refused connection only if the proxy refused it, so the reason is in the audit trail and the worker's log.
7. **Not built:** MSK IAM re-authentication before `session_lifetime_ms` (the broker closes the connection and the client reconnects, which opens a new session), Amazon MQ IAM sign-in, SCRAM and `AWS_MSK_IAM` against real services (SCRAM is tested against a real Kafka 3.9; the SCRAM maths against RFC 7677 and an independent implementation), `OAUTHBEARER`, `GSSAPI`.
8. **Tests.** Unit: 32 AMQP and 52 Kafka tests including whole sessions against fake brokers on loopback sockets (the multi-broker slot logic is tested with two of them). `demos/demo-phase11.sh` is the exit test and the scenario test in one: real RabbitMQ 4.0 with pika, and a real three-broker Apache Kafka 3.9 cluster with librdkafka.
9. **Unverified against real services:** Amazon MQ for RabbitMQ (TLS on 5671 with the AWS bundle), Amazon MSK (IAM payload acceptance, TLS), MSK Serverless.

## Review (2026-10-18)
Read once, by the author, from three seats: a RabbitMQ engineer, a Kafka engineer, and an SRE. The demo had already passed against real brokers.

**Fixed after the review**
- No metrics for the new paths: added `limen_broker_refused_total` and `limen_broker_audit_failures_total` (labelled by protocol), documented in the guide.
- Each passthrough Kafka request was copied once more than needed; the common case now frames the message straight from the read buffer.
- The guide gained an operators' section (sessions per client, upgrade order, troubleshooting, audit volume).

**Left, and why**
- *Kafka (expert).* `Fetch` isn't audited per request or per offset range: a reader is visible as "topic X was read, N requests, in this minute", not which offsets. Per-request events were the alternative (open question 1). `JoinGroup` subscriptions can name topics the role doesn't reach; they yield `TOPIC_AUTHORIZATION_FAILED` on fetch and are absent from `Metadata`, but the subscription itself is not rewritten. `DescribeGroups`, `ListGroups`, transactions, and `OffsetForLeaderEpoch` are not offered, so some tools (`kafka-consumer-groups --describe`, exactly-once producers) don't work through Limen. Rank-based broker slots shift when a broker with a lower node ID is added or removed; clients heal through `NOT_LEADER` retries, but a restart of the CLI listener is the clean answer.
- *RabbitMQ (expert).* Permission checks are by name pattern only; the broker's regex permissions and topic authorization (`topic-permissions` for routing keys on topic exchanges) are not mirrored, so a role that may publish to `amq.topic` may use any routing key (the broker's own topic permissions stay the second layer). `Queue.bind` needs `configure` on both names, where RabbitMQ asks `write` on the queue and `read` on the exchange. Consumers started before a policy change keep consuming until the session ends. `Basic.publish` with `mandatory` returns pass through unaudited.
- *SRE.* One audit event per AMQP publish is the largest cost (a lone unbatched publisher pays one fsync each); a per-exchange sampling mode is the follow-up. A Kafka client multiplies sessions by its broker count. Request memory is bounded by 128 MiB per message (response 256 MiB) per session, so many sessions with huge batches can use gigabytes: lower `max.request.size` on clients or the worker's session cap. MSK IAM connections end at the broker's session lifetime and the client reconnects; there is no in-session re-authentication.

## Review after merging main (2026-10-19)
The branch was brought up to date with Phases 8, 9, and 10 and the reorganised dev stack, then read again from the same three seats (RabbitMQ, Kafka, SRE) and checked against real brokers.

**Adapted to main**
- Sessions are merged per run, as for MongoDB and search: `limen mq connect` and `limen kafka connect` give every session of a run one group id (`SessionRequest.group`), which the proxy puts on `session.start` and the console uses to show one row for the run ("N connections") with the operations of all of them. This matters most for Kafka, where a client holds a connection to every broker. The check the command makes at startup carries no traffic and doesn't count.
- The compose stack moved to `stacks/messaging.yml` (profile `messaging`, selectable in `setup.sh`), the target files to `config/targets/messaging/` with a `provision.sh` for the Kafka topics, ACLs, and SCRAM users, the images to `deploy/compose/.env`, and the demo to `demos/demo-phase11.sh`.
- `tests`: a phase 11 end-to-end test (`limen-e2e/tests/phase11.rs`) runs an AMQP client through control plane, proxy, and worker against a stand-in broker, including a refused publish, the trail without the body, a malformed Kafka slot table, and a lock ending the session.

**Bugs found and fixed**
- *RabbitMQ (expert).* A queue declared with `x-dead-letter-exchange`, or an exchange with `alternate-exchange`, let a role with `configure` route messages to an exchange it has no `write` on; the broker accepted it because the worker's broker user may. The worker now reads the declare's argument table and requires `write` on the target, as RabbitMQ does for its own users.
- *RabbitMQ (expert).* A passive declare was refused for a role without `configure`, which breaks clients that only check that a queue exists. It now needs any one permission on the name.
- *Kafka and SRE.* One audit event could be as large as the request that caused it (a refused `Metadata` or `Produce` naming thousands of topics, a 32 KB client id): lists are cut to 32 names and strings to 256 characters, with the total recorded. The per-session state for the audit window grew with every distinct topic name a wildcard grant covers: it is now capped.
- *SRE.* Every Kafka read allocated a fresh 64 KiB buffer, and an unmodified response was copied twice; the buffer is reused and the response passes through borrowed.

**Left, and why**
- Refusals are audited one event each (bounded in size now), so a client that retries a refused request in a loop is a rate of events, not a size. Per-session refusal sampling is the follow-up; the `limen_broker_refused_total` metric shows it.
- Per-session memory is still up to 128 MiB for a request, 256 MiB for a response, and a 512 MiB backlog for a client that isn't reading (64 MiB for AMQP); size workers by sessions times that, or lower it when there are many clients.
- **The run stays active while the CLI listens.** The CLI's startup session is kept open (`database: anchor`, the same idea as the search command's anchor). The proxy and worker authorize it like any session (policy, a credential exists) and the worker then serves no protocol on it, so it ends when the CLI stops, at `max_session_ttl`, on a lock, or on a drain. Without it a run was active only while a client was connected, so an idle listener looked ended in the console.

## Amendment: concise broker-user selectors (2026-10-23)

`mq.users` and `kafka.users` select broker users directly and do not require a Limen prefix. The guides and examples use `consumer` and `admin`.
