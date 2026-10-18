# RabbitMQ and Kafka

Connect with any AMQP 0-9-1 client (pika, amqplib, Bunny, the Java client) or any Kafka client (librdkafka and `kcat`, the Java client, franz-go) through Limen. You never see a password: the worker logs in to the broker as the broker user your role names, checks every operation against your role, and audits it. Message bodies and record values are never read into the audit trail. Design: [ADR-0037](../adr/0037-messaging-access.md).

## RabbitMQ and Amazon MQ

```sh
limen mq connect events-rabbit-staging        # the user is picked from policy when there's only one
# Listening for events-rabbit-staging as limen-consumer.
# Run: amqp://limen:limen@127.0.0.1:51234/%2F
```

Point your client at that URL. Any user name and password work (some libraries insist on having one); Limen ignores them. Each connection is its own audited session. `--user` picks the broker user when policy allows several, `--listen 127.0.0.1:5673` fixes the port (loopback only), `--vhost` changes the vhost in the printed URL. The client chooses the real vhost; your role limits it.

A role grants broker users with limits shaped like RabbitMQ's own permissions:

```yaml
- resources: { kind: [rabbitmq], labels: { env: [staging] } }
  mq:
    users: [limen-consumer]
    vhosts: ["/", "orders"]        # default: only "/"
    classes: [read]                # read | write | configure. Default: read and write
    names: ["orders.*"]            # exchange and queue name patterns. Default: any name
```

- **read**: consume, get, acknowledge. **write**: publish (to the default exchange, the routing key is the queue, so it is the name checked). **configure**: declare, delete, bind, and purge exchanges and queues.
- `*` never opens the broker's own `amq.rabbitmq.*` names (the firehose tracer). Direct reply-to (`amq.rabbitmq.reply-to`) and the server-named queues your own session declared always work.
- A refused operation closes **that channel** with `403 ACCESS_REFUSED` (what RabbitMQ does for a permission error); other channels and the connection carry on. An unknown vhost is refused when the connection opens.
- Not supported: AMQP 1.0, Streams, MQTT, STOMP (a client that offers them is told what is supported), and Amazon MQ's IAM sign-in (use a broker user whose password the worker holds). The management UI and API are web apps (Phase 12).

## Kafka and MSK

```sh
limen kafka connect events-kafka-staging --brokers 4
# Listening for events-kafka-staging as limen-consumer (4 broker slots).
# Run: kcat -b 127.0.0.1:51234 -L
```

Use `127.0.0.1:51234` as the bootstrap server with `security.protocol=PLAINTEXT`. A Kafka client connects to every broker at the address the cluster advertises, so the command opens one more loopback listener per broker slot (`--brokers N`, default 8: one per broker of the cluster, at most 64) and the worker rewrites the addresses the cluster hands out to those ports. A cluster with more brokers than slots is refused with a message that says so. Restart the command (and your client) if the CLI's ports change.

```yaml
- resources: { kind: [kafka], labels: { env: [staging] } }
  kafka:
    users: [limen-consumer]
    classes: [read]                # read | write | admin. Default: read
    topics: ["orders.*"]           # default: any topic that isn't internal
    groups: ["dev-*"]              # consumer groups. Default: any
```

- **read**: fetch, offsets, consumer groups, metadata. **write**: produce. **admin**: create and delete topics (and automatic topic creation).
- A request that names topics your role doesn't reach is cut down to the ones it does; the others get `TOPIC_AUTHORIZATION_FAILED`, like a broker's ACLs. A group you can't use gets `GROUP_AUTHORIZATION_FAILED`.
- `Metadata` lists only the topics your role reaches. Internal topics (`__consumer_offsets`) need a pattern that starts with `_`.
- **Supported API versions** are pinned to the ones the worker reads (the non-flexible encodings): Produce 3–8, Fetch 4–11, Metadata 1–8, and the group, offset, and topic APIs listed in the ADR. The worker answers `ApiVersions` itself, so clients negotiate down; the Java and librdkafka clients do this without help. **Transactions, ACL and config changes, partition reassignment, and the other administration APIs are not available through Limen.**
- Logins by the worker: SASL `PLAIN`, `SCRAM-SHA-256`, `SCRAM-SHA-512`, `AWS_MSK_IAM` (unverified against MSK), or none (mutual TLS or an open listener). Set `sasl:` on the resource.

## Configuring the worker

```sh
limen-worker ... \
  --broker-credentials-file /etc/limen/broker-credentials.json \
  --broker-ca-file /etc/limen/aws-ca-bundle.pem        # for TLS targets (Amazon MQ, MSK)
```

```json
{ "events-rabbit-staging": { "limen-consumer": "password" },
  "events-kafka-staging":  { "limen-consumer": "password",
                             "svc": { "password": "…", "client_cert_file": "/c.pem", "client_key_file": "/k.pem" } } }
```

TLS to the broker is on by default and verified against `--broker-ca-file`; `tls: false` on the resource is for local brokers.

## What is audited

- **RabbitMQ:** one `mq.operation` event per decoded operation, **before** it is forwarded (if it can't be written, the operation is refused and the channel closed): `connect`, `publish` (exchange, routing key, **body size**), `consume`, `get`, `declare_queue`, `bind_queue`, and so on. Acknowledgements and deliveries are not logged one by one; `mq.summary` at the end holds the counts. A refusal is `auth.denied` with `action: mq`.
- **Kafka:** `kafka.request` events before forwarding. Group, offset, and admin requests are logged every time. `Produce` and `Fetch` arrive hundreds of times a second, so they are logged at **first contact with each topic and then once per minute**, with the counts and bytes since the last event; `kafka.summary` at the end lists what was counted and never logged. `Heartbeat` is counted only. A refusal is `auth.denied` with `action: kafka`.
- Never: message bodies and properties, record keys and values, headers.
- **Session record.** These sessions have no terminal recording. The console's session page lists the operations in order, with the refused ones marked, like Redis commands; the same events are in the hash-chained trail in S3 and Datadog.

## Running it (for operators)

- **Sessions per client.** A Kafka client holds one connection per broker it talks to, and each is a Limen session with its own login to the broker. One consumer on a 3-broker cluster is about 3 to 4 sessions, a producer similar, so count them against the worker's `--max-sessions` (default 200). SCRAM logins cost the broker a key derivation each (4096 iterations by default).
- **Upgrade order.** The new grant fields and target fields (`mq.classes`, `kafka.topics`, `sasl`, `tls`, ...) are rejected by components from before Phase 11 that load a snapshot containing them: upgrade the control plane, then proxies, then workers, and only then apply a policy that uses them.
- **Metrics** (worker): `limen_broker_refused_total{protocol}` for operations policy refused, `limen_broker_audit_failures_total{protocol}` for operations refused because the audit event could not be written (alert on this: it means producers and consumers are being turned away), and the usual `limen_worker_sessions_active`.
- **Troubleshooting.** A Kafka client that connects and then hangs after `Metadata` is usually talking to a cluster with more brokers than `--brokers` (the worker logs and audits `auth.denied` with the number to use). A client that works until a broker is replaced needs a restart of `limen kafka connect` only if the cluster's broker count changed. `auth.denied` events carry the reason in plain words.
- **Audit volume.** Every AMQP publish is an event. A producer sending thousands of messages a second makes thousands of events a second; they are written in groups per read of the socket, but plan the audit sink for it, or keep such producers off Limen.
