# RabbitMQ and Kafka

Connect with any AMQP 0-9-1 client (pika, amqplib, Bunny, the Java client) or Kafka client (librdkafka, `kcat`, the Java client, franz-go). You never see a password: the worker logs in as the broker user your role names, checks every operation against your role, and audits it. Message bodies and record values are never read into the audit trail. Design: [ADR-0037](../adr/0037-messaging-access.md).

## RabbitMQ and Amazon MQ

```sh
limen mq connect events-rabbit-staging        # user picked from policy when there's only one
# Listening for events-rabbit-staging as consumer.
# Run: amqp://limen:limen@127.0.0.1:51234/%2F
```

Point your client at that URL. Any user name and password work (some libraries insist on one); Limen ignores them. Each connection is its own audited session, and the console shows one run's connections as one row ("3 connections") listing all their operations. The command also holds one idle session open while it listens (it checked your access at start-up); it carries no traffic, isn't counted, and keeps the run shown as active between connections.

`--user` picks the broker user when policy allows several, `--listen 127.0.0.1:5673` fixes the port (loopback only), `--vhost` changes the vhost in the printed URL. The client chooses the real vhost; your role limits it.

A role grants broker users with limits shaped like RabbitMQ's own permissions:

```yaml
- resources: { kind: [rabbitmq], labels: { env: [staging] } }
  mq:
    users: [consumer]
    vhosts: ["/", "orders"]        # default: only "/"
    classes: [read]                # read | write | configure. Default: read and write
    names: ["orders.*"]            # exchange and queue name patterns. Default: any name
```

- **read** consumes, gets, acknowledges. **write** publishes (to the default exchange the routing key is the queue, so that name is checked). **configure** declares, deletes, binds and purges exchanges and queues.
- As in RabbitMQ, a queue declared with `x-dead-letter-exchange`, or an exchange with `alternate-exchange`, also needs **write** on that exchange (otherwise a role could route messages where it may not publish). A passive declare ("does this exist?") needs any one class on the name.
- `*` never opens the broker's own `amq.rabbitmq.*` names. Direct reply-to (`amq.rabbitmq.reply-to`) and server-named queues your own session declared always work.
- A refused operation closes **that channel** with `403 ACCESS_REFUSED` (as RabbitMQ does for permission errors); other channels and the connection carry on. An unknown vhost is refused when the connection opens.
- Not supported: AMQP 1.0, Streams, MQTT, STOMP (clients offering them are told what is supported) and Amazon MQ IAM sign-in (use a broker user whose password the worker holds). The management UI and API are [web apps](web-apps.md).

## Kafka and MSK

```sh
limen kafka connect events-kafka-staging --brokers 4
# Listening for events-kafka-staging as consumer (4 broker slots).
# Run: kcat -b 127.0.0.1:51234 -L
```

Use `127.0.0.1:51234` as the bootstrap server with `security.protocol=PLAINTEXT`. Kafka clients connect to every broker at its advertised address, so the command opens one more loopback listener per broker slot (`--brokers N`, default 8, at most 64) and the worker rewrites advertised addresses to those ports. A cluster with more brokers than slots is refused with a message saying so. The worker takes its login to the broker it dials, so it only dials a host in the same domain as `endpoint` (an address stays in its /16) unless the resource lists `hosts` under `kafka` (exact names, `*.suffix` patterns, IP literals); a broker outside that is refused with a message naming `kafka.hosts`. An `endpoint` of two labels, such as `kafka.corp`, shares no domain below the top level, so the worker follows only to names under it (`b-2.kafka.corp`) unless `hosts` says more. If the CLI's ports change, restart the command and your client.

```yaml
- resources: { kind: [kafka], labels: { env: [staging] } }
  kafka:
    users: [consumer]
    classes: [read]                # read | write | admin. Default: read
    topics: ["orders.*"]           # default: any topic that isn't internal
    groups: ["dev-*"]              # consumer groups. Default: any
```

- **read**: fetch, offsets, consumer groups, metadata. **write**: produce. **admin**: create and delete topics (including automatic creation).
- A request naming topics your role doesn't reach is cut down to the ones it does; the rest get `TOPIC_AUTHORIZATION_FAILED`, like broker ACLs. A group you can't use gets `GROUP_AUTHORIZATION_FAILED`.
- `Metadata` lists only topics your role reaches. Internal topics (`__consumer_offsets`) need a pattern starting with `_`.
- **API versions** are pinned to what the worker reads (non-flexible encodings): Produce 3–8, Fetch 4–11, Metadata 1–8, plus the group, offset and topic APIs in the ADR. The worker answers `ApiVersions` itself so clients negotiate down; the Java and librdkafka clients do this unaided. **Transactions, ACL and config changes, partition reassignment and other administration APIs are unavailable.**
- The worker logs in with SASL `PLAIN`, `SCRAM-SHA-256`, `SCRAM-SHA-512`, `AWS_MSK_IAM` (**unverified** against MSK), or nothing (mutual TLS or an open listener). Set `sasl:` on the resource.

## Configuring the worker

```sh
limen-worker ... \
  --broker-credentials-file /etc/limen/broker-credentials.json \
  --broker-ca-file /etc/limen/aws-ca-bundle.pem        # for TLS targets (Amazon MQ, MSK)
```

```json
{ "events-rabbit-staging": { "consumer": "password" },
  "events-kafka-staging":  { "consumer": "password",
                             "svc": { "password": "…", "client_cert_file": "/c.pem", "client_key_file": "/k.pem" } } }
```

TLS to the broker is on by default and verified against `--broker-ca-file`; `tls: false` on the resource is for local brokers.

## What is audited

- **RabbitMQ:** one `mq.operation` event per decoded operation, written *before* forwarding (if it can't be written the operation is refused and the channel closed): `connect`, `publish` (exchange, routing key, **body size**), `consume`, `get`, `declare_queue`, `bind_queue`, and so on. Acknowledgements and deliveries aren't logged individually; `mq.summary` at the end holds the counts. A refusal is `auth.denied` with `action: mq`.
- **Kafka:** `kafka.request` events before forwarding. Group, offset and admin requests are always logged. `Produce` and `Fetch` arrive hundreds of times a second, so they're logged at first contact with each topic and then once a minute with counts and bytes since the last event; `kafka.summary` at the end lists what was counted and not logged. `Heartbeat` is counted only. A refusal is `auth.denied` with `action: kafka`.
- Never logged: message bodies and properties, record keys and values, headers.
- These sessions have no terminal recording. The console session page lists operations in order with refused ones marked, like Redis commands; the same events are in the hash-chained trail.

## Running it

- **Sessions per client.** A Kafka client holds one connection per broker it talks to, each a Limen session with its own broker login. A consumer on a 3-broker cluster is about 3–4 sessions, a producer similar; count them against the worker's `--max-sessions` (default 200). Each SCRAM login costs the broker a key derivation (4096 iterations by default).
- **Upgrade order.** Components from before Phase 11 reject snapshots containing the new fields (`mq.classes`, `kafka.topics`, `sasl`, `tls`, …). Upgrade the control plane, then proxies, then workers, and only then apply a policy that uses them.
- **Metrics** (worker): `limen_broker_refused_total{protocol}` (refused by policy), `limen_broker_audit_failures_total{protocol}` (refused because the audit event couldn't be written; alert on it, since clients are being turned away) and `limen_worker_sessions_active`.
- **Troubleshooting.** A Kafka client that connects and hangs after `Metadata` usually faces a cluster with more brokers than `--brokers`; the worker logs and audits `auth.denied` with the number to use. After a broker is replaced, restart `limen kafka connect` only if the broker count changed. `auth.denied` events state the reason in plain words.
- **Audit volume.** Every AMQP publish is an event. Thousands of messages a second means thousands of events a second (written in groups per socket read). Plan the audit sink for it, or keep such producers off Limen.
