"""Phase 11 scenarios: real RabbitMQ 4 and a real three-broker Kafka cluster
through Limen, with real clients (pika, and librdkafka via confluent-kafka).
Run by demos/demo-phase11.sh, which sets the environment up."""
import collections
import json
import os
import re
import subprocess
import sys
import time

import pika
from confluent_kafka import Consumer, KafkaError, Producer, TopicPartition
from confluent_kafka.admin import AdminClient

STATE = os.environ["LIMEN_MQ_STATE"]
LIMEN = os.environ["LIMEN_BIN"]
COMPOSE = json.loads(os.environ["LIMEN_COMPOSE_JSON"])  # the demo's `docker compose` command
HOMES = {"dev": os.environ["HOME_DEV"], "sre": os.environ["HOME_ADMIN"]}
procs = []
failures = []


def check(ok, msg):
    print(("\033[32mPASS\033[0m " if ok else "\033[31mFAIL\033[0m ") + msg, flush=True)
    if not ok:
        failures.append(msg)


def step(msg):
    print(f"\n\033[1m== {msg}\033[0m", flush=True)


def listen(who, kind, resource, *extra):
    env = dict(os.environ, LIMEN_HOME=HOMES[who])
    log = os.path.join(STATE, f"listen-{who}-{kind}-{resource}.log")
    f = open(log, "w")
    p = subprocess.Popen([LIMEN, kind, "connect", resource, *extra], stdout=f, stderr=subprocess.STDOUT, env=env)
    procs.append(p)
    pattern = r"amqp://limen:limen@127\.0\.0\.1:(\d+)/" if kind == "mq" else r"kcat -b 127\.0\.0\.1:(\d+)"
    for _ in range(80):
        m = re.search(pattern, open(log).read())
        if m:
            return int(m.group(1))
        time.sleep(0.25)
    print(open(log).read())
    raise SystemExit(f"no listener for {who} {kind} {resource}")


def amqp(port, vhost="/"):
    params = pika.ConnectionParameters("127.0.0.1", port, vhost, pika.PlainCredentials("anyone", "anything"),
                                       heartbeat=30, blocked_connection_timeout=10)
    return pika.BlockingConnection(params)


def audit_events():
    out = os.path.join(STATE, "audit.jsonl")
    subprocess.run([*COMPOSE, "cp", "control-plane:/var/lib/limen/audit/control-plane.jsonl", out],
                   check=True, capture_output=True)
    text = open(out).read()
    return text, [json.loads(l) for l in text.splitlines() if l.strip()]


def kafka_conf(port, **extra):
    return {"bootstrap.servers": f"127.0.0.1:{port}", "security.protocol": "PLAINTEXT",
            "socket.timeout.ms": 10000, "reconnect.backoff.max.ms": 1000, **extra}


# ---------------------------------------------------------------- RabbitMQ
step("RabbitMQ: sre configures, publishes, and reads back, with no password")
sre = listen("sre", "mq", "events-rabbit-staging", "--user", "admin")
dev = listen("dev", "mq", "events-rabbit-staging")
conn = amqp(sre)
ch = conn.channel()
ch.queue_declare("orders.q", durable=False)
ch.exchange_declare("orders.x", exchange_type="direct")
ch.queue_bind("orders.q", "orders.x", "new")
ch.confirm_delivery()
for i in range(3):
    ch.basic_publish("orders.x", "new", f"order-{i}-card-4111111111111111".encode())
got = []
for _ in range(3):
    method, props, body = ch.basic_get("orders.q", auto_ack=True)
    got.append(body.decode())
check(got == [f"order-{i}-card-4111111111111111" for i in range(3)], "published 3 messages with confirms and got them back in order")
conn.close()

step("RabbitMQ: the developer reads, and Limen closes the channel for anything else")
ch2 = amqp(sre).channel()
ch2.basic_publish("orders.x", "new", b"for-the-developer")
time.sleep(0.5)
conn = amqp(dev)
ch = conn.channel()
method, props, body = ch.basic_get("orders.q", auto_ack=True)
check(body == b"for-the-developer", "developer consumed from orders.q (read, names orders.*)")
def refused(fn):
    c = amqp(dev)
    try:
        fn(c.channel())
    except pika.exceptions.ChannelClosedByBroker as e:
        return e.reply_code, str(e.reply_text)
    except pika.exceptions.AMQPError as e:
        return -1, repr(e)
    finally:
        try: c.close()
        except Exception: pass
    return None
r = refused(lambda ch: (ch.basic_publish("orders.x", "new", b"nope"), ch.queue_declare("zzz", passive=True)))
check(r is not None and r[0] == 403, f"publish by a read-only role: channel closed with 403 ({r})")
r = refused(lambda ch: ch.queue_declare("orders.mine", durable=False))
check(r is not None and r[0] == 403, f"declare by a role without configure: 403 ({r})")
r = refused(lambda ch: ch.basic_get("payments.q"))
check(r is not None and r[0] == 403, f"get from a queue the names don't cover: 403 ({r})")
try:
    amqp(dev, "secret")
    check(False, "vhost 'secret' must be refused")
except pika.exceptions.AMQPError as e:
    check(True, f"vhost 'secret' refused at connection time ({type(e).__name__})")
conn.close()

step("RabbitMQ: a refused channel doesn't take the connection with it")
conn = amqp(dev)
bad = conn.channel()
try:
    bad.basic_publish("orders.x", "new", b"x"); bad.queue_declare("orders.q", passive=True)
except pika.exceptions.ChannelClosedByBroker:
    pass
good = conn.channel()
m, p, b = good.basic_get("orders.q", auto_ack=True)
check(True, "a second channel on the same connection still works")
conn.close()

# ---------------------------------------------------------------- Kafka
step("Kafka: a real 3-broker cluster behind one bootstrap listener")
sre_k = listen("sre", "kafka", "events-kafka-staging", "--user", "admin", "--brokers", "4")
dev_k = listen("dev", "kafka", "events-kafka-staging")
admin = AdminClient(kafka_conf(sre_k))
md = admin.list_topics(timeout=20)
broker_addrs = {b.id: (b.host, b.port) for b in md.brokers.values()}
check(len(broker_addrs) == 3 and all(h == "127.0.0.1" for h, _ in broker_addrs.values()),
      f"Metadata advertises 3 brokers, all on loopback: {broker_addrs}")
check(len({p for _, p in broker_addrs.values()}) == 3, "each broker has its own local port")
leaders = {p.leader for p in md.topics["orders.new"].partitions.values()}
check(len(leaders) == 3, f"orders.new's 6 partitions are led by all 3 brokers: leaders {sorted(leaders)}")

step("Kafka: produce to every partition, consume it back through another listener")
prod = Producer(kafka_conf(sre_k, **{"enable.idempotence": True, "acks": "all"}))
delivered = {}
errors = []
def on_delivery(err, msg):
    if err: errors.append(str(err))
    else: delivered[msg.partition()] = delivered.get(msg.partition(), 0) + 1
for part in range(6):
    for i in range(3):
        prod.produce("orders.new", value=f"secret-payload-{part}-{i}".encode(), partition=part, callback=on_delivery)
prod.flush(30)
check(not errors and sum(delivered.values()) == 18 and set(delivered) == set(range(6)),
      f"18 records acknowledged across all 6 partitions (leaders on 3 brokers): {delivered} {errors}")
cons = Consumer(kafka_conf(dev_k, **{"group.id": "dev-g1", "auto.offset.reset": "earliest", "enable.auto.commit": False}))
cons.subscribe(["orders.new"])
seen = []
deadline = time.time() + 45
while len(seen) < 18 and time.time() < deadline:
    m = cons.poll(1.0)
    if m is None: continue
    if m.error():
        if m.error().code() in (KafkaError._PARTITION_EOF,): continue
        print("consumer error", m.error()); continue
    seen.append(m.value().decode())
check(len(seen) == 18, f"developer's consumer group dev-g1 read all 18 records through the rewritten broker addresses ({len(seen)})")
cons.commit(asynchronous=False)
check(True, "offsets committed through the group coordinator (FindCoordinator rewritten)")
cons.close()

step("Kafka: the developer sees only what the role reaches")
dmd = AdminClient(kafka_conf(dev_k)).list_topics(timeout=20)
names = set(dmd.topics)
check("orders.new" in names and "payments" not in names and "__consumer_offsets" not in names,
      f"Metadata lists only orders.new for the developer: {sorted(names)}")
errs = []
p2 = Producer(kafka_conf(dev_k))
p2.produce("orders.new", b"x", callback=lambda e, m: errs.append(e))
p2.flush(15)
check(errs and errs[0] is not None and errs[0].code() == KafkaError.TOPIC_AUTHORIZATION_FAILED,
      f"a read-only role can't produce: {errs[0] if errs else 'no result'}")
c2 = Consumer(kafka_conf(dev_k, **{"group.id": "dev-g2", "auto.offset.reset": "earliest"}))
c2.assign([TopicPartition("payments", 0)])
bad = None
for _ in range(10):
    m = c2.poll(1.0)
    if m is not None and m.error():
        bad = m.error(); break
check(bad is not None and bad.code() in (KafkaError.TOPIC_AUTHORIZATION_FAILED, KafkaError._UNKNOWN_TOPIC, KafkaError.UNKNOWN_TOPIC_OR_PART),
      f"reading payments is refused: {bad}")
c2.close()
c3 = Consumer(kafka_conf(dev_k, **{"group.id": "not-allowed", "auto.offset.reset": "earliest"}))
c3.subscribe(["orders.new"])
gerr = None
for _ in range(15):
    m = c3.poll(1.0)
    if m is not None and m.error():
        gerr = m.error(); break
check(gerr is not None, f"a consumer group outside dev-* is refused: {gerr}")
c3.close()

step("Kafka: the SCRAM resource works the same way")
scram = listen("sre", "kafka", "events-kafka-scram", "--user", "admin", "--brokers", "4")
sp = Producer(kafka_conf(scram))
res = []
sp.produce("orders.new", b"via-scram", callback=lambda e, m: res.append(e))
sp.flush(30)
check(res and res[0] is None, "SCRAM-SHA-512 login by the worker, produce acknowledged")

step("Kafka: killing a broker doesn't break the session after a metadata refresh")
subprocess.run([*COMPOSE, "stop", "kafka-3"], check=True, capture_output=True)
time.sleep(8)
fp = Producer(kafka_conf(sre_k, **{"acks": "all", "message.timeout.ms": 60000}))
out = []
for i in range(6):
    fp.produce("orders.new", f"after-failover-{i}".encode(), partition=i, callback=lambda e, m: out.append(e))
fp.flush(60)
check(len(out) == 6 and all(e is None for e in out), f"produce to all 6 partitions with broker 3 down: {out}")
subprocess.run([*COMPOSE, "start", "kafka-3"], check=True, capture_output=True)

# ---------------------------------------------------------------- audit
step("Audit trail")
time.sleep(8)
text, events = audit_events()
print("  " + ", ".join(f"{k}={v}" for k, v in sorted(collections.Counter(e["kind"] for e in events).items())))
mq = [e for e in events if e["kind"] == "mq.operation"]
check(any(e["data"]["action"] == "publish" and e["data"]["exchange"] == "orders.x" and e["data"]["size"] == len("order-0-card-4111111111111111") for e in mq),
      "mq.operation publish with exchange, routing key and body size")
check(any(e["data"]["action"] == "consume" or e["data"]["action"] == "get" for e in mq), "mq.operation get/consume")
check(any(e["kind"] == "auth.denied" and e["data"].get("action") == "mq" and e["data"].get("operation") == "publish" for e in events),
      "the refused publish is auth.denied")
kr = [e for e in events if e["kind"] == "kafka.request"]
check(any(e["data"]["api"] == "Produce" for e in kr) and any(e["data"]["api"] == "Fetch" for e in kr),
      "kafka.request for Produce and Fetch")
check(any(e["kind"] == "auth.denied" and e["data"].get("action") == "kafka" for e in events), "refused Kafka requests are auth.denied")
check(any(e["kind"] == "kafka.summary" for e in events), "kafka.summary at session end")
for secret in ("4111111111111111", "for-the-developer", "secret-payload", "admin-dev-only", "consumer-dev-only", "anything"):
    check(secret not in text, f"{secret!r} is not in the audit trail")
sessions = [e for e in events if e["kind"] == "session.start" and e["data"]["kind"] in ("rabbitmq", "kafka")]
ends = {e["session_id"] for e in events if e["kind"] == "session.end"}
check(len(sessions) > 5 and any(s["session_id"] in ends for s in sessions), "session.start/end for rabbitmq and kafka sessions")
check(all(e.get("session_id") for e in mq + kr), "every operation links to a session")

step("One row per run in the console")
# A client holds a connection to every broker, so a `limen kafka connect` run is
# many sessions. They carry the run's group and the console shows one row.
check(all(s["data"].get("group") for s in sessions), "every session start carries its run's group")
by_run = collections.defaultdict(set)
for s_ in sessions:
    by_run[(s_["user"], s_["data"]["resource"], s_["data"].get("mq_user") or s_["data"].get("kafka_user"), s_["data"]["group"])].add(s_["session_id"])
kafka_runs = [n for (u, r, p_, g), n in by_run.items() if r.startswith("events-kafka")]
check(any(len(n) >= 3 for n in kafka_runs), f"a Kafka run's connections share one group (largest run: {max(map(len, kafka_runs))} sessions)")
groups = collections.defaultdict(set)
for (u, r, p_, g) in by_run:
    groups[g].add((u, r))
check(all(len(v) == 1 for v in groups.values()), "no group spans two users or resources")
rows = subprocess.run([*COMPOSE, "exec", "-T", "postgres", "psql", "-U", "limen", "-d", "limen", "-At", "-c",
                       "select count(*), count(distinct conn_group) from sessions where kind in ('rabbitmq','kafka')"],
                      check=True, capture_output=True, text=True).stdout.strip()
total, runs = (int(x) for x in rows.split("|"))
check(total > runs >= 2, f"the console groups {total} sessions into {runs} runs")

for p in procs:
    p.terminate()
if failures:
    print(f"\n{len(failures)} check(s) failed:")
    for f in failures: print("  -", f)
    sys.exit(1)
