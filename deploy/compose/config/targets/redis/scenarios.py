#!/usr/bin/env python3
"""Phase 7 scenario tests (driven by ../../test-phase7-scenarios.sh).

Each scenario opens real `limen redis connect` listeners against the compose
stack and talks RESP to them. They run independently: a failure is reported
and the rest still run. Dev tooling only.

    scenarios.py [NAME_SUBSTRING ...]     run the scenarios whose name matches
"""
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import traceback
import uuid

E = os.environ
LIMEN = E["LIMEN_BIN"]
PROJECT = E["SCN_PROJECT"]
FILES = E["SCN_FILES"].split()
STATE = E["SCN_STATE"]
HEALTH = E["LIMEN_REDIS_HEALTH_PORT"]
HOME = {"admin": E["HOME_ADMIN"], "dev": E["HOME_DEV"]}
SECRET = "SECRETVAL-" + uuid.uuid4().hex  # must never reach an audit event or a log
CLIENT_PW = "client-pw-" + uuid.uuid4().hex


# ---------------------------------------------------------------- RESP


class Err(str):
    pass


class Push(list):
    pass


def read_line(f):
    line = f.readline()
    if not line:
        raise EOFError("connection closed")
    return line.rstrip(b"\r\n")


def read_reply(f):
    line = read_line(f)
    kind, rest = line[:1], line[1:]
    if kind == b"+":
        return rest.decode()
    if kind == b"-":
        return Err(rest.decode(errors="replace"))
    if kind == b":" or kind == b"(":
        return int(rest)
    if kind in (b"$", b"=", b"!"):
        n = int(rest)
        if n < 0:
            return None
        data = f.read(n + 2)[:-2]
        if len(data) != n:
            raise EOFError("short bulk")
        if kind == b"!":
            return Err(data.decode(errors="replace"))
        return data[4:] if kind == b"=" else data
    if kind in (b"*", b"~", b">"):
        n = int(rest)
        if n < 0:
            return None
        items = [read_reply(f) for _ in range(n)]
        return Push(items) if kind == b">" else items
    if kind == b"%":
        n = int(rest)
        out = {}
        for _ in range(n):
            k = read_reply(f)
            out[k if not isinstance(k, bytes) else k.decode(errors="replace")] = read_reply(f)
        return out
    if kind == b"|":
        for _ in range(int(rest) * 2):
            read_reply(f)
        return read_reply(f)
    if kind == b"_":
        return None
    if kind == b"#":
        return rest == b"t"
    if kind == b",":
        return float(rest)
    raise ValueError(f"unknown RESP type {line!r}")


def enc(words):
    out = b"*%d\r\n" % len(words)
    for w in words:
        w = w if isinstance(w, bytes) else str(w).encode()
        out += b"$%d\r\n%s\r\n" % (len(w), w)
    return out


class Conn:
    def __init__(self, target, timeout=20):
        if isinstance(target, int):
            self.s = socket.create_connection(("127.0.0.1", target), timeout=timeout)
        else:
            self.s = socket.socket(socket.AF_UNIX)
            self.s.settimeout(timeout)
            self.s.connect(target)
        self.f = self.s.makefile("rb")

    def send(self, *words):
        self.s.sendall(enc(words))

    def raw(self, data):
        self.s.sendall(data)

    def read(self):
        return read_reply(self.f)

    def call(self, *words):
        self.send(*words)
        return self.read()

    def close(self):
        # makefile() keeps the socket open until it is closed too.
        for closer in (lambda: self.s.shutdown(socket.SHUT_RDWR), self.f.close, self.s.close):
            try:
                closer()
            except OSError:
                pass

    def closed_within(self, seconds):
        """True if the peer closes (EOF or reset) within the time."""
        self.s.settimeout(seconds)
        try:
            return self.s.recv(1) == b""
        except socket.timeout:
            return False
        except OSError:
            return True


# ---------------------------------------------------------------- stack helpers


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def compose(*args):
    return run(["docker", "compose", "-p", PROJECT, *FILES, *args])


def server(service, *cmd):
    """A command straight to a target, as its read-write ACL user (bypasses Limen)."""
    cli = "valkey-cli" if service == "valkey-target" else "redis-cli"
    extra = ["--tls", "--cacert", "/tls/ca.crt"] if service == "redis-tls" else []
    r = compose("exec", "-T", service, cli, *extra, "--user", "limen-rw", "--pass", "rw-dev-only",
                "--no-auth-warning", *cmd)
    return r.stdout.strip()


def limen(who, *args):
    return run([LIMEN, *args], env={**E, "LIMEN_HOME": HOME[who]})


class Listener:
    """`limen redis connect` as a person; `.port` (or `.path`) once it is listening."""

    def __init__(self, resource, who="admin", user="limen-rw", extra=()):
        self.lines = []
        self.p = subprocess.Popen(
            [LIMEN, "redis", "connect", resource, "--user", user, *extra],
            env={**E, "LIMEN_HOME": HOME[who]},
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.port = None
        self.path = None
        self.ready = threading.Event()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.p.stdout:
            self.lines.append(line.rstrip())
            m = re.search(r"-p (\d+)", line)
            if m:
                self.port = int(m.group(1))
            m = re.search(r"-s (\S+)", line)
            if m:
                self.path = m.group(1)
            if self.port or self.path:
                self.ready.set()
        self.ready.set()

    def __enter__(self):
        self.ready.wait(30)
        if self.port is None and self.path is None:
            raise RuntimeError("no listener: " + " | ".join(self.lines))
        return self

    def conn(self, **kw):
        return Conn(self.port if self.port else self.path, **kw)

    def __exit__(self, *a):
        self.p.terminate()
        try:
            self.p.wait(5)
        except subprocess.TimeoutExpired:
            self.p.kill()


def failed_listener(resource, who="admin", user="limen-rw"):
    """The text `limen redis connect` fails with (it must fail, not listen)."""
    r = run([LIMEN, "redis", "connect", resource, "--user", user],
            env={**E, "LIMEN_HOME": HOME[who]}, timeout=60)
    assert r.returncode != 0, f"expected a refusal, got: {r.stdout}"
    return r.stderr + r.stdout


def audit_events():
    r = compose("cp", "control-plane:/var/lib/limen/audit/control-plane.jsonl", f"{STATE}/audit.jsonl")
    with open(f"{STATE}/audit.jsonl") as fh:
        return [json.loads(l) for l in fh if l.strip()]


# ---------------------------------------------------------------- harness

SCENARIOS = []
results = []


def scenario(fn):
    SCENARIOS.append(fn)
    return fn


def check(cond, msg="check failed"):
    if not cond:
        raise AssertionError(msg)


def denied(reply, text=None):
    return isinstance(reply, Err) and reply.startswith("NOPERM Limen") and (text is None or text in reply)


# ---------------------------------------------------------------- scenarios


@scenario
def basic_data_types_on_redis_valkey_and_tls():
    for res in ("cache-staging", "cache-valkey", "cache-tls"):
        with Listener(res) as l:
            c = l.conn()
            k = f"t:{res}:{uuid.uuid4().hex[:6]}"
            check(c.call("SET", k, "v1") == "OK", res)
            check(c.call("GET", k) == b"v1", res)
            check(c.call("INCR", k + ":n") == 1 and c.call("INCRBY", k + ":n", 41) == 42, res)
            check(c.call("HSET", k + ":h", "a", "1", "b", "2") == 2, res)
            check(sorted(c.call("HGETALL", k + ":h")) == [b"1", b"2", b"a", b"b"], res)
            check(c.call("RPUSH", k + ":l", "x", "y", "z") == 3, res)
            check(c.call("LRANGE", k + ":l", 0, -1) == [b"x", b"y", b"z"], res)
            check(c.call("ZADD", k + ":z", 1, "m") == 1 and c.call("ZRANGE", k + ":z", 0, -1) == [b"m"], res)
            check(c.call("SADD", k + ":s", "q") == 1, res)
            check(c.call("EXPIRE", k, 100) == 1 and 0 < c.call("TTL", k) <= 100, res)
            check(c.call("DEL", k, k + ":n", k + ":h", k + ":l", k + ":z", k + ":s") == 6, res)
            check(c.call("GET", k) is None, res)
            check(c.call("PING") == "PONG", res)
            c.close()


@scenario
def resp3_hello_maps_and_nulls():
    with Listener("cache-staging") as l:
        c = l.conn()
        h = c.call("HELLO", "3")
        check(isinstance(h, dict) and h.get("proto") == 3, f"HELLO 3 -> {h!r}")
        c.call("HSET", "t:r3", "f", "v")
        check(c.call("HGETALL", "t:r3") == {b"f": b"v"} or c.call("HGETALL", "t:r3") == {"f": b"v"}, "map reply")
        check(c.call("GET", "t:r3:missing") is None, "RESP3 null")
        c.call("DEL", "t:r3")
        h = c.call("HELLO", "2")
        check(isinstance(h, list), f"HELLO 2 -> {h!r}")
        check(c.call("PING") == "PONG")


@scenario
def large_and_binary_values_survive_intact():
    with Listener("cache-staging") as l:
        c = l.conn(timeout=60)
        blob = os.urandom(20 * 1024 * 1024)
        check(c.call("SET", "t:blob", blob) == "OK")
        back = c.call("GET", "t:blob")
        check(hashlib.sha256(back).digest() == hashlib.sha256(blob).digest(), "20 MiB round trip")
        weird = b"line1\r\nline2\x00\xff\xfe $5\r\n*3\r\n"
        check(c.call("SET", "t:weird", weird) == "OK" and c.call("GET", "t:weird") == weird, "CRLF and NUL in values")
        utf = "héllo ✓ 世界".encode()
        check(c.call("SET", "t:utf", utf) == "OK" and c.call("GET", "t:utf") == utf)
        check(c.call("DEL", "t:blob", "t:weird", "t:utf") == 3)


@scenario
def huge_pipeline_keeps_order():
    with Listener("cache-staging") as l:
        c = l.conn(timeout=120)
        n = 20000
        t0 = time.time()
        c.raw(b"".join(enc(["SET", f"t:p:{i}", f"v{i}"]) for i in range(n)))
        check(all(c.read() == "OK" for _ in range(n)), "SET replies")
        c.raw(b"".join(enc(["GET", f"t:p:{i}"]) for i in range(n)))
        for i in range(n):
            r = c.read()
            check(r == f"v{i}".encode(), f"reply {i} was {r!r}")
        c.raw(b"".join(enc(["DEL", f"t:p:{i}"]) for i in range(n)))
        check(sum(c.read() for _ in range(n)) == n)
        took = time.time() - t0
        print(f"    {3 * n} pipelined commands in {took:.1f}s", flush=True)
        check(took < 120, f"pipeline took {took:.0f}s")


@scenario
def one_command_at_a_time_latency_is_bounded():
    with Listener("cache-staging") as l:
        c = l.conn()
        c.call("PING")
        n = 200
        t0 = time.time()
        for _ in range(n):
            c.call("PING")
        per = (time.time() - t0) / n * 1000
        print(f"    {per:.1f} ms per sequential command (audit is written before each one)", flush=True)
        check(per < 60, f"{per:.1f} ms per command")


@scenario
def refusals_inside_a_pipeline_keep_every_reply_in_place():
    with Listener("cache-staging") as l:
        c = l.conn()
        words = []
        expect = []
        for i in range(600):
            if i % 3 == 0:
                words.append(["FLUSHALL"]); expect.append("denied")
            elif i % 3 == 1:
                words.append(["SET", f"t:o:{i}", f"v{i}"]); expect.append("OK")
            else:
                words.append(["GET", f"t:o:{i-1}"]); expect.append(f"v{i-1}".encode())
        c.raw(b"".join(enc(w) for w in words))
        for i, e in enumerate(expect):
            r = c.read()
            if e == "denied":
                check(denied(r, "FLUSHALL"), f"#{i}: {r!r}")
            else:
                check(r == e, f"#{i}: {r!r} != {e!r}")
        c.call("DEL", *[f"t:o:{i}" for i in range(1, 600, 3)])


@scenario
def transactions_run_and_a_refused_command_aborts_them():
    with Listener("cache-staging") as l:
        c = l.conn()
        check(c.call("MULTI") == "OK")
        check(c.call("SET", "t:tx:a", "1") == "QUEUED")
        check(c.call("INCR", "t:tx:a") == "QUEUED")
        r = c.call("EXEC")
        check(r == ["OK", 2], f"EXEC -> {r!r}")
        # A refused command inside MULTI must not leave the rest to run.
        check(c.call("MULTI") == "OK")
        check(c.call("SET", "t:tx:b", "should-not-exist") == "QUEUED")
        check(denied(c.call("FLUSHALL")))
        check(c.call("SET", "t:tx:c", "should-not-exist") == "QUEUED")
        r = c.call("EXEC")
        check(isinstance(r, Err) and r.startswith("EXECABORT"), f"EXEC -> {r!r}")
        check(c.call("GET", "t:tx:b") is None and c.call("GET", "t:tx:c") is None, "nothing from the aborted transaction ran")
        check(c.call("PING") == "PONG", "replies stay aligned after the abort")
        check(c.call("MULTI") == "OK" and c.call("DISCARD") == "OK")
        c.call("DEL", "t:tx:a")


@scenario
def pubsub_messages_flow_and_refusals_are_answered_while_subscribed():
    with Listener("cache-staging") as sub_l, Listener("cache-staging") as pub_l:
        sub, pub = sub_l.conn(), pub_l.conn()
        check(sub.call("SUBSCRIBE", "t:chan") == [b"subscribe", b"t:chan", 1])
        check(pub.call("PUBLISH", "t:chan", "hello") == 1)
        check(sub.read() == [b"message", b"t:chan", b"hello"], "message pushed to the subscriber")
        r = sub.call("FLUSHALL")
        check(denied(r), f"refusal while subscribed -> {r!r}")
        check(pub.call("PUBLISH", "t:chan", "again") == 1)
        check(sub.read() == [b"message", b"t:chan", b"again"])
        sub.send("UNSUBSCRIBE", "t:chan")
        check(sub.read() == [b"unsubscribe", b"t:chan", 0])
        # RESP3: pushes arrive as `>` frames, and normal commands still reply.
        r3 = sub_l.conn()
        r3.call("HELLO", "3")
        r3.send("SUBSCRIBE", "t:chan3")
        first = r3.read()
        check(isinstance(first, Push) and first[0] == b"subscribe", f"{first!r}")
        pub.call("PUBLISH", "t:chan3", "p3")
        m = r3.read()
        check(isinstance(m, Push) and m[0] == b"message" and m[2] == b"p3", f"{m!r}")
        check(r3.call("GET", "t:nothing-here") is None)


@scenario
def blocking_commands_do_not_wedge_the_session():
    with Listener("cache-staging") as l:
        c = l.conn()
        t0 = time.time()
        c.raw(enc(["BLPOP", "t:empty-list", 1]) + enc(["PING"]))
        check(c.read() is None, "BLPOP timeout -> nil")
        check(c.read() == "PONG", "the pipelined PING answers after the block")
        check(0.8 < time.time() - t0 < 5)
        other = l.conn()
        c.send("BLPOP", "t:wake", 10)
        time.sleep(0.3)
        other.call("RPUSH", "t:wake", "x")
        check(c.read() == [b"t:wake", b"x"], "woken by another session")


@scenario
def multi_key_and_pattern_commands_cannot_escape_the_key_limits():
    # developer: limen-rw through the redis-lab role (keys lab:* only)
    server("redis-target", "SET", "secret:k", "classified")
    with Listener("cache-staging", who="dev", user="limen-rw") as l:
        c = l.conn()
        check(c.call("SET", "lab:a", "1") == "OK")
        check(c.call("MSET", "lab:b", "2", "lab:c", "3") == "OK")
        for words in (
            ["GET", "secret:k"],
            ["MSET", "lab:ok", "1", "secret:k", "pwned"],
            ["DEL", "lab:a", "secret:k"],
            ["RENAME", "lab:a", "other:a"],
            ["COPY", "secret:k", "lab:stolen"],
            ["SORT", "lab:list", "BY", "secret:*"],
            ["SORT", "lab:list", "GET", "secret:*"],
            ["SORT", "lab:list", "STORE", "other:out"],
            ["ZUNIONSTORE", "lab:z", 2, "lab:a", "secret:k"],
            ["XREAD", "STREAMS", "secret:s", "0"],
            ["BITOP", "OR", "lab:dest", "lab:a", "secret:k"],
            ["EVAL", "return redis.call('get','secret:k')", 0],
            ["EVAL", "return 1", 1, "lab:a"],
            ["KEYS", "*"], ["SCAN", 0], ["RANDOMKEY"],
            ["FLUSHDB"],          # opened by allow_commands, but still wipes everything
            ["FLUSHALL"],
            ["SLOWLOG", "GET"],
            ["GEORADIUS", "lab:g", 0, 0, 1, "km", "STORE", "other:g"],
        ):
            r = c.call(*words)
            check(denied(r), f"{words} -> {r!r}")
        check(server("redis-target", "GET", "secret:k") == "classified", "nothing reached the secret key")
        check(server("redis-target", "EXISTS", "lab:ok", "other:a", "lab:stolen", "other:out", "lab:dest") == "0",
              "none of the refused writes happened")
        # Keys inside the pattern with variable-length commands are fine.
        check(c.call("DEL", "lab:a", "lab:b", "lab:c") == 3)
        check(c.call("EXISTS", "lab:a", "lab:b") == 0)
    server("redis-target", "DEL", "secret:k")


@scenario
def container_commands_and_key_events_respect_the_key_limits():
    server("redis-target", "SET", "secret:k", "classified")
    server("redis-target", "XADD", "secret:s", "*", "f", "v")
    with Listener("cache-staging", who="dev", user="limen-rw") as l:
        c = l.conn()
        check(c.call("SET", "lab:a", "1") == "OK")
        check(c.call("OBJECT", "ENCODING", "lab:a") is not None, "inside the limit")
        for words in (
            ["OBJECT", "ENCODING", "secret:k"], ["OBJECT", "FREQ", "secret:k"], ["OBJECT", "IDLETIME", "secret:k"],
            ["MEMORY", "USAGE", "secret:k"],
            ["XINFO", "STREAM", "secret:s"], ["XINFO", "GROUPS", "secret:s"],
            ["XGROUP", "CREATE", "secret:s", "g", "$"], ["XGROUP", "DESTROY", "secret:s", "g"],
            ["XREADGROUP", "GROUP", "STREAMS", "c", "STREAMS", "lab:s", "secret:s", "0", "0"],
            ["PSUBSCRIBE", "*"], ["PSUBSCRIBE", "__key*"], ["PSUBSCRIBE", "__keyevent@0__:*"],
            ["SUBSCRIBE", "__keyspace@0__:secret:k"],
            ["CLIENT", "TRACKING", "ON", "BCAST"], ["PUBSUB", "CHANNELS"], ["CLIENT", "LIST"],
        ):
            r = c.call(*words)
            check(denied(r), f"{words} -> {r!r}")
        check("g" not in server("redis-target", "XINFO", "GROUPS", "secret:s").split(), "no group was created")
        # An ordinary channel still works.
        check(c.call("PSUBSCRIBE", "news.*") is not None)
    server("redis-target", "DEL", "secret:k", "secret:s")


@scenario
def a_client_that_closes_its_writing_side_still_gets_its_replies():
    with Listener("cache-staging") as l:
        c = l.conn()
        c.send("SET", "half:k", "v")
        c.send("GET", "half:k")
        c.send("FLUSHALL")
        c.s.shutdown(socket.SHUT_WR)
        check(c.read() == "OK")
        check(c.read() == b"v")
        check(denied(c.read()))
    server("redis-target", "DEL", "half:k")


@scenario
def subscribing_after_pipelined_commands_keeps_order():
    with Listener("cache-staging") as l:
        c = l.conn()
        c.send("PING")
        c.send("FLUSHALL")
        c.send("SUBSCRIBE", "news")
        check(c.read() == "PONG")
        check(denied(c.read()))
        sub = c.read()
        check(isinstance(sub, list) and sub[0] == b"subscribe", f"{sub!r}")
        check(denied(c.call("FLUSHALL")), "refusals are answered at once while subscribed")


@scenario
def the_console_lists_the_commands_of_a_redis_session():
    marker = f"console{int(time.time())}"
    with Listener("cache-staging", who="dev", user="limen-rw") as l:
        c = l.conn()
        check(c.call("SET", f"lab:{marker}", "the-secret-value") == "OK")
        check(c.call("GET", f"lab:{marker}") == b"the-secret-value")
        check(denied(c.call("FLUSHALL")))
    rows = ""
    for _ in range(30):   # events reach the control plane in batches
        r = compose("exec", "-T", "postgres", "psql", "-U", "limen", "-d", "limen", "-At", "-F", "|", "-c",
                    "SELECT statement_type, statement, status FROM db_statements "
                    f"WHERE statement LIKE '%{marker}%' OR (statement = 'FLUSHALL' AND status = 'denied') ORDER BY at")
        rows = r.stdout
        if f"GET lab:{marker}" in rows and "FLUSHALL" in rows:
            break
        time.sleep(2)
    check(f"set|SET lab:{marker}|allowed" in rows, rows)
    check(f"get|GET lab:{marker}|allowed" in rows, rows)
    check("flushall|FLUSHALL|denied" in rows, rows)
    check("the-secret-value" not in rows, "values never reach the console table")


@scenario
def developer_readonly_user_gets_two_layers_of_control():
    with Listener("cache-staging", who="dev", user="limen-ro") as l:
        c = l.conn()
        server("redis-target", "SET", "app:s1", "ok")
        check(c.call("GET", "app:s1") == b"ok")
        check(denied(c.call("GET", "secret:1"), "outside the keys"))
        r = c.call("SET", "app:s1", "x")
        check(isinstance(r, Err) and r.startswith("NOPERM") and "Limen" not in r, f"server ACL layer -> {r!r}")
        check(denied(c.call("KEYS", "app:*")))
        server("redis-target", "DEL", "app:s1")


@scenario
def command_spelling_and_inline_forms():
    with Listener("cache-staging") as l:
        c = l.conn()
        check(denied(c.call("flushall")) and denied(c.call("FlushAll")) and denied(c.call("fLuShDb")))
        check(denied(c.call("config", "get", "*")) and denied(c.call("CONFIG", "SET", "requirepass", "x")))
        c.raw(b"set t:inline \"two words\"\r\n")
        check(c.read() == "OK")
        c.raw(b"get t:inline\r\n")
        check(c.read() == b"two words")
        c.raw(b"\r\n\r\nPING\r\n")   # blank lines are ignored
        check(c.read() == "PONG")
        c.raw(b"FLUSHALL\r\n")
        check(denied(c.read()), "inline FLUSHALL")
        c.raw(b"config   get  maxmemory\r\n")
        check(denied(c.read()), "inline CONFIG with extra spaces")
        c.call("DEL", "t:inline")


@scenario
def select_and_databases():
    with Listener("cache-staging") as l:
        c = l.conn()
        check(c.call("SELECT", 0) == "OK")
        for db in (1, 15, "abc", -1):
            check(denied(c.call("SELECT", db)), f"SELECT {db}")
        check(denied(c.call("COPY", "a", "b", "DB", 3)))
        check(denied(c.call("MOVE", "a", 2)))
        check(denied(c.call("SWAPDB", 0, 1)))


@scenario
def client_identity_is_the_workers_not_the_clients():
    with Listener("cache-staging") as l:
        c = l.conn()
        check(c.call("AUTH", CLIENT_PW) == "OK")
        check(c.call("AUTH", "default", CLIENT_PW) == "OK")
        check(c.call("CLIENT", "SETNAME", "my-evil-name") == "OK")
        name = c.call("CLIENT", "GETNAME")
        check(name.startswith(b"limen:") and b"evil" not in name, f"server sees {name!r}")
        h = c.call("HELLO", "3", "AUTH", "default", CLIENT_PW, "SETNAME", "x")
        check(isinstance(h, dict) and h.get("proto") == 3, f"{h!r}")
        check(c.call("CLIENT", "GETNAME").startswith(b"limen:"))
        who = c.call("ACL", "WHOAMI")
        check(denied(who), "ACL is refused")
        for words in (["RESET"], ["MONITOR"], ["CLIENT", "REPLY", "OFF"], ["SYNC"], ["PSYNC", "?", "-1"], ["REPLCONF", "listening-port", "1"]):
            check(denied(c.call(*words), "never allowed"), words)
        check(c.call("PING") == "PONG", "session intact after all that")


@scenario
def malformed_input_ends_the_session_but_not_the_worker():
    cases = {
        "bad count": b"*abc\r\n",
        "non-bulk element": b"*1\r\n:1\r\n",
        "null bulk": b"*1\r\n$-1\r\n",
        "negative bulk": b"*1\r\n$-5\r\n",
        "oversize bulk": b"*1\r\n$99999999999\r\n",
        "unterminated bulk": b"*1\r\n$3\r\nabcXX",
        "huge inline line": b"A" * 200_000,
        "deep nesting": b"*1\r\n" * 5000,
        "binary garbage": os.urandom(4096).replace(b"\n", b"x") + b"\xff\xfe\n",
        "unbalanced inline quote": b'set "oops\r\n',
    }
    with Listener("cache-staging") as l:
        for name, payload in cases.items():
            c = l.conn()
            try:
                c.raw(payload)
            except OSError:
                pass
            try:
                r = c.read()
                check(isinstance(r, Err), f"{name}: expected an error, got {r!r}")
            except (EOFError, OSError):
                pass  # closed without a reply is acceptable for garbage
            check(c.closed_within(10), f"{name}: session should end")
            c.close()
        # Half a request, then the client vanishes.
        c = l.conn(); c.raw(b"*2\r\n$3\r\nGET\r\n$5\r\nab"); c.close()
        # The worker and listener are fine.
        c = l.conn()
        check(c.call("PING") == "PONG")
    check(run(["curl", "-sf", f"http://localhost:{HEALTH}/readyz"]).returncode == 0, "proxy still ready")


@scenario
def many_parallel_sessions_do_not_cross_talk():
    errors = []

    def worker(i):
        try:
            with Listener("cache-staging") as l:
                c = l.conn(timeout=60)
                for j in range(150):
                    k = f"t:par:{i}:{j}"
                    v = f"{i}-{j}-{uuid.uuid4().hex}"
                    if c.call("SET", k, v) != "OK" or c.call("GET", k) != v.encode():
                        errors.append(f"session {i} op {j}")
                        return
                c.call("DEL", *[f"t:par:{i}:{j}" for j in range(150)])
        except Exception as e:  # noqa: BLE001
            errors.append(f"session {i}: {e!r}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    [t.start() for t in threads]
    [t.join(300) for t in threads]
    check(not errors, "; ".join(errors[:3]))


@scenario
def one_listener_serves_many_short_connections():
    with Listener("cache-valkey") as l:
        for i in range(60):
            c = l.conn()
            check(c.call("PING") == "PONG", f"connection {i}")
            c.close()


@scenario
def unreachable_or_misconfigured_targets_fail_cleanly():
    out = failed_listener("cache-tls-bad")
    check("couldn't connect to the Redis server" in out, out)
    out = failed_listener("cache-down")
    check("couldn't connect to the Redis server" in out, out)
    out = failed_listener("no-such-resource")
    check("access denied" in out or "no Redis access" in out or "unknown" in out.lower(), out)
    out = failed_listener("web-staging-1")   # an ssh resource
    check("denied" in out.lower() or "no Redis" in out, out)
    out = failed_listener("cache-staging", who="dev", user="root")
    check("denied" in out.lower(), out)
    with Listener("cache-staging") as l:      # and a good one still works afterwards
        check(l.conn().call("PING") == "PONG")


@scenario
def target_dying_mid_session_closes_the_client_not_hangs_it():
    with Listener("cache-staging") as l:
        c = l.conn()
        check(c.call("PING") == "PONG")
        compose("stop", "redis-target")
        try:
            check(c.closed_within(20), "client sees the close within 20s")
            out = failed_listener("cache-staging")
            check("couldn't connect" in out, out)
        finally:
            compose("start", "redis-target")
            for _ in range(60):
                if server("redis-target", "ping") == "PONG":
                    break
                time.sleep(0.5)
    with Listener("cache-staging") as l:
        check(l.conn().call("PING") == "PONG", "works again after the target is back")


@scenario
def locking_a_user_ends_their_redis_session():
    with Listener("cache-staging", who="dev", user="limen-ro") as l:
        c = l.conn()
        check(c.call("PING") == "PONG")
        r = limen("admin", "admin", "lock", "developer@example.com", "--reason", "scenario test")
        check(r.returncode == 0, r.stderr)
        try:
            check(c.closed_within(40), "locked user's session ends")
            out = failed_listener("cache-staging", who="dev", user="limen-ro")
            check("lock" in out.lower() or "denied" in out.lower(), out)
        finally:
            limen("admin", "admin", "unlock", "developer@example.com")
        time.sleep(12)
    with Listener("cache-staging", who="dev", user="limen-ro") as l:
        check(l.conn().call("PING") == "PONG", "works after unlock")


@scenario
def control_plane_outage_keeps_redis_working_and_audit_catches_up():
    marker = "outage-" + uuid.uuid4().hex[:8]
    with Listener("cache-staging") as l:
        c = l.conn()
        check(c.call("SET", f"t:{marker}:before", "1") == "OK")
        compose("stop", "control-plane")
        try:
            check(c.call("SET", f"t:{marker}:during", "2") == "OK", "running session continues")
            with Listener("cache-staging") as l2:      # new session while the control plane is down
                c2 = l2.conn()
                check(c2.call("GET", f"t:{marker}:during") == b"2", "new session works from the cached policy")
                check(c2.call("PING") == "PONG")
        finally:
            compose("start", "control-plane")
        for _ in range(120):
            if run(["curl", "-sf", f"http://localhost:{E['LIMEN_REDIS_CP_PORT']}/readyz"]).returncode == 0:
                break
            time.sleep(0.5)
        c.call("DEL", f"t:{marker}:before", f"t:{marker}:during")
    want = {f"t:{marker}:before", f"t:{marker}:during"}
    t0 = time.time()
    seen = set()
    while time.time() - t0 < 240 and not want <= seen:   # spools ship with a retry backoff
        time.sleep(5)
        seen = {w for e in audit_events() if e["kind"] == "redis.command" for w in e["data"].get("keys") or []}
    print(f"    audit caught up {time.time() - t0:.0f}s after the control plane came back", flush=True)
    check(want <= seen, f"audit events not delivered after the outage: {sorted(want - seen)}")


@scenario
def unix_socket_listener_is_private_and_works():
    import tempfile
    d = tempfile.mkdtemp(prefix="lr", dir="/tmp")   # unix socket paths are short on macOS
    os.chmod(d, 0o700)
    path = f"{d}/r.sock"
    with Listener("cache-staging", extra=["--socket", path]) as l:
        check(l.path == path, l.lines)
        check(oct(os.stat(path).st_mode & 0o777) == "0o600", oct(os.stat(path).st_mode))
        c = Conn(path)
        check(c.call("PING") == "PONG")
        c.close()
    # A stale socket file from a crashed run is replaced; an open directory is refused.
    with Listener("cache-staging", extra=["--socket", path]) as l:
        check(Conn(path).call("PING") == "PONG", "stale socket replaced")
    loose = tempfile.mkdtemp(prefix="lr", dir="/tmp")
    os.chmod(loose, 0o755)
    r = run([LIMEN, "redis", "connect", "cache-staging", "--user", "limen-rw", "--socket", f"{loose}/r.sock"],
            env={**E, "LIMEN_HOME": HOME["admin"]}, timeout=60)
    check(r.returncode != 0 and "open to other users" in r.stderr + r.stdout, r.stderr)


@scenario
def listener_rules_and_idle_timeout():
    r = run([LIMEN, "redis", "connect", "cache-staging", "--user", "limen-rw", "--listen", "0.0.0.0:0"],
            env={**E, "LIMEN_HOME": HOME["admin"]}, timeout=60)
    check(r.returncode != 0 and "loopback" in r.stderr + r.stdout, "non-loopback refused: " + r.stderr)
    t0 = time.time()
    p = subprocess.Popen([LIMEN, "redis", "connect", "cache-staging", "--user", "limen-rw", "--idle-timeout", "4s"],
                         env={**E, "LIMEN_HOME": HOME["admin"]}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    port = None
    for line in p.stdout:
        m = re.search(r"-p (\d+)", line)
        if m:
            port = int(m.group(1)); break
    check(port, "listening")
    c = Conn(port)
    check(c.call("PING") == "PONG")
    time.sleep(6)   # longer than the timeout, with the connection still open
    check(p.poll() is None, "stays up while a connection is open")
    check(c.call("PING") == "PONG")
    c.close()
    t1 = time.time()
    try:
        p.wait(timeout=15)
    except subprocess.TimeoutExpired:
        p.kill()
        raise AssertionError("did not stop after the last connection closed")
    check(3 <= time.time() - t1 <= 10, f"stopped {time.time() - t1:.1f}s after the last connection")


@scenario
def tls_target_keys_are_hashed_in_the_audit_trail():
    k = "t:email:" + uuid.uuid4().hex[:6] + "@example.com"
    with Listener("cache-tls") as l:
        c = l.conn()
        check(c.call("SET", k, SECRET) == "OK" and c.call("GET", k) == SECRET.encode())
        c.call("DEL", k)
    time.sleep(25)
    mine = [e for e in audit_events() if e["kind"] == "redis.command" and e["data"].get("resource") == "cache-tls"
            and e["data"]["command"] in ("SET", "GET", "DEL")]
    check(mine, "events for cache-tls")
    check(all(x["data"]["keys"][0].startswith("h:") for x in mine), "hashed keys")
    check(not any("example.com" in json.dumps(x["data"]) for x in mine), "key text absent")


@scenario
def proxy_session_gauge_returns_to_zero():
    for _ in range(40):
        m = run(["curl", "-sf", f"http://localhost:{HEALTH}/metrics"]).stdout
        lines = [l for l in m.splitlines() if l.startswith("limen_sessions_active") and 'kind="redis"' in l]
        if lines and all(float(l.split()[-1]) == 0 for l in lines):
            return
        time.sleep(1)
    raise AssertionError(f"active redis sessions never reached 0: {lines if m else 'no metrics'}")


@scenario
def secrets_never_reach_audit_or_logs():
    time.sleep(15)
    text = json.dumps(audit_events())
    logs = compose("logs", "--no-color").stdout
    for name, needle in (("secret value", SECRET), ("client password", CLIENT_PW),
                         ("ro password", "ro-dev-only"), ("rw password", "rw-dev-only")):
        check(needle not in text, f"{name} found in the audit trail")
    # The only place the ACL passwords may appear is the target servers' own output (none) and our mounts.
    worker_logs = compose("logs", "--no-color", "worker", "proxy", "control-plane").stdout
    for name, needle in (("secret value", SECRET), ("client password", CLIENT_PW),
                         ("ro password", "ro-dev-only"), ("rw password", "rw-dev-only")):
        check(needle not in worker_logs, f"{name} found in component logs")
    evs = audit_events()
    cmds = [e for e in evs if e["kind"] == "redis.command"]
    check(len(cmds) > 100, f"{len(cmds)} redis.command events")
    check(all(e.get("session_id") and e.get("user") for e in cmds), "every command has a user and session")
    starts = {e["session_id"] for e in evs if e["kind"] == "session.start" and e["data"].get("kind") == "redis"}
    ends = {e["session_id"] for e in evs if e["kind"] == "session.end" and e["data"].get("kind") == "redis"}
    check(len(starts - ends) <= 2, f"sessions without an end event: {len(starts - ends)}")
    check({e["session_id"] for e in cmds} <= starts, "commands belong to started sessions")


# ---------------------------------------------------------------- main


def main():
    filters = [a for a in sys.argv[1:] if not a.startswith("--")]
    chosen = [s for s in SCENARIOS if not filters or any(f in s.__name__ for f in filters)]
    failed = 0
    for s in chosen:
        t0 = time.time()
        try:
            s()
            print(f"\033[32mPASS\033[0m {s.__name__} ({time.time() - t0:.1f}s)", flush=True)
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"\033[31mFAIL\033[0m {s.__name__} ({time.time() - t0:.1f}s)", flush=True)
            traceback.print_exc()
    print(f"\n{len(chosen) - failed}/{len(chosen)} scenarios passed", flush=True)
    sys.exit(1 if failed else 0)


main()
