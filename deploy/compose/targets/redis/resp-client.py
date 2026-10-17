#!/usr/bin/env python3
"""A tiny RESP client for the Phase 7 demo when redis-cli isn't installed.

    resp-client.py PORT COMMAND [ARG...]      one command, prints the reply
    resp-client.py PORT --pipeline CMD ; CMD  several commands in one write

It sends no AUTH: Limen's listener needs none. Dev tooling only.
"""
import socket
import sys


def encode(words):
    out = b"*%d\r\n" % len(words)
    for w in words:
        w = w.encode()
        out += b"$%d\r\n%s\r\n" % (len(w), w)
    return out


def read_line(f):
    line = f.readline()
    if not line:
        raise EOFError("connection closed")
    return line.rstrip(b"\r\n")


def read_reply(f):
    line = read_line(f)
    kind, rest = line[:1], line[1:]
    if kind in (b"+", b":"):
        return rest.decode()
    if kind == b"-":
        return "(error) " + rest.decode()
    if kind == b"$":
        n = int(rest)
        if n < 0:
            return "(nil)"
        data = f.read(n + 2)[:-2]
        return data.decode(errors="replace")
    if kind == b"*":
        n = int(rest)
        return "[" + ", ".join(read_reply(f) for _ in range(max(n, 0))) + "]"
    return line.decode(errors="replace")


def main():
    port = int(sys.argv[1])
    args = sys.argv[2:]
    if args and args[0] == "--pipeline":
        commands, cur = [], []
        for a in args[1:]:
            if a == ";":
                commands.append(cur)
                cur = []
            else:
                cur.append(a)
        if cur:
            commands.append(cur)
    else:
        commands = [args]
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(b"".join(encode(c) for c in commands))
        f = s.makefile("rb")
        for _ in commands:
            print(read_reply(f))


if __name__ == "__main__":
    main()
