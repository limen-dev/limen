# ADR-0039: Detached connections (`--detach`) and `limen conns`

- Status: Accepted and built. The owner asked for it on 2026-10-24 together with issue #55; the open questions below were settled with the defaults proposed.
- Date: 2026-10-24

## Context
Every `limen <type> connect` runs in the foreground until Ctrl-C. Scripts and people who want a tunnel for the day need it in the background. Issue #55 fixed these behaviours: a second connect to the same resource does not end the first; detached listeners close when the Limen certificate expires and on `limen logout`; `limen conns ls` and `limen conns stop <id>` manage them. It asked for a decision on the state file, daemon versus forked process, and re-login.

## Decisions

### 1. A forked copy of the same command, not a daemon
`--detach` (`-d`, accepted by every command that opens a listener, and by `limen connect`) re-executes the current binary with the same arguments minus `--detach`, in its own process group, with stdout and stderr in a log file (mode 0600). The parent waits until the child has printed its address and gone quiet (about 400 ms), shows that output, writes the state file and returns. No long-lived daemon, no new protocol: the background copy is exactly the foreground command, so it has the same authorisation, auditing, idle timeout and sessions. macOS and Linux only; elsewhere `--detach` is refused.

Rejected: a per-user daemon that owns all listeners (a new always-on process and local control surface, which would need its own threat-model entry), and per-command `--detach` code (seven copies of the same logic).

### 2. State
`$LIMEN_HOME/conns/<id>.json` (mode 0600; id is six hex digits) holds the pid, proxy, command line, log path, start time and certificate expiry. `limen conns ls` drops the state of processes that no longer exist. It holds no credential: the background process loads the certificate and key from the profile like any other command.

### 3. Lifetime
A detached process ends when (a) its certificate expires (a timer inside the process), (b) `limen logout` for its proxy (SIGTERM to each), (c) `limen conns stop <id>|--all`, or (d) its idle timeout, which stays at the foreground default of 1 hour (`--idle-timeout 0` for none).

### 4. Re-login
Logging in again does not touch running connections; they keep the certificate they started with and end when it expires. Starting a new one uses the new certificate. A second connect to the same resource opens its own listener.

## Consequences
- `limen logout` and expiry end the connection, but a listener's unix socket file, if any, may be left behind.
- A new process with a local state directory: see `docs/threat-model.md` (local state).
