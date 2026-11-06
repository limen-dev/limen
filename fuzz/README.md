# Fuzzing the parsers

Limen owns the codecs that read bytes a client or a target controls: RESP (Redis), MongoDB
wire messages and BSON, AMQP 0-9-1 frames, Kafka request headers, and the MySQL and PostgreSQL
frame layers. None of them may panic, hang, or allocate without bound, whatever they are given.
These `cargo-fuzz` targets check that. They sit beside the deterministic mutation tests that run on
every `cargo test` (for example `crates/limen-worker/src/mongo/robustness.rs`) and go much deeper.

| Target | Reads |
|---|---|
| `redis_frames` | RESP frame and request scanners, `parse_command`, `parse_value` |
| `mongo_wire` | message framing, `OP_MSG`, `OP_QUERY`, the BSON reader |
| `amqp_frames` | frame parsing and the field reader |
| `kafka_header` | request header and the field reader |
| `mysql_packets` | packet framing, the hello, error and handshake parsers |
| `pg_frames` | the frame layer |
| `policy_yaml` | policy YAML parsing, validation and compiling, alone and next to valid documents |
| `policy_eval` | the evaluator and grant lookups on arbitrary requests (structured with `arbitrary`), checking deny by default |
| `policy_scalars` | durations, principals, ticket patterns, role and database names, discovery name templates |
| `cp_parsers` | the control plane's audit search language, secret masking, console date filters, notifier URLs, durations, policy source names |
| `proxy_web` | the proxy's `Host` authority, request URI, `Cookie` and header-text handling for web apps |

## Run

It needs a nightly toolchain and `cargo-fuzz` (this crate is not in the main workspace, and
`mise.toml` only pins the stable one):

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
cargo +nightly fuzz build
cargo +nightly fuzz run redis_frames -- -max_total_time=60 -max_len=4096
```

`cargo fuzz run` stops at the first crash and writes the input to `fuzz/artifacts/<target>/`.
Replay it with `cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>`. Fix the parser,
then add the input as a unit test next to the code so it stays fixed.

`.github/workflows/fuzz.yml` runs every target weekly (five minutes each) on a pinned nightly,
and on demand. A crash fails the run and uploads the input.

## How it reaches private code

The MySQL and PostgreSQL parsers are private to `limen-worker`, the web checks to `limen-proxy`
(`web.rs`), and the console date filters to `limen-control-plane` (`console/query.rs`). cargo-fuzz
builds with `--cfg fuzzing`, and under that flag only, those files expose a small `fuzz`
module. A normal build has none of it.

## What has been run

Each target ran for 60 seconds on a laptop with `-max_len=4096` on 2026-11-03 (results in
`docs/design.md` §14). That is a smoke test, not coverage: a target needs hours before a clean run
means much. The weekly job is what makes it count. The policy and request-parser targets were added later and have had only a
smoke run too. Handlers that need a network or a database are not fuzzed.
