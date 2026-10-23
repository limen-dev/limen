//! Hostile input: the parsers, the redactor, and the rules read bytes a
//! client controls, so none of them may panic, hang, or allocate without
//! bound whatever they are given. This mutates valid messages (flipped,
//! truncated, duplicated, and spliced bytes) with a fixed seed and runs every
//! entry point on the result. It is not a replacement for `cargo-fuzz`
//! (deferred), but it runs on every `cargo test`.

use std::sync::Arc;

use limen_policy::Policy;

use super::bson::{Builder, Doc, Value};
use super::redact;
use super::reply;
use super::rules::{self, Access};
use super::wire;

/// xorshift64*: small, deterministic, no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n.max(1) as u64)).unwrap_or(0)
    }
}

fn corpus() -> Vec<Vec<u8>> {
    let filter = Builder::new()
        .str("email", "ada@example.com")
        .doc("age", &Builder::new().i32("$gt", 30))
        .docs_array("$or", &[Builder::new().str("a", "b").finish()]);
    let find = Builder::new()
        .str("find", "customers")
        .doc("filter", &filter)
        .doc("sort", &Builder::new().i32("createdAt", -1))
        .i32("limit", 10)
        .doc("lsid", &Builder::new().binary("id", &[7; 16]))
        .str("$db", "orders")
        .finish();
    let pipeline = Builder::new()
        .str("aggregate", "invoices")
        .docs_array(
            "pipeline",
            &[
                Builder::new()
                    .doc("$match", &Builder::new().str("status", "paid"))
                    .finish(),
                Builder::new()
                    .doc(
                        "$lookup",
                        &Builder::new()
                            .doc(
                                "from",
                                &Builder::new().str("db", "billing").str("coll", "x"),
                            )
                            .str("as", "y"),
                    )
                    .finish(),
                Builder::new()
                    .doc("$out", &Builder::new().str("db", "o").str("coll", "c"))
                    .finish(),
            ],
        )
        .doc("cursor", &Builder::new())
        .str("$db", "orders")
        .finish();
    let get_more = Builder::new()
        .i64("getMore", 42)
        .str("collection", "customers")
        .str("$db", "orders")
        .finish();
    let kill = Builder::new()
        .str("killCursors", "customers")
        .docs_array("cursors", &[Builder::new().i64("0", 1).finish()])
        .str("$db", "orders")
        .finish();
    let reply = Builder::new()
        .f64("ok", 1.0)
        .doc(
            "cursor",
            &Builder::new()
                .i64("id", 5)
                .docs_array("firstBatch", &[Builder::new().i32("a", 1).finish()]),
        )
        .docs_array("writeErrors", &[Builder::new().i32("code", 11000).finish()])
        .finish();
    let mut msgs = Vec::new();
    for doc in [&find, &pipeline, &get_more, &kill] {
        msgs.push(doc.clone());
        // As OP_MSG bodies, with and without a document sequence.
        msgs.push(wire::op_msg_body(doc));
        let mut with_seq = 0u32.to_le_bytes().to_vec();
        with_seq.push(0);
        with_seq.extend_from_slice(doc);
        with_seq.push(1);
        let mut section = b"documents\0".to_vec();
        section.extend_from_slice(&Builder::new().str("n", "x").finish());
        with_seq.extend_from_slice(&i32::try_from(section.len() + 4).unwrap_or(0).to_le_bytes());
        with_seq.extend_from_slice(&section);
        msgs.push(with_seq);
    }
    msgs.push(reply);
    // An OP_QUERY handshake.
    let mut query = 0i32.to_le_bytes().to_vec();
    query.extend_from_slice(b"admin.$cmd\0");
    query.extend_from_slice(&[0; 8]);
    query.extend_from_slice(&Builder::new().i32("isMaster", 1).finish());
    msgs.push(query);
    msgs
}

fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut b = base.to_vec();
    for _ in 0..=rng.below(4) {
        match rng.below(6) {
            0 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] ^= 1 << rng.below(8);
            }
            1 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] = u8::try_from(rng.next() & 0xff).unwrap_or(0);
            }
            2 => {
                let n = rng.below(b.len() + 1);
                b.truncate(n);
            }
            3 if !b.is_empty() => {
                // Repeat a chunk.
                let i = rng.below(b.len());
                let j = (i + 1 + rng.below(16)).min(b.len());
                let chunk = b[i..j].to_vec();
                let at = rng.below(b.len() + 1);
                b.splice(at..at, chunk);
            }
            4 => b.push(u8::try_from(rng.next() & 0xff).unwrap_or(0)),
            _ if b.len() >= 4 => {
                // Make a length prefix lie.
                let i = rng.below(b.len() - 3);
                let lie = i32::try_from(rng.next() & 0x7fff_ffff).unwrap_or(i32::MAX);
                b[i..i + 4].copy_from_slice(&lie.to_le_bytes());
            }
            _ => {}
        }
    }
    b
}

fn access() -> Access {
    const POLICY: &str = r#"
kind: role
version: v1
metadata: { name: dev }
spec:
  allow:
    - resources: { kind: [mongodb], labels: { "*": ["*"] } }
      mongo: { roles: [read], databases: [orders] }
"#;
    const RESOURCE: &str = "kind: resource\nversion: v1\nmetadata: { name: m }\nspec:\n  mongodb: { endpoint: \"m:1\", credentials_dir: /c }\n";
    let policy = Policy::parse_yaml([("r.yaml", POLICY), ("m.yaml", RESOURCE)]).expect("policy");
    Access::new(Arc::new(policy), vec!["dev".into()], "m", "read")
}

/// Everything that reads client bytes, on one input.
fn exercise(bytes: &[u8], access: &Access) {
    if let Ok(doc) = Doc::new(bytes) {
        let _ = doc.validate();
        for _ in doc {}
        let _ = doc.get("$db");
        let _ = doc.first();
        let _ = redact::summarize(doc, &[], false);
        let _ = redact::summarize(doc, &[], true);
        let _ = reply::inspect(doc);
        if let Ok(cmd) = rules::inspect(doc) {
            let cursors = std::collections::HashSet::from([1, 5, 42]);
            let _ = rules::judge(&cmd, access, &cursors);
        }
        if let Ok(Some((_, Value::Doc(inner)))) = doc.first() {
            let _ = redact::summarize(inner, &[], false);
        }
    }
    if let Ok(msg) = wire::parse_op_msg(bytes) {
        let _ = redact::summarize(msg.command, &msg.sequences, false);
        let _ = redact::summarize(msg.command, &msg.sequences, true);
        let _ = wire::op_msg_for_server(&msg);
        if let Ok(cmd) = rules::inspect(msg.command) {
            let _ = rules::judge(&cmd, access, &std::collections::HashSet::new());
        }
    }
    let _ = wire::parse_op_query(bytes);
}

#[test]
fn mutated_messages_never_panic_or_stall() {
    let access = access();
    let corpus = corpus();
    for base in &corpus {
        exercise(base, &access);
    }
    let started = std::time::Instant::now();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    // The mutations must reach the code behind the framing checks: some inputs
    // still parse (and are walked, summarized, and judged), most are rejected.
    let (mut parsed, mut rejected) = (0, 0);
    for i in 0..60_000 {
        let base = &corpus[i % corpus.len()];
        let input = mutate(&mut rng, base);
        if Doc::new(&input).is_ok() || wire::parse_op_msg(&input).is_ok() {
            parsed += 1;
        } else {
            rejected += 1;
        }
        exercise(&input, &access);
    }
    assert!(parsed > 3_000, "only {parsed} mutated inputs parsed");
    assert!(
        rejected > 3_000,
        "only {rejected} mutated inputs were rejected"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(60),
        "60,000 hostile inputs took {:?}",
        started.elapsed()
    );
}

#[test]
fn deep_and_wide_documents_are_bounded() {
    let access = access();
    // 10,000 keys in one document, and nesting far past the limit.
    let mut wide = Builder::new().str("find", "c");
    for i in 0..10_000 {
        wide = wide.i32(&format!("k{i}"), 1);
    }
    let wide = wide.str("$db", "orders").finish();
    exercise(&wide, &access);
    let mut deep = Builder::new().i32("x", 1).finish();
    for _ in 0..5_000 {
        // { d: <deep> }
        let mut body = vec![0x03, b'd', 0];
        body.extend_from_slice(&deep);
        body.push(0);
        let mut next = i32::try_from(body.len() + 4)
            .unwrap_or(0)
            .to_le_bytes()
            .to_vec();
        next.extend_from_slice(&body);
        deep = next;
    }
    exercise(&deep, &access);
}
