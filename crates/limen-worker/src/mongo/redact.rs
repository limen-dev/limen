//! What the audit trail keeps of a command (ADR-0035).
//!
//! By default every value in a filter, update, document, or pipeline becomes
//! `?` and the shape stays: field names, operators (`$gt`, `$match`), and the
//! few options that describe the query rather than the data (`limit`, sort
//! directions, `ordered`). Inserted documents are only counted. With
//! `full_commands` the values stay, except fields that look like secrets.
//!
//! The output is JSON text written by hand, because the order of keys matters
//! (a sort or an index key is an ordered document) and `serde_json`'s map
//! would sort them.

use std::fmt::Write as _;

use super::bson::{Doc, Value};
use super::wire::Sequence;

/// Longest summary kept in one event.
pub const MAX_TEXT: usize = 16 * 1024;
/// Elements shown per array and keys shown per document.
const MAX_ITEMS: usize = 20;
const MAX_KEYS: usize = 60;
/// Nesting shown; deeper values collapse to `"…"`.
const MAX_SHOWN_DEPTH: usize = 12;
/// Longest string shown in full mode.
const MAX_STRING: usize = 1024;
const MAX_KEY: usize = 128;

/// Top-level fields that describe the connection or session, not the query.
const SKIPPED: [&str; 12] = [
    "$db",
    "lsid",
    "txnNumber",
    "$clusterTime",
    "$readPreference",
    "$configTime",
    "$topologyTime",
    "autocommit",
    "startTransaction",
    "stmtId",
    "apiVersion",
    "apiStrict",
];

/// Any scalar under these keys describes the query, not the data.
const KEPT_SCALARS: [&str; 20] = [
    "limit",
    "skip",
    "batchSize",
    "singleBatch",
    "ordered",
    "maxTimeMS",
    "allowDiskUse",
    "upsert",
    "multi",
    "new",
    "remove",
    "bypassDocumentValidation",
    "tailable",
    "awaitData",
    "noCursorTimeout",
    "showRecordId",
    "returnKey",
    "allowPartialResults",
    "unique",
    "sparse",
];

/// Everything under these keys is configuration.
const KEPT_TREES: [&str; 5] = ["readConcern", "writeConcern", "collation", "cursor", "hint"];

/// Directions and index types under these keys are structure.
const STRUCTURAL: [&str; 8] = [
    "sort",
    "$sort",
    "key",
    "projection",
    "$project",
    "fields",
    "$unset",
    "$sortByCount",
];

/// Strings under these keys are names of collections or databases, which is
/// what an auditor needs to see for `$out`, `$merge`, `$lookup`.
const NAMES: [&str; 11] = [
    "$out",
    "$merge",
    "from",
    "into",
    "to",
    "newName",
    "db",
    "coll",
    "$unionWith",
    "dropTarget",
    "renameCollection",
];

/// Fields whose values are never kept, even with `full_commands`.
const SECRETS: [&str; 11] = [
    "pwd",
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "privatekey",
    "accesskey",
    "secretkey",
    "sessiontoken",
    "payload",
];

/// A summary and whether it was cut at [`MAX_TEXT`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub text: String,
    pub truncated: bool,
}

struct Out {
    text: String,
    truncated: bool,
}

impl Out {
    fn push(&mut self, s: &str) {
        if self.truncated {
            return;
        }
        if self.text.len() + s.len() > MAX_TEXT {
            let mut end = MAX_TEXT.saturating_sub(self.text.len()).min(s.len());
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            self.text.push_str(&s[..end]);
            self.truncated = true;
        } else {
            self.text.push_str(s);
        }
    }

    fn string(&mut self, s: &str) {
        // serde_json escapes exactly as JSON requires.
        self.push(&serde_json::to_string(s).unwrap_or_else(|_| "\"?\"".into()));
    }
}

/// What the keys on the way down say about the values below them.
#[derive(Clone, Copy, Default)]
struct Scope {
    /// Scalars under this key are structure.
    scalars: bool,
    /// Directions and index types are structure.
    structural: bool,
    /// Strings are collection or database names.
    names: bool,
}

#[derive(Clone, Copy)]
struct Ctx {
    full: bool,
    scope: Scope,
    depth: usize,
}

/// Summarize a command: its fields after the command name, and the
/// document sequences of an `OP_MSG`.
#[must_use]
pub fn summarize(command: Doc<'_>, sequences: &[Sequence<'_>], full: bool) -> Summary {
    let mut out = Out {
        text: String::new(),
        truncated: false,
    };
    out.push("{");
    let mut first = true;
    let mut field = |out: &mut Out, key: &str| {
        if !first {
            out.push(",");
        }
        first = false;
        out.string(key);
        out.push(":");
    };
    let base = Ctx {
        full,
        scope: Scope::default(),
        depth: 0,
    };
    // The first element is the command name and its target, shown elsewhere.
    for (index, element) in command.iter().enumerate() {
        let Ok((key, value)) = element else {
            field(&mut out, "…");
            out.push("\"malformed\"");
            break;
        };
        // The first element is the command name and, for most commands, its
        // collection (shown elsewhere). `explain` is the exception: its value
        // is the command being explained, which must not vanish from the trail.
        if SKIPPED.contains(&key) || (index == 0 && !matches!(value, Value::Doc(_))) {
            continue;
        }
        field(&mut out, clip(key));
        top_level(&mut out, key, value, base);
    }
    for seq in sequences {
        field(&mut out, clip(seq.identifier));
        if !full && seq.identifier == "documents" {
            // Inserted documents are data: say how many.
            let _ = write!(NumberTo(&mut out), "{{\"count\":{}}}", seq.docs.len());
            continue;
        }
        out.push("[");
        for (i, doc) in seq.docs.iter().take(MAX_ITEMS).enumerate() {
            if i > 0 {
                out.push(",");
            }
            doc_value(&mut out, *doc, base);
        }
        if seq.docs.len() > MAX_ITEMS {
            let _ = write!(
                NumberTo(&mut out),
                ",\"…(+{})\"",
                seq.docs.len() - MAX_ITEMS
            );
        }
        out.push("]");
    }
    out.push("}");
    Summary {
        text: out.text,
        truncated: out.truncated,
    }
}

/// Lets `write!` append to [`Out`].
struct NumberTo<'a>(&'a mut Out);

impl std::fmt::Write for NumberTo<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.push(s);
        Ok(())
    }
}

fn clip(key: &str) -> &str {
    if key.len() <= MAX_KEY {
        return key;
    }
    let mut end = MAX_KEY;
    while !key.is_char_boundary(end) {
        end -= 1;
    }
    &key[..end]
}

fn top_level(out: &mut Out, key: &str, value: Value<'_>, mut ctx: Ctx) {
    // Inline `documents` (some drivers send small batches in the command).
    if !ctx.full && key == "documents" {
        let count = match value {
            Value::Array(a) => a.iter().count(),
            _ => 1,
        };
        let _ = write!(NumberTo(out), "{{\"count\":{count}}}");
        return;
    }
    if KEPT_TREES.contains(&key) {
        ctx.scope = Scope {
            scalars: true,
            structural: true,
            names: true,
        };
    }
    // `find: "customers"` style targets are first elements, skipped above;
    // `renameCollection` and `to` carry names in their value.
    value_for_key(out, key, value, ctx);
}

fn value_for_key(out: &mut Out, key: &str, value: Value<'_>, mut ctx: Ctx) {
    if ctx.full && SECRETS.contains(&key.to_ascii_lowercase().as_str()) {
        out.push("\"[REDACTED]\"");
        return;
    }
    if KEPT_SCALARS.contains(&key) {
        ctx.scope.scalars = true;
    }
    if STRUCTURAL.contains(&key) {
        ctx.scope.structural = true;
    }
    if NAMES.contains(&key) {
        ctx.scope.names = true;
    }
    render(out, value, ctx);
}

fn doc_value(out: &mut Out, doc: Doc<'_>, ctx: Ctx) {
    if ctx.depth >= MAX_SHOWN_DEPTH {
        out.push("\"…\"");
        return;
    }
    out.push("{");
    let mut shown = 0;
    let mut total = 0;
    for element in doc {
        let Ok((key, value)) = element else {
            if shown > 0 {
                out.push(",");
            }
            out.push("\"…\":\"malformed\"");
            shown += 1;
            break;
        };
        total += 1;
        if shown >= MAX_KEYS {
            continue;
        }
        if shown > 0 {
            out.push(",");
        }
        shown += 1;
        out.string(clip(key));
        out.push(":");
        value_for_key(
            out,
            key,
            value,
            Ctx {
                depth: ctx.depth + 1,
                ..ctx
            },
        );
    }
    if total > shown {
        let _ = write!(NumberTo(out), ",\"…\":{}", total - shown);
    }
    out.push("}");
}

fn array_value(out: &mut Out, doc: Doc<'_>, ctx: Ctx) {
    if ctx.depth >= MAX_SHOWN_DEPTH {
        out.push("\"…\"");
        return;
    }
    let elements: Vec<Value<'_>> = doc.iter().filter_map(|e| e.ok().map(|(_, v)| v)).collect();
    let scalars = elements
        .iter()
        .all(|v| !matches!(v, Value::Doc(_) | Value::Array(_)));
    if !ctx.full && scalars && !ctx.scope.scalars && !ctx.scope.names && !ctx.scope.structural {
        // `{$in: [..]}`: how many, not which.
        let _ = write!(NumberTo(out), "\"?[{}]\"", elements.len());
        return;
    }
    out.push("[");
    for (i, v) in elements.iter().take(MAX_ITEMS).enumerate() {
        if i > 0 {
            out.push(",");
        }
        render(
            out,
            *v,
            Ctx {
                depth: ctx.depth + 1,
                ..ctx
            },
        );
    }
    if elements.len() > MAX_ITEMS {
        let _ = write!(NumberTo(out), ",\"…(+{})\"", elements.len() - MAX_ITEMS);
    }
    out.push("]");
}

fn render(out: &mut Out, value: Value<'_>, ctx: Ctx) {
    match value {
        Value::Doc(d) => doc_value(out, d, ctx),
        Value::Array(a) => array_value(out, a, ctx),
        scalar => scalar_value(out, scalar, ctx),
    }
}

fn scalar_value(out: &mut Out, value: Value<'_>, ctx: Ctx) {
    let keep = ctx.full
        || ctx.scope.scalars
        || (ctx.scope.structural && is_direction(&value))
        || (ctx.scope.names && matches!(value, Value::Str(_)));
    if !keep {
        out.push("\"?\"");
        return;
    }
    match value {
        Value::Double(v) => {
            if v.is_finite() {
                let _ = write!(NumberTo(out), "{v}");
            } else {
                out.push("\"?\"");
            }
        }
        Value::Str(s) | Value::Code(s) | Value::Symbol(s) => {
            let mut end = s.len().min(MAX_STRING);
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            out.string(&s[..end]);
        }
        Value::Int32(v) => {
            let _ = write!(NumberTo(out), "{v}");
        }
        Value::Int64(v) => {
            let _ = write!(NumberTo(out), "{v}");
        }
        Value::Bool(b) => out.push(if b { "true" } else { "false" }),
        Value::Null | Value::Undefined => out.push("null"),
        Value::ObjectId(id) => {
            let mut hex = String::with_capacity(24);
            for b in id {
                let _ = write!(hex, "{b:02x}");
            }
            let _ = write!(NumberTo(out), "{{\"$oid\":\"{hex}\"}}");
        }
        Value::DateTime(ms) => {
            let _ = write!(NumberTo(out), "{{\"$date\":{ms}}}");
        }
        Value::Binary { subtype, bytes } => {
            let _ = write!(
                NumberTo(out),
                "{{\"$binary\":{{\"subtype\":{subtype},\"bytes\":{}}}}}",
                bytes.len()
            );
        }
        Value::Regex { pattern, options } => {
            out.push("{\"$regex\":");
            out.string(pattern);
            out.push(",\"$options\":");
            out.string(options);
            out.push("}");
        }
        Value::Timestamp(t) => {
            let _ = write!(NumberTo(out), "{{\"$timestamp\":{t}}}");
        }
        Value::Decimal128(_) => out.push("{\"$numberDecimal\":\"…\"}"),
        Value::MinKey => out.push("{\"$minKey\":1}"),
        Value::MaxKey => out.push("{\"$maxKey\":1}"),
        Value::DbPointer | Value::CodeWithScope | Value::Doc(_) | Value::Array(_) => {
            out.push("\"?\"");
        }
    }
}

/// Sort directions (`1`, `-1`), projection flags (`0`, `1`), and the named
/// index types are structure, not data.
fn is_direction(value: &Value<'_>) -> bool {
    match value {
        Value::Int32(_) | Value::Int64(_) | Value::Double(_) => {
            value.as_i64().is_some_and(|n| (-1..=1).contains(&n))
        }
        Value::Bool(_) => true,
        Value::Str(s) => matches!(
            *s,
            "text" | "2d" | "2dsphere" | "hashed" | "columnstore" | "asc" | "desc"
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::super::bson::Builder;
    use super::*;

    fn summary(doc: &[u8], full: bool) -> String {
        let d = Doc::new(doc).expect("doc");
        summarize(d, &[], full).text
    }

    fn find() -> Vec<u8> {
        Builder::new()
            .str("find", "customers")
            .doc(
                "filter",
                &Builder::new()
                    .str("email", "ada@example.com")
                    .doc("age", &Builder::new().i32("$gt", 30)),
            )
            .doc("sort", &Builder::new().i32("createdAt", -1).i32("name", 1))
            .i32("limit", 10)
            .str("$db", "orders")
            .doc("lsid", &Builder::new().binary("id", &[1; 16]))
            .finish()
    }

    #[test]
    fn filters_keep_their_shape_and_lose_their_values() {
        let text = summary(&find(), false);
        assert_eq!(
            text,
            r#"{"filter":{"email":"?","age":{"$gt":"?"}},"sort":{"createdAt":-1,"name":1},"limit":10}"#
        );
        assert!(!text.contains("ada@example.com") && !text.contains("lsid"));
    }

    #[test]
    fn full_mode_keeps_values_and_the_order_of_keys() {
        let text = summary(&find(), true);
        assert!(text.contains(r#""email":"ada@example.com""#), "{text}");
        assert!(text.contains(r#""$gt":30"#));
        assert!(
            text.find("createdAt").expect("a") < text.find("\"name\":1").expect("b"),
            "sort order is kept"
        );
    }

    #[test]
    fn secrets_are_redacted_even_in_full_mode() {
        let create = Builder::new()
            .str("createUser", "report")
            .str("pwd", "hunter2")
            .str_array("roles", &["read"])
            .str("$db", "admin")
            .finish();
        let full = summary(&create, true);
        assert!(
            !full.contains("hunter2") && full.contains("[REDACTED]"),
            "{full}"
        );
        let redacted = summary(&create, false);
        assert!(!redacted.contains("hunter2"), "{redacted}");
    }

    #[test]
    fn arrays_of_values_collapse_to_a_count() {
        let doc = Builder::new()
            .str("find", "c")
            .doc(
                "filter",
                &Builder::new().doc(
                    "tier",
                    &Builder::new().str_array("$in", &["gold", "silver", "bronze"]),
                ),
            )
            .str("$db", "orders")
            .finish();
        assert_eq!(
            summary(&doc, false),
            r#"{"filter":{"tier":{"$in":"?[3]"}}}"#
        );
        assert!(summary(&doc, true).contains(r#""$in":["gold","silver","bronze"]"#));
    }

    #[test]
    fn collection_names_survive_in_pipeline_stages_that_write_or_join() {
        let stage = |name: &str, v: &Builder| Builder::new().doc(name, v);
        let pipeline = {
            // An array document is a document keyed "0", "1", ...
            let mut arr = Builder::new();
            arr = arr.doc("0", &stage("$match", &Builder::new().str("status", "paid")));
            arr = arr.doc(
                "1",
                &stage(
                    "$lookup",
                    &Builder::new().str("from", "customers").str("as", "c"),
                ),
            );
            arr = arr.doc("2", &Builder::new().str("$out", "stolen"));
            arr
        };
        let mut raw = Builder::new().str("aggregate", "invoices").finish();
        // Append the pipeline as an array element by building by hand.
        raw.pop();
        raw.push(0x04);
        raw.extend_from_slice(b"pipeline\0");
        raw.extend_from_slice(&pipeline.finish());
        raw.push(0);
        let len = i32::try_from(raw.len()).expect("len");
        raw[..4].copy_from_slice(&len.to_le_bytes());
        let text = summary(&raw, false);
        assert!(text.contains(r#""$match":{"status":"?"}"#), "{text}");
        assert!(text.contains(r#""from":"customers""#), "{text}");
        assert!(text.contains(r#""as":"?""#), "{text}");
        assert!(text.contains(r#""$out":"stolen""#), "{text}");
    }

    #[test]
    fn explain_keeps_the_command_it_explains() {
        let doc = Builder::new()
            .doc(
                "explain",
                &Builder::new()
                    .str("find", "customers")
                    .doc("filter", &Builder::new().str("email", "ada@example.com")),
            )
            .str("verbosity", "queryPlanner")
            .str("$db", "orders")
            .finish();
        let text = summary(&doc, false);
        assert!(
            text.starts_with(r#"{"explain":{"find":"#) && text.contains(r#""email":"?""#),
            "{text}"
        );
        assert!(!text.contains("ada@example.com"));
    }

    #[test]
    fn inserted_documents_are_only_counted() {
        let cmd = Builder::new()
            .str("insert", "customers")
            .bool("ordered", true)
            .str("$db", "orders")
            .finish();
        let docs = [
            Builder::new().str("card", "4111111111111111").finish(),
            Builder::new().str("card", "5500005555555559").finish(),
        ];
        let seq = Sequence {
            identifier: "documents",
            docs: docs.iter().map(|d| Doc::new(d).expect("doc")).collect(),
        };
        let command = Doc::new(&cmd).expect("doc");
        let redacted = summarize(command, std::slice::from_ref(&seq), false);
        assert_eq!(redacted.text, r#"{"ordered":true,"documents":{"count":2}}"#);
        let full = summarize(command, &[seq], true);
        assert!(full.text.contains("4111111111111111"));
    }

    #[test]
    fn updates_keep_operators_and_field_names() {
        let cmd = Builder::new()
            .str("update", "customers")
            .str("$db", "orders")
            .finish();
        let upd = Builder::new()
            .doc("q", &Builder::new().str("email", "ada@example.com"))
            .doc(
                "u",
                &Builder::new().doc("$set", &Builder::new().str("tier", "gold")),
            )
            .bool("multi", false)
            .bool("upsert", true)
            .finish();
        let seq = Sequence {
            identifier: "updates",
            docs: vec![Doc::new(&upd).expect("doc")],
        };
        let text = summarize(Doc::new(&cmd).expect("doc"), &[seq], false).text;
        assert_eq!(
            text,
            r#"{"updates":[{"q":{"email":"?"},"u":{"$set":{"tier":"?"}},"multi":false,"upsert":true}]}"#
        );
    }

    #[test]
    fn long_summaries_are_cut_on_a_character_boundary() {
        let mut filter = Builder::new();
        for i in 0..2000 {
            filter = filter.str(&format!("fieldé{i}"), "v");
        }
        let doc = Builder::new()
            .str("find", "c")
            .doc("filter", &filter)
            .finish();
        let s = summarize(Doc::new(&doc).expect("doc"), &[], false);
        assert!(s.text.len() <= MAX_TEXT, "{}", s.text.len());
        // Large documents show their first keys and the number of the rest.
        assert!(s.text.contains(r#""…":"#) || s.truncated);
    }

    #[test]
    fn a_malformed_command_is_summarized_not_trusted() {
        let mut bytes = Builder::new().str("find", "c").i32("limit", 5).finish();
        // length(4) + tag(1) + "find\0"(5) + strlen(4) + "c\0"(2) = 16: the second element's tag
        bytes[16] = 0x20;
        let text = summary(&bytes, false);
        assert_eq!(text, r#"{"…":"malformed"}"#);
    }
}
