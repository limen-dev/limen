//! What the worker reads from a server's answer: whether it worked, the
//! error code, how many documents came back, and the cursor it opened. The
//! documents themselves are never inspected.

use super::bson::{Doc, Value};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReplyInfo {
    pub ok: bool,
    pub code: Option<i32>,
    pub code_name: Option<String>,
    pub message: Option<String>,
    /// Documents returned (a cursor batch) or written (`n`).
    pub docs: Option<u64>,
    /// The cursor the command opened, if it is still open.
    pub cursor_id: Option<i64>,
    /// A write that partly failed: the reply is `ok` but `writeErrors` isn't empty.
    pub write_errors: u64,
}

fn small(v: Value<'_>) -> Option<i32> {
    v.as_i64().and_then(|n| i32::try_from(n).ok())
}

/// Read the interesting parts of a reply document. A reply the worker can't
/// read is reported as `ok` with nothing else: it still goes to the client
/// unchanged.
#[must_use]
pub fn inspect(reply: Doc<'_>) -> ReplyInfo {
    let mut info = ReplyInfo::default();
    for element in reply {
        let Ok((key, value)) = element else { break };
        match (key, value) {
            ("ok", v) => info.ok = v.is_truthy(),
            ("code", v) => info.code = small(v),
            ("codeName", Value::Str(s)) => info.code_name = Some(s.to_owned()),
            ("errmsg", Value::Str(s)) => info.message = Some(s.to_owned()),
            ("n", v) => info.docs = v.as_i64().and_then(|n| u64::try_from(n).ok()),
            ("cursor", Value::Doc(c)) => {
                for e in c {
                    let Ok((k, v)) = e else { break };
                    match (k, v) {
                        ("id", v) => info.cursor_id = v.as_i64().filter(|id| *id != 0),
                        ("firstBatch" | "nextBatch", Value::Array(a)) => {
                            info.docs = Some(a.iter().count() as u64);
                        }
                        _ => {}
                    }
                }
            }
            ("writeErrors", Value::Array(errors)) => {
                info.write_errors = errors.iter().count() as u64;
                if let Some(Ok((_, Value::Doc(first)))) = errors.iter().next() {
                    info.code = first.get("code").ok().flatten().and_then(small);
                    if let Ok(Some(Value::Str(m))) = first.get("errmsg") {
                        info.message = Some(m.to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    info
}

impl ReplyInfo {
    /// Whether the command failed, as far as the audit trail is concerned.
    #[must_use]
    pub fn failed(&self) -> bool {
        !self.ok || self.write_errors > 0
    }
}

#[cfg(test)]
mod tests {
    use super::super::bson::Builder;
    use super::*;

    fn info(doc: &[u8]) -> ReplyInfo {
        inspect(Doc::new(doc).expect("doc"))
    }

    /// A reply document with one array field built by hand.
    fn with_array(prefix: Builder, key: &str, elements: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for (i, e) in elements.iter().enumerate() {
            body.push(0x03);
            body.extend_from_slice(i.to_string().as_bytes());
            body.push(0);
            body.extend_from_slice(e);
        }
        body.push(0);
        let mut array = i32::try_from(body.len() + 4)
            .expect("len")
            .to_le_bytes()
            .to_vec();
        array.extend_from_slice(&body);
        let mut raw = prefix.finish();
        raw.pop();
        raw.push(0x04);
        raw.extend_from_slice(key.as_bytes());
        raw.push(0);
        raw.extend_from_slice(&array);
        raw.push(0);
        let len = i32::try_from(raw.len()).expect("len");
        raw[..4].copy_from_slice(&len.to_le_bytes());
        raw
    }

    #[test]
    fn a_cursor_reply_reports_its_batch_and_the_open_cursor() {
        let docs = [
            Builder::new().i32("a", 1).finish(),
            Builder::new().i32("a", 2).finish(),
        ];
        let batch = with_array(
            Builder::new().i64("id", 77).str("ns", "orders.c"),
            "firstBatch",
            &docs,
        );
        let mut raw = Builder::new().f64("ok", 1.0).finish();
        raw.pop();
        raw.push(0x03);
        raw.extend_from_slice(b"cursor\0");
        raw.extend_from_slice(&batch);
        raw.push(0);
        let len = i32::try_from(raw.len()).expect("len");
        raw[..4].copy_from_slice(&len.to_le_bytes());
        let i = info(&raw);
        assert!(i.ok && !i.failed());
        assert_eq!((i.docs, i.cursor_id), (Some(2), Some(77)));
    }

    #[test]
    fn an_exhausted_cursor_reports_none() {
        let mut raw = Builder::new().f64("ok", 1.0).finish();
        let cursor = Builder::new().i64("id", 0).str("ns", "orders.c").finish();
        raw.pop();
        raw.push(0x03);
        raw.extend_from_slice(b"cursor\0");
        raw.extend_from_slice(&cursor);
        raw.push(0);
        let len = i32::try_from(raw.len()).expect("len");
        raw[..4].copy_from_slice(&len.to_le_bytes());
        assert_eq!(info(&raw).cursor_id, None);
    }

    #[test]
    fn errors_carry_their_code() {
        let i = info(
            &Builder::new()
                .f64("ok", 0.0)
                .str("errmsg", "not authorized")
                .i32("code", 13)
                .str("codeName", "Unauthorized")
                .finish(),
        );
        assert!(i.failed());
        assert_eq!(
            (i.code, i.code_name.as_deref()),
            (Some(13), Some("Unauthorized"))
        );
        assert_eq!(i.message.as_deref(), Some("not authorized"));
    }

    #[test]
    fn a_write_with_errors_is_a_failure_even_though_ok_is_one() {
        let err = Builder::new()
            .i32("index", 0)
            .i32("code", 11000)
            .str("errmsg", "E11000 dup key")
            .finish();
        let raw = with_array(
            Builder::new().i32("n", 0).f64("ok", 1.0),
            "writeErrors",
            &[err],
        );
        let i = info(&raw);
        assert!(i.ok && i.failed());
        assert_eq!((i.code, i.write_errors, i.docs), (Some(11000), 1, Some(0)));
    }

    #[test]
    fn unreadable_replies_do_not_panic() {
        let mut raw = Builder::new().f64("ok", 1.0).i32("n", 3).finish();
        raw[4] = 0x20;
        let i = info(&raw);
        assert_eq!(i, ReplyInfo::default());
    }
}
