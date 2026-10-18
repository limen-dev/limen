//! Just enough BSON for a relay (ADR-0035): walk a document without copying
//! it, read a few typed values, and build the small documents the worker
//! sends itself (the handshake answer, errors, login commands).
//!
//! Every length is checked against the bytes we hold, nesting is capped, and
//! nothing here allocates in proportion to a length the peer chose.

/// MongoDB itself stops at 100 levels.
pub const MAX_DEPTH: usize = 100;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BsonError {
    #[error("truncated BSON")]
    Truncated,
    #[error("malformed BSON")]
    Malformed,
    #[error("BSON is nested too deeply")]
    Depth,
    #[error("unknown BSON type {0:#04x}")]
    UnknownType(u8),
}

/// A BSON document: a length-prefixed, NUL-terminated list of elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Doc<'a>(&'a [u8]);

/// One value. Types the worker never looks into are kept as bytes or
/// skipped by size.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value<'a> {
    Double(f64),
    Str(&'a str),
    Doc(Doc<'a>),
    Array(Doc<'a>),
    Binary { subtype: u8, bytes: &'a [u8] },
    Undefined,
    ObjectId([u8; 12]),
    Bool(bool),
    DateTime(i64),
    Null,
    Regex { pattern: &'a str, options: &'a str },
    DbPointer,
    Code(&'a str),
    Symbol(&'a str),
    CodeWithScope,
    Int32(i32),
    Timestamp(u64),
    Int64(i64),
    Decimal128([u8; 16]),
    MinKey,
    MaxKey,
}

impl<'a> Value<'a> {
    /// Any numeric type as an integer (doubles that are whole numbers too).
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match *self {
            Value::Int32(v) => Some(i64::from(v)),
            Value::Int64(v) => Some(v),
            #[allow(clippy::cast_possible_truncation, clippy::float_cmp)]
            Value::Double(v) if v.fract() == 0.0 && v.abs() < 9.0e15 => Some(v as i64),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&'a str> {
        match *self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Truthiness the way the server reads `ok`, `1`, `true`.
    #[must_use]
    pub fn is_truthy(&self) -> bool {
        match *self {
            Value::Bool(b) => b,
            Value::Double(v) => v != 0.0,
            Value::Int32(v) => v != 0,
            Value::Int64(v) => v != 0,
            _ => false,
        }
    }
}

impl<'a> Doc<'a> {
    /// `bytes` must be exactly one document: its length prefix equals the
    /// slice and it ends with NUL.
    pub fn new(bytes: &'a [u8]) -> Result<Self, BsonError> {
        if bytes.len() < 5 {
            return Err(BsonError::Truncated);
        }
        let declared = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if usize::try_from(declared) != Ok(bytes.len()) {
            return Err(BsonError::Malformed);
        }
        if bytes[bytes.len() - 1] != 0 {
            return Err(BsonError::Malformed);
        }
        Ok(Self(bytes))
    }

    /// The first document in `bytes`, and what follows it.
    pub fn split(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), BsonError> {
        if bytes.len() < 5 {
            return Err(BsonError::Truncated);
        }
        let declared = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let len = usize::try_from(declared).map_err(|_| BsonError::Malformed)?;
        if len < 5 {
            return Err(BsonError::Malformed);
        }
        if len > bytes.len() {
            return Err(BsonError::Truncated);
        }
        Ok((Self::new(&bytes[..len])?, &bytes[len..]))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    #[must_use]
    pub fn iter(&self) -> Iter<'a> {
        Iter {
            rest: &self.0[4..self.0.len() - 1],
            failed: false,
        }
    }

    /// The first element, whose key is the command name.
    pub fn first(&self) -> Result<Option<(&'a str, Value<'a>)>, BsonError> {
        self.iter().next().transpose()
    }

    /// The value of `key`, if present. A malformed document is an error even
    /// when the key comes first.
    pub fn get(&self, key: &str) -> Result<Option<Value<'a>>, BsonError> {
        let mut found = None;
        for element in self {
            let (k, v) = element?;
            if found.is_none() && k == key {
                found = Some(v);
            }
        }
        Ok(found)
    }

    /// Check the whole document, nested ones included.
    pub fn validate(&self) -> Result<(), BsonError> {
        fn walk(doc: Doc<'_>, depth: usize) -> Result<(), BsonError> {
            if depth > MAX_DEPTH {
                return Err(BsonError::Depth);
            }
            for element in doc {
                match element?.1 {
                    Value::Doc(d) | Value::Array(d) => walk(d, depth + 1)?,
                    _ => {}
                }
            }
            Ok(())
        }
        walk(*self, 1)
    }
}

impl<'a> IntoIterator for Doc<'a> {
    type Item = Result<(&'a str, Value<'a>), BsonError>;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &Doc<'a> {
    type Item = Result<(&'a str, Value<'a>), BsonError>;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

/// Iterates a document's elements. After an error it yields nothing more.
#[derive(Debug, Clone)]
pub struct Iter<'a> {
    rest: &'a [u8],
    failed: bool,
}

impl<'a> Iterator for Iter<'a> {
    type Item = Result<(&'a str, Value<'a>), BsonError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.rest.is_empty() {
            return None;
        }
        let item = element(&mut self.rest);
        if item.is_err() {
            self.failed = true;
        }
        Some(item)
    }
}

fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8], BsonError> {
    if rest.len() < n {
        return Err(BsonError::Truncated);
    }
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    Ok(head)
}

fn cstring<'a>(rest: &mut &'a [u8]) -> Result<&'a str, BsonError> {
    let end = rest
        .iter()
        .position(|&b| b == 0)
        .ok_or(BsonError::Truncated)?;
    let s = std::str::from_utf8(&rest[..end]).map_err(|_| BsonError::Malformed)?;
    *rest = &rest[end + 1..];
    Ok(s)
}

fn i32_le(rest: &mut &[u8]) -> Result<i32, BsonError> {
    let b = take(rest, 4)?;
    Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn i64_le(rest: &mut &[u8]) -> Result<i64, BsonError> {
    let b = take(rest, 8)?;
    Ok(i64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// A BSON string: i32 length (including the NUL), bytes, NUL.
fn string<'a>(rest: &mut &'a [u8]) -> Result<&'a str, BsonError> {
    let len = usize::try_from(i32_le(rest)?).map_err(|_| BsonError::Malformed)?;
    if len == 0 {
        return Err(BsonError::Malformed);
    }
    let bytes = take(rest, len)?;
    if bytes[len - 1] != 0 {
        return Err(BsonError::Malformed);
    }
    std::str::from_utf8(&bytes[..len - 1]).map_err(|_| BsonError::Malformed)
}

fn subdoc<'a>(rest: &mut &'a [u8]) -> Result<Doc<'a>, BsonError> {
    let (doc, tail) = Doc::split(rest)?;
    *rest = tail;
    Ok(doc)
}

fn element<'a>(rest: &mut &'a [u8]) -> Result<(&'a str, Value<'a>), BsonError> {
    let tag = take(rest, 1)?[0];
    let key = cstring(rest)?;
    let value = match tag {
        0x01 => Value::Double(f64::from_le_bytes(
            take(rest, 8)?
                .try_into()
                .map_err(|_| BsonError::Truncated)?,
        )),
        0x02 => Value::Str(string(rest)?),
        0x03 => Value::Doc(subdoc(rest)?),
        0x04 => Value::Array(subdoc(rest)?),
        0x05 => {
            let len = usize::try_from(i32_le(rest)?).map_err(|_| BsonError::Malformed)?;
            let subtype = take(rest, 1)?[0];
            Value::Binary {
                subtype,
                bytes: take(rest, len)?,
            }
        }
        0x06 => Value::Undefined,
        0x07 => Value::ObjectId(
            take(rest, 12)?
                .try_into()
                .map_err(|_| BsonError::Truncated)?,
        ),
        0x08 => match take(rest, 1)?[0] {
            0 => Value::Bool(false),
            1 => Value::Bool(true),
            _ => return Err(BsonError::Malformed),
        },
        0x09 => Value::DateTime(i64_le(rest)?),
        0x0A => Value::Null,
        0x0B => Value::Regex {
            pattern: cstring(rest)?,
            options: cstring(rest)?,
        },
        0x0C => {
            string(rest)?;
            take(rest, 12)?;
            Value::DbPointer
        }
        0x0D => Value::Code(string(rest)?),
        0x0E => Value::Symbol(string(rest)?),
        0x0F => {
            // total length, code string, scope document
            let total = usize::try_from(i32_le(rest)?).map_err(|_| BsonError::Malformed)?;
            if total < 4 + 5 {
                return Err(BsonError::Malformed);
            }
            take(rest, total - 4)?;
            Value::CodeWithScope
        }
        0x10 => Value::Int32(i32_le(rest)?),
        0x11 => Value::Timestamp(u64::from_le_bytes(
            take(rest, 8)?
                .try_into()
                .map_err(|_| BsonError::Truncated)?,
        )),
        0x12 => Value::Int64(i64_le(rest)?),
        0x13 => Value::Decimal128(
            take(rest, 16)?
                .try_into()
                .map_err(|_| BsonError::Truncated)?,
        ),
        0xFF => Value::MinKey,
        0x7F => Value::MaxKey,
        other => return Err(BsonError::UnknownType(other)),
    };
    Ok((key, value))
}

/// Builds a document. Calls chain; `finish` closes it.
#[derive(Debug, Clone)]
pub struct Builder {
    buf: Vec<u8>,
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Builder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: vec![0, 0, 0, 0],
        }
    }

    fn key(&mut self, tag: u8, key: &str) {
        debug_assert!(!key.contains('\0'));
        self.buf.push(tag);
        self.buf.extend_from_slice(key.as_bytes());
        self.buf.push(0);
    }

    #[must_use]
    pub fn f64(mut self, key: &str, v: f64) -> Self {
        self.key(0x01, key);
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    #[must_use]
    pub fn str(mut self, key: &str, v: &str) -> Self {
        self.key(0x02, key);
        let len = i32::try_from(v.len() + 1).unwrap_or(i32::MAX);
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(v.as_bytes());
        self.buf.push(0);
        self
    }

    #[must_use]
    pub fn doc(mut self, key: &str, v: &Builder) -> Self {
        self.key(0x03, key);
        self.buf.extend_from_slice(&v.clone().finish());
        self
    }

    /// An array of strings.
    #[must_use]
    pub fn str_array(mut self, key: &str, values: &[&str]) -> Self {
        self.key(0x04, key);
        let mut inner = Builder::new();
        for (i, v) in values.iter().enumerate() {
            inner = inner.str(&i.to_string(), v);
        }
        self.buf.extend_from_slice(&inner.finish());
        self
    }

    /// An array of documents, each already built.
    #[must_use]
    pub fn docs_array(mut self, key: &str, docs: &[Vec<u8>]) -> Self {
        self.key(0x04, key);
        let mut inner = Vec::new();
        for (i, d) in docs.iter().enumerate() {
            inner.push(0x03);
            inner.extend_from_slice(i.to_string().as_bytes());
            inner.push(0);
            inner.extend_from_slice(d);
        }
        inner.push(0);
        let len = i32::try_from(inner.len() + 4).unwrap_or(i32::MAX);
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(&inner);
        self
    }

    #[must_use]
    pub fn binary(mut self, key: &str, v: &[u8]) -> Self {
        self.key(0x05, key);
        let len = i32::try_from(v.len()).unwrap_or(i32::MAX);
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.push(0);
        self.buf.extend_from_slice(v);
        self
    }

    #[must_use]
    pub fn bool(mut self, key: &str, v: bool) -> Self {
        self.key(0x08, key);
        self.buf.push(u8::from(v));
        self
    }

    #[must_use]
    pub fn datetime_ms(mut self, key: &str, v: i64) -> Self {
        self.key(0x09, key);
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    #[must_use]
    pub fn i32(mut self, key: &str, v: i32) -> Self {
        self.key(0x10, key);
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    #[must_use]
    pub fn i64(mut self, key: &str, v: i64) -> Self {
        self.key(0x12, key);
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    #[must_use]
    pub fn finish(mut self) -> Vec<u8> {
        self.buf.push(0);
        let len = i32::try_from(self.buf.len()).unwrap_or(i32::MAX);
        self.buf[..4].copy_from_slice(&len.to_le_bytes());
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        Builder::new()
            .str("find", "customers")
            .doc(
                "filter",
                &Builder::new().str("email", "ada@example.com").i32("n", 7),
            )
            .bool("flag", true)
            .i64("big", 1 << 40)
            .f64("pi", 3.5)
            .binary("blob", b"\x01\x02")
            .datetime_ms("when", 1_700_000_000_000)
            .str_array("tags", &["a", "b"])
            .docs_array("steps", &[Builder::new().i32("a", 1).finish()])
            .finish()
    }

    #[test]
    fn builds_and_reads_back_every_type_it_writes() {
        let bytes = sample();
        let doc = Doc::new(&bytes).expect("doc");
        doc.validate().expect("valid");
        let keys: Vec<_> = doc.iter().map(|e| e.expect("element").0).collect();
        assert_eq!(
            keys,
            [
                "find", "filter", "flag", "big", "pi", "blob", "when", "tags", "steps"
            ]
        );
        assert_eq!(doc.first().expect("ok").expect("first").0, "find");
        assert_eq!(doc.get("find").expect("ok"), Some(Value::Str("customers")));
        assert_eq!(
            doc.get("big").expect("ok").and_then(|v| v.as_i64()),
            Some(1 << 40)
        );
        assert_eq!(doc.get("pi").expect("ok"), Some(Value::Double(3.5)));
        assert_eq!(doc.get("missing").expect("ok"), None);
        let Some(Value::Doc(filter)) = doc.get("filter").expect("ok") else {
            panic!("filter is a document");
        };
        assert_eq!(filter.get("n").expect("ok"), Some(Value::Int32(7)));
        let Some(Value::Array(tags)) = doc.get("tags").expect("ok") else {
            panic!("tags is an array");
        };
        assert_eq!(tags.iter().count(), 2);
    }

    #[test]
    fn rejects_lengths_that_lie() {
        let bytes = sample();
        assert_eq!(
            Doc::new(&bytes[..bytes.len() - 1]),
            Err(BsonError::Malformed)
        );
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(Doc::new(&longer), Err(BsonError::Malformed));
        let mut no_nul = bytes.clone();
        *no_nul.last_mut().expect("byte") = 1;
        assert_eq!(Doc::new(&no_nul), Err(BsonError::Malformed));
        assert_eq!(Doc::new(&[1, 0, 0]), Err(BsonError::Truncated));
        // An element that claims more bytes than the document has.
        let mut cut = Builder::new().str("a", "hello").finish();
        cut[7] = 0x7f; // the string's length byte
        let doc = Doc::new(&cut).expect("framing is fine");
        assert!(doc.iter().next().expect("one").is_err());
    }

    #[test]
    fn rejects_unknown_types_and_stops_after_an_error() {
        let mut bytes = Builder::new().i32("a", 1).i32("b", 2).finish();
        bytes[4] = 0x20; // the first element's type tag
        let doc = Doc::new(&bytes).expect("doc");
        let mut it = doc.iter();
        assert_eq!(it.next().expect("item"), Err(BsonError::UnknownType(0x20)));
        assert!(it.next().is_none(), "nothing after an error");
        assert!(doc.validate().is_err());
    }

    #[test]
    fn caps_nesting() {
        let mut inner = Builder::new().i32("x", 1).finish();
        for _ in 0..(MAX_DEPTH + 5) {
            let mut b = Builder::new();
            b.buf.push(0x03);
            b.buf.extend_from_slice(b"d\0");
            b.buf.extend_from_slice(&inner);
            inner = b.finish();
        }
        let doc = Doc::new(&inner).expect("doc");
        assert_eq!(doc.validate(), Err(BsonError::Depth));
    }

    #[test]
    fn skips_the_types_it_does_not_read() {
        // Hand-built: ObjectId, Regex, Timestamp, Decimal128, MinKey, MaxKey,
        // Null, Undefined, code with scope, DBPointer.
        let mut body = Vec::new();
        body.extend_from_slice(&[0x07, b'a', 0]);
        body.extend_from_slice(&[7; 12]);
        body.extend_from_slice(&[0x0B, b'b', 0, b'x', 0, b'i', 0]);
        body.extend_from_slice(&[0x11, b'c', 0]);
        body.extend_from_slice(&5u64.to_le_bytes());
        body.extend_from_slice(&[0x13, b'd', 0]);
        body.extend_from_slice(&[1; 16]);
        body.extend_from_slice(&[0xFF, b'e', 0, 0x7F, b'f', 0, 0x0A, b'g', 0, 0x06, b'h', 0]);
        // CodeWithScope: total = 4 + (4 + 2) + 5
        body.extend_from_slice(&[0x0F, b'i', 0]);
        body.extend_from_slice(&15i32.to_le_bytes());
        body.extend_from_slice(&2i32.to_le_bytes());
        body.extend_from_slice(&[b'x', 0]);
        body.extend_from_slice(&[5, 0, 0, 0, 0]);
        // DBPointer: string + 12 bytes
        body.extend_from_slice(&[0x0C, b'j', 0]);
        body.extend_from_slice(&2i32.to_le_bytes());
        body.extend_from_slice(&[b'n', 0]);
        body.extend_from_slice(&[0; 12]);
        body.extend_from_slice(&[0x10, b'z', 0, 9, 0, 0, 0]);
        body.push(0);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&i32::try_from(body.len() + 4).expect("len").to_le_bytes());
        bytes.extend_from_slice(&body);
        let doc = Doc::new(&bytes).expect("doc");
        doc.validate().expect("every type is skipped by its size");
        assert_eq!(doc.get("z").expect("ok"), Some(Value::Int32(9)));
        assert_eq!(doc.iter().count(), 11);
    }

    #[test]
    fn numbers_and_truthiness() {
        assert_eq!(Value::Double(2.0).as_i64(), Some(2));
        assert_eq!(Value::Double(2.5).as_i64(), None);
        assert_eq!(Value::Str("1").as_i64(), None);
        assert!(Value::Double(1.0).is_truthy() && Value::Int32(1).is_truthy());
        assert!(!Value::Int32(0).is_truthy() && !Value::Null.is_truthy());
    }
}
