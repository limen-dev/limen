//! What a search request does and which indices it names (ADR-0036).
//!
//! The worker is the policy point, so this is written to fail closed:
//! anything it can't read with certainty is refused, and an API it doesn't
//! recognise is `admin` on every index. The functions here are pure; the
//! session code feeds them each request.
//!
//! Classification happens in two steps. [`classify`] reads only the head
//! (method, path, query) and says what the body must be read for. Then
//! [`inspect_body`] adds the indices a body names (`_bulk`, `_msearch`,
//! `_mget`, `_reindex`, `_aliases`, and the references inside a search body).
//! [`decide`] compares the result with the session's grants.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;

use limen_policy::{SearchClass, SearchGrant};
use serde_json::Value;

/// The longest request target the worker accepts.
pub const MAX_TARGET: usize = 16 * 1024;
/// The most indices an audit event lists.
pub const MAX_LISTED: usize = 100;

/// Why a request was refused. The text goes to the user and into the audit trail,
/// so it never repeats a body or a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn refuse<T>(why: impl Into<String>) -> Result<T, Refused> {
    Err(Refused(why.into()))
}

/// What the path names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// No index (cluster health, a scroll id, the root).
    None,
    /// Every index (`/_search`, `/_all/...`, `/*/...`, or an API we don't recognise).
    All,
    /// These names or patterns (`logs-*`).
    Indices(Vec<String>),
}

/// What the worker has to read from the body, if anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    None,
    /// A search-like body: look for references to other indices.
    Query,
    Bulk,
    Msearch,
    /// `_mget` and `_mtermvectors`: `docs[]._index`.
    Mget,
    Reindex,
    Aliases,
}

/// The result of reading a request's head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shape {
    /// A short API name for the audit trail (`search`, `bulk`, `doc.write`, `unrecognised`).
    pub api: &'static str,
    pub class: SearchClass,
    pub scope: Scope,
    pub body: BodyKind,
    /// Positions in `segments` that hold a document id.
    pub id_segments: Vec<usize>,
    /// The path's segments as sent (still percent-encoded).
    pub segments: Vec<String>,
    /// The API handles credentials or users; its body is never logged.
    pub sensitive: bool,
    /// The query string has `source`, which carries a request body.
    pub source_param: bool,
    /// `expand_wildcards` asks for hidden indices.
    pub hidden_wildcards: bool,
    /// Query parameter names, in order.
    pub params: Vec<String>,
}

/// What a request names once its body has been read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Named {
    pub all: bool,
    pub names: BTreeSet<String>,
}

impl Named {
    fn add_scope(&mut self, scope: &Scope) {
        match scope {
            Scope::None => {}
            Scope::All => self.all = true,
            Scope::Indices(v) => self.names.extend(v.iter().cloned()),
        }
    }
}

/// What reading the body found, for the audit event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BodyFacts {
    pub named: Named,
    /// `_bulk`: operations by index, then by action.
    pub bulk_ops: BTreeMap<String, BTreeMap<&'static str, u64>>,
    /// `_msearch` searches, or `_mget` documents.
    pub items: u64,
    /// `_reindex` reads from another cluster.
    pub remote: bool,
}

// ---- the head ------------------------------------------------------------------------

fn pct_decode(s: &str, plus_is_space: bool) -> Result<String, Refused> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = b
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                let Some(v) = hex else {
                    return refuse("the request path has an invalid percent escape");
                };
                out.push(v);
                i += 3;
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).or_else(|_| refuse("the request path isn't valid UTF-8"))
}

/// Split and decode a path. Refuses what could be read two ways: empty and dot
/// segments, an encoded `/` or `\`, control characters.
fn segments(path: &str) -> Result<(Vec<String>, Vec<String>), Refused> {
    let Some(rest) = path.strip_prefix('/') else {
        return refuse("the request target must be an absolute path");
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut raw = Vec::new();
    let mut decoded = Vec::new();
    for seg in rest.split('/') {
        let d = pct_decode(seg, false)?;
        if d.is_empty() {
            return refuse("the request path has an empty segment");
        }
        if d == "." || d == ".." {
            return refuse("the request path has a dot segment");
        }
        if d.chars().any(|c| c.is_control() || c == '/' || c == '\\') {
            return refuse("the request path has a character that can be read two ways");
        }
        raw.push(seg.to_owned());
        decoded.push(d);
    }
    Ok((raw, decoded))
}

/// One element of an index expression (`logs-*,-logs-old`).
enum Token {
    All,
    Name(String),
    Exclude,
}

fn valid_name_char(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-' | b'*')
}

/// Parse a comma-separated index expression. Date math, cross-cluster names, and
/// anything outside the characters index names use are refused: policy can't
/// say what they mean.
fn index_tokens(expr: &str) -> Result<Vec<Token>, Refused> {
    let mut out = Vec::new();
    for t in expr.split(',') {
        if t.is_empty() {
            return refuse("the index list has an empty entry");
        }
        if t == "_all" || t == "*" {
            out.push(Token::All);
            continue;
        }
        if let Some(rest) = t.strip_prefix('-') {
            if rest.is_empty() || !rest.bytes().all(valid_name_char) {
                return refuse("unsupported index expression");
            }
            out.push(Token::Exclude);
            continue;
        }
        if t.len() > 255 || t.starts_with(['_', '+']) || !t.bytes().all(valid_name_char) {
            return refuse(format!(
                "unsupported index expression {t:?}: use plain names or patterns with *"
            ));
        }
        out.push(Token::Name(t.to_owned()));
    }
    Ok(out)
}

fn scope_of(expr: &str) -> Result<Scope, Refused> {
    let tokens = index_tokens(expr)?;
    if tokens.iter().any(|t| matches!(t, Token::All)) {
        return Ok(Scope::All);
    }
    let names: Vec<String> = tokens
        .into_iter()
        .filter_map(|t| match t {
            Token::Name(n) => Some(n),
            _ => None,
        })
        .collect();
    // Only exclusions: the engine treats that as "all, minus these".
    Ok(if names.is_empty() {
        Scope::All
    } else {
        Scope::Indices(names)
    })
}

struct Route {
    api: &'static str,
    class: SearchClass,
    scope: Scope,
    body: BodyKind,
    ids: Vec<usize>,
}

fn route(api: &'static str, class: SearchClass, scope: Scope) -> Route {
    Route {
        api,
        class,
        scope,
        body: BodyKind::None,
        ids: Vec::new(),
    }
}

impl Route {
    fn body(mut self, body: BodyKind) -> Self {
        self.body = body;
        self
    }
    fn id(mut self, at: usize) -> Self {
        self.ids.push(at);
        self
    }
}

use SearchClass::{Admin, Read, Write};

/// What we don't recognise: admin, on everything.
fn unrecognised() -> Route {
    route("unrecognised", Admin, Scope::All)
}

fn read_methods(m: &str) -> bool {
    matches!(m, "GET" | "HEAD")
}
fn search_methods(m: &str) -> bool {
    matches!(m, "GET" | "POST")
}

/// Read the head of a request: what it does and what the path names.
pub fn classify(method: &str, path: &str, query: Option<&str>) -> Result<Shape, Refused> {
    if !matches!(method, "GET" | "HEAD" | "POST" | "PUT" | "DELETE") {
        return refuse(format!("the method {method} isn't supported"));
    }
    if path.len() + query.map_or(0, str::len) > MAX_TARGET {
        return refuse("the request target is too long");
    }
    let (raw, segs) = segments(path)?;
    let (params, source_param, hidden_wildcards) = parse_query(query)?;
    let r = dispatch(method, &segs)?;
    let sensitive = is_sensitive(&segs);
    Ok(Shape {
        api: r.api,
        class: r.class,
        scope: r.scope,
        body: r.body,
        id_segments: r.ids,
        segments: raw,
        sensitive,
        source_param,
        hidden_wildcards,
        params,
    })
}

fn parse_query(query: Option<&str>) -> Result<(Vec<String>, bool, bool), Refused> {
    let mut names = Vec::new();
    let mut source = false;
    let mut hidden = false;
    for pair in query
        .unwrap_or_default()
        .split('&')
        .filter(|p| !p.is_empty())
    {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let k = pct_decode(k, true)?.to_ascii_lowercase();
        if k == "source" {
            source = true;
        }
        if k == "expand_wildcards" {
            let v = pct_decode(v, true)?.to_ascii_lowercase();
            hidden |= v.split(',').any(|x| x == "all" || x == "hidden");
        }
        if names.len() < MAX_LISTED {
            names.push(k);
        }
    }
    Ok((names, source, hidden))
}

fn is_sensitive(segs: &[String]) -> bool {
    let s = |i: usize| segs.get(i).map(String::as_str);
    matches!(s(0), Some("_security"))
        || matches!(
            (s(0), s(1)),
            (Some("_plugins" | "_opendistro"), Some("_security"))
                | (Some("_xpack"), Some("security"))
        )
}

#[allow(clippy::too_many_lines, clippy::match_same_arms)] // one table; arms stay apart so each API reads on its own
fn dispatch(m: &str, segs: &[String]) -> Result<Route, Refused> {
    let seg = |i: usize| segs.get(i).map(String::as_str);
    let Some(first) = seg(0) else {
        return Ok(if read_methods(m) {
            route("info", Read, Scope::None)
        } else {
            unrecognised()
        });
    };
    if first.starts_with('_') && first != "_all" && !first.contains(',') {
        return Ok(top_level(m, segs, first));
    }
    // The first segment is an index expression.
    let scope = scope_of(first)?;
    let idx = || scope.clone();
    Ok(match (seg(1), seg(2), seg(3)) {
        (None, ..) => match m {
            "GET" | "HEAD" => route("index.get", Read, idx()),
            _ => route("index.manage", Admin, idx()),
        },
        (Some("_doc"), None, _) if m == "POST" => route("doc.write", Write, idx()),
        (Some("_doc"), Some(_), None) => match m {
            "GET" | "HEAD" => route("doc.get", Read, idx()).id(2),
            "PUT" | "POST" | "DELETE" => route("doc.write", Write, idx()).id(2),
            _ => unrecognised(),
        },
        (Some("_create"), Some(_), None) if matches!(m, "PUT" | "POST") => {
            route("doc.write", Write, idx()).id(2)
        }
        (Some("_update"), Some(_), None) if m == "POST" => route("doc.write", Write, idx()).id(2),
        (Some("_source"), Some(_), None) if read_methods(m) => route("doc.get", Read, idx()).id(2),
        (Some("_bulk"), None, _) if matches!(m, "POST" | "PUT") => {
            route("bulk", Write, idx()).body(BodyKind::Bulk)
        }
        (Some("_search"), None, _) if search_methods(m) => {
            route("search", Read, idx()).body(BodyKind::Query)
        }
        (Some("_search"), Some("template"), None) if search_methods(m) => {
            route("search", Read, idx()).body(BodyKind::Query)
        }
        (Some("_search"), Some("point_in_time"), None) if m == "POST" => route("pit", Read, idx()),
        (Some("_pit"), None, _) if m == "POST" => route("pit", Read, idx()),
        (Some("_msearch"), None | Some("template"), None) if search_methods(m) => {
            route("msearch", Read, idx()).body(BodyKind::Msearch)
        }
        (Some("_count" | "_field_caps" | "_rank_eval" | "_knn_search"), None, _)
            if search_methods(m) =>
        {
            route("search", Read, idx()).body(BodyKind::Query)
        }
        (Some("_validate"), Some("query"), None) if search_methods(m) => {
            route("search", Read, idx()).body(BodyKind::Query)
        }
        (Some("_explain"), Some(_), None) if search_methods(m) => {
            route("search", Read, idx()).body(BodyKind::Query).id(2)
        }
        (Some("_mget"), None, _) if search_methods(m) => {
            route("mget", Read, idx()).body(BodyKind::Mget)
        }
        (Some("_mtermvectors"), None, _) if search_methods(m) => {
            route("mget", Read, idx()).body(BodyKind::Mget)
        }
        (Some("_termvectors" | "_termvector"), id, None) if search_methods(m) => {
            let r = route("search", Read, idx()).body(BodyKind::Query);
            if id.is_some() { r.id(2) } else { r }
        }
        (Some("_eql"), Some("search"), None) if search_methods(m) => {
            route("search", Read, idx()).body(BodyKind::Query)
        }
        (Some("_async_search"), None, _) if m == "POST" => {
            route("search", Read, idx()).body(BodyKind::Query)
        }
        (Some("_delete_by_query" | "_update_by_query"), None, _) if m == "POST" => {
            route("by_query", Write, idx()).body(BodyKind::Query)
        }
        (Some("_analyze"), None, _) if search_methods(m) => route("analyze", Read, idx()),
        (
            Some(
                "_stats" | "_segments" | "_recovery" | "_search_shards" | "_shard_stores"
                | "_field_usage_stats",
            ),
            ..,
        ) if read_methods(m) => route("index.info", Read, idx()),
        (Some("_mapping" | "_mappings" | "_settings" | "_alias" | "_aliases"), ..)
            if read_methods(m) =>
        {
            route("index.info", Read, idx())
        }
        (Some("_resolve"), ..) if read_methods(m) => route("index.info", Read, idx()),
        _ => route("index.manage", Admin, idx()),
    })
}

#[allow(clippy::match_same_arms)] // one table, as above
fn top_level(m: &str, segs: &[String], first: &str) -> Route {
    let seg = |i: usize| segs.get(i).map(String::as_str);
    match (first, seg(1), seg(2)) {
        ("_search", None, _) if search_methods(m) => {
            route("search", Read, Scope::All).body(BodyKind::Query)
        }
        ("_search", Some("template"), None) if search_methods(m) => {
            route("search", Read, Scope::All).body(BodyKind::Query)
        }
        ("_search", Some("scroll"), _) if matches!(m, "GET" | "POST" | "DELETE") => {
            route("scroll", Read, Scope::None)
        }
        ("_search", Some("point_in_time"), _) if m == "DELETE" => route("pit", Read, Scope::None),
        ("_pit", None, _) if m == "DELETE" => route("pit", Read, Scope::None),
        ("_msearch", None | Some("template"), None) if search_methods(m) => {
            route("msearch", Read, Scope::All).body(BodyKind::Msearch)
        }
        ("_count" | "_field_caps" | "_rank_eval", None, _) if search_methods(m) => {
            route("search", Read, Scope::All).body(BodyKind::Query)
        }
        ("_validate", Some("query"), None) if search_methods(m) => {
            route("search", Read, Scope::All).body(BodyKind::Query)
        }
        ("_mget" | "_mtermvectors", None, _) if search_methods(m) => {
            route("mget", Read, Scope::All).body(BodyKind::Mget)
        }
        ("_analyze", None, _) if search_methods(m) => route("analyze", Read, Scope::None),
        ("_render", Some("template"), _) if search_methods(m) => route("render", Read, Scope::None),
        ("_bulk", None, _) if matches!(m, "POST" | "PUT") => {
            route("bulk", Write, Scope::All).body(BodyKind::Bulk)
        }
        ("_reindex", None, _) if m == "POST" => {
            route("reindex", Write, Scope::None).body(BodyKind::Reindex)
        }
        ("_aliases", None, _) if m == "POST" => {
            route("aliases", Admin, Scope::None).body(BodyKind::Aliases)
        }
        ("_stats" | "_mapping" | "_mappings" | "_settings" | "_alias" | "_aliases", ..)
            if read_methods(m) =>
        {
            let scope = match seg(1) {
                Some(s) if !s.starts_with('_') && first != "_stats" => {
                    scope_of(s).unwrap_or(Scope::All)
                }
                _ => Scope::All,
            };
            route("index.info", Read, scope)
        }
        ("_resolve", Some("index"), name) if read_methods(m) => route(
            "index.info",
            Read,
            name.map_or(Scope::All, |n| scope_of(n).unwrap_or(Scope::All)),
        ),
        ("_cat", ..) => cat(m, segs),
        ("_cluster", Some("health"), idx) if read_methods(m) => route(
            "cluster.health",
            Read,
            idx.map_or(Scope::None, |n| scope_of(n).unwrap_or(Scope::All)),
        ),
        ("_cluster", Some("stats" | "pending_tasks"), None) if read_methods(m) => {
            route("cluster.info", Read, Scope::None)
        }
        ("_nodes", Some("stats"), _) if read_methods(m) => route("cluster.info", Read, Scope::None),
        ("_sql" | "_ppl", None | Some("close" | "translate"), None) if search_methods(m) => {
            route("sql", Read, Scope::All).body(BodyKind::Query)
        }
        ("_plugins" | "_opendistro", Some("_sql" | "_ppl"), None) if search_methods(m) => {
            route("sql", Read, Scope::All).body(BodyKind::Query)
        }
        ("_async_search", None, _) if m == "POST" => {
            route("search", Read, Scope::All).body(BodyKind::Query)
        }
        ("_async_search", Some(_), _) if matches!(m, "GET" | "DELETE") => {
            route("scroll", Read, Scope::None)
        }
        _ => unrecognised(),
    }
}

/// `_cat` endpoints: some name no index, some list them.
fn cat(m: &str, segs: &[String]) -> Route {
    if !read_methods(m) {
        return unrecognised();
    }
    let seg = |i: usize| segs.get(i).map(String::as_str);
    match seg(1) {
        None
        | Some(
            "help" | "health" | "nodes" | "master" | "cluster_manager" | "plugins" | "thread_pool"
            | "nodeattrs" | "allocation" | "pending_tasks",
        ) => route("cat", Read, Scope::None),
        Some(
            "indices" | "shards" | "count" | "segments" | "recovery" | "fielddata" | "aliases",
        ) => {
            let scope = match seg(2) {
                Some(n) => scope_of(n).unwrap_or(Scope::All),
                None => Scope::All,
            };
            route("cat", Read, scope)
        }
        _ => unrecognised(),
    }
}

// ---- the body ------------------------------------------------------------------------

/// Read a request body that may be gzip-compressed, up to `limit` bytes decoded.
pub fn decode_body(
    bytes: &[u8],
    content_encoding: Option<&str>,
    limit: usize,
) -> Result<Vec<u8>, Refused> {
    match content_encoding.map(str::trim) {
        None | Some("" | "identity") => Ok(bytes.to_vec()),
        Some(e) if e.eq_ignore_ascii_case("gzip") => {
            let mut out = Vec::new();
            let limit = u64::try_from(limit).unwrap_or(u64::MAX);
            flate2::read::GzDecoder::new(bytes)
                .take(limit.saturating_add(1))
                .read_to_end(&mut out)
                .or_else(|_| refuse("the request body isn't valid gzip"))?;
            if out.len() as u64 > limit {
                return refuse("the request body is too large to inspect");
            }
            Ok(out)
        }
        Some(other) => refuse(format!(
            "this API's body must be read, and Content-Encoding {other:?} isn't supported (use gzip or none)"
        )),
    }
}

fn token_names(v: &Value, what: &str) -> Result<Vec<String>, Refused> {
    let mut out = Vec::new();
    let items: Vec<&Value> = match v {
        Value::Array(a) => a.iter().collect(),
        other => vec![other],
    };
    for item in items {
        let Some(s) = item.as_str() else {
            return refuse(format!("{what} must be a string or a list of strings"));
        };
        out.push(s.to_owned());
    }
    Ok(out)
}

/// Add the names in an index expression found in a body to `named`.
fn add_expr(named: &mut Named, expr: &str) -> Result<(), Refused> {
    named.add_scope(&scope_of(expr)?);
    Ok(())
}

/// Look in a search body for references to other indices: `_index` anywhere,
/// terms lookups, indexed shapes, and `percolate` by id. Anything that isn't
/// plainly a name is refused.
fn walk_refs(v: &Value, named: &mut Named, depth: usize) -> Result<(), Refused> {
    if depth > 64 {
        return refuse("the request body is nested too deeply");
    }
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                match k.as_str() {
                    "_index" => {
                        for n in token_names(child, "_index")? {
                            add_expr(named, &n)?;
                        }
                    }
                    "terms" => {
                        if let Value::Object(fields) = child {
                            for lookup in fields.values() {
                                if let Value::Object(l) = lookup
                                    && let Some(i) = l.get("index")
                                {
                                    for n in token_names(i, "a terms lookup index")? {
                                        add_expr(named, &n)?;
                                    }
                                }
                            }
                        }
                    }
                    "indexed_shape" => {
                        let idx = child
                            .get("index")
                            .map_or(Ok(vec!["shapes".to_owned()]), |i| {
                                token_names(i, "an indexed_shape index")
                            })?;
                        for n in idx {
                            add_expr(named, &n)?;
                        }
                    }
                    "percolate" => {
                        if let Some(i) = child.get("index") {
                            for n in token_names(i, "a percolate index")? {
                                add_expr(named, &n)?;
                            }
                        }
                        // The documents are data, not references.
                        if let Value::Object(p) = child {
                            for (pk, pv) in p {
                                if pk != "document" && pk != "documents" {
                                    walk_refs(pv, named, depth + 1)?;
                                }
                            }
                        }
                        continue;
                    }
                    _ => {}
                }
                walk_refs(child, named, depth + 1)?;
            }
        }
        Value::Array(a) => {
            for child in a {
                walk_refs(child, named, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_json(bytes: &[u8]) -> Result<Value, Refused> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Null);
    }
    serde_json::from_slice(bytes).or_else(|_| refuse("the request body isn't valid JSON"))
}

fn ndjson_lines(bytes: &[u8]) -> Vec<&[u8]> {
    bytes
        .split(|b| *b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .filter(|l| !l.iter().all(u8::is_ascii_whitespace))
        .collect()
}

fn path_names(shape: &Shape) -> Named {
    let mut n = Named::default();
    n.add_scope(&shape.scope);
    n
}

/// Read the body of a request and say which indices it names, in addition
/// to the path's.
#[allow(clippy::too_many_lines)] // one case per body kind
pub fn inspect_body(shape: &Shape, body: &[u8]) -> Result<BodyFacts, Refused> {
    let mut facts = BodyFacts {
        named: path_names(shape),
        ..BodyFacts::default()
    };
    match shape.body {
        BodyKind::None => {}
        BodyKind::Query => {
            walk_refs(&parse_json(body)?, &mut facts.named, 0)?;
        }
        BodyKind::Bulk => {
            let default_index: Option<&Vec<String>> = match &shape.scope {
                Scope::Indices(v) => Some(v),
                _ => None,
            };
            // The path's index is a default, not an extra name: replace it by
            // what each action uses.
            let mut named = Named::default();
            let mut lines = ndjson_lines(body).into_iter();
            while let Some(line) = lines.next() {
                let Value::Object(action) = serde_json::from_slice(line)
                    .or_else(|_| refuse("a _bulk action line isn't valid JSON"))?
                else {
                    return refuse("a _bulk action line isn't an object");
                };
                if action.len() != 1 {
                    return refuse("a _bulk action line must have exactly one action");
                }
                let Some((name, meta)) = action.iter().next() else {
                    return refuse("a _bulk action line is empty");
                };
                let op: &'static str = match name.as_str() {
                    "index" => "index",
                    "create" => "create",
                    "update" => "update",
                    "delete" => "delete",
                    other => return refuse(format!("unknown _bulk action {other:?}")),
                };
                let target = match meta.get("_index") {
                    Some(v) => {
                        let listed = token_names(v, "_index")?;
                        if listed.len() != 1 || listed[0].contains('*') || listed[0].contains(',') {
                            return refuse("a _bulk action must name one concrete index");
                        }
                        listed
                    }
                    None => match default_index {
                        Some(v) if v.len() == 1 && !v[0].contains('*') => v.clone(),
                        _ => {
                            return refuse(
                                "a _bulk action names no index and the path has no single one",
                            );
                        }
                    },
                };
                add_expr(&mut named, &target[0])?;
                *facts
                    .bulk_ops
                    .entry(target[0].clone())
                    .or_default()
                    .entry(op)
                    .or_insert(0) += 1;
                facts.items += 1;
                if op != "delete" && lines.next().is_none() {
                    return refuse("a _bulk action is missing its source line");
                }
            }
            facts.named = named;
        }
        BodyKind::Msearch => {
            let mut named = Named::default();
            let mut lines = ndjson_lines(body).into_iter();
            while let Some(header) = lines.next() {
                let Value::Object(h) = serde_json::from_slice(header)
                    .or_else(|_| refuse("an _msearch header line isn't valid JSON"))?
                else {
                    return refuse("an _msearch header line isn't an object");
                };
                let Some(search) = lines.next() else {
                    return refuse("an _msearch header has no body line");
                };
                match h.get("index") {
                    Some(v) => {
                        for n in token_names(v, "an _msearch index")? {
                            add_expr(&mut named, &n)?;
                        }
                    }
                    None => named.add_scope(&shape.scope),
                }
                walk_refs(&parse_json(search)?, &mut named, 0)?;
                facts.items += 1;
            }
            if facts.items == 0 {
                named.add_scope(&shape.scope);
            }
            facts.named = named;
        }
        BodyKind::Mget => {
            let v = parse_json(body)?;
            let mut named = Named::default();
            let mut inherits = v.get("ids").is_some();
            if let Some(Value::Array(docs)) = v.get("docs") {
                for d in docs {
                    match d.get("_index") {
                        Some(i) => {
                            for n in token_names(i, "a document's _index")? {
                                add_expr(&mut named, &n)?;
                            }
                        }
                        None => inherits = true,
                    }
                    facts.items += 1;
                }
            }
            if inherits || facts.items == 0 {
                named.add_scope(&shape.scope);
            }
            facts.named = named;
        }
        BodyKind::Reindex => {
            let v = parse_json(body)?;
            let mut named = Named::default();
            let source = v.get("source").and_then(Value::as_object);
            let Some(source) = source else {
                return refuse("_reindex needs a source");
            };
            facts.remote = source.contains_key("remote");
            let Some(src_index) = source.get("index") else {
                return refuse("_reindex needs source.index");
            };
            for n in token_names(src_index, "source.index")? {
                add_expr(&mut named, &n)?;
            }
            let Some(dest) = v.pointer("/dest/index") else {
                return refuse("_reindex needs dest.index");
            };
            for n in token_names(dest, "dest.index")? {
                if n.contains('*') || n.contains(',') {
                    return refuse("dest.index must be one concrete index");
                }
                add_expr(&mut named, &n)?;
            }
            facts.named = named;
        }
        BodyKind::Aliases => {
            let v = parse_json(body)?;
            let mut named = Named::default();
            let Some(actions) = v.get("actions").and_then(Value::as_array) else {
                return refuse("_aliases needs an actions list");
            };
            for a in actions {
                let Some(inner) = a.as_object().and_then(|o| o.values().next()) else {
                    return refuse("an _aliases action isn't an object");
                };
                for key in ["index", "indices", "alias", "aliases"] {
                    if let Some(v) = inner.get(key) {
                        for n in token_names(v, key)? {
                            add_expr(&mut named, &n)?;
                        }
                    }
                }
                facts.items += 1;
            }
            facts.named = named;
        }
    }
    Ok(facts)
}

// ---- the grants ----------------------------------------------------------------------

/// Does the grant pattern `pattern` cover `name` (itself a name or pattern)?
/// A `*` in `name` is a literal here, so only a `*` in the grant can cover it.
#[must_use]
pub fn covers(pattern: &str, name: &str) -> bool {
    let p = pattern.as_bytes();
    let n = name.as_bytes();
    // dp[j]: p[..i] covers n[..j]
    let mut dp = vec![false; n.len() + 1];
    dp[0] = true;
    for &pc in p {
        if pc == b'*' {
            // `*` covers any run, including none.
            for j in 1..=n.len() {
                dp[j] = dp[j] || dp[j - 1];
            }
        } else {
            for j in (1..=n.len()).rev() {
                dp[j] = dp[j - 1] && pc == n[j - 1];
            }
            dp[0] = false;
        }
    }
    dp[n.len()]
}

fn hidden(name: &str) -> bool {
    name.starts_with('.')
}

/// May one grant do `class` on everything `named` lists?
fn grant_allows(
    g: &SearchGrant,
    class: SearchClass,
    named: &Named,
    shape: &Shape,
) -> Result<(), String> {
    if !g.allowed_classes().contains(&class) {
        return Err(format!(
            "{} requests aren't allowed (this grant allows: {})",
            class.as_str(),
            g.allowed_classes()
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let restricted = !g.indices.is_empty();
    if restricted && shape.source_param {
        return Err("the source query parameter isn't allowed with index-restricted access; send the query as the body".into());
    }
    if shape.hidden_wildcards && !g.indices.iter().any(|p| hidden(p)) {
        return Err("expand_wildcards for hidden indices isn't allowed".into());
    }
    if named.all {
        if !restricted {
            return Ok(());
        }
        if g.indices.iter().any(|p| p == "*") {
            return Ok(());
        }
        return Err("the request covers every index; name the ones you may use".into());
    }
    for name in &named.names {
        if !restricted {
            if hidden(name) {
                return Err(format!("{name} is a hidden index and isn't granted"));
            }
            continue;
        }
        let ok = g
            .indices
            .iter()
            .any(|p| covers(p, name) && (!hidden(name) || hidden(p)));
        if !ok {
            return Err(format!("{name} is outside the indices granted"));
        }
    }
    Ok(())
}

/// Allowed when any one grant allows the whole request. The error is the
/// first grant's reason, or "no grant" if there are none.
pub fn decide(grants: &[SearchGrant], shape: &Shape, named: &Named) -> Result<(), Refused> {
    let mut why = String::from("no grant allows this session to do that");
    for (i, g) in grants.iter().enumerate() {
        match grant_allows(g, shape.class, named, shape) {
            Ok(()) => return Ok(()),
            Err(e) if i == 0 => why = e,
            Err(_) => {}
        }
    }
    Err(Refused(why))
}

/// A cheap check on the head alone, before a body is read: could any grant
/// allow this class at all, and the path's own names?
pub fn precheck(grants: &[SearchGrant], shape: &Shape) -> Result<(), Refused> {
    let mut named = Named::default();
    named.add_scope(&shape.scope);
    // A body-derived list replaces `All` for some APIs (bulk, msearch): don't
    // judge the scope before the body is read.
    if !matches!(shape.body, BodyKind::None | BodyKind::Query) {
        named = Named::default();
    }
    decide(grants, shape, &named)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(method: &str, target: &str) -> Shape {
        let (path, query) = target
            .split_once('?')
            .map_or((target, None), |(p, q)| (p, Some(q)));
        classify(method, path, query).unwrap_or_else(|e| panic!("{method} {target}: {e}"))
    }

    fn grant(classes: &[SearchClass], indices: &[&str]) -> SearchGrant {
        SearchGrant {
            roles: vec!["r".into()],
            classes: classes.to_vec(),
            indices: indices.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn allowed(g: &SearchGrant, method: &str, target: &str, body: &[u8]) -> Result<(), Refused> {
        let s = classify(
            method,
            target.split('?').next().unwrap_or(target),
            target.split_once('?').map(|x| x.1),
        )?;
        precheck(std::slice::from_ref(g), &s)?;
        let facts = inspect_body(&s, body)?;
        decide(std::slice::from_ref(g), &s, &facts.named)
    }

    #[test]
    fn classes_of_common_requests() {
        let cases: &[(&str, &str, &str, SearchClass)] = &[
            ("GET", "/", "info", Read),
            ("HEAD", "/", "info", Read),
            ("GET", "/logs-1/_search", "search", Read),
            ("POST", "/logs-1/_search?size=1", "search", Read),
            ("POST", "/_search", "search", Read),
            ("POST", "/logs-1/_count", "search", Read),
            ("POST", "/_msearch", "msearch", Read),
            ("POST", "/logs-1/_mget", "mget", Read),
            ("GET", "/logs-1/_doc/1", "doc.get", Read),
            ("HEAD", "/logs-1/_doc/1", "doc.get", Read),
            ("GET", "/logs-1/_source/1", "doc.get", Read),
            ("GET", "/logs-1/_mapping", "index.info", Read),
            ("GET", "/logs-1/_settings", "index.info", Read),
            ("GET", "/logs-1/_stats", "index.info", Read),
            ("GET", "/logs-1", "index.get", Read),
            ("GET", "/_cat/indices/logs-*", "cat", Read),
            ("GET", "/_cat/health", "cat", Read),
            ("GET", "/_cluster/health", "cluster.health", Read),
            ("GET", "/_cluster/health/logs-1", "cluster.health", Read),
            ("GET", "/_nodes/stats", "cluster.info", Read),
            ("POST", "/_search/scroll", "scroll", Read),
            ("DELETE", "/_search/scroll", "scroll", Read),
            ("POST", "/logs-1/_pit?keep_alive=1m", "pit", Read),
            ("POST", "/_sql?format=json", "sql", Read),
            ("POST", "/_plugins/_sql", "sql", Read),
            ("POST", "/logs-1/_doc", "doc.write", Write),
            ("PUT", "/logs-1/_doc/1", "doc.write", Write),
            ("POST", "/logs-1/_doc/1", "doc.write", Write),
            ("DELETE", "/logs-1/_doc/1", "doc.write", Write),
            ("PUT", "/logs-1/_create/1", "doc.write", Write),
            ("POST", "/logs-1/_update/1", "doc.write", Write),
            ("POST", "/_bulk", "bulk", Write),
            ("PUT", "/logs-1/_bulk", "bulk", Write),
            ("POST", "/logs-1/_delete_by_query", "by_query", Write),
            ("POST", "/logs-1/_update_by_query", "by_query", Write),
            ("POST", "/_reindex", "reindex", Write),
            ("PUT", "/logs-1", "index.manage", Admin),
            ("DELETE", "/logs-1", "index.manage", Admin),
            ("PUT", "/logs-1/_mapping", "index.manage", Admin),
            ("PUT", "/logs-1/_settings", "index.manage", Admin),
            ("POST", "/logs-1/_close", "index.manage", Admin),
            ("POST", "/logs-1/_forcemerge", "index.manage", Admin),
            ("POST", "/logs-1/_refresh", "index.manage", Admin),
            ("POST", "/_aliases", "aliases", Admin),
            ("PUT", "/logs-1/_alias/current", "index.manage", Admin),
            ("GET", "/_cluster/settings", "unrecognised", Admin),
            ("PUT", "/_cluster/settings", "unrecognised", Admin),
            ("GET", "/_cluster/state", "unrecognised", Admin),
            ("GET", "/_nodes", "unrecognised", Admin),
            ("GET", "/_nodes/hot_threads", "unrecognised", Admin),
            ("PUT", "/_snapshot/repo", "unrecognised", Admin),
            ("GET", "/_tasks", "unrecognised", Admin),
            ("POST", "/_tasks/abc:1/_cancel", "unrecognised", Admin),
            ("PUT", "/_ingest/pipeline/p", "unrecognised", Admin),
            ("GET", "/_security/user", "unrecognised", Admin),
            (
                "GET",
                "/_plugins/_security/api/internalusers",
                "unrecognised",
                Admin,
            ),
            ("PUT", "/_index_template/t", "unrecognised", Admin),
            ("PUT", "/_scripts/s", "unrecognised", Admin),
            ("DELETE", "/_search", "unrecognised", Admin),
            ("POST", "/_cat/indices", "unrecognised", Admin),
            ("GET", "/_cat/snapshots/repo", "unrecognised", Admin),
            ("GET", "/_some/new/api", "unrecognised", Admin),
        ];
        for (method, target, api, class) in cases {
            let s = shape(method, target);
            assert_eq!((s.api, s.class), (*api, *class), "{method} {target}");
        }
    }

    #[test]
    fn scopes_come_from_the_path() {
        assert_eq!(
            shape("GET", "/logs-1/_search").scope,
            Scope::Indices(vec!["logs-1".into()])
        );
        assert_eq!(
            shape("GET", "/logs-1,metrics-*/_search").scope,
            Scope::Indices(vec!["logs-1".into(), "metrics-*".into()])
        );
        assert_eq!(shape("GET", "/_search").scope, Scope::All);
        assert_eq!(shape("GET", "/_all/_search").scope, Scope::All);
        assert_eq!(shape("GET", "/*/_search").scope, Scope::All);
        assert_eq!(shape("GET", "/logs-*,_all/_search").scope, Scope::All);
        // Only exclusions: the engine reads that as everything but those.
        assert_eq!(shape("GET", "/-logs-old/_search").scope, Scope::All);
        assert_eq!(shape("GET", "/_cat/indices").scope, Scope::All);
        assert_eq!(
            shape("GET", "/_cat/indices/logs-*").scope,
            Scope::Indices(vec!["logs-*".into()])
        );
        assert_eq!(shape("GET", "/_cat/health").scope, Scope::None);
        assert_eq!(shape("GET", "/").scope, Scope::None);
        assert_eq!(shape("POST", "/_search/scroll").scope, Scope::None);
        assert_eq!(shape("GET", "/_mapping").scope, Scope::All);
        assert_eq!(shape("GET", "/_unknown").scope, Scope::All);
        // A trailing slash is the same request.
        assert_eq!(shape("GET", "/logs-1/_search/").api, "search");
    }

    #[test]
    fn evasions_are_refused() {
        for (method, path) in [
            ("GET", "/logs-1/../.security/_search"),
            ("GET", "/logs-1/./_search"),
            ("GET", "//logs-1/_search"),
            ("GET", "/logs-1//_search"),
            ("GET", "/logs-1/%2e%2e/.security/_search"),
            ("GET", "/logs-1%2F..%2F.security/_search"),
            ("GET", "/logs-1%5c/_search"),
            ("GET", "/%00/_search"),
            ("GET", "/logs-1/%zz"),
            ("GET", "/<logs-{now/d}>/_search"),
            ("GET", "/%3Clogs-%7Bnow%2Fd%7D%3E/_search"),
            ("GET", "/remote:logs-1/_search"),
            ("GET", "/Logs-1/_search"),
            ("GET", "/logs 1/_search"),
            ("GET", "/_all,/_search"),
            ("GET", "/,logs-1/_search"),
            ("CONNECT", "/"),
            ("PATCH", "/logs-1/_doc/1"),
            ("OPTIONS", "/"),
            ("TRACE", "/"),
            ("GET", "logs-1/_search"),
        ] {
            assert!(
                classify(method, path, None).is_err(),
                "{method} {path} was accepted"
            );
        }
        assert!(classify("GET", &format!("/{}", "a".repeat(MAX_TARGET)), None).is_err());
    }

    #[test]
    fn percent_encoded_api_names_are_read_as_the_engine_reads_them() {
        // The engine decodes the path; so do we, so they agree.
        assert_eq!(shape("POST", "/logs-1/%5fsearch").api, "search");
        // A doubly encoded name stays encoded, so it doesn't pass for an API.
        let s = shape("GET", "/logs-1/%255fsearch");
        assert_eq!(s.api, "index.manage");
    }

    #[test]
    fn query_parameters_are_noted() {
        let s = shape(
            "GET",
            "/logs-1/_search?source=%7B%7D&Expand_Wildcards=all&pretty",
        );
        assert!(s.source_param && s.hidden_wildcards);
        assert_eq!(s.params, ["source", "expand_wildcards", "pretty"]);
        let s = shape("GET", "/logs-1/_search?expand_wildcards=open,hidden");
        assert!(s.hidden_wildcards);
        assert!(!shape("GET", "/logs-1/_search?expand_wildcards=open").hidden_wildcards);
    }

    #[test]
    fn document_ids_are_found_in_the_path() {
        let s = shape("GET", "/users/_doc/alice%40example.com");
        assert_eq!(s.id_segments, [2]);
        assert_eq!(s.segments[2], "alice%40example.com");
        assert_eq!(shape("POST", "/users/_search").id_segments.len(), 0);
    }

    #[test]
    fn security_apis_are_marked_sensitive() {
        assert!(shape("GET", "/_security/user").sensitive);
        assert!(shape("GET", "/_plugins/_security/api/roles").sensitive);
        assert!(!shape("POST", "/logs-1/_search").sensitive);
    }

    #[test]
    fn glob_cover_is_conservative() {
        assert!(covers("logs-*", "logs-1"));
        assert!(covers("logs-*", "logs-"));
        assert!(covers("logs-*", "logs-a*"));
        assert!(covers("logs-*", "logs-*"));
        assert!(covers("*", "anything"));
        assert!(covers("*-prod", "app-prod"));
        assert!(covers("l*s-*", "logs-1"));
        assert!(covers("logs-1", "logs-1"));
        assert!(!covers("logs-1", "logs-2"));
        assert!(!covers("logs-1", "logs-1*"));
        assert!(!covers("logs-*", "log*"));
        assert!(!covers("logs-*", "*"));
        assert!(!covers("logs-a*", "logs-*"));
        assert!(!covers("*-prod", "app-prod-old"));
        assert!(!covers("", "x"));
    }

    #[test]
    fn index_patterns_in_grants_bound_what_a_request_may_name() {
        let g = grant(&[Read], &["logs-*", "metrics-2026.*"]);
        assert!(allowed(&g, "POST", "/logs-1/_search", b"{}").is_ok());
        assert!(allowed(&g, "POST", "/logs-a*/_search", b"{}").is_ok());
        assert!(allowed(&g, "POST", "/logs-1,metrics-2026.01/_search", b"{}").is_ok());
        assert!(allowed(&g, "POST", "/orders/_search", b"{}").is_err());
        assert!(allowed(&g, "POST", "/logs-1,orders/_search", b"{}").is_err());
        assert!(
            allowed(&g, "POST", "/_search", b"{}").is_err(),
            "all indices"
        );
        assert!(allowed(&g, "POST", "/_all/_search", b"{}").is_err());
        assert!(allowed(&g, "POST", "/*/_search", b"{}").is_err());
        assert!(allowed(&g, "POST", "/log*/_search", b"{}").is_err());
        // Cluster-level reads name no index.
        assert!(allowed(&g, "GET", "/_cluster/health", b"").is_ok());
        assert!(allowed(&g, "GET", "/_cat/indices", b"").is_err());
        assert!(allowed(&g, "GET", "/_cat/indices/logs-*", b"").is_ok());
    }

    #[test]
    fn an_unrestricted_grant_still_keeps_out_of_hidden_indices() {
        let g = grant(&[Read], &[]);
        assert!(allowed(&g, "POST", "/orders/_search", b"{}").is_ok());
        assert!(allowed(&g, "POST", "/_search", b"{}").is_ok());
        assert!(allowed(&g, "POST", "/.security/_search", b"{}").is_err());
        assert!(allowed(&g, "GET", "/.kibana/_doc/1", b"").is_err());
        assert!(allowed(&g, "POST", "/orders,.tasks/_search", b"{}").is_err());
        assert!(allowed(&g, "POST", "/orders/_search?expand_wildcards=all", b"{}").is_err());
    }

    #[test]
    fn a_star_grant_does_not_open_hidden_indices_but_a_dot_pattern_does() {
        let star = grant(&[Read], &["*"]);
        assert!(allowed(&star, "POST", "/_search", b"{}").is_ok());
        assert!(allowed(&star, "POST", "/orders/_search", b"{}").is_ok());
        assert!(allowed(&star, "POST", "/.security/_search", b"{}").is_err());
        let dot = grant(&[Read], &["logs-*", ".kibana*"]);
        assert!(allowed(&dot, "GET", "/.kibana_1/_doc/1", b"").is_ok());
        assert!(allowed(&dot, "POST", "/.security/_search", b"{}").is_err());
        assert!(
            allowed(
                &dot,
                "POST",
                "/logs-1/_search?expand_wildcards=hidden",
                b"{}"
            )
            .is_ok()
        );
        let plain = grant(&[Read], &["logs-*"]);
        assert!(
            allowed(
                &plain,
                "POST",
                "/logs-1/_search?expand_wildcards=hidden",
                b"{}"
            )
            .is_err()
        );
    }

    #[test]
    fn classes_must_be_granted() {
        let read = grant(&[], &[]);
        assert!(allowed(&read, "POST", "/logs-1/_search", b"{}").is_ok());
        assert!(
            allowed(&read, "PUT", "/logs-1/_doc/1", b"{}").is_err(),
            "write"
        );
        assert!(allowed(&read, "DELETE", "/logs-1", b"").is_err(), "admin");
        assert!(allowed(&read, "GET", "/_cluster/settings", b"").is_err());
        assert!(
            allowed(&read, "GET", "/_brand/new/api", b"").is_err(),
            "unknown is admin"
        );
        let rw = grant(&[Read, Write], &["logs-*"]);
        assert!(allowed(&rw, "PUT", "/logs-1/_doc/1", b"{}").is_ok());
        assert!(allowed(&rw, "DELETE", "/logs-1", b"").is_err());
        // Write doesn't imply read, or the other way round.
        let w = grant(&[Write], &[]);
        assert!(allowed(&w, "POST", "/logs-1/_search", b"{}").is_err());
        let admin = grant(&[Read, Write, Admin], &["logs-*"]);
        assert!(allowed(&admin, "PUT", "/logs-2", b"").is_ok());
        assert!(
            allowed(&admin, "PUT", "/orders", b"").is_err(),
            "still bounded by indices"
        );
    }

    #[test]
    fn the_source_parameter_is_refused_when_indices_are_restricted() {
        let g = grant(&[Read], &["logs-*"]);
        assert!(
            allowed(
                &g,
                "GET",
                "/logs-1/_search?source=%7B%22query%22%3A%7B%7D%7D",
                b""
            )
            .is_err()
        );
        assert!(
            allowed(
                &grant(&[Read], &[]),
                "GET",
                "/logs-1/_search?source=%7B%7D",
                b""
            )
            .is_ok()
        );
    }

    #[test]
    fn grants_do_not_combine_to_cover_one_request() {
        let a = grant(&[Read], &["logs-*"]);
        let b = grant(&[Read], &["metrics-*"]);
        let s = classify("POST", "/logs-1,metrics-1/_search", None).expect("classify");
        let facts = inspect_body(&s, b"{}").expect("body");
        assert!(decide(&[a.clone(), b.clone()], &s, &facts.named).is_err());
        let s = classify("POST", "/metrics-1/_search", None).expect("classify");
        let facts = inspect_body(&s, b"{}").expect("body");
        assert!(decide(&[a, b], &s, &facts.named).is_ok());
        assert!(decide(&[], &s, &facts.named).is_err());
    }

    #[test]
    fn bulk_actions_name_their_own_indices() {
        let g = grant(&[Write], &["logs-*"]);
        let ok = b"{\"index\":{\"_index\":\"logs-1\"}}\n{\"a\":1}\n{\"delete\":{\"_index\":\"logs-2\",\"_id\":\"9\"}}\n";
        assert!(allowed(&g, "POST", "/_bulk", ok).is_ok());
        let bad = b"{\"index\":{\"_index\":\"logs-1\"}}\n{\"a\":1}\n{\"index\":{\"_index\":\"orders\"}}\n{\"a\":2}\n";
        assert!(allowed(&g, "POST", "/_bulk", bad).is_err());
        // The path's index is the default, and only a single concrete one.
        let default = b"{\"create\":{\"_id\":\"1\"}}\n{\"a\":1}\n";
        assert!(allowed(&g, "POST", "/logs-1/_bulk", default).is_ok());
        assert!(allowed(&g, "POST", "/orders/_bulk", default).is_err());
        assert!(
            allowed(&g, "POST", "/_bulk", default).is_err(),
            "no index at all"
        );
        assert!(
            allowed(&g, "POST", "/logs-*/_bulk", default).is_err(),
            "wildcard default"
        );
        // Hidden indices stay hidden.
        let hidden_ = b"{\"index\":{\"_index\":\".security\"}}\n{\"a\":1}\n";
        assert!(allowed(&grant(&[Write], &[]), "POST", "/_bulk", hidden_).is_err());
    }

    #[test]
    fn bulk_bodies_that_cant_be_read_are_refused_and_counted_otherwise() {
        let s = classify("POST", "/_bulk", None).expect("classify");
        for bad in [
            &b"{\"index\":{\"_index\":\"logs-1\"}}\n"[..],
            b"not json\n{}\n",
            b"[1]\n{}\n",
            b"{\"index\":{},\"delete\":{}}\n{}\n",
            b"{\"mystery\":{\"_index\":\"logs-1\"}}\n{}\n",
            b"{\"index\":{\"_index\":\"a,b\"}}\n{}\n",
            b"{\"index\":{\"_index\":42}}\n{}\n",
        ] {
            assert!(
                inspect_body(&s, bad).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        let body = b"{\"index\":{\"_index\":\"a\"}}\n{}\n{\"index\":{\"_index\":\"a\"}}\n{}\n{\"delete\":{\"_index\":\"b\"}}\n{\"update\":{\"_index\":\"a\"}}\n{\"doc\":{}}\n";
        let facts = inspect_body(&s, body).expect("body");
        assert_eq!(facts.items, 4);
        assert_eq!(facts.bulk_ops["a"]["index"], 2);
        assert_eq!(facts.bulk_ops["a"]["update"], 1);
        assert_eq!(facts.bulk_ops["b"]["delete"], 1);
        assert_eq!(facts.named.names.len(), 2);
        // CRLF line ends are fine.
        assert!(inspect_body(&s, b"{\"delete\":{\"_index\":\"a\"}}\r\n").is_ok());
    }

    #[test]
    fn msearch_headers_name_indices() {
        let g = grant(&[Read], &["logs-*"]);
        let ok = b"{\"index\":\"logs-1\"}\n{\"query\":{\"match_all\":{}}}\n{\"index\":[\"logs-2\",\"logs-3\"]}\n{}\n";
        assert!(allowed(&g, "POST", "/_msearch", ok).is_ok());
        let bad = b"{\"index\":\"logs-1\"}\n{}\n{\"index\":\"orders\"}\n{}\n";
        assert!(allowed(&g, "POST", "/_msearch", bad).is_err());
        // A header with no index uses the path's, or means all.
        assert!(allowed(&g, "POST", "/logs-1/_msearch", b"{}\n{}\n").is_ok());
        assert!(allowed(&g, "POST", "/_msearch", b"{}\n{}\n").is_err());
        assert!(
            allowed(&g, "POST", "/_msearch", b"{\"index\":\"logs-1\"}\n").is_err(),
            "odd line count"
        );
        assert!(allowed(&g, "POST", "/_msearch", b"{\"index\":\"logs-1\"}\n{\"query\":{\"terms\":{\"u\":{\"index\":\"orders\",\"id\":\"1\",\"path\":\"x\"}}}}\n").is_err());
    }

    #[test]
    fn mget_documents_name_indices() {
        let g = grant(&[Read], &["logs-*"]);
        assert!(
            allowed(
                &g,
                "POST",
                "/_mget",
                br#"{"docs":[{"_index":"logs-1","_id":"1"}]}"#
            )
            .is_ok()
        );
        assert!(
            allowed(
                &g,
                "POST",
                "/_mget",
                br#"{"docs":[{"_index":"logs-1","_id":"1"},{"_index":"orders","_id":"2"}]}"#
            )
            .is_err()
        );
        assert!(allowed(&g, "POST", "/logs-1/_mget", br#"{"ids":["1","2"]}"#).is_ok());
        assert!(
            allowed(&g, "POST", "/_mget", br#"{"ids":["1"]}"#).is_err(),
            "ids with no index"
        );
        assert!(
            allowed(
                &g,
                "POST",
                "/logs-1/_mget",
                br#"{"docs":[{"_id":"1"},{"_index":"orders","_id":"2"}]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn reindex_reads_one_index_and_writes_another() {
        let g = grant(&[Read, Write], &["logs-*"]);
        assert!(
            allowed(
                &g,
                "POST",
                "/_reindex",
                br#"{"source":{"index":"logs-1"},"dest":{"index":"logs-2"}}"#
            )
            .is_ok()
        );
        assert!(
            allowed(
                &g,
                "POST",
                "/_reindex",
                br#"{"source":{"index":"orders"},"dest":{"index":"logs-2"}}"#
            )
            .is_err()
        );
        assert!(
            allowed(
                &g,
                "POST",
                "/_reindex",
                br#"{"source":{"index":"logs-1"},"dest":{"index":"orders-copy"}}"#
            )
            .is_err()
        );
        assert!(
            allowed(
                &g,
                "POST",
                "/_reindex",
                br#"{"source":{"index":["logs-1","logs-2"]},"dest":{"index":"logs-3"}}"#
            )
            .is_ok()
        );
        assert!(
            allowed(
                &g,
                "POST",
                "/_reindex",
                br#"{"source":{"index":"logs-*"},"dest":{"index":"logs-*"}}"#
            )
            .is_err()
        );
        assert!(
            allowed(
                &g,
                "POST",
                "/_reindex",
                br#"{"source":{},"dest":{"index":"logs-3"}}"#
            )
            .is_err()
        );
        let s = classify("POST", "/_reindex", None).expect("classify");
        let facts = inspect_body(&s, br#"{"source":{"index":"logs-1","remote":{"host":"http://x:9200"}},"dest":{"index":"logs-2"}}"#).expect("body");
        assert!(facts.remote);
    }

    #[test]
    fn alias_actions_name_indices_and_aliases() {
        let g = grant(&[Admin], &["logs-*"]);
        let ok = br#"{"actions":[{"add":{"index":"logs-1","alias":"logs-current"}}]}"#;
        assert!(allowed(&g, "POST", "/_aliases", ok).is_ok());
        let bad_index = br#"{"actions":[{"add":{"index":"orders","alias":"logs-current"}}]}"#;
        assert!(allowed(&g, "POST", "/_aliases", bad_index).is_err());
        let bad_alias = br#"{"actions":[{"add":{"index":"logs-1","alias":"public"}}]}"#;
        assert!(allowed(&g, "POST", "/_aliases", bad_alias).is_err());
        let remove = br#"{"actions":[{"remove_index":{"index":"orders"}}]}"#;
        assert!(allowed(&g, "POST", "/_aliases", remove).is_err());
    }

    #[test]
    fn search_bodies_cant_reach_other_indices() {
        let g = grant(&[Read], &["logs-*"]);
        let q = |b: &str| allowed(&g, "POST", "/logs-1/_search", b.as_bytes());
        assert!(q(r#"{"query":{"match":{"user":"x"}}}"#).is_ok());
        // Terms lookup.
        assert!(
            q(r#"{"query":{"terms":{"user":{"index":"logs-2","id":"1","path":"u"}}}}"#).is_ok()
        );
        assert!(
            q(r#"{"query":{"terms":{"user":{"index":"orders","id":"1","path":"u"}}}}"#).is_err()
        );
        assert!(q(r#"{"query":{"bool":{"filter":[{"terms":{"user":{"index":".security","id":"1","path":"u"}}}]}}}"#).is_err());
        // More like this and pinned docs name `_index`.
        assert!(q(r#"{"query":{"more_like_this":{"fields":["t"],"like":[{"_index":"orders","_id":"1"}]}}}"#).is_err());
        assert!(q(r#"{"query":{"pinned":{"docs":[{"_index":"orders","_id":"1"}],"organic":{"match_all":{}}}}}"#).is_err());
        assert!(
            q(r#"{"query":{"more_like_this":{"like":[{"_index":"logs-3","_id":"1"}]}}}"#).is_ok()
        );
        // Indexed shapes and stored percolator documents.
        assert!(q(r#"{"query":{"geo_shape":{"loc":{"indexed_shape":{"index":"orders","id":"1","path":"s"}}}}}"#).is_err());
        assert!(
            q(r#"{"query":{"geo_shape":{"loc":{"indexed_shape":{"id":"1","path":"s"}}}}}"#)
                .is_err(),
            "default index is shapes"
        );
        assert!(q(r#"{"query":{"percolate":{"field":"q","index":"orders","id":"1"}}}"#).is_err());
        // A percolated document is data, not a reference.
        assert!(
            q(r#"{"query":{"percolate":{"field":"q","document":{"_index":"orders","a":1}}}}"#)
                .is_ok()
        );
        // Not JSON, or not a name.
        assert!(q("{not json").is_err());
        assert!(q(r#"{"query":{"terms":{"u":{"index":{"x":1},"id":"1","path":"p"}}}}"#).is_err());
        assert!(q(r#"{"query":{"more_like_this":{"like":[{"_index":"<logs-{now}>"}]}}}"#).is_err());
        // An empty body is a match-all.
        assert!(allowed(&g, "GET", "/logs-1/_search", b"").is_ok());
        // Unrestricted grants don't need the references to be covered, but hidden ones still count.
        let open = grant(&[Read], &[]);
        assert!(
            allowed(
                &open,
                "POST",
                "/logs-1/_search",
                br#"{"query":{"terms":{"u":{"index":"orders","id":"1","path":"p"}}}}"#
            )
            .is_ok()
        );
        assert!(
            allowed(
                &open,
                "POST",
                "/logs-1/_search",
                br#"{"query":{"terms":{"u":{"index":".security","id":"1","path":"p"}}}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn deeply_nested_bodies_are_refused() {
        let mut body = String::new();
        for _ in 0..100 {
            body.push_str("{\"a\":");
        }
        body.push('1');
        for _ in 0..100 {
            body.push('}');
        }
        let s = classify("POST", "/logs-1/_search", None).expect("classify");
        assert!(inspect_body(&s, body.as_bytes()).is_err());
    }

    #[test]
    fn gzip_bodies_are_read_up_to_a_limit() {
        use std::io::Write as _;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"{\"query\":{}}").expect("write");
        let gz = enc.finish().expect("finish");
        assert_eq!(
            decode_body(&gz, Some("gzip"), 1024).expect("gzip"),
            b"{\"query\":{}}"
        );
        assert_eq!(decode_body(b"abc", None, 1024).expect("plain"), b"abc");
        assert_eq!(
            decode_body(b"abc", Some("identity"), 1024).expect("plain"),
            b"abc"
        );
        assert!(
            decode_body(&gz, Some("gzip"), 4).is_err(),
            "too large once decoded"
        );
        assert!(decode_body(b"nope", Some("gzip"), 1024).is_err());
        assert!(decode_body(b"x", Some("br"), 1024).is_err());
        assert!(decode_body(b"x", Some("deflate"), 1024).is_err());
        // A bomb: a megabyte of zeros is tiny compressed.
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&vec![0u8; 8 * 1024 * 1024]).expect("write");
        let bomb = enc.finish().expect("finish");
        assert!(bomb.len() < 64 * 1024);
        assert!(decode_body(&bomb, Some("gzip"), 1024 * 1024).is_err());
    }
}
