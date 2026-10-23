//! What a MongoDB session may send (ADR-0035).
//!
//! Every command names its database in `$db`, so unlike SQL the wire says
//! where a command goes. The worker checks that against the policy and adds
//! a few guards that are cheap and unambiguous. What the role may do *inside*
//! a database stays the server's job: the role's grants on the server are the
//! boundary, and this module is a second lock, not the first.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use limen_policy::model::MongoGrant;
use limen_policy::{AccessRequest, Policy, Principal};

use super::bson::{Doc, Value};

/// Handshake commands the worker answers itself (never forwarded).
const HELLO: [&str; 2] = ["hello", "ismaster"];

/// Commands that log a connection in or out. The worker logged in already,
/// and the user's client must not swap the identity.
const AUTH: [&str; 4] = ["authenticate", "saslstart", "saslcontinue", "logout"];

/// Read-only commands on `admin` that drivers and `mongosh` send on connect.
/// They're allowed even when `admin` isn't a granted database; the server
/// still applies the role's grants to them.
const ADMIN_METADATA: [&str; 7] = [
    "ping",
    "buildinfo",
    "endsessions",
    "listdatabases",
    "connectionstatus",
    "getparameter",
    "whatsmyuri",
];

/// Commands whose pipeline or options can name a collection in another
/// database. Walked for `$out`, `$merge`, `$lookup`, and `$graphLookup`.
const CROSS_DATABASE: [&str; 3] = ["aggregate", "explain", "mapreduce"];

/// Keys whose document value names a `{db, coll}` target.
const TARGET_KEYS: [&str; 5] = ["$out", "$merge", "into", "from", "out"];

/// Most open cursors tracked per session.
pub const MAX_CURSORS: usize = 10_000;

/// A command as the worker reads it.
#[derive(Debug, Clone)]
pub struct Inspected<'a> {
    /// As the client wrote it (case matters to the server).
    pub name: &'a str,
    pub lower: String,
    pub database: &'a str,
    /// The first value, when it is a string: the collection of most commands.
    pub collection: Option<&'a str>,
    pub body: Doc<'a>,
}

/// Why a command was refused, in the shape of a server error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: i32,
    pub code_name: &'static str,
    /// A stable label for the audit trail.
    pub reason: &'static str,
    pub message: String,
}

fn refuse(code: i32, code_name: &'static str, reason: &'static str, message: String) -> Refusal {
    Refusal {
        code,
        code_name,
        reason,
        message,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Answer the handshake locally.
    Hello,
    Forward,
    Refuse(Refusal),
}

pub fn inspect(body: Doc<'_>) -> Result<Inspected<'_>, Refusal> {
    let bad = |why: &str| refuse(9, "FailedToParse", "bad_command", why.to_owned());
    let (name, first) = body
        .first()
        .map_err(|_| bad("the command isn't valid BSON"))?
        .ok_or_else(|| bad("empty command"))?;
    let database = match body.get("$db") {
        Ok(Some(Value::Str(db))) => db,
        Ok(_) => return Err(bad("the command has no $db")),
        Err(_) => return Err(bad("the command isn't valid BSON")),
    };
    Ok(Inspected {
        name,
        lower: name.to_ascii_lowercase(),
        database,
        collection: first.as_str(),
        body,
    })
}

/// What policy lets this session do.
#[derive(Debug)]
pub struct Access {
    policy: Arc<Policy>,
    roles: Vec<String>,
    resource: String,
    role: String,
    grants: Vec<MongoGrant>,
    databases: Mutex<HashMap<String, bool>>,
}

impl Access {
    #[must_use]
    pub fn new(policy: Arc<Policy>, roles: Vec<String>, resource: &str, role: &str) -> Self {
        let grants = policy.mongo_grants(&roles, resource, role);
        Self {
            policy,
            roles,
            resource: resource.to_owned(),
            role: role.to_owned(),
            grants,
            databases: Mutex::new(HashMap::new()),
        }
    }

    /// Whether policy lets the role use `database` (deny rules included).
    pub fn database_allowed(&self, database: &str) -> bool {
        if let Ok(known) = self.databases.lock()
            && let Some(allowed) = known.get(database)
        {
            return *allowed;
        }
        let allowed = self
            .policy
            .evaluate(&AccessRequest {
                roles: &self.roles,
                resource: &self.resource,
                principal: Principal::MongoRole {
                    role: self.role.clone(),
                    database: database.to_owned(),
                },
            })
            .is_allowed();
        if let Ok(mut known) = self.databases.lock()
            && known.len() < 1024
        {
            known.insert(database.to_owned(), allowed);
        }
        allowed
    }

    /// Whether every grant that covers `database` denies the command: a
    /// session may do what any one covering grant permits.
    fn command_denied(&self, database: &str, lower: &str) -> bool {
        let mut covering = self
            .grants
            .iter()
            .filter(|g| g.databases.iter().any(|d| d == "*" || d == database))
            .peekable();
        covering.peek().is_some()
            && covering.all(|g| {
                g.deny_commands
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(lower))
            })
    }
}

fn plausible_database(name: &str) -> bool {
    !name.is_empty() && name.len() <= 63 && !name.bytes().any(|b| b == 0 || b == b'/' || b == b'.')
}

/// Decide what to do with one command. `cursors` are the cursor ids this
/// session was given by the server.
pub fn judge(command: &Inspected<'_>, access: &Access, cursors: &HashSet<i64>) -> Verdict {
    let lower = command.lower.as_str();
    if HELLO.contains(&lower) {
        return Verdict::Hello;
    }
    if AUTH.contains(&lower) {
        return Verdict::Refuse(refuse(
            18,
            "AuthenticationFailed",
            "auth_command",
            "Limen has already authenticated this session; connect without credentials".into(),
        ));
    }
    let database = command.database;
    if database == "$external" || !plausible_database(database) {
        return Verdict::Refuse(refuse(
            13,
            "Unauthorized",
            "database_not_granted",
            format!("not authorized on {database}"),
        ));
    }
    let metadata = database == "admin" && ADMIN_METADATA.contains(&lower);
    if !metadata && !access.database_allowed(database) {
        return Verdict::Refuse(refuse(
            13,
            "Unauthorized",
            "database_not_granted",
            format!(
                "not authorized on {database} to execute command {}",
                command.name
            ),
        ));
    }
    if !metadata && access.command_denied(database, lower) {
        return Verdict::Refuse(refuse(
            13,
            "Unauthorized",
            "command_denied",
            format!(
                "Limen policy does not allow the {} command here",
                command.name
            ),
        ));
    }
    if CROSS_DATABASE.contains(&lower)
        && let Some(other) = referenced_databases(command.body)
            .into_iter()
            .find(|db| *db != database && !access.database_allowed(db))
    {
        return Verdict::Refuse(refuse(
            13,
            "Unauthorized",
            "database_not_granted",
            format!(
                "not authorized on {other} to execute command {}",
                command.name
            ),
        ));
    }
    if let Some(unknown) = unowned_cursor(command, cursors) {
        return Verdict::Refuse(refuse(
            43,
            "CursorNotFound",
            "unknown_cursor",
            format!("cursor id {unknown} not found"),
        ));
    }
    Verdict::Forward
}

/// The databases an aggregation (or `explain`, or `mapReduce`) writes to or
/// reads from besides its own: `{db: ..., coll: ...}` under `$out`, `$merge`
/// (`into`), `$lookup` and `$graphLookup` (`from`), or `mapReduce` (`out`),
/// at any depth (`$facet` nests pipelines). A field of a filter that happens
/// to look the same is refused too: the safe side of a false match.
fn referenced_databases(body: Doc<'_>) -> Vec<&str> {
    fn walk<'a>(doc: Doc<'a>, depth: usize, out: &mut Vec<&'a str>) {
        if depth > 32 {
            return;
        }
        for element in doc {
            let Ok((key, value)) = element else { return };
            match value {
                Value::Doc(inner) => {
                    if TARGET_KEYS.contains(&key)
                        && let Ok(Some(Value::Str(db))) = inner.get("db")
                    {
                        out.push(db);
                    }
                    walk(inner, depth + 1, out);
                }
                Value::Array(items) => walk(items, depth + 1, out),
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    walk(body, 0, &mut out);
    out
}

/// A cursor id a `getMore` or `killCursors` names that this session wasn't
/// given. Cursors are tied to the server login, which sessions share, so the
/// worker keeps them apart.
fn unowned_cursor(command: &Inspected<'_>, cursors: &HashSet<i64>) -> Option<i64> {
    match command.lower.as_str() {
        "getmore" => {
            let id = command.body.first().ok()??.1.as_i64()?;
            (!cursors.contains(&id)).then_some(id)
        }
        "killcursors" => {
            let Ok(Some(Value::Array(ids))) = command.body.get("cursors") else {
                return None;
            };
            ids.iter()
                .filter_map(|e| e.ok()?.1.as_i64())
                .find(|id| !cursors.contains(id))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::bson::Builder;
    use super::*;

    const POLICY: &str = r#"
kind: role
version: v1
metadata: { name: dev }
spec:
  allow:
    - resources: { kind: [mongodb], labels: { "*": ["*"] } }
      mongo: { roles: [read], databases: [orders], deny_commands: [dropDatabase, Drop] }
    - resources: { kind: [mongodb], labels: { "*": ["*"] } }
      mongo: { roles: [write], databases: [orders, billing] }
  deny:
    - resources: { kind: [mongodb], labels: { "*": ["*"] } }
      mongo: { roles: [write], databases: [billing] }
"#;
    const RESOURCE: &str = "kind: resource\nversion: v1\nmetadata: { name: m }\nspec:\n  mongodb: { endpoint: \"m:1\", credentials_dir: /c }\n";

    fn access(role: &str) -> Access {
        let policy =
            Policy::parse_yaml([("r.yaml", POLICY), ("m.yaml", RESOURCE)]).expect("policy");
        Access::new(Arc::new(policy), vec!["dev".into()], "m", role)
    }

    fn verdict(role: &str, doc: &[u8], cursors: &[i64]) -> Verdict {
        let body = Doc::new(doc).expect("doc");
        let cmd = inspect(body).expect("inspect");
        judge(&cmd, &access(role), &cursors.iter().copied().collect())
    }

    fn cmd(name: &str, value: &str, db: &str) -> Vec<u8> {
        Builder::new().str(name, value).str("$db", db).finish()
    }

    fn refused(v: Verdict) -> Refusal {
        match v {
            Verdict::Refuse(r) => r,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn granted_databases_pass_and_others_are_refused_like_the_server_would() {
        assert_eq!(
            verdict("read", &cmd("find", "customers", "orders"), &[]),
            Verdict::Forward
        );
        let r = refused(verdict("read", &cmd("find", "ledger", "billing"), &[]));
        assert_eq!(
            (r.code, r.code_name, r.reason),
            (13, "Unauthorized", "database_not_granted")
        );
        assert!(r.message.contains("billing"));
    }

    #[test]
    fn deny_rules_beat_grants() {
        // write is granted billing and denied it by the deny rule.
        assert_eq!(
            verdict("write", &cmd("find", "customers", "orders"), &[]),
            Verdict::Forward
        );
        assert_eq!(
            refused(verdict("write", &cmd("find", "ledger", "billing"), &[])).reason,
            "database_not_granted"
        );
    }

    #[test]
    fn denied_commands_are_matched_without_regard_to_case() {
        let r = refused(verdict("read", &cmd("drop", "customers", "orders"), &[]));
        assert_eq!(r.reason, "command_denied");
        assert_eq!(
            refused(verdict("read", &cmd("dropDatabase", "1", "orders"), &[])).reason,
            "command_denied"
        );
        // The same command is fine for a role whose grant doesn't deny it.
        assert_eq!(
            verdict("write", &cmd("drop", "customers", "orders"), &[]),
            Verdict::Forward
        );
    }

    #[test]
    fn the_handshake_is_answered_locally() {
        for name in ["hello", "isMaster", "ismaster"] {
            let doc = Builder::new().i32(name, 1).str("$db", "admin").finish();
            assert_eq!(verdict("read", &doc, &[]), Verdict::Hello, "{name}");
        }
    }

    #[test]
    fn login_commands_are_refused_so_a_client_cannot_swap_the_identity() {
        for name in ["authenticate", "saslStart", "saslContinue", "logout"] {
            let doc = Builder::new().i32(name, 1).str("$db", "admin").finish();
            let r = refused(verdict("read", &doc, &[]));
            assert_eq!((r.code, r.reason), (18, "auth_command"), "{name}");
        }
    }

    #[test]
    fn admin_metadata_is_allowed_but_admin_writes_are_not() {
        for name in [
            "ping",
            "buildInfo",
            "endSessions",
            "listDatabases",
            "connectionStatus",
        ] {
            let doc = Builder::new().i32(name, 1).str("$db", "admin").finish();
            assert_eq!(verdict("read", &doc, &[]), Verdict::Forward, "{name}");
        }
        for name in [
            "createUser",
            "renameCollection",
            "shutdown",
            "replSetReconfig",
        ] {
            let doc = Builder::new().str(name, "x").str("$db", "admin").finish();
            assert_eq!(
                refused(verdict("read", &doc, &[])).reason,
                "database_not_granted",
                "{name}"
            );
        }
        // The allowance is for `admin` only.
        let doc = Builder::new()
            .i32("listDatabases", 1)
            .str("$db", "billing")
            .finish();
        assert!(matches!(verdict("read", &doc, &[]), Verdict::Refuse(_)));
    }

    #[test]
    fn external_and_implausible_databases_are_refused() {
        for db in ["$external", "", "a.b", "a/b", &"x".repeat(64)] {
            let r = refused(verdict("read", &cmd("find", "c", db), &[]));
            assert_eq!(r.reason, "database_not_granted", "{db:?}");
        }
    }

    #[test]
    fn commands_need_a_database_and_valid_bson() {
        let no_db = Builder::new().str("find", "c").finish();
        let err = inspect(Doc::new(&no_db).expect("doc")).expect_err("no $db");
        assert_eq!(err.reason, "bad_command");
        let empty = Builder::new().finish();
        assert!(inspect(Doc::new(&empty).expect("doc")).is_err());
        let mut broken = Builder::new()
            .str("find", "c")
            .str("$db", "orders")
            .finish();
        broken[4] = 0x20;
        assert!(inspect(Doc::new(&broken).expect("doc")).is_err());
    }

    /// Builds a pipeline stage aimed at a database.
    type Stage<'a> = Box<dyn Fn(&str) -> Builder + 'a>;

    /// An `aggregate` on `orders` whose last stage is `stage`.
    fn aggregate_with(stage: &Builder) -> Vec<u8> {
        let mut raw = cmd("aggregate", "customers", "orders");
        raw.pop();
        raw.push(0x04);
        raw.extend_from_slice(b"pipeline\0");
        let pipeline = Builder::new()
            .doc(
                "0",
                &Builder::new().doc("$match", &Builder::new().str("tier", "gold")),
            )
            .doc("1", stage)
            .finish();
        raw.extend_from_slice(&pipeline);
        raw.push(0);
        let len = i32::try_from(raw.len()).expect("len");
        raw[..4].copy_from_slice(&len.to_le_bytes());
        raw
    }

    #[test]
    fn pipelines_cannot_reach_a_database_the_role_is_not_granted() {
        let target = |db: &str| Builder::new().str("db", db).str("coll", "stolen");
        let out = |db: &str| Builder::new().doc("$out", &target(db));
        let merge =
            |db: &str| Builder::new().doc("$merge", &Builder::new().doc("into", &target(db)));
        let lookup = |db: &str| {
            Builder::new().doc(
                "$lookup",
                &Builder::new().doc("from", &target(db)).str("as", "x"),
            )
        };
        let stages: [Stage<'_>; 3] = [Box::new(out), Box::new(merge), Box::new(lookup)];
        for stage in &stages {
            let refused = refused(verdict("read", &aggregate_with(&stage("billing")), &[]));
            assert_eq!(refused.reason, "database_not_granted");
            assert!(refused.message.contains("billing"));
            // The same stage inside the granted database is the server's call.
            assert_eq!(
                verdict("read", &aggregate_with(&stage("orders")), &[]),
                Verdict::Forward
            );
        }
        // A plain collection name stays in the command's own database.
        let same = Builder::new().str("$out", "copy");
        assert_eq!(
            verdict("read", &aggregate_with(&same), &[]),
            Verdict::Forward
        );
        // `find` is not walked: its filter may hold any field names.
        let find = Builder::new()
            .str("find", "customers")
            .doc(
                "filter",
                &Builder::new().doc("from", &Builder::new().str("db", "billing")),
            )
            .str("$db", "orders")
            .finish();
        assert_eq!(verdict("read", &find, &[]), Verdict::Forward);
    }

    #[test]
    fn cursors_belong_to_the_session_that_was_given_them() {
        let get_more = |id: i64| {
            Builder::new()
                .i64("getMore", id)
                .str("collection", "customers")
                .str("$db", "orders")
                .finish()
        };
        assert_eq!(verdict("read", &get_more(42), &[42]), Verdict::Forward);
        let r = refused(verdict("read", &get_more(43), &[42]));
        assert_eq!(
            (r.code, r.code_name, r.reason),
            (43, "CursorNotFound", "unknown_cursor")
        );

        // killCursors with a cursor array.
        let mut raw = Builder::new()
            .str("killCursors", "customers")
            .str("$db", "orders")
            .finish();
        raw.pop();
        raw.push(0x04);
        raw.extend_from_slice(b"cursors\0");
        raw.extend_from_slice(&Builder::new().i64("0", 42).i64("1", 99).finish());
        raw.push(0);
        let len = i32::try_from(raw.len()).expect("len");
        raw[..4].copy_from_slice(&len.to_le_bytes());
        assert!(matches!(verdict("read", &raw, &[42]), Verdict::Refuse(_)));
        assert_eq!(verdict("read", &raw, &[42, 99]), Verdict::Forward);
    }
}
