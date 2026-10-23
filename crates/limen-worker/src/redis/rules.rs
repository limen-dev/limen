//! What a Redis session may run, and what its audit event says (ADR-0034).
//!
//! The target's ACL is the first control. This is the second: the worker
//! checks every command against the role's grant before it forwards it, so
//! one mistake in either place doesn't open the door.

use std::collections::{HashMap, HashSet};

use limen_policy::RedisGrant;
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

use super::codec::Value;

/// Refused unless a grant lists them in `allow_commands`. They change the
/// server, read its secrets, run code on it, or can stall it.
const DEFAULT_DENY: &[&str] = &[
    "FLUSHALL",
    "FLUSHDB",
    "CONFIG",
    "DEBUG",
    "SHUTDOWN",
    "REPLICAOF",
    "SLAVEOF",
    "MODULE",
    "ACL",
    "CLIENT KILL",
    "MIGRATE",
    "SWAPDB",
    "MOVE",
    "SAVE",
    "BGSAVE",
    "BGREWRITEAOF",
    "SCRIPT",
    "FUNCTION",
    "EVAL",
    "EVALSHA",
    "EVAL_RO",
    "EVALSHA_RO",
    "FCALL",
    "FCALL_RO",
    // Other sessions' commands and values sit in the slow log; the rest
    // reconfigure or reshape the deployment.
    "SLOWLOG",
    "FAILOVER",
    "CLUSTER",
    // Other sessions on the same server user.
    "CLIENT LIST",
    "CLIENT UNBLOCK",
];

/// Refused when a grant restricts keys: they show key names or key changes
/// the role doesn't name.
const KEY_LEAKING: &[&str] = &["CLIENT TRACKING", "PUBSUB CHANNELS", "PUBSUB SHARDCHANNELS"];

/// At most this many keys or arguments go into one audit event, so a huge
/// `DEL` can't push the event past the spool's record limit.
const AUDIT_LIST_MAX: usize = 100;

/// Refused for everyone. They stream other clients' traffic, copy the data
/// set, or would undo the worker's own authentication.
const ALWAYS_REFUSED: &[&str] = &[
    "MONITOR",
    "SYNC",
    "PSYNC",
    "REPLCONF",
    "RESET",
    "CLIENT REPLY",
    "CLIENT PAUSE",
    "CLIENT UNPAUSE",
];

/// Scripts can touch keys the grant never saw, so a key-restricted grant
/// can't use them even if it lists them in `allow_commands`.
const SCRIPTING: &[&str] = &[
    "SCRIPT",
    "FUNCTION",
    "EVAL",
    "EVALSHA",
    "EVAL_RO",
    "EVALSHA_RO",
    "FCALL",
    "FCALL_RO",
];

/// Walk or change the whole keyspace, which a key-restricted grant can't
/// allow, even when it opens the command with `allow_commands`.
const KEYSPACE_WIDE: &[&str] = &["KEYS", "SCAN", "RANDOMKEY", "FLUSHALL", "FLUSHDB", "SWAPDB"];

/// Commands whose second word is a subcommand.
const HAS_SUBCOMMAND: &[&str] = &[
    "ACL", "CLIENT", "CLUSTER", "COMMAND", "CONFIG", "DEBUG", "FUNCTION", "LATENCY", "MEMORY",
    "MODULE", "OBJECT", "PUBSUB", "SCRIPT", "SLOWLOG", "XGROUP", "XINFO",
];

/// Commands whose arguments hold credentials. Never logged.
const CREDENTIAL_COMMANDS: &[&str] = &[
    "AUTH",
    "HELLO",
    "ACL",
    "MIGRATE",
    "CONFIG",
    "REPLICAOF",
    "SLAVEOF",
];

#[derive(Debug, Clone, Copy)]
struct KeySpec {
    first: i64,
    last: i64,
    step: i64,
    movable: bool,
}

/// Where each command keeps its keys, as the target itself reports them.
#[derive(Debug, Default, Clone)]
pub struct KeySpecs {
    specs: HashMap<String, KeySpec>,
    /// Commands whose keys depend on the subcommand.
    containers: HashSet<String>,
}

impl KeySpecs {
    /// Read the reply to `COMMAND INFO`. Commands with subcommands (`OBJECT`,
    /// `XINFO`, ...) keep their key positions on the subcommands, stored here
    /// as `OBJECT|FREQ`.
    pub fn from_command_info(reply: &Value) -> Result<Self, &'static str> {
        let Value::Array(entries) = reply else {
            return Err("COMMAND INFO didn't return a list");
        };
        let mut specs = HashMap::new();
        let mut containers = HashSet::new();
        for entry in entries {
            let Value::Array(fields) = entry else {
                continue;
            };
            let Some((name, spec)) = parse_entry(fields) else {
                continue;
            };
            if let Some(Value::Array(subs)) = fields.get(9) {
                for sub in subs {
                    if let Value::Array(sub_fields) = sub
                        && let Some((sub_name, sub_spec)) = parse_entry(sub_fields)
                    {
                        containers.insert(name.clone());
                        specs.insert(sub_name, sub_spec);
                    }
                }
            }
            specs.insert(name, spec);
        }
        if specs.is_empty() {
            return Err("COMMAND INFO listed no commands");
        }
        Ok(Self { specs, containers })
    }
}

fn parse_entry(fields: &[Value]) -> Option<(String, KeySpec)> {
    let (Some(name), Some(Value::Array(flags)), Some(first), Some(last), Some(step)) = (
        fields.first().and_then(Value::as_bytes),
        fields.get(2),
        fields.get(3),
        fields.get(4),
        fields.get(5),
    ) else {
        return None;
    };
    let (Value::Integer(first), Value::Integer(last), Value::Integer(step)) = (first, last, step)
    else {
        return None;
    };
    let movable = flags
        .iter()
        .filter_map(Value::as_bytes)
        .any(|f| f == b"movablekeys");
    Some((
        String::from_utf8_lossy(name).to_ascii_uppercase(),
        KeySpec {
            first: *first,
            last: *last,
            step: *step,
            movable,
        },
    ))
}

/// A command, read for the audit trail and the policy check.
#[derive(Debug)]
pub struct Inspection {
    /// Upper-cased command name.
    pub name: String,
    /// Upper-cased subcommand, for the commands that have one.
    pub sub: Option<String>,
    /// The keys it touches, or `None` when we can't tell.
    pub keys: Option<Vec<Vec<u8>>>,
}

impl Inspection {
    fn path(&self) -> String {
        match &self.sub {
            Some(sub) => format!("{} {sub}", self.name),
            None => self.name.clone(),
        }
    }
}

/// The checks for one session: its grants and the target's key layout.
#[derive(Debug)]
pub struct Rules {
    grants: Vec<RedisGrant>,
    specs: KeySpecs,
}

impl Rules {
    #[must_use]
    pub fn new(grants: Vec<RedisGrant>, specs: KeySpecs) -> Self {
        Self { grants, specs }
    }

    /// Whether any grant restricts keys: then we need `COMMAND INFO` to be right.
    #[must_use]
    pub fn restricts_keys(&self) -> bool {
        self.grants.iter().any(|g| !g.keys.is_empty())
    }

    #[must_use]
    pub fn inspect(&self, args: &[Vec<u8>]) -> Inspection {
        let name = String::from_utf8_lossy(&args[0]).to_ascii_uppercase();
        let sub = (args.len() > 1 && HAS_SUBCOMMAND.contains(&name.as_str()))
            .then(|| String::from_utf8_lossy(&args[1]).to_ascii_uppercase());
        let keys = self.keys_of(&name, args);
        Inspection { name, sub, keys }
    }

    fn keys_of(&self, name: &str, args: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
        let counted = |numkeys_at: usize, keys_from: usize| -> Option<Vec<Vec<u8>>> {
            let n: usize = std::str::from_utf8(args.get(numkeys_at)?)
                .ok()?
                .parse()
                .ok()?;
            Some(args.get(keys_from..keys_from.checked_add(n)?)?.to_vec())
        };
        match name {
            "EVAL" | "EVALSHA" | "EVAL_RO" | "EVALSHA_RO" | "FCALL" | "FCALL_RO" => {
                return counted(2, 3);
            }
            "ZUNION" | "ZINTER" | "ZDIFF" | "ZINTERCARD" | "SINTERCARD" | "LMPOP" | "ZMPOP" => {
                return counted(1, 2);
            }
            "BLMPOP" | "BZMPOP" => return counted(2, 3),
            "ZUNIONSTORE" | "ZINTERSTORE" | "ZDIFFSTORE" => {
                let mut keys = counted(2, 3)?;
                keys.push(args.get(1)?.clone());
                return Some(keys);
            }
            "XREAD" | "XREADGROUP" => {
                // Options come first, read the way the server reads them: a
                // group or a consumer may itself be called "STREAMS".
                let mut at = 1;
                loop {
                    let word = args.get(at)?;
                    if word.eq_ignore_ascii_case(b"STREAMS") {
                        break;
                    } else if word.eq_ignore_ascii_case(b"COUNT")
                        || word.eq_ignore_ascii_case(b"BLOCK")
                    {
                        at += 2;
                    } else if word.eq_ignore_ascii_case(b"GROUP") && name == "XREADGROUP" {
                        at += 3;
                    } else if word.eq_ignore_ascii_case(b"NOACK") && name == "XREADGROUP" {
                        at += 1;
                    } else {
                        return None;
                    }
                }
                let rest = args.get(at + 1..)?;
                if rest.len() % 2 != 0 {
                    return None;
                }
                return Some(rest[..rest.len() / 2].to_vec());
            }
            "SORT" | "SORT_RO" | "GEORADIUS" | "GEORADIUSBYMEMBER" => {
                let mut keys = vec![args.get(1)?.clone()];
                for (i, a) in args.iter().enumerate().skip(2) {
                    if a.eq_ignore_ascii_case(b"STORE") || a.eq_ignore_ascii_case(b"STOREDIST") {
                        keys.push(args.get(i + 1)?.clone());
                    }
                }
                return Some(keys);
            }
            _ => {}
        }
        let spec = if self.specs.containers.contains(name) {
            // The keys of OBJECT, XINFO, XGROUP, MEMORY ... depend on the
            // subcommand. One the target doesn't list: can't tell.
            let Some(sub) = args.get(1) else {
                return Some(Vec::new());
            };
            let full = format!(
                "{name}|{}",
                String::from_utf8_lossy(sub).to_ascii_uppercase()
            );
            self.specs.specs.get(&full)?
        } else {
            // Not in the target's table (a module loaded later, say): can't
            // tell, so a key-restricted role refuses it.
            self.specs.specs.get(name)?
        };
        if spec.movable {
            return None;
        }
        if spec.first == 0 {
            return Some(Vec::new());
        }
        let count = i64::try_from(args.len()).ok()?;
        let last = if spec.last < 0 {
            count + spec.last
        } else {
            spec.last
        };
        let (mut i, step) = (spec.first, spec.step.max(1));
        let mut keys = Vec::new();
        while i <= last {
            keys.push(args.get(usize::try_from(i).ok()?)?.clone());
            i += step;
        }
        Some(keys)
    }

    /// `Ok` if some grant allows the command. Otherwise why not.
    pub fn check(&self, args: &[Vec<u8>], insp: &Inspection, db: u32) -> Result<(), String> {
        let path = insp.path();
        if ALWAYS_REFUSED
            .iter()
            .any(|c| matches_command(c, &insp.name, insp.sub.as_deref()))
        {
            return Err(format!("{path} is never allowed through Limen"));
        }
        let mut first_reason = None;
        for grant in &self.grants {
            match grant_allows(grant, args, insp, db) {
                Ok(()) => return Ok(()),
                Err(reason) => {
                    first_reason.get_or_insert(reason);
                }
            }
        }
        Err(first_reason.unwrap_or_else(|| format!("no grant allows {path}")))
    }

    /// The audit data for one command. Values stay out unless the target
    /// opts in, and credential commands never log theirs.
    #[must_use]
    pub fn audit_data(
        insp: &Inspection,
        args: &[Vec<u8>],
        audit: &limen_policy::RedisAudit,
        resource: &str,
        redis_user: &str,
    ) -> Json {
        let keys: Option<Vec<String>> = insp.keys.as_ref().map(|keys| {
            keys.iter()
                .take(AUDIT_LIST_MAX)
                .map(|k| {
                    if audit.redact_keys {
                        hash_key(resource, k)
                    } else {
                        shorten(&String::from_utf8_lossy(k))
                    }
                })
                .collect()
        });
        let mut data = json!({
            "command": insp.name,
            "subcommand": insp.sub,
            "keys": keys,
            "keys_known": keys.is_some(),
            "keys_total": insp.keys.as_ref().map(Vec::len),
            "arity": args.len(),
            "resource": resource,
            "redis_user": redis_user,
        });
        if audit.log_values {
            data["args"] = if CREDENTIAL_COMMANDS.contains(&insp.name.as_str()) {
                json!("[REDACTED]")
            } else {
                json!(
                    args[1..]
                        .iter()
                        .take(AUDIT_LIST_MAX)
                        .map(|a| shorten(&String::from_utf8_lossy(a)))
                        .collect::<Vec<_>>()
                )
            };
        }
        data
    }
}

/// The databases a grant opens: `[0]` unless it names others.
fn opens_database(grant: &RedisGrant, db: u32) -> bool {
    if grant.databases.is_empty() {
        db == 0
    } else {
        grant.databases.contains(&db)
    }
}

/// The database a `SELECT` asks for, if it is a plain number.
#[must_use]
pub fn selected_database(args: &[Vec<u8>]) -> Option<u32> {
    std::str::from_utf8(args.get(1)?).ok()?.parse().ok()
}

fn grant_allows(
    grant: &RedisGrant,
    args: &[Vec<u8>],
    insp: &Inspection,
    db: u32,
) -> Result<(), String> {
    let path = insp.path();
    let listed = |list: &[String]| {
        list.iter()
            .any(|c| matches_command(&c.to_ascii_uppercase(), &insp.name, insp.sub.as_deref()))
    };
    if listed(&grant.deny_commands) {
        return Err(format!("{path} is denied for this role"));
    }
    let opened = listed(&grant.allow_commands);
    if !opened
        && DEFAULT_DENY
            .iter()
            .any(|c| matches_command(c, &insp.name, insp.sub.as_deref()))
    {
        return Err(format!(
            "{path} is denied unless the role lists it in redis.allow_commands"
        ));
    }
    // Commands run in the database the connection has selected; a grant only
    // covers the databases it names.
    // (A `SELECT` is judged by the database it asks for, below.)
    if insp.name != "SELECT" && !opens_database(grant, db) {
        return Err(format!("database {db} is not one this role names"));
    }
    match insp.name.as_str() {
        "SELECT" => {
            if !selected_database(args).is_some_and(|wanted| opens_database(grant, wanted)) {
                return Err("SELECT of a database this role doesn't name".into());
            }
        }
        "MOVE" => {
            if !selected_database(&args[1..]).is_some_and(|to| opens_database(grant, to)) {
                return Err("MOVE to a database this role doesn't name".into());
            }
        }
        "COPY" => {
            if let Some(at) = args.iter().position(|a| a.eq_ignore_ascii_case(b"DB"))
                && !selected_database(&args[at..]).is_some_and(|to| opens_database(grant, to))
            {
                return Err("COPY to a database this role doesn't name".into());
            }
        }
        _ => {}
    }
    if !grant.keys.is_empty() {
        if SCRIPTING.contains(&insp.name.as_str()) {
            return Err(format!("{path} can reach keys the role doesn't name"));
        }
        if KEY_LEAKING
            .iter()
            .any(|c| matches_command(c, &insp.name, insp.sub.as_deref()))
        {
            return Err(format!("{path} shows keys the role doesn't name"));
        }
        if SUBSCRIBE_COMMANDS.contains(&insp.name.as_str())
            && args[1..]
                .iter()
                .any(|channel| reaches_keyspace_channels(&insp.name, channel))
        {
            return Err(format!(
                "{path} would show key events for keys the role doesn't name"
            ));
        }
        if KEYSPACE_WIDE.contains(&insp.name.as_str()) {
            return Err(format!("{path} walks every key; the role restricts keys"));
        }
        // `BY` and `GET` patterns name other keys than the one sorted.
        if matches!(insp.name.as_str(), "SORT" | "SORT_RO")
            && args
                .iter()
                .skip(2)
                .any(|a| a.eq_ignore_ascii_case(b"BY") || a.eq_ignore_ascii_case(b"GET"))
        {
            return Err(format!(
                "{path} with BY or GET reads keys the role doesn't name"
            ));
        }
        let Some(keys) = &insp.keys else {
            return Err(format!(
                "can't tell which keys {path} touches; the role restricts keys"
            ));
        };
        // The reason goes into the audit trail, which may hash keys: name the
        // place of the key, not the key.
        if let Some(n) = keys
            .iter()
            .position(|k| !grant.keys.iter().any(|p| glob_match(p.as_bytes(), k)))
        {
            return Err(format!(
                "key {} of {} is outside the keys this role allows",
                n + 1,
                keys.len()
            ));
        }
    }
    Ok(())
}

const SUBSCRIBE_COMMANDS: &[&str] = &["SUBSCRIBE", "PSUBSCRIBE", "SSUBSCRIBE"];

/// Whether subscribing to `channel` (a glob for `PSUBSCRIBE`) could deliver
/// keyspace or keyevent notifications, which carry other roles' key names.
fn reaches_keyspace_channels(command: &str, channel: &[u8]) -> bool {
    const PREFIXES: [&[u8]; 2] = [b"__keyspace@", b"__keyevent@"];
    if command != "PSUBSCRIBE" {
        return PREFIXES.iter().any(|p| channel.starts_with(p));
    }
    let literal = channel
        .iter()
        .position(|b| matches!(b, b'*' | b'?' | b'[' | b'\\'))
        .map_or(channel, |at| &channel[..at]);
    literal.len() == channel.len() && PREFIXES.iter().any(|p| channel.starts_with(p))
        || literal.len() < channel.len()
            && PREFIXES
                .iter()
                .any(|p| p.starts_with(literal) || literal.starts_with(p))
}

/// `entry` is `NAME` (any subcommand) or `NAME SUB`.
fn matches_command(entry: &str, name: &str, sub: Option<&str>) -> bool {
    match entry.split_once(' ') {
        None => entry == name,
        Some((n, s)) => n == name && sub == Some(s.trim()),
    }
}

fn hash_key(resource: &str, key: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(resource.as_bytes());
    h.update([0]);
    h.update(key);
    let digest = h.finalize();
    format!("h:{}", super::target::hex(&digest[..8]))
}

fn shorten(s: &str) -> String {
    const MAX: usize = 256;
    if s.chars().count() <= MAX {
        s.to_owned()
    } else {
        format!("{}…", s.chars().take(MAX).collect::<String>())
    }
}

/// `*` matches any run of bytes and `?` any one byte. Nothing else is special.
#[must_use]
pub fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while t < text.len() {
        if p < pattern.len()
            && (pattern[p] == b'?' || (pattern[p] != b'*' && pattern[p] == text[t]))
        {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if let Some(s) = star {
            p = s + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|b| *b == b'*')
}

#[cfg(test)]
mod tests {
    use super::*;
    use limen_policy::RedisAudit;

    fn args(words: &[&str]) -> Vec<Vec<u8>> {
        words.iter().map(|w| w.as_bytes().to_vec()).collect()
    }

    fn grant(deny: &[&str], allow: &[&str], keys: &[&str]) -> RedisGrant {
        let owned = |l: &[&str]| l.iter().map(|s| (*s).to_owned()).collect();
        RedisGrant {
            users: vec!["u".into()],
            deny_commands: owned(deny),
            allow_commands: owned(allow),
            keys: owned(keys),
            databases: Vec::new(),
        }
    }

    /// A tiny `COMMAND INFO`.
    fn specs() -> KeySpecs {
        let entry = |name: &str, flags: &[&str], first, last, step| {
            Value::Array(vec![
                Value::Bulk(name.as_bytes().to_vec()),
                Value::Integer(-2),
                Value::Array(flags.iter().map(|f| Value::Simple((*f).into())).collect()),
                Value::Integer(first),
                Value::Integer(last),
                Value::Integer(step),
            ])
        };
        let container = |name: &str, subs: &[(&str, i64, i64, i64)]| {
            let Value::Array(mut fields) = entry(name, &["readonly"], 0, 0, 0) else {
                unreachable!()
            };
            fields.extend([
                Value::Array(vec![]),
                Value::Array(vec![]),
                Value::Array(vec![]),
            ]);
            fields.push(Value::Array(
                subs.iter()
                    .map(|(n, f, l, st)| entry(n, &["readonly"], *f, *l, *st))
                    .collect(),
            ));
            Value::Array(fields)
        };
        KeySpecs::from_command_info(&Value::Array(vec![
            entry("get", &["readonly"], 1, 1, 1),
            entry("set", &["write"], 1, 1, 1),
            entry("mset", &["write"], 1, -1, 2),
            entry("del", &["write"], 1, -1, 1),
            entry("ping", &["fast"], 0, 0, 0),
            entry("sort", &["write", "movablekeys"], 1, 1, 1),
            entry("select", &["fast"], 0, 0, 0),
            container(
                "object",
                &[("object|encoding", 2, 2, 1), ("object|help", 0, 0, 0)],
            ),
            container("xinfo", &[("xinfo|stream", 2, 2, 1)]),
            entry("subscribe", &["pubsub"], 0, 0, 0),
            entry("psubscribe", &["pubsub"], 0, 0, 0),
            entry("xreadgroup", &["write"], 0, 0, 0),
            entry("move", &["write"], 1, 1, 1),
            entry("pubsub", &["pubsub"], 0, 0, 0),
            entry("migrate", &["write", "movablekeys"], 3, 3, 1),
            entry("xtrim", &["write", "movablekeys"], 0, 0, 0),
            entry("keys", &["readonly"], 0, 0, 0),
            entry("eval", &["write", "movablekeys"], 0, 0, 0),
            entry("flushall", &["write"], 0, 0, 0),
            entry("config", &["admin"], 0, 0, 0),
            entry("client", &["admin"], 0, 0, 0),
            entry("monitor", &["admin"], 0, 0, 0),
            entry("copy", &["write"], 1, 2, 1),
        ]))
        .expect("specs")
    }

    fn run(rules: &Rules, words: &[&str]) -> Result<(), String> {
        let a = args(words);
        let insp = rules.inspect(&a);
        rules.check(&a, &insp, 0)
    }

    fn run_in(rules: &Rules, db: u32, words: &[&str]) -> Result<(), String> {
        let a = args(words);
        let insp = rules.inspect(&a);
        rules.check(&a, &insp, db)
    }

    fn keyed(keys: &[&str]) -> Rules {
        Rules::new(vec![grant(&[], &[], keys)], specs())
    }

    #[test]
    fn container_commands_are_checked_by_their_subcommand() {
        let rules = keyed(&["app:*"]);
        assert!(run(&rules, &["OBJECT", "ENCODING", "app:1"]).is_ok());
        assert!(run(&rules, &["OBJECT", "ENCODING", "secret"]).is_err());
        assert!(run(&rules, &["XINFO", "STREAM", "secret"]).is_err());
        assert!(run(&rules, &["XINFO", "STREAM", "app:s"]).is_ok());
        // No keys at all, or a subcommand the target doesn't list.
        assert!(run(&rules, &["OBJECT", "HELP"]).is_ok());
        assert!(run(&rules, &["OBJECT", "NEWTHING", "secret"]).is_err());
        // A command the target's table doesn't have.
        assert!(run(&rules, &["MYMODULE.GET", "secret"]).is_err());
        assert!(run(&keyed(&[]), &["MYMODULE.GET", "secret"]).is_ok());
    }

    #[test]
    fn xreadgroup_reads_its_options_like_the_server() {
        let rules = keyed(&["app:*"]);
        let a = args(&[
            "XREADGROUP",
            "GROUP",
            "STREAMS",
            "c",
            "STREAMS",
            "app:a",
            "secret",
            "0",
            "0",
        ]);
        assert_eq!(
            rules.inspect(&a).keys,
            Some(vec![b"app:a".to_vec(), b"secret".to_vec()])
        );
        assert!(
            run(
                &rules,
                &[
                    "XREADGROUP",
                    "GROUP",
                    "g",
                    "c",
                    "COUNT",
                    "5",
                    "STREAMS",
                    "app:a",
                    ">"
                ]
            )
            .is_ok()
        );
        assert!(
            run(
                &rules,
                &[
                    "XREADGROUP",
                    "GROUP",
                    "g",
                    "c",
                    "STREAMS",
                    "app:a",
                    "secret",
                    ">",
                    ">"
                ]
            )
            .is_err()
        );
        assert!(run(&rules, &["XREAD", "BOGUS", "STREAMS", "secret", "0"]).is_err());
    }

    #[test]
    fn a_grant_covers_only_the_database_in_use() {
        let mut a = grant(&[], &[], &["a:*"]);
        a.databases = vec![0];
        let mut b = grant(&[], &[], &["b:*"]);
        b.databases = vec![5];
        let rules = Rules::new(vec![a, b], specs());
        assert!(run_in(&rules, 0, &["GET", "a:1"]).is_ok());
        assert!(
            run_in(&rules, 5, &["GET", "a:1"]).is_err(),
            "a:* is for database 0"
        );
        assert!(run_in(&rules, 5, &["GET", "b:1"]).is_ok());
        assert!(run_in(&rules, 0, &["GET", "b:1"]).is_err());
        assert!(run_in(&rules, 0, &["SELECT", "5"]).is_ok());
        assert!(run_in(&rules, 0, &["SELECT", "6"]).is_err());
        // A role that names only database 3 has nothing to run in database 0.
        let mut only3 = grant(&[], &[], &[]);
        only3.databases = vec![3];
        let rules = Rules::new(vec![only3], specs());
        assert!(run_in(&rules, 0, &["GET", "k"]).is_err());
        assert!(run_in(&rules, 0, &["SELECT", "3"]).is_ok());
        assert!(run_in(&rules, 3, &["GET", "k"]).is_ok());
    }

    #[test]
    fn move_and_copy_name_their_target_database() {
        let mut g = grant(&[], &["MOVE"], &[]);
        g.databases = vec![0, 2];
        let rules = Rules::new(vec![g], specs());
        assert!(run(&rules, &["MOVE", "k", "2"]).is_ok());
        assert!(run(&rules, &["MOVE", "k", "9"]).is_err());
        assert!(run(&rules, &["COPY", "a", "b", "DB", "2"]).is_ok());
        assert!(run(&rules, &["COPY", "a", "b", "DB", "9"]).is_err());
    }

    #[test]
    fn key_restricted_roles_cannot_listen_for_key_events() {
        let rules = keyed(&["app:*"]);
        for pattern in [
            "*",
            "__key*",
            "__keyevent@0__:*",
            "__keyspace@0__:app:*",
            "_*",
            "?_keyevent@0__:del",
            "[_]*",
        ] {
            assert!(run(&rules, &["PSUBSCRIBE", pattern]).is_err(), "{pattern}");
        }
        for ok in ["news", "app:*", "chat.*"] {
            assert!(run(&rules, &["PSUBSCRIBE", ok]).is_ok(), "{ok}");
        }
        assert!(run(&rules, &["SUBSCRIBE", "__keyevent@0__:set"]).is_err());
        assert!(run(&rules, &["SUBSCRIBE", "news"]).is_ok());
        assert!(run(&rules, &["PUBSUB", "CHANNELS"]).is_err());
        assert!(run(&keyed(&[]), &["PSUBSCRIBE", "*"]).is_ok());
    }

    #[test]
    fn a_huge_key_list_stays_small_in_the_audit_event() {
        let rules = Rules::new(vec![grant(&[], &[], &[])], specs());
        let mut words = vec!["DEL".to_owned()];
        words.extend((0..5000).map(|i| format!("key:{i}")));
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();
        let a = args(&refs);
        let insp = rules.inspect(&a);
        let audit = RedisAudit {
            redact_keys: false,
            log_values: true,
        };
        let data = Rules::audit_data(&insp, &a, &audit, "r", "u");
        assert_eq!(data["keys"].as_array().map(Vec::len), Some(AUDIT_LIST_MAX));
        assert_eq!(data["args"].as_array().map(Vec::len), Some(AUDIT_LIST_MAX));
        assert_eq!(data["keys_total"], 5000);
        assert!(data.to_string().len() < 64 * 1024);
    }

    #[test]
    fn a_denial_does_not_name_the_key() {
        let rules = keyed(&["app:*"]);
        let reason = run(&rules, &["GET", "very-secret-key"]).expect_err("outside");
        assert!(!reason.contains("very-secret-key"), "{reason}");
    }

    #[test]
    fn globs() {
        assert!(glob_match(b"session:*", b"session:42"));
        assert!(glob_match(b"*", b""));
        assert!(glob_match(b"a?c", b"abc"));
        assert!(!glob_match(b"a?c", b"ac"));
        assert!(glob_match(b"*:cache:*", b"x:cache:y"));
        assert!(!glob_match(b"session:*", b"other:1"));
        assert!(glob_match(b"a*b*c", b"aXXbYYc"));
        assert!(!glob_match(b"a*b*c", b"aXXbYY"));
        assert!(glob_match(b"k[1]", b"k[1]"));
    }

    #[test]
    fn extracts_keys_from_the_targets_table() {
        let rules = Rules::new(vec![grant(&[], &[], &[])], specs());
        let keys = |w: &[&str]| rules.inspect(&args(w)).keys;
        assert_eq!(keys(&["GET", "a"]), Some(vec![b"a".to_vec()]));
        assert_eq!(
            keys(&["mset", "a", "1", "b", "2"]),
            Some(vec![b"a".to_vec(), b"b".to_vec()])
        );
        assert_eq!(keys(&["DEL", "a", "b", "c"]).map(|k| k.len()), Some(3));
        assert_eq!(keys(&["PING"]), Some(vec![]));
        assert_eq!(
            keys(&["OBJECT", "ENCODING", "k"]),
            Some(vec![b"k".to_vec()])
        );
        assert_eq!(keys(&["GET"]), None, "missing argument: can't name the key");
        // Movable keys with no handler: we can't tell.
        assert_eq!(keys(&["XTRIM", "s", "MAXLEN", "1"]), None);
    }

    #[test]
    fn extracts_movable_keys() {
        let rules = Rules::new(vec![grant(&[], &[], &[])], specs());
        let keys = |w: &[&str]| rules.inspect(&args(w)).keys;
        assert_eq!(
            keys(&["EVAL", "return 1", "2", "k1", "k2", "arg"]),
            Some(vec![b"k1".to_vec(), b"k2".to_vec()])
        );
        assert_eq!(keys(&["EVAL", "x", "5", "k1"]), None);
        assert_eq!(
            keys(&["ZUNIONSTORE", "dest", "2", "a", "b", "WEIGHTS", "1", "2"]),
            Some(vec![b"a".to_vec(), b"b".to_vec(), b"dest".to_vec()])
        );
        assert_eq!(
            keys(&["XREAD", "COUNT", "1", "STREAMS", "s1", "s2", "0", "0"]),
            Some(vec![b"s1".to_vec(), b"s2".to_vec()])
        );
        assert_eq!(
            keys(&["SORT", "list", "BY", "x", "STORE", "out"]),
            Some(vec![b"list".to_vec(), b"out".to_vec()])
        );
        assert_eq!(
            keys(&["BLMPOP", "0", "1", "q", "LEFT"]),
            Some(vec![b"q".to_vec()])
        );
    }

    #[test]
    fn default_deny_list_blocks_dangerous_commands() {
        let rules = Rules::new(vec![grant(&[], &[], &[])], specs());
        for w in [
            &["FLUSHALL"][..],
            &["flushdb"],
            &["CONFIG", "GET", "*"],
            &["CLIENT", "KILL", "ID", "1"],
            &["EVAL", "return 1", "0"],
            &["MIGRATE", "h", "1", "k", "0", "1"],
        ] {
            assert!(run(&rules, w).is_err(), "{w:?}");
        }
        assert!(run(&rules, &["GET", "a"]).is_ok());
        assert!(run(&rules, &["CLIENT", "LIST"]).is_err(), "other sessions");
        assert!(run(&rules, &["CLIENT", "SETNAME", "x"]).is_ok());
        assert!(
            run(&rules, &["KEYS", "*"]).is_ok(),
            "KEYS is audited, not denied"
        );
    }

    #[test]
    fn grants_can_open_and_close_commands() {
        let opened = Rules::new(vec![grant(&[], &["CONFIG GET"], &[])], specs());
        assert!(run(&opened, &["CONFIG", "GET", "maxmemory"]).is_ok());
        assert!(run(&opened, &["CONFIG", "SET", "a", "b"]).is_err());
        let closed = Rules::new(vec![grant(&["KEYS", "client list"], &[], &[])], specs());
        assert!(run(&closed, &["keys", "*"]).is_err());
        assert!(run(&closed, &["CLIENT", "LIST"]).is_err());
        assert!(run(&closed, &["CLIENT", "ID"]).is_ok());
        // An explicit deny beats an allow.
        let both = Rules::new(vec![grant(&["FLUSHALL"], &["FLUSHALL"], &[])], specs());
        assert!(run(&both, &["FLUSHALL"]).is_err());
    }

    #[test]
    fn never_allowed_commands_ignore_grants() {
        let rules = Rules::new(
            vec![grant(&[], &["MONITOR", "RESET", "CLIENT REPLY"], &[])],
            specs(),
        );
        for w in [
            &["MONITOR"][..],
            &["RESET"],
            &["CLIENT", "REPLY", "OFF"],
            &["psync", "?", "-1"],
        ] {
            assert!(run(&rules, w).is_err(), "{w:?}");
        }
    }

    #[test]
    fn key_patterns_confine_the_session() {
        let rules = Rules::new(
            vec![grant(&[], &["EVAL"], &["session:*", "cache:?"])],
            specs(),
        );
        assert!(run(&rules, &["GET", "session:1"]).is_ok());
        assert!(run(&rules, &["GET", "cache:a"]).is_ok());
        assert!(run(&rules, &["GET", "secret"]).is_err());
        assert!(run(&rules, &["MSET", "session:1", "x", "other", "y"]).is_err());
        assert!(run(&rules, &["DEL", "session:1", "session:2"]).is_ok());
        assert!(run(&rules, &["PING"]).is_ok());
        assert!(run(&rules, &["KEYS", "session:*"]).is_err());
        assert!(
            run(&rules, &["EVAL", "return 1", "0"]).is_err(),
            "scripts escape key patterns"
        );
        assert!(
            run(&rules, &["XTRIM", "session:s", "MAXLEN", "1"]).is_err(),
            "unknown key layout"
        );
    }

    #[test]
    fn key_restricted_grants_cannot_wipe_the_keyspace_even_if_opened() {
        let rules = Rules::new(
            vec![grant(&[], &["FLUSHDB", "FLUSHALL", "SWAPDB"], &["a:*"])],
            specs(),
        );
        for w in [&["FLUSHDB"][..], &["FLUSHALL"], &["SWAPDB", "0", "1"]] {
            assert!(run(&rules, w).is_err(), "{w:?}");
        }
        // Without a key restriction the role's own choice stands.
        let open = Rules::new(vec![grant(&[], &["FLUSHDB"], &[])], specs());
        assert!(run(&open, &["FLUSHDB"]).is_ok());
    }

    #[test]
    fn any_one_grant_is_enough() {
        let rules = Rules::new(
            vec![
                grant(&[], &[], &["a:*"]),
                grant(&["FLUSHALL"], &[], &["b:*"]),
            ],
            specs(),
        );
        assert!(run(&rules, &["GET", "a:1"]).is_ok());
        assert!(run(&rules, &["GET", "b:1"]).is_ok());
        assert!(run(&rules, &["GET", "c:1"]).is_err());
    }

    #[test]
    fn select_is_limited_to_named_databases() {
        let rules = Rules::new(vec![grant(&[], &[], &[])], specs());
        assert!(run(&rules, &["SELECT", "0"]).is_ok());
        assert!(run(&rules, &["SELECT", "1"]).is_err());
        assert!(run(&rules, &["SELECT", "x"]).is_err());
        let mut g = grant(&[], &[], &[]);
        g.databases = vec![0, 3];
        let rules = Rules::new(vec![g], specs());
        assert!(run(&rules, &["SELECT", "3"]).is_ok());
        assert!(run(&rules, &["SELECT", "4"]).is_err());
        assert!(run(&rules, &["COPY", "a", "b", "DB", "2"]).is_err());
    }

    #[test]
    fn audit_never_holds_values_by_default() {
        let rules = Rules::new(vec![grant(&[], &[], &[])], specs());
        let a = args(&["SET", "user:1", "hunter2"]);
        let insp = rules.inspect(&a);
        let data = Rules::audit_data(&insp, &a, &RedisAudit::default(), "cache", "write");
        let text = data.to_string();
        assert!(!text.contains("hunter2"), "{text}");
        assert_eq!(data["command"], "SET");
        assert_eq!(data["keys"], json!(["user:1"]));
        assert_eq!(data["arity"], 3);
        assert_eq!(data["redis_user"], "write");
    }

    #[test]
    fn opted_in_values_are_logged_but_credentials_never() {
        let rules = Rules::new(vec![grant(&[], &[], &[])], specs());
        let on = RedisAudit {
            log_values: true,
            redact_keys: false,
        };
        let a = args(&["SET", "k", "v"]);
        let data = Rules::audit_data(&rules.inspect(&a), &a, &on, "c", "u");
        assert_eq!(data["args"], json!(["k", "v"]));
        for words in [
            &["AUTH", "default", "s3cret"][..],
            &["HELLO", "3", "AUTH", "default", "s3cret"],
            &["ACL", "SETUSER", "x", ">s3cret"],
            &["CONFIG", "SET", "requirepass", "s3cret"],
            &["MIGRATE", "h", "1", "k", "0", "1", "AUTH", "s3cret"],
        ] {
            let a = args(words);
            let data = Rules::audit_data(&rules.inspect(&a), &a, &on, "c", "u");
            assert!(!data.to_string().contains("s3cret"), "{words:?}: {data}");
        }
    }

    #[test]
    fn hashed_keys_hide_the_name_but_stay_comparable() {
        let rules = Rules::new(vec![grant(&[], &[], &[])], specs());
        let on = RedisAudit {
            log_values: false,
            redact_keys: true,
        };
        let a = args(&["GET", "email:jo@example.com"]);
        let one = Rules::audit_data(&rules.inspect(&a), &a, &on, "c", "u");
        let two = Rules::audit_data(&rules.inspect(&a), &a, &on, "c", "u");
        let other = Rules::audit_data(&rules.inspect(&a), &a, &on, "d", "u");
        assert!(!one.to_string().contains("example.com"));
        assert_eq!(one["keys"], two["keys"]);
        assert_ne!(one["keys"], other["keys"], "hashes differ per resource");
    }
}
