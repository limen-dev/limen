//! The search box's language (ADR-0026): free words and "quoted phrases",
//! plus `user:`, `resource:`, `kind:`, `session:`, `after:`, `before:` and
//! `outcome:` filters. Parsed into a typed [`Query`] and never into SQL: the
//! store binds every value as a parameter.

use time::OffsetDateTime;
use uuid::Uuid;

const MAX_QUERY_BYTES: usize = 512;
const MAX_TERMS: usize = 20;
const MAX_TERM_BYTES: usize = 200;
const MAX_VALUES: usize = 10;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    /// Every one must appear, as a case-insensitive substring.
    pub terms: Vec<String>,
    pub users: Vec<String>,
    pub resources: Vec<String>,
    pub kinds: Vec<String>,
    pub session: Option<Uuid>,
    pub after: Option<OffsetDateTime>,
    pub before: Option<OffsetDateTime>,
    /// `ok` or `denied`.
    pub outcome: Option<String>,
}

impl Query {
    /// A query with no words and no filters finds everything: refused.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
            && self.users.is_empty()
            && self.resources.is_empty()
            && self.kinds.is_empty()
            && self.session.is_none()
            && self.after.is_none()
            && self.before.is_none()
            && self.outcome.is_none()
    }
}

/// Split into tokens on whitespace, keeping quoted runs together. A token is
/// `(key, value, was_quoted)`.
fn tokens(input: &str) -> Result<Vec<(Option<String>, String, bool)>, String> {
    let mut out = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut key = None;
        let mut buf = String::new();
        let mut quoted = false;
        // Read up to whitespace, handling `key:` and quotes.
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() {
                break;
            }
            chars.next();
            if c == '"' {
                quoted = true;
                let mut closed = false;
                for q in chars.by_ref() {
                    if q == '"' {
                        closed = true;
                        break;
                    }
                    buf.push(q);
                }
                if !closed {
                    return Err("a quote is not closed".into());
                }
            } else if c == ':' && key.is_none() && !quoted && is_filter_key(&buf) {
                key = Some(std::mem::take(&mut buf));
            } else {
                buf.push(c);
            }
        }
        out.push((key, buf, quoted));
    }
    Ok(out)
}

fn is_filter_key(key: &str) -> bool {
    matches!(
        key,
        "user" | "resource" | "kind" | "session" | "after" | "before" | "outcome"
    )
}

/// Parse a search. `now` anchors relative times such as `after:24h`.
pub fn parse(input: &str, now: OffsetDateTime) -> Result<Query, String> {
    if input.len() > MAX_QUERY_BYTES {
        return Err(format!("the query is longer than {MAX_QUERY_BYTES} bytes"));
    }
    if input.chars().any(|c| c.is_control() && !c.is_whitespace()) {
        return Err("the query has control characters".into());
    }
    let toks = tokens(input)?;
    if toks.len() > MAX_TERMS {
        return Err(format!("at most {MAX_TERMS} words and filters"));
    }
    let mut q = Query::default();
    for (key, value, quoted) in toks {
        match key.as_deref() {
            None => {
                if value.is_empty() {
                    continue;
                }
                if value.len() > MAX_TERM_BYTES {
                    return Err(format!("a word is longer than {MAX_TERM_BYTES} bytes"));
                }
                q.terms.push(value);
            }
            Some(key) => {
                if value.is_empty() {
                    return Err(format!("{key}: needs a value"));
                }
                if value.len() > MAX_TERM_BYTES {
                    return Err(format!("the value of {key}: is too long"));
                }
                let _ = quoted;
                match key {
                    "user" => push_limited(&mut q.users, value.to_lowercase(), key)?,
                    "resource" => push_limited(&mut q.resources, value, key)?,
                    "kind" => {
                        if !value
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b == b'.' || b == b'_')
                        {
                            return Err(
                                "kind: is an event kind such as ssh.exec or db.query".into()
                            );
                        }
                        push_limited(&mut q.kinds, value, key)?;
                    }
                    "session" => {
                        q.session = Some(
                            Uuid::parse_str(&value)
                                .map_err(|_| "session: needs a session id".to_owned())?,
                        );
                    }
                    "after" => q.after = Some(parse_time(&value, now, "after")?),
                    "before" => q.before = Some(parse_time(&value, now, "before")?),
                    "outcome" => {
                        if !matches!(value.as_str(), "ok" | "denied") {
                            return Err("outcome: is ok or denied".into());
                        }
                        q.outcome = Some(value);
                    }
                    _ => unreachable!("only filter keys are split off"),
                }
            }
        }
    }
    if let (Some(a), Some(b)) = (q.after, q.before)
        && a >= b
    {
        return Err("after: must be earlier than before:".into());
    }
    Ok(q)
}

fn push_limited(list: &mut Vec<String>, value: String, key: &str) -> Result<(), String> {
    if list.len() >= MAX_VALUES {
        return Err(format!("at most {MAX_VALUES} values for {key}:"));
    }
    list.push(value);
    Ok(())
}

/// `2026-10-01`, `2026-10-01T12:30:00Z`, or a time ago: `90m`, `24h`, `7d`.
fn parse_time(value: &str, now: OffsetDateTime, key: &str) -> Result<OffsetDateTime, String> {
    let bad = || format!("{key}: needs a date (2026-10-01), a time, or an age such as 24h or 7d");
    if let Some((digits, unit)) = value.split_at_checked(value.len().saturating_sub(1))
        && let Ok(n) = digits.parse::<i64>()
        && n > 0
    {
        let secs = match unit {
            "m" => n.checked_mul(60),
            "h" => n.checked_mul(3600),
            "d" => n.checked_mul(86_400),
            "w" => n.checked_mul(604_800),
            _ => None,
        };
        if let Some(secs) = secs {
            return now
                .checked_sub(time::Duration::seconds(secs))
                .ok_or_else(bad);
        }
    }
    if let Ok(t) = OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339) {
        return Ok(t);
    }
    let date = time::Date::parse(
        value,
        &time::macros::format_description!("[year]-[month]-[day]"),
    )
    .map_err(|_| bad())?;
    Ok(date.midnight().assume_utc())
}

/// A `LIKE` pattern matching `term` anywhere, with its wildcards escaped.
#[must_use]
pub fn like_pattern(term: &str) -> String {
    let mut out = String::with_capacity(term.len() + 2);
    out.push('%');
    for c in term.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    const NOW: OffsetDateTime = datetime!(2026-10-25 12:00:00 UTC);

    fn ok(s: &str) -> Query {
        parse(s, NOW).expect(s)
    }

    #[test]
    fn words_phrases_and_filters() {
        let q =
            ok(r#"drop "orders table" user:Alice@Example.com resource:orders-prod kind:db.query"#);
        assert_eq!(q.terms, ["drop", "orders table"]);
        assert_eq!(
            q.users,
            ["alice@example.com"],
            "users are matched case-insensitively"
        );
        assert_eq!(q.resources, ["orders-prod"]);
        assert_eq!(q.kinds, ["db.query"]);
        assert!(!q.is_empty());
    }

    #[test]
    fn quoted_filter_values_and_unknown_keys() {
        let q = ok(r#"resource:"web prod" http://example.com foo:bar"#);
        assert_eq!(q.resources, ["web prod"]);
        // `http:` and `foo:` aren't filters: they stay words.
        assert_eq!(q.terms, ["http://example.com", "foo:bar"]);
    }

    #[test]
    fn times_can_be_dates_instants_or_ages() {
        assert_eq!(
            ok("after:2026-10-01").after,
            Some(datetime!(2026-10-01 00:00:00 UTC))
        );
        assert_eq!(
            ok("before:2026-10-01T12:30:00Z").before,
            Some(datetime!(2026-10-01 12:30:00 UTC))
        );
        assert_eq!(
            ok("after:24h").after,
            Some(datetime!(2026-10-24 12:00:00 UTC))
        );
        assert_eq!(
            ok("after:7d").after,
            Some(datetime!(2026-10-18 12:00:00 UTC))
        );
        assert!(parse("after:soon", NOW).is_err());
        assert!(parse("after:2026-10-02 before:2026-10-01", NOW).is_err());
        assert!(parse("after:0d", NOW).is_err());
    }

    #[test]
    fn session_outcome_and_kind_are_checked() {
        let id = "0198a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        assert_eq!(
            ok(&format!("session:{id}")).session,
            Some(id.parse().expect("uuid"))
        );
        assert!(parse("session:nope", NOW).is_err());
        assert_eq!(ok("outcome:denied").outcome.as_deref(), Some("denied"));
        assert!(parse("outcome:maybe", NOW).is_err());
        assert!(parse("kind:SSH.exec", NOW).is_err());
        assert!(parse("kind:ssh;drop", NOW).is_err());
    }

    #[test]
    fn it_refuses_what_could_hurt() {
        assert!(parse(&"x".repeat(513), NOW).is_err());
        assert!(parse(&"a ".repeat(21), NOW).is_err());
        assert!(parse(&"y".repeat(201), NOW).is_err());
        assert!(parse("\"unclosed", NOW).is_err());
        assert!(parse("user:", NOW).is_err());
        assert!(parse("a\u{0}b", NOW).is_err());
        assert!(
            parse(
                "user:a user:b user:c user:d user:e user:f user:g user:h user:i user:j user:k",
                NOW
            )
            .is_err()
        );
    }

    #[test]
    fn an_empty_search_is_empty() {
        assert!(ok("").is_empty());
        assert!(ok("   ").is_empty());
        assert!(!ok("after:1d").is_empty());
    }

    #[test]
    fn like_patterns_escape_wildcards() {
        assert_eq!(like_pattern("100%_done\\"), "%100\\%\\_done\\\\%");
        assert_eq!(like_pattern("plain"), "%plain%");
    }
}
