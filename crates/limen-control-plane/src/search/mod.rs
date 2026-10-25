//! Searching recent audit events and, when switched on, recording text
//! (ADR-0026). The index is a convenience copy in PostgreSQL for the console
//! and the CLI; the audit sinks stay the record and `limen-audit-verify` the
//! source of truth. **Every search is audited** with who looked for what, and
//! rate limited, because search is also a way to read a lot at once.

pub mod index;
pub mod mask;
pub mod query;
pub mod recording;

use limen_audit::{Context, EventKind};
use serde_json::json;
use sqlx::Row;
use time::OffsetDateTime;
use tonic::Status;
use uuid::Uuid;

use self::query::Query;
use crate::state::{AppState, internal};

/// The most hits one search returns.
pub const MAX_HITS: i64 = 200;
const DEFAULT_HITS: i64 = 50;
/// Characters of context on each side of a match.
const CONTEXT: usize = 70;
/// How far before a hit the player starts, so the moment has its lead-in.
const LEAD_IN_SECS: i64 = 3;

/// A piece of text with the match marked, for display. Rendered escaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snippet {
    pub before: String,
    pub hit: String,
    pub after: String,
}

#[derive(Debug, Clone)]
pub struct Hit {
    pub at: OffsetDateTime,
    pub kind: String,
    pub user: Option<String>,
    pub session_id: Option<Uuid>,
    pub resource: Option<String>,
    pub outcome: String,
    pub snippet: Snippet,
    /// Where to start the recording so the moment plays, when there is one.
    pub recording_offset_secs: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct Results {
    pub hits: Vec<Hit>,
    /// More matched than were returned.
    pub truncated: bool,
}

/// A snippet around the first place any term matches, case-insensitively.
#[must_use]
pub fn snippet(text: &str, terms: &[String]) -> Snippet {
    let chars: Vec<char> = text.chars().collect();
    // One lowered char per original char keeps the two aligned for any text.
    let lower: Vec<char> = chars
        .iter()
        .map(|c| c.to_lowercase().next().unwrap_or(*c))
        .collect();
    // The words together as written first ("drop table"), then each alone.
    let joined = terms.join(" ");
    let candidates = std::iter::once(&joined).chain(terms);
    let found = candidates.filter(|t| !t.is_empty()).find_map(|term| {
        let needle: Vec<char> = term
            .chars()
            .map(|c| c.to_lowercase().next().unwrap_or(c))
            .collect();
        lower
            .windows(needle.len())
            .position(|w| w == needle.as_slice())
            .map(|p| (p, needle.len()))
    });
    let (start, len) = found.unwrap_or((0, 0));
    let from = start.saturating_sub(CONTEXT);
    let to = (start + len + CONTEXT).min(chars.len());
    let part = |a: usize, b: usize| chars[a..b].iter().collect::<String>();
    let mut before = part(from, start);
    let mut after = part(start + len, to);
    if from > 0 {
        before.insert(0, '…');
    }
    if to < chars.len() {
        after.push('…');
    }
    Snippet {
        before,
        hit: part(start, start + len),
        after,
    }
}

/// Who is searching.
#[derive(Debug, Clone, Copy)]
pub struct Searcher<'a> {
    pub username: &'a str,
    /// `api` or `console`.
    pub via: &'static str,
}

/// Audit, rate limit, and run a search. The caller has already checked that
/// the person may search at all (`limen:admin` or `limen:auditor`).
pub async fn search(
    state: &AppState,
    who: Searcher<'_>,
    raw: &str,
    limit: u32,
) -> Result<Results, Status> {
    let query = query::parse(raw, OffsetDateTime::now_utc()).map_err(Status::invalid_argument)?;
    if query.is_empty() {
        return Err(Status::invalid_argument(
            "say what to look for: a word, or a filter such as user:, resource:, kind:, or after:",
        ));
    }
    state.limits.check_search(who.username)?;
    // Recorded before the search runs: a search that can't be audited doesn't happen.
    state
        .audit
        .emit(
            EventKind::AuditSearch,
            Context {
                user: Some(who.username.to_owned()),
                session_id: None,
            },
            json!({
                "query": raw.trim(),
                "terms": query.terms.len(),
                "filters": filters(&query),
                "via": who.via,
            }),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "audit unavailable; refusing a search");
            Status::unavailable("audit unavailable")
        })?;
    metrics::counter!("limen_audit_searches_total").increment(1);
    let limit = match i64::from(limit) {
        0 => DEFAULT_HITS,
        n => n.min(MAX_HITS),
    };
    run(state, &query, limit).await
}

fn filters(q: &Query) -> serde_json::Value {
    json!({
        "users": q.users, "resources": q.resources, "kinds": q.kinds,
        "session": q.session, "after": q.after.map(OffsetDateTime::unix_timestamp),
        "before": q.before.map(OffsetDateTime::unix_timestamp), "outcome": q.outcome,
    })
}

/// Run a parsed search. No audit, no rate limit: [`search`] does both.
pub async fn run(state: &AppState, q: &Query, limit: i64) -> Result<Results, Status> {
    let patterns: Vec<String> = q.terms.iter().map(|t| query::like_pattern(t)).collect();
    let tsq = query::tsquery(&q.terms);
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| internal("starting a search", e))?;
    // A search that takes longer is cancelled.
    sqlx::query("SET LOCAL statement_timeout = '10s'")
        .execute(&mut *tx)
        .await
        .map_err(|e| internal("starting a search", e))?;
    // One more than asked for, to know whether there is more.
    let fetch = limit + 1;
    let rows = sqlx::query(
        "SELECT s.at, s.kind, s.username, s.session_id, s.resource, s.outcome, s.text,
                ss.started_at, (ss.recording_uri IS NOT NULL) AS has_recording
         FROM audit_search s LEFT JOIN sessions ss ON ss.session_id = s.session_id
         WHERE ($1::timestamptz IS NULL OR s.at >= $1)
           AND ($2::timestamptz IS NULL OR s.at < $2)
           AND (cardinality($3::text[]) = 0 OR lower(s.username) = ANY($3))
           AND (cardinality($4::text[]) = 0 OR s.resource = ANY($4))
           AND (cardinality($5::text[]) = 0 OR s.kind = ANY($5))
           AND ($6::uuid IS NULL OR s.session_id = $6)
           AND ($7::text IS NULL OR s.outcome = $7)
           AND ($8::text IS NULL OR s.tsv @@ to_tsquery('simple', $8))
           AND (cardinality($9::text[]) = 0 OR s.text ILIKE ALL ($9))
         ORDER BY s.at DESC LIMIT $10",
    )
    .bind(q.after)
    .bind(q.before)
    .bind(&q.users)
    .bind(&q.resources)
    .bind(&q.kinds)
    .bind(q.session)
    .bind(q.outcome.as_deref())
    .bind(tsq.as_deref())
    .bind(&patterns)
    .bind(fetch)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| search_error("searching events", &e))?;

    let mut hits: Vec<Hit> = Vec::with_capacity(rows.len());
    for r in &rows {
        let at: OffsetDateTime = get(r, "at")?;
        let text: String = get(r, "text")?;
        let started: Option<OffsetDateTime> = get(r, "started_at")?;
        let has_recording: Option<bool> = get(r, "has_recording")?;
        hits.push(Hit {
            at,
            kind: get(r, "kind")?,
            user: get(r, "username")?,
            session_id: get(r, "session_id")?,
            resource: get(r, "resource")?,
            outcome: get(r, "outcome")?,
            snippet: snippet(&text, &q.terms),
            recording_offset_secs: started
                .filter(|_| has_recording == Some(true))
                .map(|s| ((at - s).whole_seconds() - LEAD_IN_SECS).max(0)),
        });
    }

    // Terminal output, if anyone is indexing it.
    let wants_recordings = q.kinds.is_empty() || q.kinds.iter().any(|k| k == "recording.output");
    if wants_recordings && !q.terms.is_empty() {
        let rows = sqlx::query(
            "SELECT ss.started_at + r.t * interval '1 second' AS at, r.t, r.text, r.session_id,
                    ss.username, ss.resource
             FROM recording_text r JOIN sessions ss ON ss.session_id = r.session_id
             WHERE ($1::timestamptz IS NULL OR ss.started_at + r.t * interval '1 second' >= $1)
               AND ($2::timestamptz IS NULL OR ss.started_at + r.t * interval '1 second' < $2)
               AND (cardinality($3::text[]) = 0 OR lower(ss.username) = ANY($3))
               AND (cardinality($4::text[]) = 0 OR ss.resource = ANY($4))
               AND ($5::uuid IS NULL OR r.session_id = $5)
               AND $6::text IS NULL
               AND ($7::text IS NULL OR r.tsv @@ to_tsquery('simple', $7))
               AND r.text ILIKE ALL ($8)
             ORDER BY at DESC LIMIT $9",
        )
        .bind(q.after)
        .bind(q.before)
        .bind(&q.users)
        .bind(&q.resources)
        .bind(q.session)
        // A recording has no denied/ok outcome: an outcome filter skips it.
        .bind(q.outcome.as_deref())
        .bind(tsq.as_deref())
        .bind(&patterns)
        .bind(fetch)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| search_error("searching recordings", &e))?;
        for r in &rows {
            let t: f64 = get(r, "t")?;
            let text: String = get(r, "text")?;
            #[allow(clippy::cast_possible_truncation)]
            let offset = (t as i64 - LEAD_IN_SECS).max(0);
            hits.push(Hit {
                at: get(r, "at")?,
                kind: "recording.output".to_owned(),
                user: get(r, "username")?,
                session_id: get(r, "session_id")?,
                resource: get(r, "resource")?,
                outcome: "ok".to_owned(),
                snippet: snippet(&text, &q.terms),
                recording_offset_secs: Some(offset),
            });
        }
    }
    tx.commit()
        .await
        .map_err(|e| internal("finishing a search", e))?;
    hits.sort_by_key(|h| std::cmp::Reverse(h.at));
    let truncated = i64::try_from(hits.len()).unwrap_or(i64::MAX) > limit;
    hits.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    Ok(Results { hits, truncated })
}

fn get<'r, T>(row: &'r sqlx::postgres::PgRow, col: &str) -> Result<T, Status>
where
    T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(col).map_err(|e| internal("reading a hit", e))
}

/// A timeout is the caller's to fix (narrow the search); the rest is ours.
fn search_error(what: &str, e: &sqlx::Error) -> Status {
    if e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|c| c == "57014")
    {
        return Status::deadline_exceeded(
            "the search took too long; narrow it with user:, resource:, kind:, or after:",
        );
    }
    internal(what, e)
}

/// The URL for the same filters in the full-history store, if one is
/// configured (`--search-athena-url`, with `{query}`, `{user}`, `{resource}`,
/// `{kind}`, `{after}`, and `{before}` placeholders).
#[must_use]
pub fn history_link(template: &str, raw: &str, q: &Query) -> String {
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    let first = |v: &[String]| v.first().map_or_else(String::new, |s| enc(s));
    let time = |t: Option<OffsetDateTime>| {
        t.and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .map_or_else(String::new, |s| enc(&s))
    };
    template
        .replace("{query}", &enc(raw.trim()))
        .replace("{user}", &first(&q.users))
        .replace("{resource}", &first(&q.resources))
        .replace("{kind}", &first(&q.kinds))
        .replace("{after}", &time(q.after))
        .replace("{before}", &time(q.before))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snippets_mark_the_first_match_and_trim_the_rest() {
        let text = format!("{}DROP TABLE orders{}", "a".repeat(200), "b".repeat(200));
        let s = snippet(&text, &["drop table".to_owned()]);
        assert_eq!(s.hit, "DROP TABLE");
        assert!(s.before.starts_with('…') && s.after.ends_with('…'));
        assert!(s.before.chars().count() <= CONTEXT + 1);
        assert!(s.after.starts_with(" orders"));
        // No match (a filter-only search) shows the start of the text.
        let s = snippet("select 1", &[]);
        assert_eq!((s.before.as_str(), s.hit.as_str()), ("", ""));
        assert_eq!(s.after, "select 1");
    }

    #[test]
    fn snippets_survive_text_whose_lowercase_is_longer() {
        let s = snippet("İstanbul DROP now", &["drop".to_owned()]);
        assert_eq!(s.hit, "DROP");
        assert_eq!(s.before, "İstanbul ");
    }

    #[test]
    fn the_history_link_fills_the_filters_encoded() {
        let q = query::parse(
            "user:a@b.c resource:orders kind:db.query after:2026-10-01 drop",
            datetime(),
        )
        .expect("query");
        let url = history_link(
            "https://athena.example/q?u={user}&r={resource}&k={kind}&a={after}&q={query}",
            "user:a@b.c drop table",
            &q,
        );
        assert_eq!(
            url,
            "https://athena.example/q?u=a%40b.c&r=orders&k=db.query&a=2026-10-01T00%3A00%3A00Z&q=user%3Aa%40b.c+drop+table"
        );
    }

    fn datetime() -> OffsetDateTime {
        time::macros::datetime!(2026-10-25 12:00:00 UTC)
    }
}
