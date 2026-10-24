//! Shared plumbing for the console's filterable lists (audit trail, sessions) and
//! for the links that lead to them from the dashboards: building a link from
//! filters, and reading the `from`/`to` times those links carry.

use time::macros::format_description;
use time::{Date, Duration, OffsetDateTime, PrimitiveDateTime};

use super::views::path_segment;

/// `base?key=value&...`, skipping empty values and percent-encoding the rest.
#[must_use]
pub fn href(base: &str, pairs: &[(&str, &str)]) -> String {
    let query: Vec<String> = pairs
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={}", path_segment(v)))
        .collect();
    if query.is_empty() {
        base.to_owned()
    } else {
        format!("{base}?{}", query.join("&"))
    }
}

/// A moment in the form the filters and dashboard links use: `YYYY-MM-DDTHH:MM`, UTC.
#[must_use]
pub fn when_text(t: PrimitiveDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute()
    )
}

/// Reads `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM` or `YYYY-MM-DDTHH:MM:SS` (UTC).
/// A bare date means the whole day: its start for a lower bound, and the start
/// of the next day for an upper bound (`end`), which is always exclusive.
#[must_use]
pub fn parse_when(s: &str, end: bool) -> Option<OffsetDateTime> {
    let s = s.trim();
    if let Ok(date) = Date::parse(s, format_description!("[year]-[month]-[day]")) {
        let start = date.midnight().assume_utc();
        return Some(if end {
            start + Duration::days(1)
        } else {
            start
        });
    }
    PrimitiveDateTime::parse(
        s,
        format_description!("[year]-[month]-[day]T[hour]:[minute]"),
    )
    .or_else(|_| {
        PrimitiveDateTime::parse(
            s,
            format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]"),
        )
    })
    .ok()
    .map(PrimitiveDateTime::assume_utc)
}

/// A `from`/`to` pair from the query string; the second value lists what was ignored.
#[must_use]
pub fn parse_range(
    from: Option<&str>,
    to: Option<&str>,
) -> (Option<OffsetDateTime>, Option<OffsetDateTime>, Vec<String>) {
    let mut ignored = Vec::new();
    let mut one = |label: &str, value: Option<&str>, end: bool| {
        let value = value.map(str::trim).filter(|v| !v.is_empty())?;
        let parsed = parse_when(value, end);
        if parsed.is_none() {
            ignored.push(format!(
                "Ignored “{value}” for {label}: use YYYY-MM-DD or YYYY-MM-DDTHH:MM (UTC)."
            ));
        }
        parsed
    };
    let from = one("From", from, false);
    let to = one("To", to, true);
    (from, to, ignored)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_skip_empty_values_and_encode() {
        assert_eq!(href("/x", &[("a", ""), ("b", "")]), "/x");
        assert_eq!(
            href(
                "/x",
                &[("kind", "auth.denied"), ("q", "a b&c"), ("user", "")]
            ),
            "/x?kind=auth.denied&q=a%20b%26c"
        );
    }

    #[test]
    fn times_round_trip_and_dates_cover_the_day() {
        let from = parse_when("2026-10-24T09:30", false).expect("datetime");
        assert_eq!(
            when_text(PrimitiveDateTime::new(from.date(), from.time())),
            "2026-10-24T09:30"
        );
        let a = parse_when("2026-10-24", false).expect("date");
        let b = parse_when("2026-10-24", true).expect("date");
        assert_eq!(b - a, Duration::days(1));
        assert!(parse_when("2026-10-24T09:30:15", true).is_some());
        assert!(parse_when("yesterday", false).is_none());
    }

    #[test]
    fn bad_times_are_reported_not_applied() {
        let (from, to, ignored) = parse_range(Some("nope"), Some("2026-10-24"));
        assert!(from.is_none() && to.is_some());
        assert_eq!(ignored.len(), 1);
    }
}
