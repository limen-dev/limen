//! Built-in dashboards (ADR-0017): what is happening, drawn on the server as
//! plain SVG, so the console needs no charting library and no script. The data
//! comes from the console's own tables, so it covers the last 30 days. Grafana
//! dashboards for the full history are an optional extra (`deploy/grafana`).

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Response;
use serde::Deserialize;
use sqlx::Row;
use time::{Duration, OffsetDateTime, PrimitiveDateTime};

use super::views::{Chrome, error_page, path_segment};
use super::{Auth, html};
use crate::db::Db;
use crate::state::AppState;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Range {
    Day,
    Week,
    Month,
}

impl Range {
    fn parse(s: Option<&str>) -> Self {
        match s {
            Some("7d") => Self::Week,
            Some("30d") => Self::Month,
            _ => Self::Day,
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::Day => "24h",
            Self::Week => "7d",
            Self::Month => "30d",
        }
    }

    /// Bucket size for the time series, as a `date_trunc` unit.
    fn unit(self) -> &'static str {
        match self {
            Self::Day => "hour",
            _ => "day",
        }
    }

    fn step(self) -> Duration {
        match self {
            Self::Day => Duration::hours(1),
            _ => Duration::days(1),
        }
    }

    fn buckets(self) -> i64 {
        match self {
            Self::Day => 24,
            Self::Week => 7,
            Self::Month => 30,
        }
    }

    fn label(self, t: PrimitiveDateTime) -> String {
        match self {
            Self::Day => format!("{:02}:00", t.hour()),
            _ => format!("{:02}-{:02}", u8::from(t.month()), t.day()),
        }
    }
}

// ---- chart geometry ------------------------------------------------------------

const W: i32 = 640;
const H: i32 = 200;
const LEFT: i32 = 40;
const RIGHT: i32 = 8;
const TOP: i32 = 10;
const BOTTOM: i32 = 24;

pub struct Bar {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub class: &'static str,
    pub tip: String,
}

pub struct Tick {
    pub y: i32,
    pub label: String,
}

pub struct XLabel {
    pub x: i32,
    pub text: String,
}

pub struct Chart {
    pub bars: Vec<Bar>,
    pub ticks: Vec<Tick>,
    pub xlabels: Vec<XLabel>,
    pub empty: bool,
    pub left: i32,
    pub right: i32,
    pub base: i32,
}

pub struct Series {
    pub name: &'static str,
    pub class: &'static str,
    pub values: Vec<i64>,
}

pub struct Panel {
    pub title: &'static str,
    pub sub: &'static str,
    pub chart: Chart,
    pub legend: Vec<(&'static str, &'static str)>,
}

/// The smallest 1, 2, or 5 times a power of ten that is at least `n`.
fn nice_ceiling(n: i64) -> i64 {
    let n = n.max(1);
    let mut p = 1_i64;
    while p * 10 <= n {
        p *= 10;
    }
    [1, 2, 5, 10]
        .iter()
        .map(|m| m * p)
        .find(|c| *c >= n)
        .unwrap_or(10 * p)
}

/// Grouped bars: one group per label, one bar per series.
pub fn bar_chart(labels: &[String], series: &[Series]) -> Chart {
    let groups = i32::try_from(labels.len()).unwrap_or(1).max(1);
    let per_group = i32::try_from(series.len()).unwrap_or(1).max(1);
    let peak = series
        .iter()
        .flat_map(|s| s.values.iter().copied())
        .max()
        .unwrap_or(0);
    let top = nice_ceiling(peak);
    let plot_w = W - LEFT - RIGHT;
    let plot_h = H - TOP - BOTTOM;
    let group_w = plot_w / groups;
    let bar_w = ((group_w * 7 / 10) / per_group).max(1);
    let pad = (group_w - bar_w * per_group) / 2;
    let mut bars = Vec::new();
    for (index, label) in labels.iter().enumerate() {
        let group = i32::try_from(index).unwrap_or(0);
        for (position, one) in series.iter().enumerate() {
            let value = one.values.get(index).copied().unwrap_or(0);
            let slot = i32::try_from(position).unwrap_or(0);
            let height = if value == 0 {
                0
            } else {
                i32::try_from(value * i64::from(plot_h) / top)
                    .unwrap_or(plot_h)
                    .max(2)
            };
            bars.push(Bar {
                x: LEFT + group * group_w + pad + slot * bar_w,
                y: TOP + plot_h - height,
                w: bar_w,
                h: height,
                class: one.class,
                tip: format!("{label}: {value} {}", one.name),
            });
        }
    }
    let mut ticks = vec![Tick {
        y: TOP + plot_h,
        label: "0".into(),
    }];
    if top >= 2 {
        ticks.push(Tick {
            y: TOP + plot_h / 2,
            label: (top / 2).to_string(),
        });
    }
    ticks.push(Tick {
        y: TOP,
        label: top.to_string(),
    });
    // About six labels along the bottom, whatever the number of groups.
    let every = usize::try_from((groups + 5) / 6).unwrap_or(1).max(1);
    let xlabels = labels
        .iter()
        .enumerate()
        .filter(|(index, _)| index % every == 0)
        .map(|(index, text)| XLabel {
            x: LEFT + i32::try_from(index).unwrap_or(0) * group_w + group_w / 2,
            text: text.clone(),
        })
        .collect();
    Chart {
        bars,
        ticks,
        xlabels,
        empty: peak == 0,
        left: LEFT,
        right: W - RIGHT,
        base: TOP + plot_h,
    }
}

pub struct Ranked {
    pub label: String,
    pub value: i64,
    pub pct: i64,
    pub link: Option<String>,
}

fn rank(rows: Vec<(String, i64)>, link: impl Fn(&str) -> Option<String>) -> Vec<Ranked> {
    let max = rows.iter().map(|r| r.1).max().unwrap_or(1).max(1);
    rows.into_iter()
        .map(|(label, value)| Ranked {
            pct: (value * 100 / max).max(2),
            link: link(&label),
            label,
            value,
        })
        .collect()
}

pub struct RankPanel {
    pub title: &'static str,
    pub sub: &'static str,
    pub rows: Vec<Ranked>,
    pub class: &'static str,
}

// ---- data ----------------------------------------------------------------------

fn utc_now() -> PrimitiveDateTime {
    let now = OffsetDateTime::now_utc();
    PrimitiveDateTime::new(now.date(), now.time())
}

fn truncate(t: PrimitiveDateTime, unit: &str) -> PrimitiveDateTime {
    let time = if unit == "hour" {
        time::Time::from_hms(t.hour(), 0, 0)
    } else {
        time::Time::from_hms(0, 0, 0)
    };
    PrimitiveDateTime::new(t.date(), time.unwrap_or(time::Time::MIDNIGHT))
}

/// `(bucket starts, labels)`, oldest first, ending with the current bucket.
fn buckets(range: Range) -> (Vec<PrimitiveDateTime>, Vec<String>) {
    let last = truncate(utc_now(), range.unit());
    let starts: Vec<_> = (0..range.buckets())
        .rev()
        .map(|i| last - range.step() * i32::try_from(i).unwrap_or(0))
        .collect();
    let labels = starts.iter().map(|s| range.label(*s)).collect();
    (starts, labels)
}

fn slot(starts: &[PrimitiveDateTime], t: PrimitiveDateTime) -> Option<usize> {
    starts.iter().position(|s| *s == t)
}

async fn counts(
    db: &Db,
    sql: &'static str,
    since: OffsetDateTime,
) -> Result<Vec<(String, i64)>, sqlx::Error> {
    let rows = sqlx::query(sql).bind(since).fetch_all(db).await?;
    rows.iter()
        .map(|r| Ok((r.try_get::<String, _>(0)?, r.try_get::<i64, _>(1)?)))
        .collect()
}

pub struct Tile {
    pub value: String,
    pub label: &'static str,
    pub icon: &'static str,
    pub tone: &'static str,
}

fn duration_text(ms: f64) -> String {
    if ms < 1000.0 {
        format!("{ms:.0} ms")
    } else if ms < 60_000.0 {
        format!("{:.1} s", ms / 1000.0)
    } else if ms < 3_600_000.0 {
        format!("{:.1} min", ms / 60_000.0)
    } else {
        format!("{:.1} h", ms / 3_600_000.0)
    }
}

#[derive(Template)]
#[template(path = "dashboards.html")]
pub struct DashboardsPage {
    pub chrome: Chrome,
    pub range: &'static str,
    pub tiles: Vec<Tile>,
    pub panels: Vec<Panel>,
    pub ranked: Vec<RankPanel>,
}

#[derive(Deserialize)]
pub struct DashQuery {
    range: Option<String>,
}

pub async fn dashboards(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<DashQuery>,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let range = Range::parse(q.range.as_deref());
    match build(&state, range).await {
        Ok((tiles, panels, ranked)) => html(
            DashboardsPage {
                chrome: Chrome::new(&auth, "dashboards", state.policy.current().version),
                range: range.key(),
                tiles,
                panels,
                ranked,
            }
            .render(),
        ),
        Err(e) => {
            tracing::error!(error = %e, "building dashboards");
            error_page(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "Unavailable",
                "The console can't read its database right now. Try again shortly.",
            )
        }
    }
}

/// Sessions started, sign-ins, and denials per bucket, with empty buckets as zero.
async fn time_series(
    db: &Db,
    unit: &'static str,
    starts: &[PrimitiveDateTime],
    since: OffsetDateTime,
) -> Result<TimeSeries, sqlx::Error> {
    let mut sessions = vec![0_i64; starts.len()];
    let mut bot_sessions = vec![0_i64; starts.len()];
    for r in sqlx::query(
        "SELECT date_trunc($1, started_at AT TIME ZONE 'UTC') AS b, actor_type, count(*) AS n FROM sessions
         WHERE started_at >= $2 GROUP BY 1, 2",
    )
    .bind(unit)
    .bind(since)
    .fetch_all(db)
    .await?
    {
        if let Some(i) = slot(starts, r.try_get("b")?) {
            let n: i64 = r.try_get("n")?;
            if r.try_get::<String, _>("actor_type")? == "bot" {
                bot_sessions[i] = n;
            } else {
                sessions[i] = n;
            }
        }
    }
    let mut logins = vec![0_i64; starts.len()];
    let mut denied = vec![0_i64; starts.len()];
    for r in sqlx::query(
        "SELECT date_trunc($1, at AT TIME ZONE 'UTC') AS b, kind, count(*) AS n FROM audit_events
         WHERE at >= $2 AND kind IN ('auth.login', 'auth.denied') GROUP BY 1, 2",
    )
    .bind(unit)
    .bind(since)
    .fetch_all(db)
    .await?
    {
        if let Some(i) = slot(starts, r.try_get("b")?) {
            let n: i64 = r.try_get("n")?;
            if r.try_get::<String, _>("kind")? == "auth.login" {
                logins[i] = n;
            } else {
                denied[i] = n;
            }
        }
    }
    Ok(TimeSeries {
        sessions,
        bot_sessions,
        logins,
        denied,
    })
}

/// Counts per bucket: people's sessions, bots' sessions, sign-ins, denials.
struct TimeSeries {
    sessions: Vec<i64>,
    bot_sessions: Vec<i64>,
    logins: Vec<i64>,
    denied: Vec<i64>,
}

/// The ranked lists: busiest resources and people, session length, denials, admin actions.
async fn rankings(db: &Db, since: OffsetDateTime) -> Result<Vec<RankPanel>, sqlx::Error> {
    let top_resources = counts(
        db,
        "SELECT resource, count(*) FROM sessions WHERE started_at >= $1 AND resource IS NOT NULL
         GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 8",
        since,
    )
    .await?;
    let top_users = counts(
        db,
        "SELECT username, count(*) FROM sessions WHERE started_at >= $1 AND username IS NOT NULL AND actor_type = 'user'
         GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 8",
        since,
    )
    .await?;
    let bot_repos = counts(
        db,
        "SELECT COALESCE(ci->>'repository', ci->>'project_path', username), count(*) FROM sessions
         WHERE started_at >= $1 AND actor_type = 'bot' GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 8",
        since,
    )
    .await?;
    let denials = counts(
        db,
        "SELECT summary, count(*) FROM audit_events WHERE kind = 'auth.denied' AND at >= $1
         GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 6",
        since,
    )
    .await?;
    let actions = counts(
        db,
        "SELECT kind, count(*) FROM audit_events WHERE at >= $1 AND kind IN
         ('user.lock', 'user.unlock', 'session.kill', 'component.revoke', 'join_token.create', 'policy.change')
         GROUP BY 1 ORDER BY 2 DESC, 1",
        since,
    )
    .await?;
    let lengths = counts(
        db,
        "SELECT CASE WHEN duration_ms < 60000 THEN '0 under 1 min' WHEN duration_ms < 300000 THEN '1 1 to 5 min'
                     WHEN duration_ms < 1800000 THEN '2 5 to 30 min' WHEN duration_ms < 7200000 THEN '3 30 min to 2 h'
                     ELSE '4 over 2 h' END AS b, count(*)
         FROM sessions WHERE started_at >= $1 AND duration_ms IS NOT NULL GROUP BY 1 ORDER BY 1",
        since,
    )
    .await?
    .into_iter()
    .map(|(k, n)| (k.split_once(' ').map_or(k.clone(), |(_, t)| t.to_owned()), n))
    .collect::<Vec<_>>();

    let ranked = vec![
        RankPanel {
            title: "Busiest resources",
            sub: "Sessions",
            rows: rank(top_resources, |name| {
                Some(format!("/console/resources/{}", path_segment(name)))
            }),
            class: "bar-a",
        },
        RankPanel {
            title: "Most active people",
            sub: "Sessions",
            rows: rank(top_users, |name| {
                Some(format!("/console/users/{}", path_segment(name)))
            }),
            class: "bar-b",
        },
        RankPanel {
            title: "Bot sessions by repository",
            sub: "CI jobs, by the repository or project that ran them",
            rows: rank(bot_repos, |_| None),
            class: "bar-bot",
        },
        RankPanel {
            title: "Session length",
            sub: "Finished sessions",
            rows: rank(lengths, |_| None),
            class: "bar-c",
        },
        RankPanel {
            title: "Why access was denied",
            sub: "Denied attempts",
            rows: rank(denials, |_| None),
            class: "bar-bad",
        },
        RankPanel {
            title: "Admin actions",
            sub: "Locks, kills, revokes, tokens, policy",
            rows: rank(actions, |_| None),
            class: "bar-d",
        },
    ];
    Ok(ranked)
}

async fn build(
    state: &AppState,
    range: Range,
) -> Result<(Vec<Tile>, Vec<Panel>, Vec<RankPanel>), sqlx::Error> {
    let db = &state.db;
    let (starts, labels) = buckets(range);
    let since = starts.first().copied().unwrap_or_else(utc_now).assume_utc();
    let unit = range.unit();

    let TimeSeries {
        sessions,
        bot_sessions,
        logins,
        denied,
    } = time_series(db, unit, &starts, since).await?;

    let people: i64 =
        sqlx::query_scalar(
            "SELECT count(DISTINCT username) FROM sessions WHERE started_at >= $1 AND actor_type = 'user'",
        )
            .bind(since)
            .fetch_one(db)
            .await?;
    let average: Option<f64> = sqlx::query_scalar(
        "SELECT avg(duration_ms)::float8 FROM sessions WHERE started_at >= $1 AND duration_ms IS NOT NULL",
    )
    .bind(since)
    .fetch_one(db)
    .await?;

    let total_bot_sessions: i64 = bot_sessions.iter().sum();
    let total_sessions: i64 = sessions.iter().sum::<i64>() + total_bot_sessions;
    let total_denied: i64 = denied.iter().sum();
    let tiles = vec![
        Tile {
            value: total_sessions.to_string(),
            label: "Sessions",
            icon: "terminal",
            tone: "c-green",
        },
        Tile {
            value: people.to_string(),
            label: "People",
            icon: "users",
            tone: "c-blue",
        },
        Tile {
            value: total_bot_sessions.to_string(),
            label: "Bot sessions",
            icon: "bot",
            tone: "c-violet",
        },
        Tile {
            value: logins.iter().sum::<i64>().to_string(),
            label: "Sign-ins",
            icon: "key-round",
            tone: "c-teal",
        },
        Tile {
            value: total_denied.to_string(),
            label: "Denied",
            icon: "ban",
            tone: if total_denied > 0 { "bad" } else { "c-amber" },
        },
        Tile {
            value: average.map_or_else(|| "—".into(), duration_text),
            label: "Average session",
            icon: "clock",
            tone: "c-amber",
        },
    ];
    let panels = vec![
        Panel {
            title: "Sessions",
            sub: "Started per period",
            chart: bar_chart(
                &labels,
                &[
                    Series {
                        name: "people's sessions",
                        class: "bar-a",
                        values: sessions,
                    },
                    Series {
                        name: "bot sessions",
                        class: "bar-bot",
                        values: bot_sessions,
                    },
                ],
            ),
            legend: vec![("bar-a", "People"), ("bar-bot", "Bots")],
        },
        Panel {
            title: "Sign-ins and denials",
            sub: "Successful logins next to refused attempts",
            chart: bar_chart(
                &labels,
                &[
                    Series {
                        name: "sign-ins",
                        class: "bar-a",
                        values: logins,
                    },
                    Series {
                        name: "denied",
                        class: "bar-bad",
                        values: denied,
                    },
                ],
            ),
            legend: vec![("bar-a", "Sign-ins"), ("bar-bad", "Denied")],
        },
    ];
    let ranked = rankings(db, since).await?;
    Ok((tiles, panels, ranked))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nice_ceilings() {
        assert_eq!(nice_ceiling(0), 1);
        assert_eq!(nice_ceiling(1), 1);
        assert_eq!(nice_ceiling(3), 5);
        assert_eq!(nice_ceiling(11), 20);
        assert_eq!(nice_ceiling(51), 100);
        assert_eq!(nice_ceiling(100), 100);
    }

    #[test]
    fn bars_scale_and_stay_inside_the_plot() {
        let labels: Vec<String> = (0..24).map(|h| format!("{h:02}:00")).collect();
        let mut values = vec![0; 24];
        values[3] = 7;
        values[23] = 10;
        let c = bar_chart(
            &labels,
            &[Series {
                name: "sessions",
                class: "bar-a",
                values,
            }],
        );
        assert!(!c.empty);
        let tall = c
            .bars
            .iter()
            .find(|b| b.tip.starts_with("23:00"))
            .expect("bar");
        assert_eq!(tall.y, TOP, "the peak reaches the top of the plot");
        assert!(
            c.bars.iter().all(|b| b.x >= LEFT
                && b.x + b.w <= W - RIGHT
                && b.y >= TOP
                && b.y + b.h <= c.base)
        );
        assert!(c.xlabels.len() <= 7);
    }

    #[test]
    fn an_empty_period_is_flagged() {
        let c = bar_chart(
            &["a".into()],
            &[Series {
                name: "x",
                class: "bar-a",
                values: vec![0],
            }],
        );
        assert!(c.empty);
        assert!(c.bars.iter().all(|b| b.h == 0));
    }

    #[test]
    fn ranked_bars_are_relative_to_the_largest() {
        let r = rank(vec![("a".into(), 10), ("b".into(), 5)], |_| None);
        assert_eq!((r[0].pct, r[1].pct), (100, 50));
    }

    #[test]
    fn buckets_end_now_and_have_the_right_count() {
        let (starts, labels) = buckets(Range::Week);
        assert_eq!((starts.len(), labels.len()), (7, 7));
        assert_eq!(starts[6], truncate(utc_now(), "day"));
    }
}
