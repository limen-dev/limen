//! Template structs and the view models they render. Every string a page
//! shows goes through askama's HTML escaping; nothing is built with `format!`
//! into markup.

use askama::Template;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use time::OffsetDateTime;

use super::store::{SessionRow, UserRow};
use super::{Auth, html};

/// Page chrome: who is signed in, and the navigation state.
#[allow(clippy::struct_excessive_bools)] // independent flags, not a state machine
pub struct Chrome {
    pub username: String,
    pub initial: String,
    pub avatar: String,
    pub is_admin: bool,
    pub is_auditor: bool,
    /// Admin or auditor: sees the audit record.
    pub reads_record: bool,
    pub sees_access: bool,
    pub sees_reviews: bool,
    pub sees_changes: bool,
    pub csrf: String,
    pub active: &'static str,
    pub version: &'static str,
    pub assets: &'static str,
    pub policy_version: i64,
}

impl Chrome {
    #[must_use]
    pub fn new(auth: &Auth, active: &'static str, policy_version: i64) -> Self {
        Self {
            initial: auth
                .username
                .chars()
                .next()
                .map_or_else(|| "?".to_owned(), |c| c.to_uppercase().collect()),
            avatar: avatar_class(&auth.username),
            username: auth.username.clone(),
            is_admin: auth.is_admin,
            is_auditor: auth.is_auditor,
            reads_record: auth.reads_record(),
            sees_access: auth.sees_access,
            sees_reviews: auth.sees_reviews,
            sees_changes: auth.sees_changes,
            csrf: auth.csrf.clone(),
            active,
            version: limen_core::VERSION,
            assets: super::assets::version(),
            policy_version,
        }
    }
}

// ---- colour and icons ----------------------------------------------------------

fn hash_byte(s: &str) -> u8 {
    s.bytes()
        .fold(0u8, |h, b| h.wrapping_mul(31).wrapping_add(b))
}

/// A stable colour slot (0 to 5) for a role or group name.
#[must_use]
pub fn chip_color(s: &str) -> u8 {
    hash_byte(s) % 6
}

/// A stable avatar gradient class for a user name.
#[must_use]
pub fn avatar_class(s: &str) -> String {
    format!("av-{}", hash_byte(s) % 8)
}

/// Icon symbol and colour class for a resource kind.
#[must_use]
pub fn kind_icon(kind: &str) -> (&'static str, &'static str) {
    match kind {
        "ssh" => ("terminal", "k-ssh"),
        "postgres" | "postgresql" => ("k-postgres", "k-postgres"),
        "mysql" => ("k-mysql", "k-mysql"),
        "redis" => ("k-redis", "k-redis"),
        "kubernetes" | "kube" | "kubectl" => ("k-kubernetes", "k-kubernetes"),
        "redshift" => ("warehouse", "k-redshift"),
        "mongodb" => ("k-mongodb", "k-mongodb"),
        "opensearch" => ("k-opensearch", "k-opensearch"),
        "elasticsearch" => ("k-elasticsearch", "k-elasticsearch"),
        "rabbitmq" => ("k-rabbitmq", "k-rabbitmq"),
        "kafka" => ("k-kafka", "k-kafka"),
        "web" => ("globe", "k-web"),
        "tcp" => ("network", "k-tcp"),
        _ => ("database", "k-other"),
    }
}

/// A group of audit event kinds, shown as a tab and as the icon beside each event.
pub struct Category {
    pub label: &'static str,
    pub icon: &'static str,
    pub kclass: &'static str,
    /// Comma-separated kinds and `prefix.*` patterns, as the `kind` filter takes them.
    pub kinds: &'static str,
}

pub const CATEGORIES: [Category; 10] = [
    Category {
        label: "Sign-ins",
        icon: "key-round",
        kclass: "k-auth",
        kinds: "auth.*",
    },
    Category {
        label: "Sessions",
        icon: "terminal",
        kclass: "k-ssh",
        kinds: "session.*,ssh.*",
    },
    Category {
        label: "SQL",
        icon: "k-postgres",
        kclass: "k-postgres",
        kinds: "db.*",
    },
    Category {
        label: "MongoDB",
        icon: "k-mongodb",
        kclass: "k-mongodb",
        kinds: "mongo.*",
    },
    Category {
        label: "Redis",
        icon: "k-redis",
        kclass: "k-redis",
        kinds: "redis.*",
    },
    Category {
        label: "Search",
        icon: "k-opensearch",
        kclass: "k-opensearch",
        kinds: "search.*",
    },
    Category {
        label: "Messaging",
        icon: "k-kafka",
        kclass: "k-kafka",
        kinds: "kafka.*,mq.*",
    },
    Category {
        label: "Web",
        icon: "globe",
        kclass: "k-web",
        kinds: "web.*",
    },
    Category {
        label: "Kubernetes",
        icon: "k-kubernetes",
        kclass: "k-kubernetes",
        kinds: "kube.*",
    },
    Category {
        label: "Admin",
        icon: "shield-check",
        kclass: "k-admin",
        kinds: "policy.*,component.*,join_token.*,worker.*,user.*",
    },
];

/// The category an event kind belongs to.
#[must_use]
pub fn category_of(kind: &str) -> Option<&'static Category> {
    CATEGORIES.iter().find(|c| {
        c.kinds.split(',').any(|p| match p.strip_suffix('*') {
            Some(prefix) => kind.starts_with(prefix),
            None => kind == p,
        })
    })
}

/// One tab of the audit trail's category bar.
pub struct CategoryTab {
    pub label: &'static str,
    pub icon: &'static str,
    pub kclass: &'static str,
    pub href: String,
    pub active: bool,
}

/// How to open a resource: the command, and the phase that delivers it while
/// only the data side exists.
pub struct Connect {
    pub command: String,
    /// `Some("Phase 7")` and so on until the kind is served.
    pub planned: Option<&'static str>,
}

#[must_use]
pub fn connect_for(kind: &str, name: &str) -> Connect {
    let access = limen_core::resource::ResourceKind::parse(kind)
        .map(limen_core::resource::ResourceKind::access);
    match access {
        Some(a) => Connect {
            command: a.command.replace("{name}", name),
            planned: a.planned,
        },
        None => Connect {
            command: String::new(),
            planned: Some("planned"),
        },
    }
}

/// A role or group shown as a coloured chip.
pub struct Chip {
    pub text: String,
    pub c: u8,
}

fn chips(items: &[String]) -> Vec<Chip> {
    items
        .iter()
        .map(|t| Chip {
            text: t.clone(),
            c: chip_color(t),
        })
        .collect()
}

// ---- formatting ----------------------------------------------------------------

#[must_use]
pub fn time_text(t: Option<OffsetDateTime>) -> String {
    t.map_or_else(
        || "—".into(),
        |t| {
            let t = t.to_offset(time::UtcOffset::UTC);
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                t.year(),
                u8::from(t.month()),
                t.day(),
                t.hour(),
                t.minute(),
                t.second()
            )
        },
    )
}

#[must_use]
pub fn duration_text(ms: Option<i64>) -> String {
    let Some(ms) = ms.filter(|m| *m >= 0) else {
        return "—".into();
    };
    let secs = ms / 1000;
    match (secs / 3600, (secs % 3600) / 60, secs % 60) {
        (0, 0, _) if ms < 1000 => format!("{ms} ms"),
        (0, 0, s) => format!("{s}s"),
        (0, m, s) => format!("{m}m {s}s"),
        (h, m, _) => format!("{h}h {m}m"),
    }
}

#[must_use]
pub fn bytes_text(n: i64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let f = n as f64;
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KiB", f / 1024.0)
    } else {
        format!("{:.1} MiB", f / (1024.0 * 1024.0))
    }
}

#[must_use]
pub fn list_text(items: &[String]) -> String {
    if items.is_empty() {
        "—".into()
    } else {
        items.join(", ")
    }
}

fn dash(s: Option<&str>) -> String {
    s.filter(|s| !s.is_empty())
        .map_or_else(|| "—".into(), str::to_owned)
}

/// A user name as one URL path segment.
#[must_use]
pub fn path_segment(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

// ---- sessions --------------------------------------------------------------------

#[allow(clippy::struct_excessive_bools)]
pub struct SessionView {
    pub id: String,
    pub user: String,
    pub user_path: String,
    pub kind: String,
    pub icon: &'static str,
    pub kclass: &'static str,
    pub resource: String,
    pub login: String,
    pub started: String,
    pub ended: String,
    pub duration: String,
    /// More than one: the connections a driver opened in one run.
    pub connections: i64,
    pub status: &'static str,
    pub status_class: &'static str,
    pub reason: String,
    pub active: bool,
    pub has_recording: bool,
    /// A Redis or Valkey session: no recording, but audited commands.
    pub is_redis: bool,
    /// A MongoDB session: no recording, but audited commands.
    pub is_mongo: bool,
    /// An `OpenSearch` or Elasticsearch session: no recording, but audited requests.
    pub is_search: bool,
    /// A browser web request: no recording, but an audited request/response.
    pub is_web: bool,
    /// A `RabbitMQ` or Kafka session: no recording, but audited operations.
    pub is_broker: bool,
    /// Any of those: the page lists what was sent instead of a recording.
    pub has_statements: bool,
    /// One login's kubectl requests on a cluster: the page lists them.
    pub is_kubectl: bool,
    pub recording_sha256: String,
    pub recording_note: &'static str,
    pub bytes: String,
    pub client_addr: String,
    pub proxy: String,
    pub worker: String,
    pub bot: bool,
    pub ci: Vec<Fact>,
    pub run_url: Option<String>,
}

impl From<&SessionRow> for SessionView {
    fn from(s: &SessionRow) -> Self {
        // A login ended by `limen logout` ends its kubectl session at once.
        let (status, status_class) = if s.active {
            ("active", "live")
        } else if s.ended_at.is_some() {
            ("ended", "")
        } else {
            ("unknown", "warn")
        };
        let has_recording = s.recording_uri.is_some() && s.recording_sha256.is_some();
        Self {
            id: s.session_id.to_string(),
            user: dash(s.username.as_deref()),
            user_path: path_segment(s.username.as_deref().unwrap_or_default()),
            kind: dash(s.kind.as_deref()),
            icon: kind_icon(s.kind.as_deref().unwrap_or_default()).0,
            kclass: kind_icon(s.kind.as_deref().unwrap_or_default()).1,
            resource: dash(s.resource.as_deref()),
            login: dash(s.login.as_deref()),
            started: time_text(s.started_at),
            ended: time_text(s.logged_out_at.or(s.ended_at)),
            duration: duration_text(s.duration_ms),
            connections: s.connections,
            status,
            status_class,
            // "ended" says nothing the status doesn't.
            reason: if s.active {
                String::new()
            } else if s.logged_out_at.is_some() {
                "logged out".to_owned()
            } else {
                s.end_reason
                    .clone()
                    .filter(|r| r != "ended")
                    .unwrap_or_default()
            },
            active: s.active,
            has_recording,
            is_redis: s.kind.as_deref() == Some("redis"),
            is_kubectl: s.kind.as_deref() == Some("kubectl"),
            is_mongo: s.kind.as_deref() == Some("mongodb"),
            is_search: matches!(s.kind.as_deref(), Some("opensearch" | "elasticsearch")),
            is_web: s.kind.as_deref() == Some("web"),
            is_broker: matches!(s.kind.as_deref(), Some("rabbitmq" | "kafka")),
            has_statements: matches!(
                s.kind.as_deref(),
                Some(
                    "postgres"
                        | "mysql"
                        | "redshift"
                        | "redis"
                        | "mongodb"
                        | "opensearch"
                        | "elasticsearch"
                        | "rabbitmq"
                        | "kafka"
                )
            ),
            recording_sha256: s.recording_sha256.clone().unwrap_or_default(),
            recording_note: if s.active {
                "The recording is uploaded when the session ends."
            } else if s.recording_sha256.is_some() {
                "The recording was made but hasn't reached the control plane yet. Check again shortly."
            } else if matches!(s.kind.as_deref(), Some("postgres" | "mysql" | "redshift")) {
                "Database sessions have no terminal recording. Every statement is in the audit trail as db.query events that carry this session id (in S3 and Datadog)."
            } else if s.kind.as_deref() == Some("mongodb") {
                "MongoDB sessions have no terminal recording. Every command is in the audit trail as mongo.command events that carry this session id (in S3 and Datadog)."
            } else if s.kind.as_deref() == Some("redis") {
                "Redis sessions have no terminal recording. Every command is in the audit trail as redis.command events that carry this session id (in S3 and Datadog)."
            } else if matches!(s.kind.as_deref(), Some("opensearch" | "elasticsearch")) {
                "Search sessions have no terminal recording. Every request is in the audit trail as search.request and search.response events that carry this session id (in S3 and Datadog)."
            } else if matches!(s.kind.as_deref(), Some("rabbitmq" | "kafka")) {
                "RabbitMQ and Kafka sessions have no terminal recording. Every operation is in the audit trail as mq.operation or kafka.request events that carry this session id (in S3 and Datadog). Message content is never recorded."
            } else if s.kind.as_deref() == Some("web") {
                "Web requests have no recording. The audited request and response metadata are shown below; query strings, headers, and bodies are never kept."
            } else {
                "This session wasn't recorded."
            },
            bytes: match (s.bytes_in, s.bytes_out) {
                (Some(i), Some(o)) => format!("{} in, {} out", bytes_text(i), bytes_text(o)),
                _ => "—".into(),
            },
            client_addr: dash(s.client_addr.as_deref()),
            proxy: dash(s.proxy_id.as_deref()),
            worker: dash(s.worker_id.as_deref()),
            bot: s.actor_type == "bot",
            ci: ci_facts(s.ci.as_ref()),
            run_url: run_url(s.ci.as_ref()),
        }
    }
}

// ---- bots (ADR-0019) -----------------------------------------------------------------

/// One fact about a bot's CI run, ready to show.
pub struct Fact {
    pub key: String,
    pub value: String,
}

/// The facts of a CI run in a readable order: where it ran, what ran, who
/// triggered it. Values are text from a signed token; templates escape them.
#[must_use]
pub fn ci_facts(ci: Option<&serde_json::Value>) -> Vec<Fact> {
    const ORDER: [&str; 14] = [
        "provider",
        "repository",
        "project_path",
        "ref",
        "environment",
        "workflow",
        "job_workflow_ref",
        "run_id",
        "run_attempt",
        "pipeline_id",
        "job_id",
        "sha",
        "actor",
        "user_login",
    ];
    let Some(map) = ci.and_then(serde_json::Value::as_object) else {
        return Vec::new();
    };
    let show = |k: &str, v: &serde_json::Value| {
        let text = v.as_str()?;
        let text = if k == "sha" {
            text.chars().take(12).collect()
        } else {
            text.to_owned()
        };
        Some(Fact {
            key: k.to_owned(),
            value: text,
        })
    };
    let mut out: Vec<Fact> = ORDER
        .iter()
        .filter_map(|k| map.get(*k).and_then(|v| show(k, v)))
        .collect();
    out.extend(
        map.iter()
            .filter(|(k, _)| !ORDER.contains(&k.as_str()) && !matches!(k.as_str(), "iss" | "sub"))
            .filter_map(|(k, v)| show(k, v)),
    );
    out
}

/// A link to the CI run, when the provider has a stable address for one and
/// every piece of it is plain. Anything unusual yields no link.
#[must_use]
pub fn run_url(ci: Option<&serde_json::Value>) -> Option<String> {
    let map = ci?.as_object()?;
    let get = |k: &str| map.get(k)?.as_str();
    let plain = |s: &str, slash: bool| {
        !s.is_empty()
            && s.len() <= 200
            && s.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.') || (slash && b == b'/')
            })
    };
    match get("provider")? {
        "github_actions" => {
            let (repo, run) = (get("repository")?, get("run_id")?);
            (plain(repo, true) && run.bytes().all(|b| b.is_ascii_digit()) && !run.is_empty())
                .then(|| format!("https://github.com/{repo}/actions/runs/{run}"))
        }
        "gitlab" => {
            let (base, project, pipeline) =
                (get("iss")?, get("project_path")?, get("pipeline_id")?);
            (base.starts_with("https://")
                && !base.contains(['?', '#', '@', ' '])
                && plain(project, true)
                && !pipeline.is_empty()
                && pipeline.bytes().all(|b| b.is_ascii_digit()))
            .then(|| {
                format!(
                    "{}/{project}/-/pipelines/{pipeline}",
                    base.trim_end_matches('/')
                )
            })
        }
        _ => None,
    }
}

// ---- users --------------------------------------------------------------------------

pub struct UserView {
    pub name: String,
    pub path: String,
    pub role_list: Vec<Chip>,
    pub group_list: Vec<Chip>,
    pub av: String,
    pub initial: String,
    pub first_login: String,
    pub last_login: String,
    pub logins: i64,
    pub locked: bool,
    pub lock_reason: String,
    pub locked_by: String,
    pub locked_at: String,
    pub is_bot: bool,
    pub ci: Vec<Fact>,
    pub run_url: Option<String>,
}

impl From<&UserRow> for UserView {
    fn from(u: &UserRow) -> Self {
        Self {
            name: u.username.clone(),
            path: path_segment(&u.username),
            role_list: chips(&u.roles),
            group_list: chips(&u.groups),
            av: avatar_class(&u.username),
            initial: u
                .username
                .chars()
                .next()
                .map_or_else(|| "?".to_owned(), |c| c.to_uppercase().collect()),
            first_login: time_text(Some(u.first_login_at)),
            last_login: time_text(Some(u.last_login_at)),
            logins: u.login_count,
            locked: u.lock_reason.is_some(),
            lock_reason: u.lock_reason.clone().unwrap_or_default(),
            locked_by: u.locked_by.clone().unwrap_or_default(),
            locked_at: time_text(u.locked_at),
            is_bot: u.actor_type == "bot",
            ci: ci_facts(u.last_ci.as_ref()),
            run_url: run_url(u.last_ci.as_ref()),
        }
    }
}

// ---- pages -----------------------------------------------------------------------------

pub struct Stats {
    pub active_sessions: i64,
    pub users: usize,
    pub locked: usize,
    pub workers_up: usize,
}

pub struct ResourceView {
    pub name: String,
    pub connect: Connect,
    pub kind: String,
    pub icon: &'static str,
    pub kclass: &'static str,
    pub labels: Vec<String>,
    pub principals: Vec<String>,
}

#[derive(Template)]
#[template(path = "home.html")]
pub struct Home {
    pub chrome: Chrome,
    pub notice: Option<&'static str>,
    pub stats: Stats,
    pub resources: Vec<ResourceView>,
    pub sessions: Vec<SessionView>,
    pub roles_text: String,
    pub expires: String,
}

#[derive(Template)]
#[template(path = "sessions.html")]
pub struct SessionsPage {
    pub chrome: Chrome,
    pub notice: Option<&'static str>,
    pub sessions: Vec<SessionView>,
    pub active_only: bool,
    pub user_filter: Option<String>,
    pub filter: SessionFilterView,
    pub chips: Vec<FilterChip>,
    pub presets: Vec<Preset>,
    pub suggest: Suggestions,
    pub more_open: bool,
    pub clear: String,
    pub problems: Vec<String>,
    pub newer: Option<String>,
    pub older: Option<String>,
}

/// The values to put back in the sessions filter form.
#[derive(Default)]
pub struct SessionFilterView {
    pub user: String,
    pub resource: String,
    pub kind: String,
    pub actor: String,
    pub login: String,
    pub addr: String,
    pub end: String,
    pub repo: String,
    pub from: String,
    pub to: String,
}

#[derive(Template)]
#[template(path = "session.html")]
pub struct SessionPage {
    pub chrome: Chrome,
    pub s: SessionView,
    /// Seconds into the recording to start at (a search hit's moment).
    pub start_at: i64,
    /// The access requests whose grants allowed this session (ADR-0025).
    pub allowed_by: Vec<String>,
    /// Who watched it live, and when (ADR-0030).
    pub watched: Vec<(String, String, String)>,
    pub can_watch: bool,
    /// Database sessions: the statements sent, oldest first.
    pub statements: Vec<StatementView>,
    /// kubectl sessions: the API requests, oldest first.
    pub requests: Vec<KubeView>,
    pub request_total: i64,
    pub request_problems: i64,
    /// Browser web requests, oldest first.
    pub web_requests: Vec<WebRequestView>,
    pub web_request_total: i64,
    pub web_request_problems: i64,
    pub statement_total: i64,
    pub statement_errors: i64,
}

pub struct WebRequestView {
    pub time: String,
    pub method: String,
    pub path: String,
    pub status: String,
    pub status_class: &'static str,
    pub traffic: String,
    pub latency: String,
    pub outcome: String,
}

impl From<&super::store::WebRequestRow> for WebRequestView {
    fn from(request: &super::store::WebRequestRow) -> Self {
        let status = request
            .status
            .map_or_else(|| "in flight".into(), |status| status.to_string());
        let status_class = match request.status {
            Some(200..=399) => "ok",
            Some(400..) => "bad",
            _ => "warn",
        };
        let traffic = match (request.bytes_in, request.bytes_out) {
            (Some(bytes_in), Some(bytes_out)) => {
                format!("{} in, {} out", bytes_text(bytes_in), bytes_text(bytes_out))
            }
            _ => "—".into(),
        };
        Self {
            time: time_text(Some(request.at)),
            method: request.method.clone(),
            path: request.path.clone(),
            status,
            status_class,
            traffic,
            latency: request
                .duration_ms
                .map_or_else(|| "—".into(), |ms| format!("{ms} ms")),
            outcome: request.outcome.clone().unwrap_or_default(),
        }
    }
}

/// One statement of a database session, ready to show.
#[derive(Debug)]
pub struct StatementView {
    pub time: String,
    pub kind: String,
    pub text: String,
    pub outcome: String,
    pub outcome_class: &'static str,
    pub detail: String,
}

impl From<&super::store::DbStatementRow> for StatementView {
    fn from(r: &super::store::DbStatementRow) -> Self {
        let failed = matches!(r.status.as_deref(), Some("error" | "denied"));
        let outcome = match r.status.as_deref() {
            Some("ok") => "ok",
            // Redis: policy allowed it and the audit event was written before it
            // was forwarded. ("sent" is what earlier versions stored.)
            Some("allowed" | "sent") => "allowed",
            // MongoDB: the client asked for no answer (`w: 0`).
            Some("unacknowledged") => "sent, no reply",
            Some("denied") => "refused",
            Some("error") => "error",
            Some(_) => "not completed",
            None => "…",
        };
        let mut detail = Vec::new();
        if let Some(n) = r.rows {
            detail.push(format!("{n} row{}", if n == 1 { "" } else { "s" }));
        }
        if let Some(ms) = r.duration_ms {
            detail.push(format!("{ms} ms"));
        }
        if failed {
            detail.push(
                [r.error_code.as_deref(), r.error.as_deref()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(": "),
            );
        }
        let kind = r.statement_type.clone().unwrap_or_default();
        Self {
            time: time_text(Some(r.at)),
            text: match (&r.statement, r.phase.as_deref()) {
                (Some(t), _) if r.truncated => format!("{t} … (cut)"),
                (Some(t), _) => t.clone(),
                (None, Some("execute")) => "(prepared statement; see its parse)".to_owned(),
                (None, _) => String::new(),
            },
            kind: match r.phase.as_deref() {
                Some("parse") => format!("{kind} (prepare)"),
                Some("execute") => format!("{kind} (run)"),
                _ => kind,
            },
            outcome: outcome.to_owned(),
            outcome_class: match r.status.as_deref() {
                Some("ok" | "allowed" | "sent" | "unacknowledged") => "ok",
                Some("error" | "denied") => "bad",
                _ => "warn",
            },
            detail: detail.join(" · "),
        }
    }
}

/// One bot from policy, with what the control plane has seen of it.
pub struct BotView {
    pub av: String,
    pub name: String,
    pub path: String,
    pub description: String,
    pub method: &'static str,
    pub issuer: String,
    pub rules: Vec<Fact>,
    pub roles: Vec<Chip>,
    pub ttl: String,
    pub seen: bool,
    pub last_login: String,
    pub logins: i64,
    pub sessions: i64,
    pub locked: bool,
    pub lock_reason: String,
    pub last_run: Vec<Fact>,
    pub run_url: Option<String>,
}

#[derive(Template)]
#[template(path = "bots.html")]
pub struct BotsPage {
    pub chrome: Chrome,
    pub notice: Option<&'static str>,
    pub query: String,
    pub bots: Vec<BotView>,
}

#[derive(Template)]
#[template(path = "users.html")]
pub struct UsersPage {
    pub chrome: Chrome,
    pub notice: Option<&'static str>,
    pub users: Vec<UserView>,
    pub query: String,
    pub orphan_locks: Vec<UserView>,
}

#[derive(Template)]
#[template(path = "user.html")]
pub struct UserPage {
    pub chrome: Chrome,
    pub notice: Option<&'static str>,
    pub u: UserView,
    /// What the user's roles reach under the active policy.
    pub access: Vec<ResourceView>,
    pub policy_version: i64,
    pub sessions: Vec<SessionView>,
    pub events: Vec<EventView>,
}

pub struct ComponentView {
    pub id: String,
    /// Display name approved at enrollment, if any.
    pub name: Option<String>,
    /// For a worker: the proxies holding its tunnels (names, else ids).
    pub tunnel_peers: String,
    pub path: String,
    pub kind: String,
    pub label_list: Vec<String>,
    pub icon: &'static str,
    pub kclass: &'static str,
    pub last_seen: String,
    pub tunnels: usize,
    pub cert_expires: String,
    pub revoked: bool,
}

impl ComponentView {
    /// The day and the clock time of a "2026-10-25 09:27:38 UTC" text, for a two-line cell.
    pub fn last_seen_day(&self) -> &str {
        split_when(&self.last_seen).0
    }
    pub fn last_seen_clock(&self) -> &str {
        split_when(&self.last_seen).1
    }
    pub fn cert_day(&self) -> &str {
        split_when(&self.cert_expires).0
    }
    pub fn cert_clock(&self) -> &str {
        split_when(&self.cert_expires).1
    }
}

fn split_when(t: &str) -> (&str, &str) {
    t.split_once(' ').unwrap_or((t, ""))
}

pub struct PendingTokenView {
    pub kind: String,
    /// The name or pattern it approves, if any.
    pub name: Option<String>,
    pub kclass: &'static str,
    pub icon: &'static str,
    pub label_list: Vec<String>,
    pub created_by: String,
    pub expires: String,
}

#[derive(Template)]
#[template(path = "workers.html")]
pub struct Workers {
    pub chrome: Chrome,
    pub notice: Option<&'static str>,
    pub query: String,
    pub components: Vec<ComponentView>,
    pub pending: Vec<PendingTokenView>,
}

pub struct EventView {
    pub at: String,
    pub icon: &'static str,
    pub kclass: &'static str,
    pub kind: String,
    pub tone: &'static str,
    pub user: Option<String>,
    pub user_path: Option<String>,
    pub session_path: Option<String>,
    pub summary: String,
}

#[derive(Template)]
#[template(path = "audit.html")]
pub struct AuditPage {
    pub chrome: Chrome,
    /// The search box, and its results when something was searched for.
    pub q: String,
    pub search: Option<SearchView>,
    pub events: Vec<EventView>,
    pub kinds: Vec<String>,
    pub tabs: Vec<CategoryTab>,
    pub groups: &'static [Category],
    pub filter: AuditFilterView,
    pub chips: Vec<FilterChip>,
    pub presets: Vec<Preset>,
    pub suggest: Suggestions,
    pub more_open: bool,
    pub clear: String,
    pub problems: Vec<String>,
    pub newer: Option<String>,
    pub older: Option<String>,
}

/// One hit of an audit search: the match marked, and where to go next.
pub struct HitView {
    pub at: String,
    pub kind: String,
    pub user: String,
    pub resource: String,
    pub denied: bool,
    pub before: String,
    pub hit: String,
    pub after: String,
    /// The session page, at the moment of the hit when it has a recording.
    pub href: Option<String>,
    pub moment: Option<String>,
}

pub struct SearchView {
    pub error: Option<String>,
    pub hits: Vec<HitView>,
    pub truncated: bool,
    pub history_url: Option<String>,
}

/// The values to put back in the audit filter form.
#[derive(Default)]
pub struct AuditFilterView {
    pub kind: String,
    pub user: String,
    pub actor: String,
    pub text: String,
    pub session: String,
    pub from: String,
    pub to: String,
}

/// A quick time range: a link that applies it and keeps the other filters.
pub struct Preset {
    pub label: &'static str,
    pub href: String,
    pub active: bool,
}

/// Names to offer while typing in the filter boxes.
#[derive(Debug, Default)]
pub struct Suggestions {
    pub users: Vec<String>,
    pub resources: Vec<String>,
    pub kinds: Vec<String>,
    pub ends: Vec<String>,
}

/// An applied filter, with the link that removes just that one.
pub struct FilterChip {
    pub label: String,
    pub remove: String,
}

/// One Kubernetes API request, in kubectl's terms.
pub struct KubeView {
    pub at: String,
    pub user: Option<String>,
    pub user_path: Option<String>,
    /// The kubectl session (one login on one cluster) that lists the request.
    pub session_path: Option<String>,
    /// For exec, attach, and port-forward: the stream's own session, which has the recording.
    pub stream_path: Option<String>,
    pub cluster: String,
    pub verb: String,
    /// `pods`, `pods/exec`, `deployments.apps`.
    pub resource: String,
    pub namespace: String,
    pub name: String,
    pub status: i32,
    /// `ok` below 400, `bad` from 400 up.
    pub tone: &'static str,
    pub latency: String,
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "kube_requests.html")]
pub struct KubePage {
    pub chrome: Chrome,
    pub tabs: Vec<CategoryTab>,
    pub requests: Vec<KubeView>,
    pub clusters: Vec<String>,
    pub verbs: Vec<String>,
    pub cluster_filter: Option<String>,
    pub verb_filter: Option<String>,
    pub user_filter: Option<String>,
    pub namespace_filter: Option<String>,
    pub problems_only: bool,
    pub newer: Option<String>,
    pub older: Option<String>,
}

#[derive(Template)]
#[template(path = "token.html")]
pub struct TokenPage {
    pub chrome: Chrome,
    pub token: String,
    pub kind: String,
    pub expires: String,
}

pub struct PolicyDoc {
    pub kind: &'static str,
    pub name: String,
    pub summary: String,
    pub yaml: String,
    /// Who manages it, in words.
    pub owner: String,
    /// The console manages it, so it can be edited here.
    pub editable: bool,
    pub etag: String,
}

pub struct PolicyGroup {
    pub title: &'static str,
    pub docs: Vec<PolicyDoc>,
}

pub struct WhoRow {
    pub role: Chip,
    pub how: &'static str,
    pub principals: String,
    pub who: String,
    pub approvers: String,
}

/// What a group or bot can reach, for the access simulator.
pub struct Simulation {
    pub who: String,
    pub error: Option<String>,
    pub standing: Vec<(String, String, String)>,
    pub requestable: Vec<(String, String, String)>,
}

pub struct DryRun {
    /// Who gains or loses access, one line each (ADR-0028).
    pub access: Vec<(bool, String)>,
    pub warnings: Vec<String>,
    /// `(passed, line)` for each `policy_test` case in the pasted policy.
    pub tests: Vec<(bool, String)>,
    pub error: Option<String>,
    pub no_changes: bool,
    pub added: Vec<String>,
    pub changed: Vec<String>,
    pub removed: Vec<String>,
}

#[derive(Template)]
#[template(path = "policy.html")]
pub struct PolicyPage {
    pub chrome: Chrome,
    pub version: i64,
    pub digest: String,
    pub author: String,
    pub created: String,
    pub groups: Vec<PolicyGroup>,
    pub query: String,
    pub pasted: String,
    pub result: Option<DryRun>,
    pub simulation: Option<Simulation>,
    pub draft: String,
    pub error: Option<String>,
    pub notice: Option<String>,
}

pub struct RoleAccess {
    pub chip: Chip,
}

pub struct WorkerMatch {
    pub id: String,
    pub name: Option<String>,
    pub tunnels: usize,
    pub last_seen: String,
}

pub struct KindTab {
    pub href: String,
    pub name: String,
    pub icon: &'static str,
    pub kclass: &'static str,
    pub current: bool,
}

/// A `key=value` label that links to the resources page filtered by it.
pub struct LabelLink {
    pub text: String,
    pub href: String,
}

pub struct ResourceRow {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub icon: &'static str,
    pub kclass: &'static str,
    pub labels: Vec<String>,
    pub principals: Vec<String>,
    pub roles: Vec<RoleAccess>,
    pub target: String,
    pub workers: usize,
    pub sessions: i64,
    pub active: i64,
}

#[derive(Template)]
#[template(path = "resources.html")]
pub struct ResourcesPage {
    pub chrome: Chrome,
    pub kinds: Vec<KindTab>,
    pub all_selected: bool,
    pub all_href: String,
    pub active_labels: Vec<LabelLink>,
    pub clear_href: String,
    pub kind_value: String,
    pub label_values: Vec<String>,
    pub query: String,
    pub rows: Vec<(ResourceRow, Vec<LabelLink>)>,
}

#[derive(Template)]
#[template(path = "resource.html")]
pub struct ResourcePage {
    pub chrome: Chrome,
    /// The viewer can ask for this resource (ADR-0025).
    pub can_request: bool,
    /// Who can reach it, for admins and auditors (ADR-0028).
    pub who_can: Vec<WhoRow>,
    pub connect: Connect,
    pub name: String,
    pub kind: String,
    pub icon: &'static str,
    pub kclass: &'static str,
    pub labels: Vec<String>,
    pub selector: Vec<String>,
    pub target: String,
    pub pinned: bool,
    pub description: String,
    pub principals: Vec<String>,
    pub workers: Vec<WorkerMatch>,
    pub sessions: Vec<SessionView>,
}

#[derive(Template)]
#[template(path = "signout.html")]
pub struct SignoutPage {
    pub chrome: Chrome,
}

#[derive(Template)]
#[template(path = "signin.html")]
pub struct SigninPage {
    pub assets: &'static str,
    pub version: &'static str,
}

#[derive(Template)]
#[template(path = "message.html")]
struct MessagePage<'a> {
    title: &'a str,
    message: &'a str,
    assets: &'static str,
}

/// A plain page with a status code, for errors and confirmations. It has no
/// navigation, so it is safe to show without a session.
#[must_use]
pub fn error_page(status: StatusCode, title: &str, message: &str) -> Response {
    let mut response = html(
        MessagePage {
            title,
            message,
            assets: super::assets::version(),
        }
        .render(),
    );
    if response.status() == StatusCode::OK {
        *response.status_mut() = status;
    }
    response.into_response()
}

#[cfg(test)]
mod bot_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn facts_come_in_a_readable_order_and_hide_token_plumbing() {
        let ci = json!({
            "run_id": "42", "repository": "acme/infra", "provider": "github_actions",
            "sha": "0123456789abcdef0123456789", "sub": "repo:x", "iss": "https://i", "zzz": "last",
            "nested": { "a": 1 },
        });
        let keys: Vec<String> = ci_facts(Some(&ci)).into_iter().map(|f| f.key).collect();
        assert_eq!(keys, ["provider", "repository", "run_id", "sha", "zzz"]);
        let sha = ci_facts(Some(&ci))
            .into_iter()
            .find(|f| f.key == "sha")
            .expect("sha");
        assert_eq!(sha.value, "0123456789ab", "shortened");
        assert!(ci_facts(None).is_empty());
    }

    #[test]
    fn run_links_exist_only_when_every_piece_is_plain() {
        let github = |repo: &str, run: &str| {
            run_url(Some(
                &json!({ "provider": "github_actions", "repository": repo, "run_id": run }),
            ))
        };
        assert_eq!(
            github("acme/infra", "424242").as_deref(),
            Some("https://github.com/acme/infra/actions/runs/424242")
        );
        for (repo, run) in [
            ("acme/infra?x=1", "1"),
            ("acme/infra#frag", "1"),
            ("acme infra", "1"),
            ("acme/infra", "1/../../x"),
            ("acme/infra", ""),
            ("", "1"),
        ] {
            assert_eq!(github(repo, run), None, "{repo} {run}");
        }
        let gitlab = |iss: &str, project: &str, pipeline: &str| {
            run_url(Some(
                &json!({ "provider": "gitlab", "iss": iss, "project_path": project, "pipeline_id": pipeline }),
            ))
        };
        assert_eq!(
            gitlab("https://gitlab.com", "acme/reports", "7").as_deref(),
            Some("https://gitlab.com/acme/reports/-/pipelines/7")
        );
        assert_eq!(
            gitlab("http://gitlab.internal", "acme/r", "7"),
            None,
            "https only"
        );
        assert_eq!(gitlab("https://u@evil.example", "acme/r", "7"), None);
        assert_eq!(run_url(Some(&json!({ "provider": "oidc" }))), None);
        assert_eq!(run_url(None), None);
    }
}

#[cfg(test)]
mod category_tests {
    use super::category_of;

    #[test]
    fn every_event_kind_has_a_service_category() {
        for (kind, label) in [
            ("auth.denied", "Sign-ins"),
            ("session.start", "Sessions"),
            ("ssh.exec", "Sessions"),
            ("db.query.end", "SQL"),
            ("mongo.command", "MongoDB"),
            ("redis.command", "Redis"),
            ("search.request", "Search"),
            ("kafka.request", "Messaging"),
            ("mq.operation", "Messaging"),
            ("web.websocket", "Web"),
            ("kube.request", "Kubernetes"),
            ("policy.change", "Admin"),
            ("user.lock", "Admin"),
            ("worker.enroll", "Admin"),
        ] {
            assert_eq!(category_of(kind).map(|c| c.label), Some(label), "{kind}");
        }
        assert!(category_of("nothing.here").is_none());
    }
}
