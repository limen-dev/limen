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
    /// This page can be saved as a view (and the viewer may open the page).
    pub saveable: bool,
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
            // The script shows the control only where the address is exactly one of these pages.
            saveable: matches!(active, "resources" | "sessions" | "audit" | "dashboards"),
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

/// One way in to a resource: the principal it opens as (when the kind lets you choose one) and the
/// command that does it.
pub struct ConnectOption {
    pub principal: Option<String>,
    pub command: String,
}

/// A principal goes on a command line only when it is plain: letters, digits, `_`, `.` and `-`,
/// not starting with `-`. Anything else is left off and the generic command is shown instead, so
/// a command copied from the console never needs quoting or can be read as an option.
fn plain_principal(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 64
        && !p.starts_with('-')
        && p.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// The commands that open `name` for someone who may use `principals`.
///
/// SSH takes `login@resource`; the database, MongoDB, Redis, search, `RabbitMQ` and Kafka kinds each
/// take one flag for who you act as (required only when policy allows several, so one identity gets
/// the plain command). Every other kind has one command. Nothing here invents a flag.
#[must_use]
pub fn connect_options(kind: &str, name: &str, principals: &[String]) -> Vec<ConnectOption> {
    let base = connect_for(kind, name);
    let plain: Vec<&String> = principals.iter().filter(|p| plain_principal(p)).collect();
    let flag = super::connect_builder::who_flag(kind);
    let per_principal = match kind {
        "ssh" => !plain.is_empty(),
        // Optional when policy allows one identity, so only several need naming.
        _ => flag.is_some() && principals.len() > 1 && !plain.is_empty(),
    };
    if !per_principal {
        return vec![ConnectOption {
            principal: None,
            command: base.command,
        }];
    }
    plain
        .into_iter()
        .map(|p| ConnectOption {
            principal: Some(p.clone()),
            command: match flag {
                None => format!("limen ssh {p}@{name}"),
                Some(flag) => format!("{} {flag} {p}", base.command),
            },
        })
        .collect()
}

/// Whether a resource can be reached right now, from the workers that match its selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// At least one matching worker holds a tunnel.
    Up,
    /// Matching workers are enrolled but none holds a tunnel, so a session would fail.
    Offline,
    /// No enrolled worker matches the selector at all.
    NoWorker,
}

impl Health {
    #[must_use]
    pub fn of(workers: &[WorkerMatch]) -> Self {
        if workers.is_empty() {
            Self::NoWorker
        } else if workers.iter().any(|w| w.tunnels > 0) {
            Self::Up
        } else {
            Self::Offline
        }
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Up => "reachable",
            Self::Offline => "offline",
            Self::NoWorker => "no worker",
        }
    }

    #[must_use]
    pub fn pill(self) -> &'static str {
        match self {
            Self::Up => "ok",
            Self::Offline => "bad",
            Self::NoWorker => "warn",
        }
    }

    /// What it means for the person looking at it.
    #[must_use]
    pub fn hint(self) -> &'static str {
        match self {
            Self::Up => "A matching worker holds a tunnel.",
            Self::Offline => {
                "Matching workers are enrolled but none is connected, so sessions will fail."
            }
            Self::NoWorker => "No enrolled worker matches the selector, so sessions will fail.",
        }
    }

    #[must_use]
    pub fn needs_attention(self) -> bool {
        self != Self::Up
    }
}

/// A time as RFC 3339, for `<time datetime>`: the script turns it into "5 minutes ago" and keeps
/// the absolute UTC text as the tooltip.
#[must_use]
pub fn iso_text(t: Option<OffsetDateTime>) -> String {
    t.and_then(|t| {
        t.to_offset(time::UtcOffset::UTC)
            .format(&time::format_description::well_known::Rfc3339)
            .ok()
    })
    .unwrap_or_default()
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
    /// Set only when the session names a user, so a link never points at nothing.
    pub user_known: bool,
    /// Set only when the session names a resource.
    pub resource_path: Option<String>,
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
            user_known: s.username.as_deref().is_some_and(|u| !u.is_empty()),
            resource_path: s
                .resource
                .as_deref()
                .filter(|r| !r.is_empty())
                .map(path_segment),
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
    /// False for a name that only appears in the audit trail (such as `system:idp-check`):
    /// there is no account to disable and no roles to show.
    pub manageable: bool,
    pub ci: Vec<Fact>,
    pub run_url: Option<String>,
    /// Where the account came from, in words ("IdP sign-in", "CI bot").
    pub source: String,
    /// The IdP's host, for a tooltip.
    pub issuer: String,
    /// What the IdP check last found, in words.
    pub idp: String,
    /// `ok`, `warn`, `bad` or empty: the pill's tone.
    pub idp_tone: &'static str,
    /// Access the IdP's groups give or take away at the next sign-in, e.g.
    /// "+ops −dba"; empty when nothing is pending.
    pub pending: String,
}

impl UserView {
    /// Who disabled the person: the IdP check, or an admin. Empty when enabled.
    pub fn disabled_by(&self) -> &'static str {
        if !self.locked {
            ""
        } else if crate::idp_check::placed_by_idp(&self.locked_by) {
            "the IdP"
        } else {
            "an admin"
        }
    }
}

/// A sign-in time, or "never" for a person SCIM provisioned who has not signed in.
fn signed_in_text(logins: i64, at: OffsetDateTime) -> String {
    if logins == 0 {
        "never".to_owned()
    } else {
        time_text(Some(at))
    }
}

/// How the IdP check stands, in words and as a tone (ADR-0047).
pub fn idp_check_text(
    status: &str,
    checked: Option<OffsetDateTime>,
    is_bot: bool,
) -> (String, &'static str) {
    if is_bot {
        return ("not applicable".into(), "");
    }
    match status {
        "ok" => (format!("checked {}", time_text(checked)), "ok"),
        "check_failed" => (
            format!("IdP not reachable since {}", time_text(checked)),
            "warn",
        ),
        "groups_missing" => (
            "IdP sent no groups: group removals not checked".into(),
            "warn",
        ),
        "offboarded" => (format!("ended by the IdP {}", time_text(checked)), "bad"),
        _ => ("not checked: no refresh token".into(), ""),
    }
}

/// The host of an issuer URL, for display.
fn issuer_host(issuer: Option<&str>) -> String {
    issuer
        .and_then(|i| url::Url::parse(i).ok())
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default()
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
            first_login: signed_in_text(u.login_count, u.first_login_at),
            last_login: signed_in_text(u.login_count, u.last_login_at),
            logins: u.login_count,
            locked: u.lock_reason.is_some(),
            lock_reason: u.lock_reason.clone().unwrap_or_default(),
            locked_by: u.locked_by.clone().unwrap_or_default(),
            locked_at: time_text(u.locked_at),
            is_bot: u.actor_type == "bot",
            manageable: true,
            ci: ci_facts(u.last_ci.as_ref()),
            run_url: run_url(u.last_ci.as_ref()),
            source: match u.source.as_str() {
                "bot" => "CI bot".to_owned(),
                "scim" => "SCIM".to_owned(),
                _ => "IdP sign-in".to_owned(),
            },
            issuer: issuer_host(u.issuer.as_deref()),
            idp: idp_check_text(&u.idp_status, u.idp_checked_at, u.actor_type == "bot").0,
            idp_tone: idp_check_text(&u.idp_status, u.idp_checked_at, u.actor_type == "bot").1,
            pending: String::new(),
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

/// One line of the Overview's "needs you" card: what is waiting, and where to deal with it.
pub struct AttentionItem {
    pub text: String,
    pub href: String,
    /// `bad`, `warn` or empty, as a pill class.
    pub tone: &'static str,
}

/// A view someone saved: a console page with its filters.
pub struct SavedView {
    pub label: String,
    pub href: String,
    /// The page it opens ("Resources") and that page's icon.
    pub page: &'static str,
    pub icon: &'static str,
}

/// How a card on the Overview gets you in. One command when the kind needs no choice; when there
/// are several logins, roles or users, a command with none of them named would not run, so the card
/// leads to the resource page, where each choice has its own command.
pub struct CardConnect {
    pub command: Option<String>,
}

/// The card's way in for someone who may act as `principals` on `name`.
#[must_use]
pub fn card_connect(kind: &str, name: &str, principals: &[String]) -> CardConnect {
    let mut options = connect_options(kind, name, principals);
    CardConnect {
        command: if options.len() == 1 {
            options.pop().map(|o| o.command)
        } else {
            None
        },
    }
}

/// A resource someone marked as a favourite, still reachable for them.
pub struct FavouriteResource {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub icon: &'static str,
    pub kclass: &'static str,
    /// `None` for an admin who can see the resource but has no principal on it.
    pub connect: Option<CardConnect>,
    pub health: Option<Health>,
}

/// A resource the viewer used lately, with the command to use it again.
pub struct RecentResource {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub icon: &'static str,
    pub kclass: &'static str,
    pub connect: CardConnect,
    pub last: Stamp,
}

pub struct ResourceView {
    pub name: String,
    pub path: String,
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
    pub attention: Vec<AttentionItem>,
    pub recent: Vec<RecentResource>,
    pub favourites: Vec<FavouriteResource>,
    pub saved: Vec<SavedView>,
}

#[derive(Template)]
#[template(path = "sessions.html")]
pub struct SessionsPage {
    pub chrome: Chrome,
    pub notice: Option<&'static str>,
    pub sessions: Vec<SessionView>,
    /// At least one listed session can be ended (open, and not a kubectl login).
    pub has_open: bool,
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
    pub filter: UserFilter,
    /// The applied search and filters, each with the link that removes it.
    pub chips: Vec<FilterChip>,
    /// Every group and role among the people listed, for the filter menus.
    pub groups: Vec<String>,
    pub roles: Vec<String>,
    pub total: usize,
}

/// The users page's filters, from the query string (`?group=&role=&status=`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserFilter {
    pub group: String,
    pub role: String,
    /// `ok`, `unchecked`, `check_failed`, `offboarded` or `locked`.
    pub status: String,
    /// `enabled`, `disabled`, `disabled_idp` or `disabled_admin`. A disabled
    /// person is a locked one; the lock's author says who disabled them.
    pub state: String,
}

impl UserFilter {
    /// Whether the state filter admits a person: `locked_by` is the author of
    /// their lock, if they are locked.
    #[must_use]
    pub fn admits_state(&self, locked_by: Option<&str>) -> bool {
        let idp = locked_by.is_some_and(crate::idp_check::placed_by_idp);
        match self.state.as_str() {
            "" => true,
            "enabled" => locked_by.is_none(),
            "disabled" => locked_by.is_some(),
            "disabled_idp" => idp,
            "disabled_admin" => locked_by.is_some() && !idp,
            _ => false,
        }
    }

    /// Whether a person passes every filter that is set.
    #[must_use]
    pub fn admits(&self, u: &UserRow, locked: bool) -> bool {
        self.admits_state(locked.then(|| u.locked_by.as_deref().unwrap_or("")))
            && (self.group.is_empty() || u.groups.contains(&self.group))
            && (self.role.is_empty() || u.roles.contains(&self.role))
            && match self.status.as_str() {
                "" => true,
                "locked" => locked,
                s => u.idp_status == s,
            }
    }
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
    /// Not seen for over five minutes (the dashboards' "gone quiet" line).
    pub quiet: bool,
    /// The certificate is past its end and was not renewed: the component has stopped.
    pub cert_expired: bool,
    /// Workers: the resources whose selector this worker's labels satisfy.
    pub serves: Vec<ServedResource>,
    pub serves_more: usize,
    pub last_seen_iso: String,
}

/// A resource a worker can serve, as a link.
pub struct ServedResource {
    pub name: String,
    pub path: String,
}

/// The resources a worker can serve, up to `limit`, and how many more there are.
#[must_use]
pub fn resources_served(
    policy: &limen_policy::Policy,
    labels: &std::collections::BTreeMap<String, String>,
    limit: usize,
) -> (Vec<ServedResource>, usize) {
    let mut all: Vec<ServedResource> = policy
        .documents()
        .iter()
        .filter_map(|d| match d {
            limen_policy::Document::Resource(r) => Some(r),
            _ => None,
        })
        .filter(|r| {
            r.spec
                .worker_selector
                .iter()
                .all(|(k, v)| labels.get(k).is_some_and(|actual| actual == v))
        })
        .map(|r| ServedResource {
            name: r.metadata.name.clone(),
            path: path_segment(&r.metadata.name),
        })
        .collect();
    all.sort_by(|a, b| a.name.cmp(&b.name));
    let more = all.len().saturating_sub(limit);
    all.truncate(limit);
    (all, more)
}

impl ComponentView {
    /// The day and the clock time of a "2026-10-25 09:27:38 UTC" text, for a two-line cell.
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
    /// At least one listed component is not revoked.
    pub has_enrolled: bool,
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
    pub no_changes: bool,
    pub added: Vec<String>,
    pub changed: Vec<String>,
    pub removed: Vec<String>,
    /// Saving it would wait for another admin's approval.
    pub waits: bool,
    /// Recorded sessions replayed through the change (ADR-0051), when asked.
    pub replay: Option<ReplayView>,
}

/// The replay of recorded sessions, ready to show. Every string is escaped
/// by the template.
pub struct ReplayView {
    pub headline: String,
    pub partial: bool,
    pub affected: Vec<ReplayRow>,
    /// Shadow rules that would have fired, sessions already refused, and what
    /// was not replayed, one line each.
    pub notes: Vec<String>,
    pub caveat: &'static str,
    pub error: Option<String>,
}

pub struct ReplayRow {
    pub who: String,
    pub bot: bool,
    pub principal: String,
    pub resource: String,
    pub sessions: u64,
    pub now: &'static str,
    pub labels_changed: bool,
}

impl ReplayView {
    #[must_use]
    pub fn new(r: &limen_policy::replay::ReplayReport) -> Self {
        let mut notes = Vec::new();
        for s in &r.shadow {
            notes.push(format!(
                "Shadow rule {} would have fired for {} sessions.",
                s.rule, s.sessions
            ));
        }
        if r.affected_omitted > 0 {
            notes.push(format!(
                "{} more groups are not listed; the totals count them.",
                r.affected_omitted
            ));
        }
        if r.already_refused > 0 {
            notes.push(format!(
                "{} sessions are refused by the active policy today already (groups or roles changed since): not caused by this change.",
                r.already_refused
            ));
        }
        for (reason, n) in &r.skipped {
            notes.push(format!("{n} sessions not replayed: {reason}."));
        }
        Self {
            headline: r.headline(),
            partial: r.truncated,
            affected: r
                .affected
                .iter()
                .map(|a| ReplayRow {
                    who: a.user.clone(),
                    bot: a.bot,
                    principal: a.principal.clone(),
                    resource: a.resource.clone(),
                    sessions: a.sessions,
                    now: a.now.text(),
                    labels_changed: a.labels_changed,
                })
                .collect(),
            notes,
            caveat: limen_policy::replay::CAVEAT,
            error: None,
        }
    }

    /// A replay that could not run, with the reason.
    #[must_use]
    pub fn failed(message: &str) -> Self {
        Self {
            headline: String::new(),
            partial: false,
            affected: Vec::new(),
            notes: Vec::new(),
            caveat: limen_policy::replay::CAVEAT,
            error: Some(message.to_owned()),
        }
    }
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
    pub draft: String,
    /// "Preview impact" on a form: which document (kind and name empty for a
    /// new one), the YAML as typed, and what saving it would do.
    pub preview: Option<DryRun>,
    pub preview_kind: String,
    pub preview_name: String,
    pub preview_yaml: String,
    pub error: Option<String>,
    pub notice: Option<String>,
}

#[derive(Template)]
#[template(path = "simulator.html")]
pub struct SimulatorPage {
    pub chrome: Chrome,
    pub simulation: Option<Simulation>,
    /// Clickable choices; a click runs the simulation.
    pub groups: Vec<Pick>,
    pub bots: Vec<Pick>,
    pub people: Vec<Pick>,
    /// People beyond those shown as choices: found with the search box.
    pub more_people: usize,
    pub q: String,
}

/// One choice: where it leads, and whether it is part of the current pick.
pub struct Pick {
    pub name: String,
    pub href: String,
    pub on: bool,
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

/// A time shown relative ("5 minutes ago") with the absolute UTC text as its tooltip.
pub struct Stamp {
    pub text: String,
    pub iso: String,
}

impl Stamp {
    #[must_use]
    pub fn of(t: OffsetDateTime) -> Self {
        Self {
            text: time_text(Some(t)),
            iso: iso_text(Some(t)),
        }
    }
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
    /// Admins only: whether a worker can serve it right now.
    pub health: Option<Health>,
    /// The latest session on it: anyone's for an admin, your own for everyone else.
    pub last_used: Option<Stamp>,
    /// What to run to open it; `None` when the viewer has no access to copy a command for.
    pub connect: Option<Connect>,
    /// Admins: errors in the last 24 hours, and what they were (for the tooltip).
    pub errors: i64,
    pub errors_text: String,
    pub favourite: bool,
}

impl ResourceRow {
    /// Unreachable, or reachable and failing.
    #[must_use]
    pub fn needs_attention(&self) -> bool {
        self.health.is_some_and(Health::needs_attention) || self.errors > 0
    }
}

/// One entry of the sort menu.
pub struct SortOption {
    pub value: &'static str,
    pub label: &'static str,
    pub selected: bool,
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
    pub sorts: Vec<SortOption>,
    /// The sort in effect when it isn't the default, so a filter link keeps it.
    pub sort_value: String,
    /// Admins: the "needs attention" filter, whether it is on, and the link that flips it.
    pub attention_on: bool,
    pub attention_href: String,
    /// How many resources (before filters) need attention, for the filter's badge.
    pub attention_count: usize,
    pub favourites_on: bool,
    pub favourites_href: String,
    pub favourite_count: usize,
    /// Views saved for this page, and the address a new one would be saved for.
    pub saved: Vec<SavedView>,
    pub here: String,
    /// Everything below the filters is empty because nothing matched, not because there is nothing.
    pub total: usize,
}

/// A session that is open on the resource now.
pub struct LiveSession {
    pub id: String,
    pub user: String,
    pub login: String,
    pub since: Stamp,
    /// The viewer may watch it (SSH only, and only with the separate power).
    pub watch: bool,
    /// It can be ended from here: not a kubectl login, which has no connection to end.
    pub endable: bool,
}

pub struct DetailTab {
    pub href: String,
    pub label: &'static str,
    pub current: bool,
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
    /// One command per principal where the kind takes one, else a single command.
    pub options: Vec<ConnectOption>,
    /// The builder under the Connect card: what the viewer may act as, and the command for it.
    pub builder: Option<super::connect_builder::Builder>,
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
    pub tab: &'static str,
    pub tabs: Vec<DetailTab>,
    /// Admins: whether a worker can serve it right now.
    pub health: Option<Health>,
    pub last_used: Option<Stamp>,
    /// Admins and auditors: sessions open on it now.
    pub live: Vec<LiveSession>,
    pub sessions_href: String,
    pub audit_href: Option<String>,
    /// The viewer marked this resource as a favourite.
    pub starred: bool,
    /// Where to come back to after changing a favourite.
    pub here: String,
    /// Admins: what went wrong here in the last 24 hours, by where it was recorded.
    pub errors: Vec<ErrorPart>,
}

/// One kind of error on a resource, with where to look at it.
pub struct ErrorPart {
    pub label: &'static str,
    pub count: i64,
    pub href: String,
}

/// "2 refused, 1 statement error": the parts that are not zero, for a tooltip.
#[must_use]
pub fn errors_text(e: super::store::ResourceErrors) -> String {
    // (count, one, many): "refused" and "web 5xx" read the same either way.
    let parts = [
        (e.denied, "refused", "refused"),
        (e.db, "statement error", "statement errors"),
        (e.web, "web 5xx", "web 5xx"),
        (e.kube, "Kubernetes error", "Kubernetes errors"),
    ];
    parts
        .iter()
        .filter(|(n, _, _)| *n > 0)
        .map(|(n, one, many)| format!("{n} {}", if *n == 1 { one } else { many }))
        .collect::<Vec<_>>()
        .join(", ")
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
    /// What to do next, by kind of failure; empty for none.
    next: &'static str,
    /// The failure is on our side, so trying again may work.
    retry: bool,
    assets: &'static str,
}

/// What a person can do about a failure, by status. Short and about their next move.
fn next_step(status: StatusCode) -> &'static str {
    match status {
        StatusCode::NOT_FOUND => "Check the address, or start again from the console.",
        StatusCode::FORBIDDEN => {
            "If you need this, ask an admin, or ask for access from the Access page."
        }
        StatusCode::BAD_REQUEST | StatusCode::CONFLICT => "Go back, change it, and try again.",
        s if s.is_server_error() => "This is on our side. Try again in a moment.",
        _ => "",
    }
}

/// A plain page with a status code, for errors and confirmations. It has no
/// navigation, so it is safe to show without a session.
#[must_use]
pub fn error_page(status: StatusCode, title: &str, message: &str) -> Response {
    let mut response = html(
        MessagePage {
            title,
            message,
            next: next_step(status),
            retry: status.is_server_error(),
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

#[cfg(test)]
mod user_filter_tests {
    use super::*;

    fn person(groups: &[&str], roles: &[&str], status: &str) -> UserRow {
        UserRow {
            username: "a@example.com".into(),
            roles: roles.iter().map(|s| (*s).to_owned()).collect(),
            groups: groups.iter().map(|s| (*s).to_owned()).collect(),
            first_login_at: OffsetDateTime::UNIX_EPOCH,
            last_login_at: OffsetDateTime::UNIX_EPOCH,
            login_count: 1,
            lock_reason: None,
            locked_by: None,
            locked_at: None,
            actor_type: "user".into(),
            last_ci: None,
            source: "idp_login".into(),
            issuer: None,
            idp_status: status.into(),
            idp_checked_at: None,
            idp_groups: None,
        }
    }

    #[test]
    fn filters_combine_and_an_empty_filter_admits_everyone() {
        let u = person(&["platform"], &["dev"], "ok");
        assert!(UserFilter::default().admits(&u, false));
        let f = |g: &str, r: &str, s: &str| UserFilter {
            group: g.into(),
            role: r.into(),
            status: s.into(),
            ..UserFilter::default()
        };
        assert!(f("platform", "", "").admits(&u, false));
        assert!(!f("other", "", "").admits(&u, false));
        assert!(f("platform", "dev", "ok").admits(&u, false));
        assert!(!f("platform", "admin", "ok").admits(&u, false));
        assert!(!f("", "", "check_failed").admits(&u, false));
        assert!(f("", "", "locked").admits(&u, true));
        let state = |s: &str, by: Option<&str>| {
            let mut u = person(&[], &[], "ok");
            u.lock_reason = by.map(|_| "why".to_owned());
            u.locked_by = by.map(str::to_owned);
            UserFilter {
                state: s.into(),
                ..UserFilter::default()
            }
            .admits(&u, by.is_some())
        };
        let idp = Some("system:idp-check");
        let admin = Some("admin@example.com");
        assert!(state("enabled", None) && !state("enabled", idp) && !state("enabled", admin));
        assert!(!state("disabled", None) && state("disabled", idp) && state("disabled", admin));
        assert!(state("disabled_idp", idp) && !state("disabled_idp", admin));
        let scim = Some("system:scim");
        assert!(
            state("disabled_idp", scim) && !state("disabled_admin", scim),
            "SCIM is the IdP too"
        );
        assert!(state("disabled_admin", admin) && !state("disabled_admin", idp));
        assert!(!state("disabled_admin", None) && !state("nonsense", None));
        assert!(!f("", "", "locked").admits(&u, false));
        assert!(
            !f("", "", "nonsense").admits(&u, false),
            "unknown matches nobody"
        );
    }

    #[test]
    fn the_check_is_described_honestly() {
        assert_eq!(idp_check_text("unchecked", None, false).1, "");
        assert!(
            idp_check_text("unchecked", None, false)
                .0
                .contains("no refresh token")
        );
        assert_eq!(idp_check_text("check_failed", None, false).1, "warn");
        assert_eq!(idp_check_text("offboarded", None, false).1, "bad");
        assert_eq!(idp_check_text("ok", None, false).1, "ok");
        assert_eq!(idp_check_text("ok", None, true).0, "not applicable");
    }
}

#[cfg(test)]
mod resource_ui_tests {
    use super::*;

    fn principals(p: &[&str]) -> Vec<String> {
        p.iter().map(|s| (*s).to_owned()).collect()
    }

    fn commands(kind: &str, p: &[&str]) -> Vec<String> {
        connect_options(kind, "bastion", &principals(p))
            .into_iter()
            .map(|o| o.command)
            .collect()
    }

    #[test]
    fn ssh_names_the_login_for_each_principal() {
        assert_eq!(
            commands("ssh", &["deploy", "root"]),
            ["limen ssh deploy@bastion", "limen ssh root@bastion"]
        );
    }

    #[test]
    fn databases_name_the_role_only_when_there_are_several() {
        assert_eq!(commands("postgres", &["app"]), ["limen db connect bastion"]);
        assert_eq!(
            commands("postgres", &["app", "ro"]),
            [
                "limen db connect bastion --db-role app",
                "limen db connect bastion --db-role ro"
            ]
        );
    }

    #[test]
    fn each_kind_that_takes_an_identity_uses_its_own_flag_when_there_are_several() {
        for (kind, command, flag) in [
            ("redis", "limen redis connect", "--user"),
            ("mongodb", "limen mongo connect", "--role"),
            ("opensearch", "limen search connect", "--role"),
            ("elasticsearch", "limen search connect", "--role"),
            ("rabbitmq", "limen mq connect", "--user"),
            ("kafka", "limen kafka connect", "--user"),
        ] {
            assert_eq!(
                commands(kind, &["a", "b"]),
                [
                    format!("{command} bastion {flag} a"),
                    format!("{command} bastion {flag} b")
                ],
                "{kind}"
            );
            assert_eq!(commands(kind, &["a"]), [format!("{command} bastion")]);
        }
    }

    #[test]
    fn kinds_with_nothing_to_choose_have_one_command_and_no_invented_flag() {
        assert_eq!(commands("kubernetes", &["a"]), ["limen kube login bastion"]);
        assert_eq!(
            commands("kubernetes", &["a", "b"]),
            ["limen kube login bastion"]
        );
        assert_eq!(commands("web", &["a", "b"]), ["limen web open bastion"]);
        assert_eq!(commands("tcp", &["a", "b"]), ["limen tcp bastion"]);
    }

    #[test]
    fn a_principal_that_needs_quoting_never_reaches_a_command_line() {
        for bad in [
            "a b",
            "x;rm -rf",
            "$(id)",
            "-oProxyCommand=x",
            "a'b",
            "",
            "é",
        ] {
            let ssh = commands("ssh", &[bad]);
            assert_eq!(ssh, ["limen ssh bastion"], "{bad:?}");
            let db = commands("mysql", &[bad, "ok"]);
            assert_eq!(db, ["limen db connect bastion --db-role ok"], "{bad:?}");
        }
        // Over the length cap too.
        assert_eq!(commands("ssh", &[&"a".repeat(65)]), ["limen ssh bastion"]);
    }

    #[test]
    fn no_principals_is_the_generic_command() {
        assert_eq!(commands("ssh", &[]), ["limen ssh bastion"]);
        assert!(
            connect_options("ssh", "bastion", &[])
                .iter()
                .all(|o| o.principal.is_none())
        );
    }

    fn worker(tunnels: usize) -> WorkerMatch {
        WorkerMatch {
            id: "w".into(),
            name: None,
            tunnels,
            last_seen: String::new(),
        }
    }

    #[test]
    fn health_follows_workers_and_tunnels() {
        assert_eq!(Health::of(&[]), Health::NoWorker);
        assert_eq!(Health::of(&[worker(0), worker(0)]), Health::Offline);
        assert_eq!(Health::of(&[worker(0), worker(2)]), Health::Up);
        assert!(Health::NoWorker.needs_attention());
        assert!(Health::Offline.needs_attention());
        assert!(!Health::Up.needs_attention());
    }

    #[test]
    fn error_counts_read_naturally_and_skip_zeros() {
        use super::super::store::ResourceErrors;
        assert_eq!(errors_text(ResourceErrors::default()), "");
        let e = ResourceErrors {
            denied: 2,
            db: 1,
            web: 3,
            kube: 2,
        };
        assert_eq!(
            errors_text(e),
            "2 refused, 1 statement error, 3 web 5xx, 2 Kubernetes errors"
        );
        assert_eq!(e.total(), 8);
        let one = ResourceErrors {
            denied: 1,
            ..ResourceErrors::default()
        };
        assert_eq!(errors_text(one), "1 refused");
    }

    #[test]
    fn a_worker_serves_the_resources_whose_selector_its_labels_satisfy() {
        let policy = limen_policy::Policy::default();
        let labels = std::collections::BTreeMap::new();
        let (served, more) = resources_served(&policy, &labels, 6);
        assert!(served.is_empty() && more == 0);
    }

    #[test]
    fn iso_text_is_utc_rfc3339_or_empty() {
        let t = time::macros::datetime!(2026-11-13 12:30:05 +2);
        assert_eq!(iso_text(Some(t)), "2026-11-13T10:30:05Z");
        assert_eq!(iso_text(None), "");
    }
}
