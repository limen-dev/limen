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
pub struct Chrome {
    pub username: String,
    pub initial: String,
    pub avatar: String,
    pub is_admin: bool,
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
        "kubernetes" => ("k-kubernetes", "k-kubernetes"),
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
    pub status: &'static str,
    pub status_class: &'static str,
    pub reason: String,
    pub active: bool,
    pub has_recording: bool,
    pub recording_sha256: String,
    pub recording_note: &'static str,
    pub bytes: String,
    pub client_addr: String,
    pub proxy: String,
    pub worker: String,
}

impl From<&SessionRow> for SessionView {
    fn from(s: &SessionRow) -> Self {
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
            ended: time_text(s.ended_at),
            duration: duration_text(s.duration_ms),
            status,
            status_class,
            // "ended" says nothing the status doesn't.
            reason: if s.active {
                String::new()
            } else {
                s.end_reason
                    .clone()
                    .filter(|r| r != "ended")
                    .unwrap_or_default()
            },
            active: s.active,
            has_recording,
            recording_sha256: s.recording_sha256.clone().unwrap_or_default(),
            recording_note: if s.active {
                "The recording is uploaded when the session ends."
            } else if s.recording_sha256.is_some() {
                "The recording was made but hasn't reached the control plane yet. Check again shortly."
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
        }
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
    pub newer: Option<String>,
    pub older: Option<String>,
}

#[derive(Template)]
#[template(path = "session.html")]
pub struct SessionPage {
    pub chrome: Chrome,
    pub s: SessionView,
}

#[derive(Template)]
#[template(path = "users.html")]
pub struct UsersPage {
    pub chrome: Chrome,
    pub notice: Option<&'static str>,
    pub users: Vec<UserView>,
    pub orphan_locks: Vec<UserView>,
}

#[derive(Template)]
#[template(path = "user.html")]
pub struct UserPage {
    pub chrome: Chrome,
    pub notice: Option<&'static str>,
    pub u: UserView,
    pub sessions: Vec<SessionView>,
    pub events: Vec<EventView>,
}

pub struct ComponentView {
    pub id: String,
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

pub struct PendingTokenView {
    pub kind: String,
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
    pub components: Vec<ComponentView>,
    pub pending: Vec<PendingTokenView>,
}

pub struct EventView {
    pub at: String,
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
    pub events: Vec<EventView>,
    pub kinds: Vec<String>,
    pub kind_filter: Option<String>,
    pub user_filter: Option<String>,
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
    pub name: String,
    pub summary: String,
    pub yaml: String,
}

pub struct PolicyGroup {
    pub title: &'static str,
    pub docs: Vec<PolicyDoc>,
}

pub struct DryRun {
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
    pub pasted: String,
    pub result: Option<DryRun>,
}

pub struct RoleAccess {
    pub chip: Chip,
    pub principals: Vec<String>,
}

pub struct WorkerMatch {
    pub id: String,
    pub tunnels: usize,
    pub last_seen: String,
}

pub struct KindTab {
    pub name: String,
    pub icon: &'static str,
    pub kclass: &'static str,
    pub current: bool,
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
    pub query: String,
    pub rows: Vec<ResourceRow>,
}

#[derive(Template)]
#[template(path = "resource.html")]
pub struct ResourcePage {
    pub chrome: Chrome,
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
    pub roles: Vec<RoleAccess>,
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
