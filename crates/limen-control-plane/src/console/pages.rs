//! Console page handlers. Admins see everything; everyone else sees their
//! own identity, resources, and sessions (ADR-0017).

use std::collections::BTreeMap;
use std::time::Duration;

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use limen_core::names::NAME_LABEL;
use limen_policy::Document;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::store::{self, SessionFilter};
use super::views::{
    self, AuditPage, BotView, BotsPage, Chrome, ComponentView, DryRun, EventView, Home, KindTab,
    PendingTokenView, PolicyDoc, PolicyGroup, PolicyPage, ResourcePage, ResourceRow, ResourceView,
    ResourcesPage, RoleAccess, SessionPage, SessionView, SessionsPage, StatementView, Stats,
    TokenPage, UserPage, UserView, UsersPage, WorkerMatch, Workers, error_page, list_text,
    path_segment, time_text,
};
use super::{Auth, Console, html};
use crate::db;
use crate::services::ops::{self, Actor};
use crate::state::AppState;

const PAGE_SIZE: i64 = 50;

fn chrome(state: &AppState, auth: &Auth, active: &'static str) -> Chrome {
    Chrome::new(auth, active, state.policy.current().version)
}

fn event_view(e: &store::EventRow) -> EventView {
    EventView {
        at: time_text(Some(e.at)),
        tone: match e.kind.as_str() {
            "auth.denied" | "user.lock" | "session.kill" | "component.revoke" => "bad",
            "auth.login" | "user.unlock" | "worker.enroll" => "ok",
            _ => "",
        },
        kind: e.kind.clone(),
        user: e.username.clone(),
        user_path: e.username.as_deref().map(path_segment),
        session_path: e.session_id.map(|id| id.to_string()),
        summary: e.summary.clone(),
    }
}

fn actor(auth: &Auth) -> Actor<'_> {
    Actor {
        username: &auth.username,
        via: "console",
    }
}

fn console(state: &AppState) -> Result<&Console, Response> {
    state
        .console
        .as_ref()
        .ok_or_else(|| StatusCode::NOT_FOUND.into_response())
}

fn db_error(what: &str, e: &sqlx::Error) -> Response {
    tracing::error!(error = %e, "{what}");
    error_page(
        StatusCode::SERVICE_UNAVAILABLE,
        "Unavailable",
        "The console can't read its database right now. Try again shortly.",
    )
}

/// An admin action failed: show why, using the status the API would return.
fn action_error(status: &tonic::Status) -> Response {
    let code = match status.code() {
        tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    error_page(code, "That didn't work", status.message())
}

/// Fixed messages for `?done=` so no page reflects arbitrary text.
fn notice(code: Option<&str>) -> Option<&'static str> {
    Some(match code? {
        "locked" => "User locked. Their sessions end within about 11 seconds.",
        "unlocked" => "User unlocked.",
        "killed" => "The session will end within about 11 seconds.",
        "revoked" => "Revoked. Proxies drop its tunnels within about 10 seconds.",
        _ => return None,
    })
}

#[derive(Deserialize)]
pub struct DoneQuery {
    done: Option<String>,
}

/// `GET /console/logout`: a page with the sign-out button. Signing out is a
/// POST, so a link or an image tag can't log someone out.
pub async fn signout(State(state): State<AppState>, auth: Auth) -> Response {
    html(
        views::SignoutPage {
            chrome: chrome(&state, &auth, ""),
        }
        .render(),
    )
}

/// The branded page unauthenticated visitors land on. It does nothing but
/// offer the way in, so it needs no session.
pub async fn signin() -> Response {
    html(
        views::SigninPage {
            assets: super::assets::version(),
            version: limen_core::VERSION,
        }
        .render(),
    )
}

// ---- overview ------------------------------------------------------------------------

pub async fn home(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<DoneQuery>,
) -> Response {
    let loaded = state.policy.current();
    let resources = loaded
        .policy
        .accessible(&auth.roles)
        .into_iter()
        .map(|r| ResourceView {
            connect: views::connect_for(r.kind.as_str(), &r.name),
            name: r.name,
            kind: r.kind.as_str().to_owned(),
            icon: views::kind_icon(r.kind.as_str()).0,
            kclass: views::kind_icon(r.kind.as_str()).1,
            labels: r
                .labels
                .into_iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect(),
            principals: r.principals,
        })
        .collect();
    let filter = SessionFilter {
        username: (!auth.is_admin).then(|| auth.username.clone()),
        limit: 10,
        ..SessionFilter::default()
    };
    let sessions = match store::list_sessions(&state.db, &filter).await {
        Ok(rows) => rows.iter().take(10).map(SessionView::from).collect(),
        Err(e) => return db_error("listing sessions", &e),
    };
    let mut overview = Stats {
        active_sessions: 0,
        users: 0,
        locked: 0,
        workers_up: 0,
    };
    if auth.is_admin {
        let counted = async {
            let active = store::active_session_count(&state.db).await?;
            let users = store::list_users(&state.db).await?;
            let locks = db::active_locks(&state.db).await?;
            let (components, tunnels) = db::list_components(&state.db).await?;
            Ok::<_, sqlx::Error>((active, users.len(), locks.len(), components, tunnels))
        }
        .await;
        match counted {
            Ok((active, users, locked, components, tunnels)) => {
                overview.active_sessions = active;
                overview.users = users;
                overview.locked = locked;
                overview.workers_up = components
                    .iter()
                    .filter(|c| {
                        c.kind == "worker"
                            && c.revoked_at.is_none()
                            && tunnels.iter().any(|t| t.worker_id == c.id)
                    })
                    .count();
            }
            Err(e) => return db_error("counting for the overview", &e),
        }
    }
    html(
        Home {
            chrome: chrome(&state, &auth, "home"),
            notice: notice(q.done.as_deref()),
            stats: overview,
            resources,
            sessions,
            roles_text: format!("the roles {}", list_text(&auth.roles)),
            expires: time_text(Some(auth.expires_at)),
        }
        .render(),
    )
}

// ---- resources ---------------------------------------------------------------------

/// Where a resource points, for admins. Never shown to non-admins.
fn target_text(spec: &limen_policy::model::ResourceSpec) -> String {
    spec.target().unwrap_or_else(|| "—".into())
}

fn spec_kind(spec: &limen_policy::model::ResourceSpec) -> &'static str {
    spec.kinds().first().map_or("other", |k| k.as_str())
}

/// Roles that grant access to `resource`, with the principals each allows.
fn access_roles(policy: &limen_policy::Policy, resource: &str) -> Vec<RoleAccess> {
    let mut out = Vec::new();
    for doc in policy.documents() {
        if let Document::Role(role) = doc {
            let name = role.metadata.name.clone();
            if let Some(r) = policy
                .accessible(std::slice::from_ref(&name))
                .into_iter()
                .find(|r| r.name == resource)
            {
                out.push(RoleAccess {
                    chip: views::Chip {
                        c: views::chip_color(&name),
                        text: name,
                    },
                    principals: r.principals,
                });
            }
        }
    }
    out
}

/// Live, enrolled workers whose certificate labels satisfy `selector`.
fn matching_workers(
    components: &[db::ComponentRow],
    tunnels: &[db::TunnelRow],
    selector: &limen_core::labels::Labels,
) -> Vec<WorkerMatch> {
    components
        .iter()
        .filter(|c| c.kind == "worker" && c.revoked_at.is_none())
        .filter(|c| {
            let labels: BTreeMap<String, String> =
                serde_json::from_value(c.labels.clone()).unwrap_or_default();
            selector
                .iter()
                .all(|(k, v)| labels.get(k).is_some_and(|actual| actual == v))
        })
        .map(|c| WorkerMatch {
            id: c.id.clone(),
            name: c.name.clone(),
            tunnels: tunnels.iter().filter(|t| t.worker_id == c.id).count(),
            last_seen: time_text(Some(c.last_seen_at)),
        })
        .collect()
}

#[derive(Deserialize)]
pub struct ResourcesQuery {
    kind: Option<String>,
    q: Option<String>,
}

pub async fn resources(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<ResourcesQuery>,
) -> Response {
    let loaded = state.policy.current();
    let (components, tunnels) = if auth.is_admin {
        match db::list_components(&state.db).await {
            Ok(pair) => pair,
            Err(e) => return db_error("listing components", &e),
        }
    } else {
        (Vec::new(), Vec::new())
    };
    let counts = if auth.is_admin {
        store::session_counts_by_resource(&state.db)
            .await
            .unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    };
    // Admins see every resource; everyone else only what their roles allow.
    let accessible = loaded.policy.accessible(&auth.roles);
    let mut rows: Vec<ResourceRow> = Vec::new();
    for doc in loaded.policy.documents() {
        let Document::Resource(r) = doc else { continue };
        let name = r.metadata.name.clone();
        let mine = accessible.iter().find(|a| a.name == name);
        if !auth.is_admin && mine.is_none() {
            continue;
        }
        let kind = spec_kind(&r.spec);
        let (icon, kclass) = views::kind_icon(kind);
        let (total, active) = counts.get(&name).copied().unwrap_or((0, 0));
        rows.push(ResourceRow {
            roles: if auth.is_admin {
                access_roles(&loaded.policy, &name)
            } else {
                Vec::new()
            },
            workers: matching_workers(&components, &tunnels, &r.spec.worker_selector).len(),
            labels: r
                .metadata
                .labels
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect(),
            principals: mine.map(|m| m.principals.clone()).unwrap_or_default(),
            target: if auth.is_admin {
                target_text(&r.spec)
            } else {
                String::new()
            },
            path: path_segment(&name),
            name,
            kind: kind.to_owned(),
            icon,
            kclass,
            sessions: total,
            active,
        });
    }
    // Filters apply after access control, so a filter can't reveal anything.
    let needle =
        q.q.as_deref()
            .map(str::to_lowercase)
            .filter(|s| !s.is_empty());
    let kind_filter = q.kind.clone().filter(|k| !k.is_empty());
    let mut kinds: Vec<String> = rows.iter().map(|r| r.kind.clone()).collect();
    kinds.sort();
    kinds.dedup();
    rows.retain(|r| {
        kind_filter.as_deref().is_none_or(|k| k == r.kind)
            && needle.as_deref().is_none_or(|n| {
                r.name.to_lowercase().contains(n)
                    || r.labels.iter().any(|l| l.to_lowercase().contains(n))
            })
    });
    html(
        ResourcesPage {
            chrome: chrome(&state, &auth, "resources"),
            kinds: kinds
                .into_iter()
                .map(|k| {
                    let (icon, kclass) = views::kind_icon(&k);
                    KindTab {
                        current: kind_filter.as_deref() == Some(k.as_str()),
                        icon,
                        kclass,
                        name: k,
                    }
                })
                .collect(),
            all_selected: kind_filter.is_none(),
            query: q.q.unwrap_or_default(),
            rows,
        }
        .render(),
    )
}

pub async fn resource_detail(
    State(state): State<AppState>,
    auth: Auth,
    Path(name): Path<String>,
) -> Response {
    let not_found = || {
        error_page(
            StatusCode::NOT_FOUND,
            "Not found",
            "There is no such resource.",
        )
    };
    let loaded = state.policy.current();
    let Some(r) = loaded.policy.resource(&name) else {
        return not_found();
    };
    let accessible = loaded.policy.accessible(&auth.roles);
    let mine = accessible.iter().find(|a| a.name == name);
    if !auth.is_admin && mine.is_none() {
        return not_found();
    }
    let kind = spec_kind(&r.spec);
    let (icon, kclass) = views::kind_icon(kind);
    let filter = SessionFilter {
        username: (!auth.is_admin).then(|| auth.username.clone()),
        resource: Some(name.clone()),
        limit: 10,
        ..SessionFilter::default()
    };
    let sessions = match store::list_sessions(&state.db, &filter).await {
        Ok(rows) => rows.iter().take(10).map(SessionView::from).collect(),
        Err(e) => return db_error("listing a resource's sessions", &e),
    };
    let (workers, roles) = if auth.is_admin {
        let (components, tunnels) = match db::list_components(&state.db).await {
            Ok(pair) => pair,
            Err(e) => return db_error("listing components", &e),
        };
        (
            matching_workers(&components, &tunnels, &r.spec.worker_selector),
            access_roles(&loaded.policy, &name),
        )
    } else {
        (Vec::new(), Vec::new())
    };
    html(
        ResourcePage {
            chrome: chrome(&state, &auth, "resources"),
            connect: views::connect_for(kind, &name),
            name: name.clone(),
            kind: kind.to_owned(),
            icon,
            kclass,
            labels: r
                .metadata
                .labels
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect(),
            selector: r
                .spec
                .worker_selector
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect(),
            // Internal addresses are for admins only.
            target: if auth.is_admin {
                target_text(&r.spec)
            } else {
                String::new()
            },
            pinned: r.spec.ssh.as_ref().is_some_and(|s| s.host_key.is_some()),
            description: r.metadata.description.clone().unwrap_or_default(),
            principals: mine.map(|m| m.principals.clone()).unwrap_or_default(),
            workers,
            roles,
            sessions,
        }
        .render(),
    )
}

// ---- sessions --------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SessionsQuery {
    filter: Option<String>,
    user: Option<String>,
    offset: Option<i64>,
    done: Option<String>,
}

pub async fn sessions(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<SessionsQuery>,
) -> Response {
    let active_only = q.filter.as_deref() == Some("active");
    // Non-admins only ever see their own, whatever the query says.
    let user_filter = if auth.is_admin {
        q.user.clone().filter(|u| !u.is_empty())
    } else {
        Some(auth.username.clone())
    };
    let offset = q.offset.unwrap_or(0).max(0);
    let filter = SessionFilter {
        username: user_filter.clone(),
        active_only,
        limit: PAGE_SIZE,
        offset,
        ..SessionFilter::default()
    };
    let mut rows = match store::list_sessions(&state.db, &filter).await {
        Ok(rows) => rows,
        Err(e) => return db_error("listing sessions", &e),
    };
    let has_more = i64::try_from(rows.len()).is_ok_and(|n| n > PAGE_SIZE);
    rows.truncate(usize::try_from(PAGE_SIZE).unwrap_or(50));
    let link = |offset: i64| {
        let mut url = format!("/console/sessions?offset={offset}");
        if active_only {
            url.push_str("&filter=active");
        }
        if auth.is_admin
            && let Some(u) = &user_filter
        {
            url.push_str("&user=");
            url.push_str(&path_segment(u));
        }
        url
    };
    html(
        SessionsPage {
            chrome: chrome(&state, &auth, "sessions"),
            notice: notice(q.done.as_deref()),
            sessions: rows.iter().map(SessionView::from).collect(),
            active_only,
            user_filter: auth.is_admin.then(|| user_filter.clone()).flatten(),
            newer: (offset > 0).then(|| link((offset - PAGE_SIZE).max(0))),
            older: has_more.then(|| link(offset + PAGE_SIZE)),
        }
        .render(),
    )
}

/// The session, if the viewer may see it. Others get the same "not found" as
/// a session that doesn't exist.
async fn visible_session(
    state: &AppState,
    auth: &Auth,
    id: &str,
) -> Result<store::SessionRow, Response> {
    let not_found = || {
        error_page(
            StatusCode::NOT_FOUND,
            "Not found",
            "There is no such session.",
        )
    };
    let id = Uuid::parse_str(id).map_err(|_| not_found())?;
    let row = store::session(&state.db, id)
        .await
        .map_err(|e| db_error("reading a session", &e))?
        .ok_or_else(not_found)?;
    if auth.is_admin || row.username.as_deref() == Some(auth.username.as_str()) {
        Ok(row)
    } else {
        Err(not_found())
    }
}

/// The most statements the session page lists.
const STATEMENT_LIMIT: i64 = 500;

pub async fn session_detail(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> Response {
    match visible_session(&state, &auth, &id).await {
        Ok(row) => {
            let mut s = SessionView::from(&row);
            // Names beside the ids, for the components that have one.
            s.proxy = with_name(&state, row.proxy_id.as_deref(), s.proxy).await;
            s.worker = with_name(&state, row.worker_id.as_deref(), s.worker).await;
            // Best effort: the page still renders without the statements.
            let (statements, statement_total, statement_errors) = if s.is_db {
                let list = store::db_statements(&state.db, row.session_id, STATEMENT_LIMIT)
                    .await
                    .unwrap_or_default();
                let (total, errors) = store::db_session_counts(&state.db, row.session_id)
                    .await
                    .unwrap_or_default();
                (
                    list.iter().map(StatementView::from).collect(),
                    total,
                    errors,
                )
            } else {
                (Vec::new(), 0, 0)
            };
            html(
                SessionPage {
                    chrome: chrome(&state, &auth, "sessions"),
                    s,
                    statements,
                    statement_total,
                    statement_errors,
                }
                .render(),
            )
        }
        Err(r) => r,
    }
}

/// `text` (a component id) followed by the component's name, if it has one.
/// Best effort: on a lookup error the id alone is shown.
async fn with_name(state: &AppState, id: Option<&str>, text: String) -> String {
    let Some(id) = id else { return text };
    match db::component(&state.db, id).await {
        Ok(Some(db::ComponentRow {
            name: Some(name), ..
        })) => format!("{text} ({name})"),
        _ => text,
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The recording as asciicast, after checking it against the hash the worker
/// reported when the session ended.
pub async fn recording(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> Response {
    let row = match visible_session(&state, &auth, &id).await {
        Ok(row) => row,
        Err(r) => return r,
    };
    let (Some(uri), Some(expected)) = (&row.recording_uri, &row.recording_sha256) else {
        return error_page(
            StatusCode::NOT_FOUND,
            "No recording",
            "This session has no recording yet.",
        );
    };
    let bytes = match state.pipeline.recordings.get(uri).await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(session = %row.session_id, error = %e, "reading a recording");
            return error_page(
                StatusCode::BAD_GATEWAY,
                "Recording unavailable",
                "The recording couldn't be read from storage.",
            );
        }
    };
    if hex(&Sha256::digest(&bytes)) != *expected {
        tracing::error!(session = %row.session_id, "recording doesn't match its recorded hash; refusing to serve it");
        return error_page(
            StatusCode::BAD_GATEWAY,
            "Recording failed its integrity check",
            "The stored recording doesn't match the hash recorded when the session ended, so it won't be played.",
        );
    }
    (
        [
            (CONTENT_TYPE, "application/x-asciicast"),
            (CACHE_CONTROL, "no-store"),
            (CONTENT_DISPOSITION, "inline; filename=\"session.cast\""),
        ],
        bytes,
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct ReasonForm {
    csrf: String,
    reason: String,
}

pub async fn kill_session(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<ReasonForm>,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let console = match console(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = auth.check_post(console, &headers, &form.csrf) {
        return r;
    }
    match ops::kill_session(&state, actor(&auth), &id, &form.reason).await {
        Ok(_) => Redirect::to("/console/sessions?filter=active&done=killed").into_response(),
        Err(s) => action_error(&s),
    }
}

// ---- users -----------------------------------------------------------------------------

pub async fn users(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<DoneQuery>,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let users = match store::list_users(&state.db).await {
        Ok(u) => u,
        Err(e) => return db_error("listing users", &e),
    };
    let locks = match db::active_locks(&state.db).await {
        Ok(l) => l,
        Err(e) => return db_error("listing locks", &e),
    };
    // A locked bot has a row too: it isn't "never signed in".
    let known: Vec<String> = match store::list_bots(&state.db).await {
        Ok(bots) => users
            .iter()
            .chain(&bots)
            .map(|u| u.username.clone())
            .collect(),
        Err(e) => return db_error("listing bots", &e),
    };
    let orphan_locks = locks
        .iter()
        .filter(|l| !known.contains(&l.username))
        .map(|l| lock_only_view(&l.username, l))
        .collect();
    html(
        UsersPage {
            chrome: chrome(&state, &auth, "users"),
            notice: notice(q.done.as_deref()),
            users: users.iter().map(UserView::from).collect(),
            orphan_locks,
        }
        .render(),
    )
}

fn lock_only_view(name: &str, l: &db::LockRow) -> UserView {
    UserView {
        name: name.to_owned(),
        path: path_segment(name),
        role_list: Vec::new(),
        group_list: Vec::new(),
        av: views::avatar_class(name),
        initial: name
            .chars()
            .next()
            .map_or_else(|| "?".to_owned(), |c| c.to_uppercase().collect()),
        first_login: "never".into(),
        last_login: "never".into(),
        logins: 0,
        locked: true,
        lock_reason: l.reason.clone(),
        locked_by: l.locked_by.clone(),
        locked_at: time_text(Some(l.locked_at)),
        is_bot: limen_core::identity::is_bot(name),
        ci: Vec::new(),
        run_url: None,
    }
}

pub async fn bots(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<DoneQuery>,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let seen = match store::list_bots(&state.db).await {
        Ok(rows) => rows,
        Err(e) => return db_error("listing bots", &e),
    };
    let counts: BTreeMap<String, i64> = store::bot_session_counts(&state.db)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();
    let locks = db::active_locks(&state.db).await.unwrap_or_default();
    let policy = state.policy.current();
    let bots = policy
        .policy
        .bots()
        .map(|b| {
            let username = b.username();
            let row = seen.iter().find(|r| r.username == username);
            let lock = locks.iter().find(|l| l.username == username);
            BotView {
                av: views::avatar_class(&username),
                path: path_segment(&username),
                name: username.clone(),
                description: b.metadata.description.clone().unwrap_or_default(),
                method: b.spec.join.method.as_str(),
                issuer: b.spec.join.issuer().unwrap_or_default(),
                rules: b
                    .spec
                    .join
                    .claims
                    .iter()
                    .map(|(k, v)| views::Fact {
                        key: k.clone(),
                        value: v.values().join(" or "),
                    })
                    .collect(),
                roles: b
                    .spec
                    .roles
                    .iter()
                    .map(|r| views::Chip {
                        text: r.clone(),
                        c: views::chip_color(r),
                    })
                    .collect(),
                ttl: format!("{} minutes", b.ttl().as_secs() / 60),
                seen: row.is_some(),
                last_login: row
                    .map_or_else(|| "never".into(), |r| time_text(Some(r.last_login_at))),
                logins: row.map_or(0, |r| r.login_count),
                sessions: counts.get(&username).copied().unwrap_or(0),
                locked: lock.is_some(),
                lock_reason: lock.map(|l| l.reason.clone()).unwrap_or_default(),
                last_run: views::ci_facts(row.and_then(|r| r.last_ci.as_ref())),
                run_url: views::run_url(row.and_then(|r| r.last_ci.as_ref())),
            }
        })
        .collect();
    html(
        BotsPage {
            chrome: chrome(&state, &auth, "bots"),
            notice: notice(q.done.as_deref()),
            bots,
        }
        .render(),
    )
}

pub async fn user_detail(
    State(state): State<AppState>,
    auth: Auth,
    Path(name): Path<String>,
    Query(q): Query<DoneQuery>,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let row = match store::user(&state.db, &name).await {
        Ok(r) => r,
        Err(e) => return db_error("reading a user", &e),
    };
    let view = match row {
        Some(row) => UserView::from(&row),
        None => {
            // A lock can name someone who never signed in.
            let locks = db::active_locks(&state.db).await.unwrap_or_default();
            match locks.iter().find(|l| l.username == name) {
                Some(l) => lock_only_view(&name, l),
                None => {
                    return error_page(
                        StatusCode::NOT_FOUND,
                        "Not found",
                        "There is no such user.",
                    );
                }
            }
        }
    };
    let events = match store::list_events(&state.db, Some(&name), None, 15, 0).await {
        Ok(rows) => rows.iter().take(15).map(event_view).collect(),
        Err(e) => return db_error("reading a user's activity", &e),
    };
    let filter = SessionFilter {
        username: Some(name),
        limit: PAGE_SIZE,
        ..SessionFilter::default()
    };
    let sessions = match store::list_sessions(&state.db, &filter).await {
        Ok(rows) => rows
            .iter()
            .take(usize::try_from(PAGE_SIZE).unwrap_or(50))
            .map(SessionView::from)
            .collect(),
        Err(e) => return db_error("listing a user's sessions", &e),
    };
    html(
        UserPage {
            chrome: chrome(&state, &auth, "users"),
            notice: notice(q.done.as_deref()),
            u: view,
            sessions,
            events,
        }
        .render(),
    )
}

pub async fn lock_user(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<ReasonForm>,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let console = match console(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = auth.check_post(console, &headers, &form.csrf) {
        return r;
    }
    if name == auth.username {
        return error_page(
            StatusCode::BAD_REQUEST,
            "That would lock you out",
            "You can't lock your own account from the console. Ask another admin, or use the CLI if you really mean it.",
        );
    }
    match ops::lock_user(&state, actor(&auth), &name, &form.reason).await {
        Ok(_) => {
            let _ = store::delete_console_sessions_of(&state.db, &name).await;
            Redirect::to(&format!(
                "/console/users/{}?done=locked",
                path_segment(&name)
            ))
            .into_response()
        }
        Err(s) => action_error(&s),
    }
}

#[derive(Deserialize)]
pub struct CsrfOnly {
    csrf: String,
}

pub async fn unlock_user(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<CsrfOnly>,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let console = match console(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = auth.check_post(console, &headers, &form.csrf) {
        return r;
    }
    match ops::unlock_user(&state, actor(&auth), &name).await {
        Ok(_) => Redirect::to(&format!(
            "/console/users/{}?done=unlocked",
            path_segment(&name)
        ))
        .into_response(),
        Err(s) => action_error(&s),
    }
}

// ---- workers ---------------------------------------------------------------------------

pub async fn workers(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<DoneQuery>,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let (components, tunnels) = match db::list_components(&state.db).await {
        Ok(pair) => pair,
        Err(e) => return db_error("listing components", &e),
    };
    let components = components
        .into_iter()
        .map(|c| {
            let labels: BTreeMap<String, String> =
                serde_json::from_value(c.labels).unwrap_or_default();
            ComponentView {
                tunnels: tunnels
                    .iter()
                    .filter(|t| t.worker_id == c.id || t.proxy_id == c.id)
                    .count(),
                tunnel_peers: tunnel_peers(&tunnels, &c.id),
                name: c.name,
                path: path_segment(&c.id),
                last_seen: time_text(Some(c.last_seen_at)),
                cert_expires: time_text(c.cert_expires_at),
                revoked: c.revoked_at.is_some(),
                icon: if c.kind == "worker" {
                    "server"
                } else {
                    "radio"
                },
                kclass: if c.kind == "worker" {
                    "k-worker"
                } else {
                    "k-proxy"
                },
                // The name has its own place.
                label_list: labels
                    .iter()
                    .filter(|(k, _)| *k != NAME_LABEL)
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect(),
                kind: c.kind,
                id: c.id,
            }
        })
        .collect();
    let pending = match db::list_pending_join_tokens(&state.db).await {
        Ok(rows) => rows
            .into_iter()
            .map(|t| {
                let labels: BTreeMap<String, String> =
                    serde_json::from_value(t.labels).unwrap_or_default();
                let worker = t.kind == "worker";
                PendingTokenView {
                    name: t.name,
                    icon: if worker { "server" } else { "radio" },
                    kclass: if worker { "k-worker" } else { "k-proxy" },
                    label_list: labels.iter().map(|(k, v)| format!("{k}={v}")).collect(),
                    kind: t.kind,
                    created_by: t.created_by,
                    expires: time_text(Some(t.expires_at)),
                }
            })
            .collect(),
        Err(e) => return db_error("listing join tokens", &e),
    };
    html(
        Workers {
            chrome: chrome(&state, &auth, "workers"),
            notice: notice(q.done.as_deref()),
            components,
            pending,
        }
        .render(),
    )
}

/// The proxies holding `worker_id`'s tunnels, by name where they have one.
fn tunnel_peers(tunnels: &[db::TunnelRow], worker_id: &str) -> String {
    let mut proxies: Vec<&str> = tunnels
        .iter()
        .filter(|t| t.worker_id == worker_id)
        .map(|t| t.proxy_name.as_deref().unwrap_or(&t.proxy_id))
        .collect();
    proxies.dedup();
    if proxies.is_empty() {
        String::new()
    } else {
        format!("via {}", proxies.join(", "))
    }
}

#[derive(Deserialize)]
pub struct TokenForm {
    csrf: String,
    kind: String,
    #[serde(default)]
    labels: String,
    ttl_minutes: u32,
    #[serde(default)]
    dns_names: String,
    /// An exact name, or a pattern with one `*`. Empty: no name.
    #[serde(default)]
    name: String,
}

fn lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

pub async fn create_token(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let console = match console(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = auth.check_post(console, &headers, &form.csrf) {
        return r;
    }
    let mut labels = BTreeMap::new();
    for line in lines(&form.labels) {
        let Some((k, v)) = line.split_once('=') else {
            return error_page(
                StatusCode::BAD_REQUEST,
                "That didn't work",
                "Each label must be written key=value.",
            );
        };
        labels.insert(k.trim().to_owned(), v.trim().to_owned());
    }
    let dns_names: Vec<String> = lines(&form.dns_names)
        .into_iter()
        .map(str::to_owned)
        .collect();
    let ttl = Duration::from_secs(u64::from(form.ttl_minutes.clamp(1, 1440)) * 60);
    match ops::create_join_token(
        &state,
        actor(&auth),
        &form.kind,
        &labels,
        Some(ttl),
        &dns_names,
        Some(form.name.trim()),
    )
    .await
    {
        Ok((token, expires)) => html(
            TokenPage {
                chrome: chrome(&state, &auth, "workers"),
                token,
                kind: form.kind,
                expires: time_text(Some(expires)),
            }
            .render(),
        ),
        Err(s) => action_error(&s),
    }
}

pub async fn revoke(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<ReasonForm>,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let console = match console(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = auth.check_post(console, &headers, &form.csrf) {
        return r;
    }
    match ops::revoke_component(&state, actor(&auth), &id, &form.reason).await {
        Ok(_) => Redirect::to("/console/workers?done=revoked").into_response(),
        Err(s) => action_error(&s),
    }
}

// ---- policy ----------------------------------------------------------------------------

fn summarize(doc: &Document) -> String {
    match doc {
        Document::Role(r) => format!(
            "{} allow, {} deny rules",
            r.spec.allow.len(),
            r.spec.deny.len()
        ),
        Document::RoleMapping(m) => format!("{} group mappings", m.spec.len()),
        Document::Bot(b) => format!(
            "{} · roles {}",
            b.spec.join.method.as_str(),
            b.spec.roles.join(", ")
        ),
        Document::Resource(r) => r
            .spec
            .kinds()
            .iter()
            .map(|k| k.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    }
}

fn policy_groups(state: &AppState) -> Vec<PolicyGroup> {
    let docs = state.policy.current().policy.documents();
    [
        ("Roles", "role"),
        ("Role mappings", "role_mapping"),
        ("Resources", "resource"),
        ("Bots", "bot"),
    ]
    .into_iter()
    .map(|(title, kind)| PolicyGroup {
        title,
        docs: docs
            .iter()
            .filter(|d| d.kind() == kind)
            .map(|d| PolicyDoc {
                name: d.name().to_owned(),
                summary: summarize(d),
                yaml: serde_saphyr::to_string(d)
                    .unwrap_or_else(|e| format!("(couldn't render: {e})")),
            })
            .collect(),
    })
    .collect()
}

fn policy_page(state: &AppState, auth: &Auth, pasted: String, result: Option<DryRun>) -> Response {
    let loaded = state.policy.current();
    html(
        PolicyPage {
            chrome: chrome(state, auth, "policy"),
            version: loaded.version,
            digest: loaded.policy.digest(),
            author: if loaded.author.is_empty() {
                "—".into()
            } else {
                loaded.author.clone()
            },
            created: time_text(loaded.created_at),
            groups: policy_groups(state),
            pasted,
            result,
        }
        .render(),
    )
}

pub async fn policy(State(state): State<AppState>, auth: Auth) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    policy_page(&state, &auth, String::new(), None)
}

#[derive(Deserialize)]
pub struct DryRunForm {
    csrf: String,
    yaml: String,
}

/// What `limen admin apply --dry-run` would show. Never applies anything.
pub async fn dry_run(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Form(form): Form<DryRunForm>,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let console = match console(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = auth.check_post(console, &headers, &form.csrf) {
        return r;
    }
    if form.yaml.len() > 1024 * 1024 {
        return error_page(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Too large",
            "Policy YAML is limited to 1 MiB.",
        );
    }
    let result = match limen_policy::Policy::parse_yaml([("pasted", form.yaml.as_str())]) {
        Ok(next) => {
            let diff = state.policy.current().policy.diff(&next);
            DryRun {
                error: None,
                no_changes: diff.is_empty(),
                added: diff.added,
                changed: diff.changed,
                removed: diff.removed,
            }
        }
        Err(e) => DryRun {
            error: Some(e.to_string()),
            no_changes: false,
            added: vec![],
            changed: vec![],
            removed: vec![],
        },
    };
    policy_page(&state, &auth, form.yaml, Some(result))
}

#[derive(Deserialize)]
pub struct AuditQuery {
    user: Option<String>,
    kind: Option<String>,
    offset: Option<i64>,
}

pub async fn audit(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<AuditQuery>,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let user = q.user.clone().filter(|u| !u.is_empty());
    let kind = q.kind.clone().filter(|k| !k.is_empty());
    let offset = q.offset.unwrap_or(0).max(0);
    let mut rows = match store::list_events(
        &state.db,
        user.as_deref(),
        kind.as_deref(),
        PAGE_SIZE,
        offset,
    )
    .await
    {
        Ok(rows) => rows,
        Err(e) => return db_error("listing audit events", &e),
    };
    let kinds = store::event_kinds(&state.db).await.unwrap_or_default();
    let has_more = i64::try_from(rows.len()).is_ok_and(|n| n > PAGE_SIZE);
    rows.truncate(usize::try_from(PAGE_SIZE).unwrap_or(50));
    let link = |offset: i64| {
        let mut url = format!("/console/audit?offset={offset}");
        if let Some(u) = &user {
            url.push_str("&user=");
            url.push_str(&path_segment(u));
        }
        if let Some(k) = &kind {
            url.push_str("&kind=");
            url.push_str(&path_segment(k));
        }
        url
    };
    html(
        AuditPage {
            chrome: chrome(&state, &auth, "audit"),
            events: rows.iter().map(event_view).collect(),
            kinds,
            newer: (offset > 0).then(|| link((offset - PAGE_SIZE).max(0))),
            older: has_more.then(|| link(offset + PAGE_SIZE)),
            kind_filter: kind.clone(),
            user_filter: user.clone(),
        }
        .render(),
    )
}
