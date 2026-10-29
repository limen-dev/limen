//! Console page handlers. Admins see everything; everyone else sees their
//! own identity, resources, and sessions (ADR-0017).

use std::collections::BTreeMap;
use std::time::Duration;

use askama::Template;
use axum::extract::{Form, Path, Query, RawQuery, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use limen_core::names::NAME_LABEL;
use limen_policy::Document;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::query;
use super::store::{self, SessionFilter};
use super::views::{
    self, AuditPage, BotView, BotsPage, Chip, Chrome, ComponentView, DryRun, EventView, HitView,
    Home, KindTab, KubePage, KubeView, LabelLink, PendingTokenView, PolicyDoc, PolicyGroup,
    PolicyPage, ResourcePage, ResourceRow, ResourceView, ResourcesPage, RoleAccess, SearchView,
    SessionPage, SessionView, SessionsPage, Simulation, StatementView, Stats, TokenPage, UserPage,
    UserView, UsersPage, WebRequestView, WhoRow, WorkerMatch, Workers, error_page, list_text,
    path_segment, time_text,
};
use super::{Auth, Console, html};
use crate::db;
use crate::services::ops::{self, Actor};
use crate::state::AppState;

const PAGE_SIZE: i64 = 50;

pub(super) fn chrome(state: &AppState, auth: &Auth, active: &'static str) -> Chrome {
    Chrome::new(auth, active, state.policy.current().version)
}

/// What the viewer reaches: the roles in their login, plus roles approved
/// access requests gave them, less any an access review took away.
pub(super) async fn reachable_for(
    state: &AppState,
    auth: &Auth,
) -> Result<Vec<limen_policy::AccessibleResource>, Response> {
    crate::access::reachable(state, &auth.username, &auth.roles)
        .await
        .map(|v| v.into_iter().map(|(r, _)| r).collect())
        .map_err(|e| db_error("reading access grants", &e))
}

fn event_view(e: &store::EventRow) -> EventView {
    let (icon, kclass) =
        views::category_of(&e.kind).map_or(("activity", "k-other"), |c| (c.icon, c.kclass));
    EventView {
        at: time_text(Some(e.at)),
        icon,
        kclass,
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

/// The audit trail's category bar. `applied` is kept (period, user, text), the kind is
/// replaced by the tab's own; Kubernetes has its own page, which keeps none of them.
fn category_tabs(
    applied: &[(&str, String)],
    kind: &str,
    on_kube_page: bool,
) -> Vec<views::CategoryTab> {
    let keep: Vec<(&str, &str)> = applied
        .iter()
        .filter(|(k, _)| *k != "kind")
        .map(|(k, v)| (*k, v.as_str()))
        .collect();
    let mut tabs = vec![views::CategoryTab {
        label: "All events",
        icon: "activity",
        kclass: "k-other",
        href: query::href("/console/audit", &keep),
        active: kind.is_empty() && !on_kube_page,
    }];
    tabs.extend(views::CATEGORIES.iter().map(|c| {
        let kube = c.kinds == "kube.*";
        let mut pairs = keep.clone();
        pairs.push(("kind", c.kinds));
        views::CategoryTab {
            label: c.label,
            icon: c.icon,
            kclass: c.kclass,
            href: if kube {
                "/console/audit/kubernetes".to_owned()
            } else {
                query::href("/console/audit", &pairs)
            },
            active: if kube {
                on_kube_page
            } else {
                !on_kube_page && kind == c.kinds
            },
        }
    }));
    tabs
}

/// What `roles` reach under `policy`, and as which accounts.
fn access_for(policy: &limen_policy::Policy, roles: &[String]) -> Vec<ResourceView> {
    policy
        .accessible(roles)
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
        .collect()
}

fn actor(auth: &Auth) -> Actor<'_> {
    Actor {
        username: &auth.username,
        via: "console",
    }
}

pub(super) fn console(state: &AppState) -> Result<&Console, Response> {
    state
        .console
        .as_ref()
        .ok_or_else(|| StatusCode::NOT_FOUND.into_response())
}

pub(super) fn db_error(what: &str, e: &sqlx::Error) -> Response {
    tracing::error!(error = %e, "{what}");
    error_page(
        StatusCode::SERVICE_UNAVAILABLE,
        "Unavailable",
        "The console can't read its database right now. Try again shortly.",
    )
}

/// An admin action failed: show why, using the status the API would return.
pub(super) fn action_error(status: &tonic::Status) -> Response {
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
    /// The search box of the list pages.
    q: Option<String>,
}

/// The trimmed search text, empty if none.
fn search_text(q: Option<&String>) -> String {
    q.map(|s| s.trim().chars().take(200).collect())
        .unwrap_or_default()
}

/// Every word of `needle` appears (case-insensitively) in one of `fields`.
fn search_matches(needle: &str, fields: &[&str]) -> bool {
    let hay = fields.join(" ").to_lowercase();
    needle
        .to_lowercase()
        .split_whitespace()
        .all(|word| hay.contains(word))
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
    let reach = match reachable_for(&state, &auth).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let resources = reach
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
        username: (!auth.reads_record()).then(|| auth.username.clone()),
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
            if policy
                .accessible(std::slice::from_ref(&name))
                .iter()
                .any(|r| r.name == resource)
            {
                out.push(RoleAccess {
                    chip: views::Chip {
                        c: views::chip_color(&name),
                        text: name,
                    },
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

/// Every `label=key=value` in the query string (repeatable; a value may contain commas).
fn label_filters(raw: Option<&str>) -> Vec<String> {
    let mut labels: Vec<String> = url::form_urlencoded::parse(raw.unwrap_or_default().as_bytes())
        .filter(|(k, v)| k == "label" && v.split_once('=').is_some_and(|(key, _)| !key.is_empty()))
        .map(|(_, v)| v.into_owned())
        .collect();
    labels.sort();
    labels.dedup();
    labels
}

/// A `/console/resources` link for one filter combination, so every filter is shareable.
fn resources_href(kind: Option<&str>, q: &str, labels: &[String]) -> String {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    if let Some(k) = kind {
        ser.append_pair("kind", k);
    }
    if !q.is_empty() {
        ser.append_pair("q", q);
    }
    for l in labels {
        ser.append_pair("label", l);
    }
    let query = ser.finish();
    if query.is_empty() {
        "/console/resources".to_owned()
    } else {
        format!("/console/resources?{query}")
    }
}

pub async fn resources(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<ResourcesQuery>,
    RawQuery(raw): RawQuery,
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
    let accessible = match reachable_for(&state, &auth).await {
        Ok(r) => r,
        Err(r) => return r,
    };
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
    let label_filter = label_filters(raw.as_deref());
    let query_text = q.q.clone().unwrap_or_default();
    let mut kinds: Vec<String> = rows.iter().map(|r| r.kind.clone()).collect();
    kinds.sort();
    kinds.dedup();
    rows.retain(|r| {
        kind_filter.as_deref().is_none_or(|k| k == r.kind)
            && label_filter.iter().all(|l| r.labels.contains(l))
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
                        href: resources_href(Some(&k), &query_text, &label_filter),
                        current: kind_filter.as_deref() == Some(k.as_str()),
                        icon,
                        kclass,
                        name: k,
                    }
                })
                .collect(),
            all_selected: kind_filter.is_none(),
            all_href: resources_href(None, &query_text, &label_filter),
            active_labels: label_filter
                .iter()
                .map(|l| LabelLink {
                    text: l.clone(),
                    href: resources_href(
                        kind_filter.as_deref(),
                        &query_text,
                        &label_filter
                            .iter()
                            .filter(|o| *o != l)
                            .cloned()
                            .collect::<Vec<_>>(),
                    ),
                })
                .collect(),
            clear_href: resources_href(kind_filter.as_deref(), &query_text, &[]),
            kind_value: kind_filter.clone().unwrap_or_default(),
            label_values: label_filter.clone(),
            query: query_text.clone(),
            rows: rows
                .into_iter()
                .map(|r| {
                    let labels = r
                        .labels
                        .iter()
                        .map(|l| {
                            let mut next = label_filter.clone();
                            if !next.contains(l) {
                                next.push(l.clone());
                            }
                            LabelLink {
                                text: l.clone(),
                                href: resources_href(kind_filter.as_deref(), &query_text, &next),
                            }
                        })
                        .collect();
                    (r, labels)
                })
                .collect(),
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
    let accessible = match reachable_for(&state, &auth).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let mine = accessible.iter().find(|a| a.name == name);
    let may_ask = match crate::access::requestable_for(&state, &auth.username, &auth.roles).await {
        Ok(v) => v.into_iter().any(|r| r.name == name),
        Err(e) => return db_error("reading groups", &e),
    };
    if !auth.reads_record() && mine.is_none() && !may_ask {
        return not_found();
    }
    let kind = spec_kind(&r.spec);
    let (icon, kclass) = views::kind_icon(kind);
    let filter = SessionFilter {
        username: (!auth.reads_record()).then(|| auth.username.clone()),
        resource: Some(name.clone()),
        limit: 10,
        ..SessionFilter::default()
    };
    let sessions = match store::list_sessions(&state.db, &filter).await {
        Ok(rows) => rows.iter().take(10).map(SessionView::from).collect(),
        Err(e) => return db_error("listing a resource's sessions", &e),
    };
    let workers = if auth.is_admin {
        let (components, tunnels) = match db::list_components(&state.db).await {
            Ok(pair) => pair,
            Err(e) => return db_error("listing components", &e),
        };
        matching_workers(&components, &tunnels, &r.spec.worker_selector)
    } else {
        Vec::new()
    };
    let who_can = if auth.reads_record() {
        loaded
            .policy
            .who_can(&name)
            .into_iter()
            .map(|e| {
                let mut who: Vec<String> = e.groups.iter().map(|g| format!("group {g}")).collect();
                who.extend(e.bots.iter().map(|b| format!("bot {b}")));
                WhoRow {
                    role: Chip {
                        c: views::chip_color(&e.role),
                        text: e.role,
                    },
                    how: match e.via {
                        limen_policy::tooling::Via::Standing => "standing",
                        limen_policy::tooling::Via::Request => "by request",
                        limen_policy::tooling::Via::BreakGlass => "break-glass",
                    },
                    principals: e.principals.join(", "),
                    who: who.join(", "),
                    approvers: e.approvers.join(", "),
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    html(
        ResourcePage {
            can_request: may_ask && mine.is_none(),
            who_can,
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
            sessions,
        }
        .render(),
    )
}

// ---- sessions --------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct SessionsQuery {
    filter: Option<String>,
    user: Option<String>,
    resource: Option<String>,
    kind: Option<String>,
    actor: Option<String>,
    login: Option<String>,
    addr: Option<String>,
    end: Option<String>,
    repo: Option<String>,
    since: Option<String>,
    from: Option<String>,
    to: Option<String>,
    offset: Option<i64>,
    done: Option<String>,
}

pub async fn sessions(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<SessionsQuery>,
) -> Response {
    let active_only = q.filter.as_deref() == Some("active");
    // Others only ever see their own, whatever the query says.
    let user_filter = if auth.reads_record() {
        q.user.clone().filter(|u| !u.trim().is_empty())
    } else {
        Some(auth.username.clone())
    };
    let mut problems = Vec::new();
    let actor = actor_param(q.actor.as_ref());
    if q.actor.as_deref().is_some_and(|a| !a.is_empty()) && actor.is_none() {
        problems.push("Ignored the actor filter: use user or bot.".to_owned());
    }
    let (mut from, to, ignored) = query::parse_range(q.from.as_deref(), q.to.as_deref());
    problems.extend(ignored);
    let since = since_param(q.since.as_ref(), from.is_some());
    if let Some(key) = &since {
        from = query::since(key);
    }
    let since_text = since.unwrap_or_default();
    let actor_text = actor.clone().unwrap_or_default();
    let when = |t: Option<time::OffsetDateTime>, raw: &Option<String>| {
        t.map(|_| raw.clone().unwrap_or_default().trim().to_owned())
            .unwrap_or_default()
    };
    let (from_text, to_text) = (
        if since_text.is_empty() {
            when(from, &q.from)
        } else {
            String::new()
        },
        when(to, &q.to),
    );
    let shown_user = if auth.is_admin {
        user_filter.clone().unwrap_or_default()
    } else {
        String::new()
    };
    let active_text = if active_only {
        "active".to_owned()
    } else {
        String::new()
    };
    let applied = present(&[
        ("filter", Some(&active_text)),
        ("user", Some(&shown_user)),
        ("resource", q.resource.as_ref()),
        ("kind", q.kind.as_ref()),
        ("actor", Some(&actor_text)),
        ("login", q.login.as_ref()),
        ("addr", q.addr.as_ref()),
        ("end", q.end.as_ref()),
        ("repo", q.repo.as_ref()),
        ("since", Some(&since_text)),
        ("from", Some(&from_text)),
        ("to", Some(&to_text)),
    ]);
    let value = |key: &str| {
        applied
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.clone())
    };
    let offset = q.offset.unwrap_or(0).max(0);
    let filter = SessionFilter {
        username: user_filter.clone(),
        resource: value("resource"),
        actor,
        kind: value("kind"),
        login: value("login"),
        client_addr: value("addr"),
        end_reason: value("end"),
        repo: value("repo"),
        from,
        to,
        active_only,
        limit: PAGE_SIZE,
        offset,
    };
    let mut rows = match store::list_sessions(&state.db, &filter).await {
        Ok(rows) => rows,
        Err(e) => return db_error("listing sessions", &e),
    };
    let has_more = i64::try_from(rows.len()).is_ok_and(|n| n > PAGE_SIZE);
    rows.truncate(usize::try_from(PAGE_SIZE).unwrap_or(50));
    let link = |offset: i64| {
        let offset = offset.to_string();
        let mut pairs: Vec<(&str, &str)> = applied.iter().map(|(k, v)| (*k, v.as_str())).collect();
        pairs.push(("offset", offset.as_str()));
        query::href("/console/sessions", &pairs)
    };
    html(
        SessionsPage {
            chrome: chrome(&state, &auth, "sessions"),
            notice: notice(q.done.as_deref()),
            sessions: rows.iter().map(SessionView::from).collect(),
            active_only,
            user_filter: auth.reads_record().then(|| user_filter.clone()).flatten(),
            filter: views::SessionFilterView {
                user: shown_user.clone(),
                resource: value("resource").unwrap_or_default(),
                kind: value("kind").unwrap_or_default(),
                actor: actor_text.clone(),
                login: value("login").unwrap_or_default(),
                addr: value("addr").unwrap_or_default(),
                end: value("end").unwrap_or_default(),
                repo: value("repo").unwrap_or_default(),
                from: from_text.clone(),
                to: to_text.clone(),
            },
            chips: chips("/console/sessions", &applied),
            presets: presets("/console/sessions", &applied),
            suggest: store::suggestions(
                &state.db,
                (!auth.reads_record()).then_some(auth.username.as_str()),
            )
            .await,
            more_open: !from_text.is_empty() || !to_text.is_empty(),
            clear: if active_only {
                "/console/sessions?filter=active".to_owned()
            } else {
                "/console/sessions".to_owned()
            },
            problems,
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
    if auth.reads_record() || row.username.as_deref() == Some(auth.username.as_str()) {
        Ok(row)
    } else {
        Err(not_found())
    }
}

/// The most statements the session page lists.
const STATEMENT_LIMIT: i64 = 500;

#[derive(Deserialize)]
pub struct MomentQuery {
    t: Option<i64>,
}

pub async fn session_detail(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Query(moment): Query<MomentQuery>,
) -> Response {
    match visible_session(&state, &auth, &id).await {
        Ok(row) => {
            let mut s = SessionView::from(&row);
            // Names beside the ids, for the components that have one.
            s.proxy = with_name(&state, row.proxy_id.as_deref(), s.proxy).await;
            s.worker = with_name(&state, row.worker_id.as_deref(), s.worker).await;
            // Best effort: the page still renders without the statements.
            let (requests, request_total, request_problems) = if s.is_kubectl {
                let filter = store::KubeFilter {
                    login_session: Some(row.session_id),
                    limit: STATEMENT_LIMIT,
                    ..store::KubeFilter::default()
                };
                let list = store::list_kube_requests(&state.db, &filter)
                    .await
                    .unwrap_or_default();
                let (total, problems) = store::kube_session_counts(&state.db, row.session_id)
                    .await
                    .unwrap_or_default();
                let shown = usize::try_from(STATEMENT_LIMIT).unwrap_or(500);
                (
                    list.iter().take(shown).map(kube_view).collect(),
                    total,
                    problems,
                )
            } else {
                (Vec::new(), 0, 0)
            };
            let (statements, statement_total, statement_errors) = if s.has_statements {
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
            let (web_requests, web_request_total, web_request_problems) = if s.is_web {
                let rows = store::web_requests(&state.db, row.session_id, STATEMENT_LIMIT)
                    .await
                    .unwrap_or_default();
                let (total, problems) = store::web_session_counts(&state.db, row.session_id)
                    .await
                    .unwrap_or_default();
                (
                    rows.iter().map(WebRequestView::from).collect(),
                    total,
                    problems,
                )
            } else {
                (Vec::new(), 0, 0)
            };
            let (allowed_by, watched) =
                super::workflows::session_extras(&state, row.session_id).await;
            html(
                SessionPage {
                    start_at: moment.t.unwrap_or(0).clamp(0, 86_400 * 7),
                    allowed_by,
                    watched,
                    can_watch: crate::live::may_watch(&state, auth.is_admin, auth.is_auditor),
                    chrome: chrome(&state, &auth, "sessions"),
                    s,
                    statements,
                    requests,
                    request_total,
                    request_problems,
                    web_requests,
                    web_request_total,
                    web_request_problems,
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
    let query = search_text(q.q.as_ref());
    let wanted = |u: &UserView| {
        let chips: Vec<&str> = u
            .role_list
            .iter()
            .chain(&u.group_list)
            .map(|c| c.text.as_str())
            .collect();
        search_matches(&query, &[u.name.as_str(), &chips.join(" ")])
    };
    let orphan_locks = locks
        .iter()
        .filter(|l| !known.contains(&l.username))
        .map(|l| lock_only_view(&l.username, l))
        .filter(&wanted)
        .collect();
    html(
        UsersPage {
            chrome: chrome(&state, &auth, "users"),
            notice: notice(q.done.as_deref()),
            users: users.iter().map(UserView::from).filter(&wanted).collect(),
            query,
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
    let bots: Vec<BotView> = policy
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
    let query = search_text(q.q.as_ref());
    let bots: Vec<BotView> = bots
        .into_iter()
        .filter(|b| {
            let role_names: Vec<&str> = b.roles.iter().map(|c| c.text.as_str()).collect();
            let claims: Vec<&str> = b
                .rules
                .iter()
                .flat_map(|f| [f.key.as_str(), f.value.as_str()])
                .collect();
            search_matches(
                &query,
                &[
                    &b.name,
                    &b.description,
                    &b.issuer,
                    b.method,
                    &role_names.join(" "),
                    &claims.join(" "),
                ],
            )
        })
        .collect();
    html(
        BotsPage {
            chrome: chrome(&state, &auth, "bots"),
            notice: notice(q.done.as_deref()),
            query,
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
    let events = match store::list_events(
        &state.db,
        &store::EventFilter {
            username: Some(name.clone()),
            ..store::EventFilter::default()
        },
        15,
        0,
    )
    .await
    {
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
    let loaded = state.policy.current();
    let role_names: Vec<String> = view.role_list.iter().map(|r| r.text.clone()).collect();
    html(
        UserPage {
            chrome: chrome(&state, &auth, "users"),
            notice: notice(q.done.as_deref()),
            access: access_for(&loaded.policy, &role_names),
            policy_version: loaded.version,
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
    let components: Vec<ComponentView> = components
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
    let query = search_text(q.q.as_ref());
    let components: Vec<ComponentView> = components
        .into_iter()
        .filter(|c| {
            search_matches(
                &query,
                &[
                    &c.id,
                    c.name.as_deref().unwrap_or_default(),
                    &c.kind,
                    &c.label_list.join(" "),
                ],
            )
        })
        .collect();
    html(
        Workers {
            chrome: chrome(&state, &auth, "workers"),
            notice: notice(q.done.as_deref()),
            query,
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
        Document::Discovery(d) => format!(
            "{} matchers in {}",
            d.spec.matchers.len(),
            d.spec.regions.join(", ")
        ),
        Document::PolicyTest(t) => format!("{} cases", t.spec.cases.len()),
        Document::ResourceProfile(p) => format!(
            "{} settable fields: {}",
            p.spec.settable.len(),
            p.spec
                .settable
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Document::PolicyWriter(w) => format!(
            "bot {} · namespace {} · up to {} documents",
            w.spec.bot, w.spec.namespace, w.spec.max_documents
        ),
    }
}

/// The policy's documents by kind, each with its owner. Only documents the
/// console owns can be edited here; the rest belong to another channel.
async fn policy_groups(state: &AppState) -> Vec<PolicyGroup> {
    let docs = state.policy.base().policy.documents();
    let heads = crate::policy_store::heads(&state.db)
        .await
        .inspect_err(|e| tracing::warn!(error = %e, "reading document owners"))
        .unwrap_or_default();
    let console = super::policy_edit::console_owner();
    [
        ("Roles", "role"),
        ("Role mappings", "role_mapping"),
        ("Resources", "resource"),
        ("Bots", "bot"),
        ("Discovery", "discovery"),
        ("Policy tests", "policy_test"),
        ("Resource profiles", "resource_profile"),
        ("Policy writers", "policy_writer"),
    ]
    .into_iter()
    .map(|(title, kind)| PolicyGroup {
        title,
        docs: docs
            .iter()
            .filter(|d| d.kind() == kind)
            .map(|d| {
                let head = heads.get(&(kind.to_owned(), d.name().to_owned()));
                PolicyDoc {
                    kind,
                    name: d.name().to_owned(),
                    summary: summarize(d),
                    yaml: serde_saphyr::to_string(d)
                        .unwrap_or_else(|e| format!("(couldn't render: {e})")),
                    owner: head.map_or_else(|| "unknown".to_owned(), |h| h.owner.describe()),
                    editable: head.is_some_and(|h| h.owner == console),
                    etag: head.map(|h| h.etag.clone()).unwrap_or_default(),
                }
            })
            .collect(),
    })
    .collect()
}

/// What the policy page shows besides the documents.
#[derive(Default)]
struct PolicyExtras {
    pasted: String,
    result: Option<DryRun>,
    simulation: Option<Simulation>,
    query: String,
    /// A new document being written, kept when the write was refused.
    draft: String,
    error: Option<String>,
    notice: Option<String>,
}

async fn policy_page(state: &AppState, auth: &Auth, extras: PolicyExtras) -> Response {
    let loaded = state.policy.base();
    let query = extras.query;
    let groups: Vec<views::PolicyGroup> = policy_groups(state)
        .await
        .into_iter()
        .map(|mut g| {
            g.docs
                .retain(|d| search_matches(&query, &[&d.name, &d.summary, &d.yaml]));
            g
        })
        .filter(|g| !g.docs.is_empty())
        .collect();
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
            groups,
            query,
            pasted: extras.pasted,
            result: extras.result,
            simulation: extras.simulation,
            draft: extras.draft,
            error: extras.error,
            notice: extras.notice,
        }
        .render(),
    )
}

/// The policy page after a refused console write: the reason, and a new
/// document's YAML kept for another try.
pub(super) async fn policy_page_with(
    state: &AppState,
    auth: &Auth,
    draft: String,
    error: Option<String>,
) -> Response {
    policy_page(
        state,
        auth,
        PolicyExtras {
            draft,
            error,
            ..PolicyExtras::default()
        },
    )
    .await
}

pub async fn policy(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<DoneQuery>,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    policy_page(
        &state,
        &auth,
        PolicyExtras {
            query: search_text(q.q.as_ref()),
            notice: q.done.as_deref().and_then(super::policy_edit::notice),
            ..PolicyExtras::default()
        },
    )
    .await
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
            let base = state.policy.base();
            let diff = base.policy.diff(&next);
            let access = base.policy.access_diff(&next);
            let report = next.run_tests();
            DryRun {
                access: access
                    .changes
                    .iter()
                    .map(|c| {
                        (
                            c.change == limen_policy::tooling::ChangeKind::Gain,
                            c.text(),
                        )
                    })
                    .collect(),
                warnings: next.warnings(),
                tests: report
                    .results
                    .iter()
                    .map(|r| {
                        (
                            r.passed,
                            if r.passed {
                                format!("{}: {}", r.test, r.name)
                            } else {
                                format!(
                                    "{}: {} (expected {}, got {} {})",
                                    r.test, r.name, r.expected, r.got, r.detail
                                )
                            },
                        )
                    })
                    .collect(),
                error: None,
                no_changes: diff.is_empty(),
                added: diff.added,
                changed: diff.changed,
                removed: diff.removed,
            }
        }
        Err(e) => DryRun {
            access: vec![],
            warnings: vec![],
            tests: vec![],
            error: Some(e.to_string()),
            no_changes: false,
            added: vec![],
            changed: vec![],
            removed: vec![],
        },
    };
    policy_page(
        &state,
        &auth,
        PolicyExtras {
            pasted: form.yaml,
            result: Some(result),
            ..PolicyExtras::default()
        },
    )
    .await
}

#[derive(Deserialize)]
pub struct SimulateForm {
    csrf: String,
    #[serde(default)]
    groups: String,
    #[serde(default)]
    bot: String,
}

/// `POST /console/policy/simulate`: what groups or a bot can reach and could ask for.
pub async fn simulate(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Form(form): Form<SimulateForm>,
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
    let groups: Vec<String> = form
        .groups
        .split(',')
        .map(str::trim)
        .filter(|g| !g.is_empty())
        .take(50)
        .map(str::to_owned)
        .collect();
    let bot = Some(form.bot.trim()).filter(|b| !b.is_empty());
    let who = match (groups.is_empty(), bot) {
        (false, _) => format!("Members of {}", groups.join(" and ")),
        (true, Some(b)) => format!("The bot {b}"),
        (true, None) => String::new(),
    };
    let current = state.policy.current();
    let sim = if who.is_empty() {
        Simulation {
            who,
            error: Some("Name at least one group, or a bot.".into()),
            standing: vec![],
            requestable: vec![],
        }
    } else {
        match current
            .policy
            .what_can(&groups, if groups.is_empty() { bot } else { None })
        {
            Ok(can) => Simulation {
                who,
                error: None,
                standing: can
                    .standing
                    .into_iter()
                    .map(|r| (r.name, r.kind.as_str().to_owned(), r.principals.join(", ")))
                    .collect(),
                requestable: can
                    .requestable
                    .into_iter()
                    .map(|r| (r.name, r.kind.as_str().to_owned(), r.roles.join(", ")))
                    .collect(),
            },
            Err(e) => Simulation {
                who,
                error: Some(e),
                standing: vec![],
                requestable: vec![],
            },
        }
    };
    policy_page(
        &state,
        &auth,
        PolicyExtras {
            simulation: Some(sim),
            ..PolicyExtras::default()
        },
    )
    .await
}

fn kube_view(r: &store::KubeRow) -> KubeView {
    // No resource (`/version`, `/healthz`): the path says what was asked.
    let mut resource = if r.resource.is_empty() {
        r.path.clone()
    } else {
        r.resource.clone()
    };
    if !r.api_group.is_empty() && !r.resource.is_empty() {
        resource = format!("{resource}.{}", r.api_group);
    }
    if !r.subresource.is_empty() {
        resource = format!("{resource}/{}", r.subresource);
    }
    KubeView {
        at: time_text(Some(r.at)),
        user_path: r.username.as_deref().map(path_segment),
        user: r.username.clone(),
        session_path: r.login_session.map(|id| id.to_string()),
        stream_path: r
            .session_id
            .filter(|_| matches!(r.subresource.as_str(), "exec" | "attach" | "portforward"))
            .map(|id| id.to_string()),
        cluster: r.cluster.clone(),
        verb: r.verb.clone(),
        resource,
        namespace: r.namespace.clone(),
        name: r.name.clone(),
        status: r.status,
        tone: if r.status >= 400 { "bad" } else { "ok" },
        latency: r
            .latency_ms
            .map(|ms| format!("{ms} ms"))
            .unwrap_or_default(),
        error: r.error.clone(),
    }
}

#[derive(Deserialize)]
pub struct KubeQuery {
    user: Option<String>,
    cluster: Option<String>,
    namespace: Option<String>,
    verb: Option<String>,
    problems: Option<String>,
    offset: Option<i64>,
}

/// The audit trail's Kubernetes tab: every API request, as kubectl would say it.
pub async fn kube_requests(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<KubeQuery>,
) -> Response {
    if let Err(r) = auth.reader() {
        return r;
    }
    let pick = |v: &Option<String>| v.clone().filter(|s| !s.is_empty());
    let offset = q.offset.unwrap_or(0).max(0);
    let filter = store::KubeFilter {
        username: pick(&q.user),
        cluster: pick(&q.cluster),
        namespace: pick(&q.namespace),
        verb: pick(&q.verb),
        problems_only: q.problems.is_some_and(|p| p == "1"),
        login_session: None,
        limit: PAGE_SIZE,
        offset,
    };
    let mut rows = match store::list_kube_requests(&state.db, &filter).await {
        Ok(rows) => rows,
        Err(e) => return db_error("listing Kubernetes requests", &e),
    };
    let (clusters, verbs) = store::kube_filter_options(&state.db)
        .await
        .unwrap_or_default();
    let has_more = i64::try_from(rows.len()).is_ok_and(|n| n > PAGE_SIZE);
    rows.truncate(usize::try_from(PAGE_SIZE).unwrap_or(50));
    let link = |offset: i64| {
        let mut url = format!("/console/audit/kubernetes?offset={offset}");
        for (key, value) in [
            ("user", &filter.username),
            ("cluster", &filter.cluster),
            ("namespace", &filter.namespace),
            ("verb", &filter.verb),
        ] {
            if let Some(v) = value {
                url.push_str(&["&", key, "=", &path_segment(v)].concat());
            }
        }
        if filter.problems_only {
            url.push_str("&problems=1");
        }
        url
    };
    html(
        KubePage {
            chrome: chrome(&state, &auth, "audit"),
            tabs: category_tabs(&[], "", true),
            requests: rows.iter().map(kube_view).collect(),
            clusters,
            verbs,
            cluster_filter: filter.cluster.clone(),
            verb_filter: filter.verb.clone(),
            user_filter: filter.username.clone(),
            namespace_filter: filter.namespace.clone(),
            problems_only: filter.problems_only,
            newer: (offset > 0).then(|| link((offset - PAGE_SIZE).max(0))),
            older: has_more.then(|| link(offset + PAGE_SIZE)),
        }
        .render(),
    )
}

#[derive(Deserialize, Default)]
pub struct AuditQuery {
    /// The full-text search (`q` is the details filter).
    find: Option<String>,
    user: Option<String>,
    kind: Option<String>,
    actor: Option<String>,
    q: Option<String>,
    session: Option<String>,
    since: Option<String>,
    from: Option<String>,
    to: Option<String>,
    offset: Option<i64>,
}

/// The non-empty values of the filters a query asked for, in a fixed order.
fn present<'a>(fields: &[(&'a str, Option<&String>)]) -> Vec<(&'a str, String)> {
    fields
        .iter()
        .filter_map(|(k, v)| {
            v.map(|v| v.trim().chars().take(200).collect::<String>())
                .filter(|v| !v.is_empty())
                .map(|v| (*k, v))
        })
        .collect()
}

fn filter_name(key: &str) -> &'static str {
    match key {
        "kind" => "Kind",
        "user" => "User",
        "actor" => "Actor",
        "q" => "Text",
        "session" => "Session",
        "from" => "From",
        "to" => "To",
        "resource" => "Resource",
        "login" => "Account",
        "addr" => "Address",
        "end" => "Ended",
        "repo" => "Repository",
        "filter" => "Show",
        "since" => "Period",
        _ => "Filter",
    }
}

/// A removable chip for each applied filter; `base` is the page's path.
fn chips(base: &str, applied: &[(&str, String)]) -> Vec<views::FilterChip> {
    applied
        .iter()
        .filter(|(key, _)| *key != "filter")
        .map(|(key, value)| {
            let rest: Vec<(&str, &str)> = applied
                .iter()
                .filter(|(k, _)| k != key)
                .map(|(k, v)| (*k, v.as_str()))
                .collect();
            let shown = if *key == "since" {
                query::PRESETS
                    .iter()
                    .find(|p| p.0 == value)
                    .map_or(value.as_str(), |p| p.1)
            } else if *key == "kind" {
                views::CATEGORIES
                    .iter()
                    .find(|c| c.kinds == value)
                    .map_or(value.as_str(), |c| c.label)
            } else {
                value.as_str()
            };
            views::FilterChip {
                label: format!("{}: {shown}", filter_name(key)),
                remove: query::href(base, &rest),
            }
        })
        .collect()
}

/// `user` or `bot`, or nothing.
fn actor_param(raw: Option<&String>) -> Option<String> {
    raw.map(|a| a.trim().to_ascii_lowercase())
        .filter(|a| a == "user" || a == "bot")
}

/// A quick range: its key if known (and no explicit `from`), else nothing.
fn since_param(raw: Option<&String>, explicit_from: bool) -> Option<String> {
    raw.map(|k| k.trim().to_owned())
        .filter(|k| !explicit_from && query::since(k).is_some())
}

/// The quick-range links for a page; `applied` is what's in effect now.
fn presets(base: &str, applied: &[(&str, String)]) -> Vec<views::Preset> {
    let current = applied
        .iter()
        .find(|(k, _)| *k == "since")
        .map_or("", |(_, v)| v.as_str());
    let custom = applied.iter().any(|(k, _)| *k == "from" || *k == "to");
    query::PRESETS
        .iter()
        .map(|(key, label, _)| {
            let mut pairs: Vec<(&str, &str)> = applied
                .iter()
                .filter(|(k, _)| !matches!(*k, "since" | "from" | "to"))
                .map(|(k, v)| (*k, v.as_str()))
                .collect();
            pairs.push(("since", key));
            views::Preset {
                label,
                href: query::href(base, &pairs),
                active: !custom && current == *key,
            }
        })
        .collect()
}

pub async fn audit(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<AuditQuery>,
) -> Response {
    if let Err(r) = auth.reader() {
        return r;
    }
    let find = q.find.clone().unwrap_or_default();
    let search = if find.trim().is_empty() {
        None
    } else {
        Some(run_search(&state, &auth, &find).await)
    };
    let mut problems = Vec::new();
    let actor = actor_param(q.actor.as_ref());
    if q.actor.as_deref().is_some_and(|a| !a.is_empty()) && actor.is_none() {
        problems.push("Ignored the actor filter: use user or bot.".to_owned());
    }
    let session = q
        .session
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| {
            let id = Uuid::parse_str(s).ok();
            if id.is_none() {
                problems.push(format!("Ignored “{s}” for Session: not a session id."));
            }
            id
        });
    let (mut from, to, ignored) = query::parse_range(q.from.as_deref(), q.to.as_deref());
    problems.extend(ignored);
    let since = since_param(q.since.as_ref(), from.is_some());
    if let Some(key) = &since {
        from = query::since(key);
    }
    let since_text = since.unwrap_or_default();
    let actor_text = actor.clone().unwrap_or_default();
    let session_text = session.map(|id| id.to_string()).unwrap_or_default();
    let when = |t: Option<time::OffsetDateTime>, raw: &Option<String>| {
        t.map(|_| raw.clone().unwrap_or_default().trim().to_owned())
            .unwrap_or_default()
    };
    let (from_text, to_text) = (
        if since_text.is_empty() {
            when(from, &q.from)
        } else {
            String::new()
        },
        when(to, &q.to),
    );
    let applied = present(&[
        ("kind", q.kind.as_ref()),
        ("user", q.user.as_ref()),
        ("actor", Some(&actor_text)),
        ("q", q.q.as_ref()),
        ("session", Some(&session_text)),
        ("since", Some(&since_text)),
        ("from", Some(&from_text)),
        ("to", Some(&to_text)),
    ]);
    let value = |key: &str| {
        applied
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.clone())
    };
    let filter = store::EventFilter {
        username: value("user"),
        kind: value("kind"),
        actor,
        text: value("q"),
        session_id: session,
        from,
        to,
    };
    let offset = q.offset.unwrap_or(0).max(0);
    let mut rows = match store::list_events(&state.db, &filter, PAGE_SIZE, offset).await {
        Ok(rows) => rows,
        Err(e) => return db_error("listing audit events", &e),
    };
    let kinds = store::event_kinds(&state.db).await.unwrap_or_default();
    let has_more = i64::try_from(rows.len()).is_ok_and(|n| n > PAGE_SIZE);
    rows.truncate(usize::try_from(PAGE_SIZE).unwrap_or(50));
    let link = |offset: i64| {
        let offset = offset.to_string();
        let mut pairs: Vec<(&str, &str)> = applied.iter().map(|(k, v)| (*k, v.as_str())).collect();
        pairs.push(("offset", offset.as_str()));
        query::href("/console/audit", &pairs)
    };
    html(
        AuditPage {
            q: find,
            search,
            chrome: chrome(&state, &auth, "audit"),
            events: rows.iter().map(event_view).collect(),
            tabs: category_tabs(&applied, &value("kind").unwrap_or_default(), false),
            groups: &views::CATEGORIES,
            kinds,
            filter: views::AuditFilterView {
                kind: value("kind").unwrap_or_default(),
                user: value("user").unwrap_or_default(),
                actor: actor_text.clone(),
                text: value("q").unwrap_or_default(),
                session: session_text.clone(),
                from: from_text.clone(),
                to: to_text.clone(),
            },
            chips: chips("/console/audit", &applied),
            presets: presets("/console/audit", &applied),
            suggest: store::suggestions(&state.db, None).await,
            more_open: !from_text.is_empty() || !to_text.is_empty(),
            clear: "/console/audit".to_owned(),
            problems,
            newer: (offset > 0).then(|| link((offset - PAGE_SIZE).max(0))),
            older: has_more.then(|| link(offset + PAGE_SIZE)),
        }
        .render(),
    )
}

/// Search the audit trail for the Audit page. A failed search shows why on
/// the page instead of replacing it.
async fn run_search(state: &AppState, auth: &Auth, text: &str) -> SearchView {
    let searcher = crate::search::Searcher {
        username: &auth.username,
        via: "console",
    };
    match crate::search::search(state, searcher, text, 50).await {
        Ok(r) => SearchView {
            error: None,
            truncated: r.truncated,
            history_url: state.config.search_history_url.as_deref().and_then(|t| {
                crate::search::query::parse(text, time::OffsetDateTime::now_utc())
                    .ok()
                    .map(|q| crate::search::history_link(t, text, &q))
            }),
            hits: r
                .hits
                .iter()
                .map(|h| {
                    let moment = h
                        .recording_offset_secs
                        .map(|s| format!("{}:{:02}", s / 60, s % 60));
                    HitView {
                        at: time_text(Some(h.at)),
                        kind: h.kind.clone(),
                        user: h.user.clone().unwrap_or_default(),
                        resource: h.resource.clone().unwrap_or_default(),
                        denied: h.outcome == "denied",
                        before: h.snippet.before.clone(),
                        hit: h.snippet.hit.clone(),
                        after: h.snippet.after.clone(),
                        href: h.session_id.map(|id| match h.recording_offset_secs {
                            Some(t) => format!("/console/sessions/{id}?t={t}"),
                            None => format!("/console/sessions/{id}"),
                        }),
                        moment,
                    }
                })
                .collect(),
        },
        Err(status) => SearchView {
            error: Some(status.message().to_owned()),
            hits: Vec::new(),
            truncated: false,
            history_url: None,
        },
    }
}

#[cfg(test)]
mod label_filter_tests {
    use super::*;

    #[test]
    fn collects_repeated_labels_and_keeps_commas() {
        let got = label_filters(Some(
            "kind=ssh&label=env%3Dprod&label=note%3Da%2Cb&label=bad&label=env%3Dprod",
        ));
        assert_eq!(got, ["env=prod", "note=a,b"]);
        assert_eq!(label_filters(None), Vec::<String>::new());
    }

    #[test]
    fn href_round_trips() {
        let href = resources_href(Some("ssh"), "web", &["note=a,b".into(), "env=prod".into()]);
        let (_, query) = href.split_once('?').expect("query string");
        assert_eq!(label_filters(Some(query)), ["env=prod", "note=a,b"]);
    }
}
