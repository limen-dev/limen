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
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use super::connect_builder;
use super::pins;
use super::query;
use super::resource_ui::{self, ResourceSort};
use super::store::{self, SessionFilter};
use super::views::{
    self, AuditPage, BotView, BotsPage, Chip, Chrome, ComponentView, EventView, HitView, Home,
    KindTab, KubePage, KubeView, LabelLink, PendingTokenView, PolicyDoc, PolicyGroup, PolicyPage,
    ResourcePage, ResourceRow, ResourceView, ResourcesPage, RoleAccess, SearchView, SessionPage,
    SessionView, SessionsPage, Simulation, SimulatorPage, StatementView, Stats, TokenPage,
    UserPage, UserView, UsersPage, WebRequestView, WhoRow, WorkerMatch, Workers, error_page,
    list_text, path_segment, time_text,
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
            "auth.denied" | "user.lock" | "user.delete" | "session.kill" | "component.revoke"
            | "idp.offboard" | "idp.check_failed" => "bad",
            "auth.login" | "user.unlock" | "user.provision" | "worker.enroll" => "ok",
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
            path: path_segment(&r.name),
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
        "deleted" => "User deleted. Their sessions and audit history stay.",
        "killed" => "The session will end within about 11 seconds.",
        "killed_many" => "The selected sessions will end within about 11 seconds.",
        "killed_some" => {
            "Some of the selected sessions were ended; the rest had already ended or could not be."
        }
        "revoked" => "Revoked. Proxies drop its tunnels within about 10 seconds.",
        "revoked_many" => "Revoked. Proxies drop their tunnels within about 10 seconds.",
        "revoked_some" => {
            "Some of the selected components were revoked; the rest were already revoked or could not be."
        }
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

/// What is waiting for this viewer, most urgent first. Each line links to where it is dealt with.
/// Counts are of things the viewer may already see on those pages; a line with nothing behind it
/// is left out, so an empty card is no card.
async fn attention_items(
    state: &AppState,
    auth: &Auth,
    overview: &Stats,
) -> Result<Vec<views::AttentionItem>, Response> {
    let mut items = Vec::new();
    // A console session that is about to end loses an unsaved form and the page you were on.
    let left = auth.expires_at - time::OffsetDateTime::now_utc();
    if left < time::Duration::minutes(30) {
        let minutes = usize::try_from(left.whole_minutes().max(0)).unwrap_or(0);
        items.push(views::AttentionItem {
            text: format!(
                "Your console session ends in {}. Sign in again to keep working",
                plural(minutes, "minute", "minutes")
            ),
            href: "/console/login".to_owned(),
            tone: "warn",
        });
    }
    if auth.is_admin {
        items.extend(admin_attention(state, overview).await?);
    }
    items.extend(approval_attention(state, auth).await?);
    Ok(items)
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Admins: resources no worker serves, and disabled accounts.
async fn admin_attention(
    state: &AppState,
    overview: &Stats,
) -> Result<Vec<views::AttentionItem>, Response> {
    let mut items = Vec::new();
    let (components, tunnels) = db::list_components(&state.db)
        .await
        .map_err(|e| db_error("listing components", &e))?;
    let loaded = state.policy.current();
    let down = loaded
        .policy
        .documents()
        .iter()
        .filter_map(|d| match d {
            Document::Resource(r) => Some(r),
            _ => None,
        })
        .filter(|r| {
            views::Health::of(&matching_workers(
                &components,
                &tunnels,
                &r.spec.worker_selector,
            ))
            .needs_attention()
        })
        .count();
    if down > 0 {
        items.push(views::AttentionItem {
            text: format!(
                "{} without a connected worker, so sessions will fail",
                plural(down, "resource", "resources")
            ),
            href: "/console/resources?sort=attention&attention=1".to_owned(),
            tone: "bad",
        });
    }
    if overview.locked > 0 {
        items.push(views::AttentionItem {
            text: format!(
                "{} disabled",
                plural(overview.locked, "account", "accounts")
            ),
            href: "/console/users".to_owned(),
            tone: "warn",
        });
    }
    Ok(items)
}

/// Policy changes, access reviews and access requests that wait for this viewer, and their own
/// requests that still wait for someone else.
async fn approval_attention(
    state: &AppState,
    auth: &Auth,
) -> Result<Vec<views::AttentionItem>, Response> {
    let mut items = Vec::new();
    if auth.sees_changes {
        let waiting = super::policy_edit::waiting_for(state, auth).await;
        if waiting > 0 {
            items.push(views::AttentionItem {
                text: format!(
                    "{} waiting for your review",
                    plural(waiting, "policy change", "policy changes")
                ),
                href: "/console/changes".to_owned(),
                tone: "warn",
            });
        }
    }
    if auth.sees_reviews {
        let who = crate::reviews::Who {
            username: &auth.username,
            is_admin: auth.is_admin,
            is_auditor: auth.is_auditor,
            via: "console",
        };
        let open = crate::reviews::list(state, &who, false)
            .await
            .map_err(|s| action_error(&s))?
            .iter()
            .filter(|r| r.status != "complete")
            .count();
        if open > 0 {
            items.push(views::AttentionItem {
                text: format!(
                    "{} with items for you",
                    plural(open, "open access review", "open access reviews")
                ),
                href: "/console/reviews".to_owned(),
                tone: "warn",
            });
        }
    }
    if auth.sees_access {
        let who = crate::access::Who {
            username: &auth.username,
            is_admin: auth.is_admin,
            is_auditor: auth.is_auditor,
            via: "console",
        };
        let count = |scope: &'static str, status: &'static str, decidable: bool| async move {
            crate::access::list_requests(
                state,
                &who,
                &limen_proto::v1::ListAccessRequestsRequest {
                    scope: scope.into(),
                    status: status.into(),
                    limit: 100,
                },
            )
            .await
            .map(|v| v.iter().filter(|r| !decidable || r.can_decide).count())
            .map_err(|s| action_error(&s))
        };
        let waiting = count("approvable", "", true).await?;
        if waiting > 0 {
            items.push(views::AttentionItem {
                text: format!(
                    "{} waiting for your decision",
                    plural(waiting, "access request", "access requests")
                ),
                href: "/console/access?tab=approvals".to_owned(),
                tone: "warn",
            });
        }
        let mine = count("mine", "pending", false).await?;
        if mine > 0 {
            items.push(views::AttentionItem {
                text: format!(
                    "{} still waiting for an approver",
                    plural(
                        mine,
                        "access request of yours is",
                        "access requests of yours are"
                    )
                ),
                href: "/console/access".to_owned(),
                tone: "",
            });
        }
    }
    Ok(items)
}

/// The viewer's pinned resources (only those they can still open) and saved views.
async fn pinned_and_saved(
    state: &AppState,
    auth: &Auth,
    reachable: &[ResourceView],
) -> Result<(Vec<views::PinnedResource>, Vec<views::SavedView>), Response> {
    let pins = store::list_pins(&state.db, &auth.username)
        .await
        .map_err(|e| db_error("reading your pins", &e))?;
    // Health is worker state, which is admin-only.
    let workers = if auth.is_admin {
        Some(
            db::list_components(&state.db)
                .await
                .map_err(|e| db_error("listing components", &e))?,
        )
    } else {
        None
    };
    let loaded = state.policy.current();
    let mut resources = Vec::new();
    let mut saved = Vec::new();
    for pin in pins {
        if pin.kind == "view" {
            saved.push(views::SavedView {
                label: pin.label,
                href: pin.target,
            });
            continue;
        }
        // A resource that has gone from policy is skipped; so is one a member can no longer open.
        let Some(res) = loaded.policy.resource(&pin.target) else {
            continue;
        };
        let mine = reachable.iter().find(|r| r.name == pin.target);
        if !auth.is_admin && mine.is_none() {
            continue;
        }
        let kind = spec_kind(&res.spec);
        let (icon, kclass) = views::kind_icon(kind);
        let health = workers.as_ref().map(|(components, tunnels)| {
            views::Health::of(&matching_workers(
                components,
                tunnels,
                &res.spec.worker_selector,
            ))
        });
        resources.push(views::PinnedResource {
            name: pin.target.clone(),
            path: path_segment(&pin.target),
            kind: kind.to_owned(),
            icon,
            kclass,
            connect: mine.map(|_| views::connect_for(kind, &pin.target)),
            health,
        });
    }
    Ok((resources, saved))
}

/// The resources the viewer used last, among those they can still open. Only their own sessions
/// count, for admins too: this is "where *you* left off".
async fn recent_resources(
    state: &AppState,
    auth: &Auth,
    reachable: &[ResourceView],
) -> Result<Vec<views::RecentResource>, Response> {
    let used = store::resource_activity(&state.db, Some(&auth.username))
        .await
        .map_err(|e| db_error("reading your recent resources", &e))?;
    let mut recent: Vec<views::RecentResource> = reachable
        .iter()
        .filter(|r| r.connect.planned.is_none())
        .filter_map(|r| {
            let at = used.get(&r.name)?.last_started?;
            Some(views::RecentResource {
                name: r.name.clone(),
                path: r.path.clone(),
                kind: r.kind.clone(),
                icon: r.icon,
                kclass: r.kclass,
                connect: views::connect_for(&r.kind, &r.name),
                last: views::Stamp::of(at),
            })
        })
        .collect();
    recent.sort_by(|a, b| {
        b.last
            .iso
            .cmp(&a.last.iso)
            .then_with(|| a.name.cmp(&b.name))
    });
    recent.truncate(4);
    Ok(recent)
}

pub async fn home(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<DoneQuery>,
) -> Response {
    let reach = match reachable_for(&state, &auth).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let resources: Vec<ResourceView> = reach
        .into_iter()
        .map(|r| ResourceView {
            connect: views::connect_for(r.kind.as_str(), &r.name),
            path: path_segment(&r.name),
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
    let attention = match attention_items(&state, &auth, &overview).await {
        Ok(items) => items,
        Err(r) => return r,
    };
    let recent = match recent_resources(&state, &auth, &resources).await {
        Ok(items) => items,
        Err(r) => return r,
    };
    let (pinned, saved) = match pinned_and_saved(&state, &auth, &resources).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    html(
        Home {
            chrome: chrome(&state, &auth, "home"),
            notice: notice(q.done.as_deref()),
            stats: overview,
            resources,
            sessions,
            roles_text: format!("the roles {}", list_text(&auth.roles)),
            expires: time_text(Some(auth.expires_at)),
            attention,
            recent,
            pinned,
            saved,
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
    sort: Option<String>,
    attention: Option<String>,
    pinned: Option<String>,
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

/// Every resource the viewer may see, with what the list shows about each. Admins see every
/// resource and everyone's activity; anyone else sees only what their roles open and only their
/// own last use. Filters and sorting come after this, so they can't reveal anything.
async fn resource_rows(state: &AppState, auth: &Auth) -> Result<Vec<ResourceRow>, Response> {
    let loaded = state.policy.current();
    let (components, tunnels) = if auth.is_admin {
        match db::list_components(&state.db).await {
            Ok(pair) => pair,
            Err(e) => return Err(db_error("listing components", &e)),
        }
    } else {
        (Vec::new(), Vec::new())
    };
    // Admins see everyone's sessions; anyone else only learns when they last used a resource.
    let activity = match store::resource_activity(
        &state.db,
        (!auth.is_admin).then_some(auth.username.as_str()),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return Err(db_error("counting sessions per resource", &e)),
    };
    // What went wrong in the last day is audit data: admins only.
    let errors = if auth.is_admin {
        store::resource_errors(&state.db)
            .await
            .map_err(|e| db_error("counting errors per resource", &e))?
    } else {
        std::collections::HashMap::new()
    };
    // Admins see every resource; everyone else only what their roles allow.
    let accessible = match reachable_for(state, auth).await {
        Ok(r) => r,
        Err(r) => return Err(r),
    };
    let pinned: std::collections::HashSet<String> = store::list_pins(&state.db, &auth.username)
        .await
        .map_err(|e| db_error("reading your pins", &e))?
        .into_iter()
        .filter(|p| p.kind == "resource")
        .map(|p| p.target)
        .collect();
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
        let seen = activity.get(&name).copied().unwrap_or_default();
        let workers = auth
            .is_admin
            .then(|| matching_workers(&components, &tunnels, &r.spec.worker_selector));
        rows.push(ResourceRow {
            roles: if auth.is_admin {
                access_roles(&loaded.policy, &name)
            } else {
                Vec::new()
            },
            workers: workers.as_ref().map_or(0, Vec::len),
            health: workers.as_deref().map(views::Health::of),
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
            // Only what the viewer can open gets a command to copy.
            connect: mine.map(|_| views::connect_for(kind, &name)),
            last_used: seen.last_started.map(views::Stamp::of),
            errors: errors.get(&name).copied().unwrap_or_default().total(),
            errors_text: views::errors_text(errors.get(&name).copied().unwrap_or_default()),
            pinned: pinned.contains(&name),
            name,
            kind: kind.to_owned(),
            icon,
            kclass,
            // Counts of everyone's sessions are admin-only; the query above is scoped otherwise.
            sessions: if auth.is_admin { seen.total } else { 0 },
            active: if auth.is_admin { seen.active } else { 0 },
        });
    }
    Ok(rows)
}

pub async fn resources(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<ResourcesQuery>,
    RawQuery(raw): RawQuery,
) -> Response {
    let mut rows = match resource_rows(&state, &auth).await {
        Ok(rows) => rows,
        Err(r) => return r,
    };
    // Filters apply after access control, so a filter can't reveal anything.
    let needle =
        q.q.as_deref()
            .map(str::to_lowercase)
            .filter(|s| !s.is_empty());
    let kind_filter = q.kind.clone().filter(|k| !k.is_empty());
    let label_filter = label_filters(raw.as_deref());
    let query_text = q.q.clone().unwrap_or_default();
    let sort = ResourceSort::parse(q.sort.as_deref(), auth.is_admin);
    // Worker health is admin-only, so the filter is too.
    let attention = auth.is_admin && q.attention.as_deref() == Some("1");
    let pinned_only = q.pinned.as_deref() == Some("1");
    let total = rows.len();
    let pinned_count = rows.iter().filter(|r| r.pinned).count();
    let attention_count = rows.iter().filter(|r| r.needs_attention()).count();
    let mut kinds: Vec<String> = rows.iter().map(|r| r.kind.clone()).collect();
    kinds.sort();
    kinds.dedup();
    rows.retain(|r| {
        kind_filter.as_deref().is_none_or(|k| k == r.kind)
            && label_filter.iter().all(|l| r.labels.contains(l))
            && (!attention || r.needs_attention())
            && (!pinned_only || r.pinned)
            && needle.as_deref().is_none_or(|n| {
                r.name.to_lowercase().contains(n)
                    || r.labels.iter().any(|l| l.to_lowercase().contains(n))
            })
    });
    sort_rows(&mut rows, sort);
    let filters = |kind: Option<&str>, labels: &[String], attention: bool| {
        resource_ui::Filters {
            kind,
            q: &query_text,
            labels,
            sort,
            attention,
            pinned: pinned_only,
        }
        .href()
    };
    let here = filters(kind_filter.as_deref(), &label_filter, attention);
    let saved: Vec<views::SavedView> = match store::list_pins(&state.db, &auth.username).await {
        Ok(p) => p
            .into_iter()
            .filter(|p| p.kind == "view" && p.target.starts_with("/console/resources"))
            .map(|p| views::SavedView {
                label: p.label,
                href: p.target,
            })
            .collect(),
        Err(e) => return db_error("reading your saved views", &e),
    };
    html(
        ResourcesPage {
            chrome: chrome(&state, &auth, "resources"),
            kinds: kinds
                .into_iter()
                .map(|k| {
                    let (icon, kclass) = views::kind_icon(&k);
                    KindTab {
                        href: filters(Some(&k), &label_filter, attention),
                        current: kind_filter.as_deref() == Some(k.as_str()),
                        icon,
                        kclass,
                        name: k,
                    }
                })
                .collect(),
            all_selected: kind_filter.is_none(),
            all_href: filters(None, &label_filter, attention),
            active_labels: label_filter
                .iter()
                .map(|l| LabelLink {
                    text: l.clone(),
                    href: filters(
                        kind_filter.as_deref(),
                        &label_filter
                            .iter()
                            .filter(|o| *o != l)
                            .cloned()
                            .collect::<Vec<_>>(),
                        attention,
                    ),
                })
                .collect(),
            clear_href: filters(kind_filter.as_deref(), &[], attention),
            kind_value: kind_filter.clone().unwrap_or_default(),
            label_values: label_filter.clone(),
            query: query_text.clone(),
            sorts: sort.options(auth.is_admin),
            sort_value: if sort == ResourceSort::Name {
                String::new()
            } else {
                sort.value().to_owned()
            },
            attention_on: attention,
            attention_href: filters(kind_filter.as_deref(), &label_filter, !attention),
            attention_count,
            pinned_on: pinned_only,
            pinned_href: resource_ui::Filters {
                kind: kind_filter.as_deref(),
                q: &query_text,
                labels: &label_filter,
                sort,
                attention,
                pinned: !pinned_only,
            }
            .href(),
            pinned_count,
            saved,
            here,
            total,
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
                                href: filters(kind_filter.as_deref(), &next, attention),
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

/// Lay the rows out in the order the pure rules give, so the ordering lives in one tested place.
fn sort_rows(rows: &mut Vec<ResourceRow>, sort: ResourceSort) {
    let mut keys: Vec<resource_ui::SortKey<'_>> = rows
        .iter()
        .map(|r| resource_ui::SortKey {
            name: &r.name,
            last_used: r
                .last_used
                .as_ref()
                .and_then(|s| OffsetDateTime::parse(&s.iso, &Rfc3339).ok()),
            active: r.active,
            total: r.sessions,
            health: r.health,
            errors: r.errors,
        })
        .collect();
    resource_ui::sort_keys(&mut keys, sort);
    let order: Vec<String> = keys.iter().map(|k| k.name.to_owned()).collect();
    let mut taken: Vec<Option<ResourceRow>> = std::mem::take(rows).into_iter().map(Some).collect();
    for name in order {
        if let Some(slot) = taken
            .iter_mut()
            .find(|r| r.as_ref().is_some_and(|r| r.name == name))
        {
            rows.extend(slot.take());
        }
    }
}

/// The detail page's sections, as plain links. The access table is for readers of the record.
fn detail_tabs(name: &str, current: &str, reads_record: bool) -> Vec<views::DetailTab> {
    let href = |t: &str| {
        if t == "overview" {
            format!("/console/resources/{}", path_segment(name))
        } else {
            format!("/console/resources/{}?tab={t}", path_segment(name))
        }
    };
    let mut tabs = vec![("overview", "Overview")];
    if reads_record {
        tabs.push(("access", "Access"));
    }
    tabs.push(("activity", "Activity"));
    tabs.into_iter()
        .map(|(t, label)| views::DetailTab {
            href: href(t),
            label,
            current: t == current,
        })
        .collect()
}

/// Sessions open on a resource now, for readers of the record; nobody else sees who is on it.
async fn live_sessions(
    state: &AppState,
    auth: &Auth,
    name: &str,
) -> Result<Vec<views::LiveSession>, Response> {
    if !auth.reads_record() {
        return Ok(Vec::new());
    }
    let open = SessionFilter {
        resource: Some(name.to_owned()),
        active_only: true,
        limit: 10,
        ..SessionFilter::default()
    };
    let can_watch = crate::live::may_watch(state, auth.is_admin, auth.is_auditor);
    let rows = store::list_sessions(&state.db, &open)
        .await
        .map_err(|e| db_error("listing the sessions open on a resource", &e))?;
    Ok(rows
        .iter()
        .take(10)
        .filter_map(|s| {
            Some(views::LiveSession {
                id: s.session_id.to_string(),
                user: s.username.clone().unwrap_or_else(|| "—".to_owned()),
                login: s.login.clone().unwrap_or_else(|| "—".to_owned()),
                since: views::Stamp::of(s.started_at?),
                // Watching is SSH only, and a separate power from reading the record.
                watch: can_watch && s.kind.as_deref() == Some("ssh"),
                endable: s.kind.as_deref() != Some("kubectl"),
            })
        })
        .collect())
}

/// Who can reach a resource, and how (ADR-0028).
fn who_can_rows(policy: &limen_policy::Policy, name: &str) -> Vec<WhoRow> {
    policy
        .who_can(name)
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
}

/// What went wrong on a resource in the last 24 hours, one part per kind that is not zero, each
/// with where to look at it. For admins: it is audit data.
async fn error_parts(state: &AppState, name: &str) -> Result<Vec<views::ErrorPart>, Response> {
    let seen = store::resource_errors(&state.db)
        .await
        .map_err(|e| db_error("counting errors on a resource", &e))?
        .remove(name)
        .unwrap_or_default();
    let encoded: String = url::form_urlencoded::byte_serialize(name.as_bytes()).collect();
    let sessions = format!("/console/sessions?resource={encoded}");
    Ok([
        (
            "refused",
            seen.denied,
            format!("/console/audit?kind=auth.denied&q={encoded}"),
        ),
        ("statement errors", seen.db, sessions.clone()),
        ("web 5xx", seen.web, sessions),
        (
            "Kubernetes errors",
            seen.kube,
            "/console/audit/kubernetes".to_owned(),
        ),
    ]
    .into_iter()
    .filter(|(_, n, _)| *n > 0)
    .map(|(label, count, href)| views::ErrorPart { label, count, href })
    .collect())
}

#[derive(Deserialize)]
pub struct ResourceTabQuery {
    tab: Option<String>,
    // The command builder's choices (all optional, all checked against what the viewer may do).
    who: Option<String>,
    database: Option<String>,
    vhost: Option<String>,
    port: Option<String>,
}

/// The command builder under the Connect card: what the viewer may act as on this resource, and
/// the command for what they picked. Only for what their own roles open, never for an admin's
/// view of someone else's access.
async fn command_builder(
    state: &AppState,
    auth: &Auth,
    kind: &str,
    name: &str,
    q: &ResourceTabQuery,
) -> Result<Option<connect_builder::Builder>, Response> {
    let scopes = crate::access::scopes_for(state, &auth.username, &auth.roles, name)
        .await
        .map_err(|e| db_error("reading access grants", &e))?;
    let picks = connect_builder::Picks {
        who: q.who.clone(),
        database: q.database.clone(),
        vhost: q.vhost.clone(),
        port: q.port.clone(),
    };
    Ok(connect_builder::build(kind, name, &scopes, &picks))
}

pub async fn resource_detail(
    State(state): State<AppState>,
    auth: Auth,
    Path(name): Path<String>,
    Query(tab_query): Query<ResourceTabQuery>,
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
    // The tab is a plain link, so it can be bookmarked. The access table is for people who may
    // read the record; an unknown tab, or one the viewer can't have, is the overview.
    let tab = match tab_query.tab.as_deref() {
        Some("access") if auth.reads_record() => "access",
        Some("activity") => "activity",
        _ => "overview",
    };
    let tabs = detail_tabs(&name, tab, auth.reads_record());
    let own = (!auth.reads_record()).then(|| auth.username.clone());
    let shown: usize = if tab == "activity" { 25 } else { 10 };
    let filter = SessionFilter {
        username: own.clone(),
        resource: Some(name.clone()),
        limit: i64::try_from(shown).unwrap_or(10),
        ..SessionFilter::default()
    };
    let sessions = match store::list_sessions(&state.db, &filter).await {
        Ok(rows) => rows.iter().take(shown).map(SessionView::from).collect(),
        Err(e) => return db_error("listing a resource's sessions", &e),
    };
    let last_used = match store::resource_activity(&state.db, own.as_deref()).await {
        Ok(a) => a
            .get(&name)
            .and_then(|a| a.last_started)
            .map(views::Stamp::of),
        Err(e) => return db_error("reading a resource's activity", &e),
    };
    let live = match live_sessions(&state, &auth, &name).await {
        Ok(v) => v,
        Err(r) => return r,
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
    let health = auth.is_admin.then(|| views::Health::of(&workers));
    let errors = if auth.is_admin {
        match error_parts(&state, &name).await {
            Ok(parts) => parts,
            Err(r) => return r,
        }
    } else {
        Vec::new()
    };
    let who_can = if auth.reads_record() && tab == "access" {
        who_can_rows(&loaded.policy, &name)
    } else {
        Vec::new()
    };
    let principals = mine.map(|m| m.principals.clone()).unwrap_or_default();
    let builder = match mine {
        Some(_) => match command_builder(&state, &auth, kind, &name, &tab_query).await {
            Ok(b) => b,
            Err(r) => return r,
        },
        None => None,
    };
    let starred = match store::list_pins(&state.db, &auth.username).await {
        Ok(p) => p.iter().any(|p| p.kind == "resource" && p.target == name),
        Err(e) => return db_error("reading your pins", &e),
    };
    let encoded = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    let here = tabs
        .iter()
        .find(|t| t.current)
        .map_or_else(String::new, |t| t.href.clone());
    html(
        ResourcePage {
            can_request: may_ask && mine.is_none(),
            who_can,
            chrome: chrome(&state, &auth, "resources"),
            connect: views::connect_for(kind, &name),
            options: views::connect_options(kind, &name, &principals),
            builder,
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
            principals,
            workers,
            sessions,
            tab,
            tabs,
            health,
            last_used,
            live,
            errors,
            starred,
            here,
            sessions_href: format!("/console/sessions?resource={}", encoded(&name)),
            audit_href: auth
                .reads_record()
                .then(|| format!("/console/audit?q={}", encoded(&name))),
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
            has_open: rows
                .iter()
                .any(|s| s.active && s.kind.as_deref() != Some("kubectl")),
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

#[derive(Deserialize)]
pub struct PinForm {
    csrf: String,
    kind: String,
    target: String,
    /// `add` or `remove`.
    action: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    back: String,
}

/// `POST /console/pins`: pin a resource or save a view (`action=add`), or take it off again
/// (`action=remove`). Only the signed-in
/// person's own list. A resource must be one they can see; a view must be one of the listed
/// console pages, and for a page they may open. Nothing here is audited: it is a preference, not
/// access, and it grants nothing.
pub async fn pin_toggle(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Form(form): Form<PinForm>,
) -> Response {
    let console = match console(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = auth.check_post(console, &headers, &form.csrf) {
        return r;
    }
    let back = pins::local_back(&form.back);
    let bad = |what: &str| error_page(StatusCode::BAD_REQUEST, "Not saved", what);
    let (kind, target, label) = match form.kind.as_str() {
        "resource" => {
            // Taking a pin off always works, even for a resource that has gone or been hidden
            // since: otherwise it could never be removed. Adding needs a resource they can see.
            let known = state
                .policy
                .current()
                .policy
                .resource(&form.target)
                .is_some();
            let visible = auth.is_admin
                || match reachable_for(&state, &auth).await {
                    Ok(r) => r.iter().any(|a| a.name == form.target),
                    Err(r) => return r,
                };
            if form.action == "add" && (!known || !visible) {
                return error_page(
                    StatusCode::NOT_FOUND,
                    "Not found",
                    "There is no such resource.",
                );
            }
            ("resource", form.target.clone(), form.target.clone())
        }
        "view" => {
            if !pins::valid_view_target(&form.target) {
                return bad("That page can't be saved as a view.");
            }
            let allowed = match pins::required_power(&form.target) {
                pins::Power::Anyone => true,
                pins::Power::ReadsRecord => auth.reads_record(),
                pins::Power::Admin => auth.is_admin,
            };
            if form.action == "add" && !allowed {
                return error_page(
                    StatusCode::FORBIDDEN,
                    "Not allowed",
                    "You can't open that page, so it can't be saved.",
                );
            }
            (
                "view",
                form.target.clone(),
                pins::clean_label(&form.label, "Saved view"),
            )
        }
        _ => return bad("Pin a resource or save a view."),
    };
    if form.action == "remove" {
        return match store::remove_pin(&state.db, &auth.username, kind, &target).await {
            Ok(()) => Redirect::to(&back).into_response(),
            Err(e) => db_error("removing your pin", &e),
        };
    }
    if form.action != "add" {
        return bad("Add it or remove it.");
    }
    match store::add_pin(&state.db, &auth.username, kind, &target, &label).await {
        Ok(true) => Redirect::to(&back).into_response(),
        Ok(false) => error_page(
            StatusCode::CONFLICT,
            "Too many pins",
            &format!(
                "You can keep {} pins and saved views. Remove one first.",
                store::PIN_LIMIT
            ),
        ),
        Err(e) => db_error("saving your pin", &e),
    }
}

/// A bulk form: the CSRF token, the reason, and every `id`. A field repeated (`id=..&id=..`) is not
/// a struct, so the pairs are read by hand.
fn read_bulk(body: &[u8]) -> (String, String, Vec<String>) {
    let (mut csrf, mut reason, mut ids) = (String::new(), String::new(), Vec::new());
    for (k, v) in url::form_urlencoded::parse(body) {
        match k.as_ref() {
            "csrf" => csrf = v.into_owned(),
            "reason" => reason = v.into_owned(),
            "id" => ids.push(v.into_owned()),
            _ => {}
        }
    }
    (csrf, reason, ids)
}

/// Most sessions one bulk request may end. Each is its own audited kill.
const BULK_KILL_LIMIT: usize = 50;

/// `POST /console/sessions/kill`: end the selected sessions (`id`, repeated) with one reason. Each
/// goes through the same code as ending one, so each has its own audit event; there is no bulk
/// shortcut around the audit. Admins only.
pub async fn kill_sessions(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let console = match console(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (csrf, reason, mut ids) = read_bulk(&body);
    if let Err(r) = auth.check_post(console, &headers, &csrf) {
        return r;
    }
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Nothing selected",
            "Tick the sessions to end, then try again.",
        );
    }
    if ids.len() > BULK_KILL_LIMIT {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Too many sessions",
            &format!("End at most {BULK_KILL_LIMIT} sessions at once."),
        );
    }
    let (mut ended, mut missed) = (0_usize, 0_usize);
    let mut first_error = None;
    for id in &ids {
        match ops::kill_session(&state, actor(&auth), id, &reason).await {
            Ok(true) => ended += 1,
            Ok(false) => missed += 1,
            Err(s) => {
                missed += 1;
                first_error.get_or_insert(s);
            }
        }
    }
    match (ended, missed, first_error) {
        // Nothing ended and something was wrong with the request itself (no reason, say): say so.
        (0, _, Some(s)) => action_error(&s),
        (_, 0, _) => {
            Redirect::to("/console/sessions?filter=active&done=killed_many").into_response()
        }
        _ => Redirect::to("/console/sessions?filter=active&done=killed_some").into_response(),
    }
}

// ---- users -----------------------------------------------------------------------------

/// The users page's query string: the search box and the filters.
#[derive(Deserialize)]
pub struct UsersQuery {
    done: Option<String>,
    q: Option<String>,
    group: Option<String>,
    role: Option<String>,
    status: Option<String>,
    state: Option<String>,
}

/// A filter value from the query string: bounded, and only what the menus offer
/// is acted on (an unknown status simply matches nobody).
fn filter_value(v: Option<&String>) -> String {
    v.map(|s| s.trim().chars().take(200).collect())
        .unwrap_or_default()
}

pub async fn users(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<UsersQuery>,
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
    let filter = views::UserFilter {
        group: filter_value(q.group.as_ref()),
        role: filter_value(q.role.as_ref()),
        status: filter_value(q.status.as_ref()),
        state: filter_value(q.state.as_ref()),
    };
    let total = users.len();
    let chips = user_chips(&query, &filter);
    let mut groups: Vec<String> = users.iter().flat_map(|u| u.groups.clone()).collect();
    let mut roles: Vec<String> = users.iter().flat_map(|u| u.roles.clone()).collect();
    for list in [&mut groups, &mut roles] {
        list.sort();
        list.dedup();
    }
    let wanted = |u: &UserView| {
        let chips: Vec<&str> = u
            .role_list
            .iter()
            .chain(&u.group_list)
            .map(|c| c.text.as_str())
            .collect();
        search_matches(&query, &[u.name.as_str(), &chips.join(" ")])
    };
    // Someone who never signed in has no groups, roles or IdP check to filter on.
    let orphan_locks = locks
        .iter()
        .filter(|l| !known.contains(&l.username))
        .map(|l| lock_only_view(&l.username, l))
        .filter(&wanted)
        // Never signed in: no groups, roles or IdP check, but disabled all the same.
        .filter(|_| {
            filter.group.is_empty()
                && filter.role.is_empty()
                && (filter.status.is_empty() || filter.status == "locked")
        })
        .filter(|u| filter.admits_state(Some(u.locked_by.as_str())))
        .collect();
    html(
        UsersPage {
            chrome: chrome(&state, &auth, "users"),
            notice: notice(q.done.as_deref()),
            users: users
                .iter()
                .filter(|u| filter.admits(u, u.lock_reason.is_some()))
                .map(|u| with_pending(&state, u))
                .filter(&wanted)
                .collect(),
            query,
            orphan_locks,
            chips,
            filter,
            groups,
            roles,
            total,
        }
        .render(),
    )
}

/// A removable chip for each applied filter on the users page; removing one
/// keeps the rest (and the search text).
fn user_chips(query: &str, f: &views::UserFilter) -> Vec<views::FilterChip> {
    let state = match f.state.as_str() {
        "enabled" => "Enabled",
        "disabled" => "Disabled",
        "disabled_idp" => "Disabled by the IdP",
        "disabled_admin" => "Disabled by an admin",
        other => other,
    };
    let status = match f.status.as_str() {
        "ok" => "Checked",
        "unchecked" => "Not checked",
        "check_failed" => "IdP not reachable",
        "groups_missing" => "IdP sent no groups",
        "offboarded" => "Ended by the IdP",
        "locked" => "Disabled",
        other => other,
    };
    // (parameter, label, shown value, value)
    let all = [
        ("q", "Search", query, query),
        ("state", "State", state, f.state.as_str()),
        ("group", "Group", f.group.as_str(), f.group.as_str()),
        ("role", "Role", f.role.as_str(), f.role.as_str()),
        ("status", "IdP check", status, f.status.as_str()),
    ];
    all.iter()
        .filter(|(_, _, _, v)| !v.is_empty())
        .map(|(key, label, shown, _)| {
            let rest: Vec<(&str, &str)> = all
                .iter()
                .filter(|(k, ..)| k != key)
                .map(|(k, _, _, v)| (*k, *v))
                .collect();
            views::FilterChip {
                label: format!("{label}: {shown}"),
                remove: query::href("/console/users", &rest),
            }
        })
        .collect()
}

/// A user's view, with the access their IdP groups would change at the next
/// sign-in (roles are fixed at sign-in, so it is shown, not applied).
fn with_pending(state: &AppState, u: &store::UserRow) -> UserView {
    let mut view = UserView::from(u);
    let (gained, lost) = crate::idp_check::pending_roles(state, &u.roles, u.idp_groups.as_deref());
    let mut parts: Vec<String> = gained.iter().map(|r| format!("+{r}")).collect();
    parts.extend(lost.iter().map(|r| format!("\u{2212}{r}")));
    view.pending = parts.join(" ");
    view
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
        manageable: true,
        ci: Vec::new(),
        run_url: None,
        source: "never signed in".into(),
        issuer: String::new(),
        idp: "—".into(),
        idp_tone: "",
        pending: String::new(),
    }
}

/// A bot that policy defines but that has not logged in: no user row exists yet.
fn policy_bot_view(name: &str, roles: &[String]) -> UserView {
    UserView {
        name: name.to_owned(),
        path: path_segment(name),
        role_list: roles
            .iter()
            .map(|r| views::Chip {
                text: r.clone(),
                c: views::chip_color(r),
            })
            .collect(),
        group_list: Vec::new(),
        av: views::avatar_class(name),
        initial: name
            .chars()
            .next()
            .map_or_else(|| "?".to_owned(), |c| c.to_uppercase().collect()),
        first_login: "never".into(),
        last_login: "never".into(),
        logins: 0,
        locked: false,
        lock_reason: String::new(),
        locked_by: String::new(),
        locked_at: String::new(),
        is_bot: true,
        manageable: true,
        ci: Vec::new(),
        run_url: None,
        source: "CI bot, defined in policy".into(),
        issuer: String::new(),
        idp: "not applicable".into(),
        idp_tone: "",
        pending: String::new(),
    }
}

/// A name that appears in the audit trail but is neither an account nor a policy bot,
/// such as the actor the IdP check or SCIM records. Its page shows the activity only.
fn audit_only_view(name: &str) -> UserView {
    UserView {
        manageable: false,
        is_bot: false,
        source: "No account: the name only appears in the audit trail".into(),
        idp: "not applicable".into(),
        ..policy_bot_view(name, &[])
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
        Some(row) => with_pending(&state, &row),
        None => {
            // A lock can name someone who never signed in.
            let locks = db::active_locks(&state.db).await.unwrap_or_default();
            let loaded = state.policy.current();
            let defined_bot = loaded.policy.bots().find(|b| b.username() == name);
            match (locks.iter().find(|l| l.username == name), defined_bot) {
                (Some(l), _) => lock_only_view(&name, l),
                // A bot in policy that has not logged in yet: the Bots page links here.
                (None, Some(b)) => policy_bot_view(&name, &b.spec.roles),
                (None, None) => {
                    let named = store::EventFilter {
                        username: Some(name.clone()),
                        ..store::EventFilter::default()
                    };
                    match store::list_events(&state.db, &named, 1, 0).await {
                        Ok(rows) if !rows.is_empty() => audit_only_view(&name),
                        Ok(_) => {
                            return error_page(
                                StatusCode::NOT_FOUND,
                                "Not found",
                                "There is no such user.",
                            );
                        }
                        Err(e) => return db_error("reading a user's activity", &e),
                    }
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
            // A bot is reached from the Bots page, so that is the entry to highlight.
            chrome: chrome(&state, &auth, if view.is_bot { "bots" } else { "users" }),
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

/// `POST /console/users/{name}/delete`: delete a disabled person's record.
/// Enabled people can't be deleted, and their history stays (ADR-0047).
pub async fn delete_user(
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
    match ops::delete_disabled_user(&state, actor(&auth), &name, &form.reason).await {
        Ok(Ok(())) => Redirect::to("/console/users?done=deleted").into_response(),
        Ok(Err(ops::DeleteRefused::NotDisabled)) => error_page(
            StatusCode::CONFLICT,
            "Disable them first",
            "Only a disabled user can be deleted. Disable the account, then delete it.",
        ),
        Ok(Err(ops::DeleteRefused::NoRecord)) => error_page(
            StatusCode::CONFLICT,
            "Nothing to delete",
            "This person has no user record: they never signed in. Enable them to remove the lock.",
        ),
        Ok(Err(ops::DeleteRefused::Bot)) => error_page(
            StatusCode::BAD_REQUEST,
            "That is a bot",
            "Bots are managed on the Bots page, not deleted here.",
        ),
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
    let loaded = state.policy.current();
    let components: Vec<ComponentView> = components
        .into_iter()
        .map(|c| {
            let labels: BTreeMap<String, String> =
                serde_json::from_value(c.labels).unwrap_or_default();
            let (serves, serves_more) = if c.kind == "worker" {
                views::resources_served(&loaded.policy, &labels, 6)
            } else {
                (Vec::new(), 0)
            };
            let now = time::OffsetDateTime::now_utc();
            ComponentView {
                quiet: c.revoked_at.is_none() && now - c.last_seen_at > time::Duration::minutes(5),
                cert_expired: c.revoked_at.is_none() && c.cert_expires_at.is_some_and(|t| t < now),
                serves,
                serves_more,
                last_seen_iso: views::iso_text(Some(c.last_seen_at)),
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
            has_enrolled: components.iter().any(|c| !c.revoked),
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

/// `POST /console/workers/revoke`: revoke the selected components (`id`, repeated) with one
/// reason, each through the same code, and so with its own audit event, as revoking one. Admins only.
pub async fn revoke_components(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let console = match console(&state) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (csrf, reason, mut ids) = read_bulk(&body);
    if let Err(r) = auth.check_post(console, &headers, &csrf) {
        return r;
    }
    ids.sort();
    ids.dedup();
    if ids.is_empty() || ids.len() > BULK_KILL_LIMIT {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Nothing to revoke",
            &format!("Tick between 1 and {BULK_KILL_LIMIT} components, then try again."),
        );
    }
    let (mut done, mut missed) = (0_usize, 0_usize);
    let mut first_error = None;
    for id in &ids {
        match ops::revoke_component(&state, actor(&auth), id, &reason).await {
            Ok(true) => done += 1,
            Ok(false) => missed += 1,
            Err(s) => {
                missed += 1;
                first_error.get_or_insert(s);
            }
        }
    }
    match (done, missed, first_error) {
        (0, _, Some(s)) => action_error(&s),
        (_, 0, _) => Redirect::to("/console/workers?done=revoked_many").into_response(),
        _ => Redirect::to("/console/workers?done=revoked_some").into_response(),
    }
}

// ---- policy ----------------------------------------------------------------------------

fn summarize(doc: &Document) -> String {
    match doc {
        Document::Role(r) => {
            let rules = format!(
                "{} allow, {} deny rules",
                r.spec.allow.len(),
                r.spec.deny.len()
            );
            // Shadow mode (ADR-0046): reported, not enforced, and until when.
            let shadow = if r.spec.is_shadow() {
                r.spec
                    .shadow_until
                    .map(|until| format!(" · shadow until {until}, grants nothing"))
            } else {
                let dates: Vec<_> = r
                    .spec
                    .shadow_deny()
                    .filter_map(|(_, rule)| r.spec.shadow_until_of(rule))
                    .collect();
                dates
                    .iter()
                    .min()
                    .map(|first| format!(" · {} in shadow until {first}", dates.len()))
            };
            format!("{rules}{}", shadow.unwrap_or_default())
        }
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
    preview: Option<(String, String, String, views::DryRun)>,
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
            draft: extras.draft,
            preview_kind: extras
                .preview
                .as_ref()
                .map(|p| p.0.clone())
                .unwrap_or_default(),
            preview_name: extras
                .preview
                .as_ref()
                .map(|p| p.1.clone())
                .unwrap_or_default(),
            preview_yaml: extras
                .preview
                .as_ref()
                .map(|p| p.2.clone())
                .unwrap_or_default(),
            preview: extras.preview.map(|p| p.3),
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

/// The policy page with what saving a document would do, from "Preview impact".
pub(super) async fn policy_page_preview(
    state: &AppState,
    auth: &Auth,
    kind: String,
    name: String,
    yaml: String,
    result: views::DryRun,
) -> Response {
    policy_page(
        state,
        auth,
        PolicyExtras {
            preview: Some((kind, name, yaml, result)),
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

/// How many people are offered as choices; the rest are found by searching.
const PEOPLE_SHOWN: usize = 12;

/// The simulator's address: `group` (any number), `person`, `bot` and `q`.
fn parse_simulator_query(raw: Option<&str>) -> (Vec<String>, String, String, String) {
    let (mut groups, mut person, mut bot, mut q) =
        (Vec::new(), String::new(), String::new(), String::new());
    for (k, v) in url::form_urlencoded::parse(raw.unwrap_or("").as_bytes()) {
        let v = v.trim().to_owned();
        if v.is_empty() {
            continue;
        }
        match k.as_ref() {
            "group" if groups.len() < 50 => groups.push(v),
            "person" => person = v,
            "bot" => bot = v,
            "q" => q = v.chars().take(300).collect(),
            _ => {}
        }
    }
    (groups, person, bot, q)
}

/// Everything the simulator can look at: people (most recent sign-in first),
/// bots in policy, and the IdP groups a mapping names or people carry.
async fn simulator_sources(
    state: &AppState,
) -> (
    Vec<store::UserRow>,
    Vec<String>,
    std::collections::BTreeSet<String>,
) {
    let current = state.policy.current();
    let mut users = store::list_users(&state.db).await.unwrap_or_default();
    users.sort_by_key(|u| std::cmp::Reverse(u.last_login_at));
    let bots: Vec<String> = current
        .policy
        .bots()
        .map(|b| b.metadata.name.clone())
        .collect();
    let mut names: std::collections::BTreeSet<String> =
        current.policy.mapped_groups().cloned().collect();
    for u in &users {
        names.extend(u.idp_groups.clone().unwrap_or_else(|| u.groups.clone()));
    }
    (users, bots, names)
}

#[derive(Deserialize)]
pub struct SuggestQuery {
    #[serde(default)]
    q: String,
}

/// `GET /console/simulator/suggest?q=`: what to offer as the box is typed in,
/// as JSON `[{name, kind, href}]`. People, bots and groups whose name contains
/// the text, those that start with it first; nothing typed offers a few of each.
pub async fn simulator_suggest(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<SuggestQuery>,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let (users, bots, names) = simulator_sources(&state).await;
    let needle: String =
        q.q.trim()
            .chars()
            .take(100)
            .collect::<String>()
            .to_lowercase();
    let rank = |name: &str| -> Option<u8> {
        let n = name.to_lowercase();
        if needle.is_empty() || n.starts_with(&needle) {
            Some(0)
        } else {
            n.contains(&needle).then_some(1)
        }
    };
    let pick = |names: Vec<&str>, kind: &str, key: &str, limit: usize| -> Vec<serde_json::Value> {
        let mut hits: Vec<(u8, &str)> = names
            .into_iter()
            .filter_map(|n| rank(n).map(|r| (r, n)))
            .collect();
        hits.sort_by_key(|(r, _)| *r);
        hits.into_iter()
            .take(limit)
            .map(|(_, n)| {
                serde_json::json!({
                    "name": n,
                    "kind": kind,
                    "href": query::href("/console/simulator", &[(key, n)]),
                })
            })
            .collect()
    };
    let (people_max, bots_max, groups_max) = if needle.is_empty() {
        (4, 3, 5)
    } else {
        (6, 4, 6)
    };
    let mut out = pick(
        users.iter().map(|u| u.username.as_str()).collect(),
        "person",
        "person",
        people_max,
    );
    out.extend(pick(
        bots.iter().map(String::as_str).collect(),
        "bot",
        "bot",
        bots_max,
    ));
    out.extend(pick(
        names.iter().map(String::as_str).collect(),
        "group",
        "group",
        groups_max,
    ));
    (
        [(CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::Value::Array(out)),
    )
        .into_response()
}

/// The resources named in a palette answer, at most.
const PALETTE_RESOURCES: usize = 8;

/// How well a resource matches what was typed: its name starts with it, contains it, or one of its
/// labels does. `None` is no match. An empty needle matches everything alike.
fn palette_rank(needle: &str, name: &str, labels: &[String]) -> Option<u8> {
    if needle.is_empty() {
        return Some(0);
    }
    let n = name.to_lowercase();
    if n.starts_with(needle) {
        Some(0)
    } else if n.contains(needle) {
        Some(1)
    } else if labels.iter().any(|l| l.to_lowercase().contains(needle)) {
        Some(2)
    } else {
        None
    }
}

/// `GET /console/suggest/resources?q=`: the command palette's resources, as JSON
/// `[{name, kind, href}]`. The same set as the Resources page (admins: every resource; everyone
/// else: only what their roles open), so the palette never names a resource the page would hide.
pub async fn resource_suggest(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<SuggestQuery>,
) -> Response {
    let accessible = match reachable_for(&state, &auth).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let needle: String =
        q.q.trim()
            .chars()
            .take(100)
            .collect::<String>()
            .to_lowercase();
    let loaded = state.policy.current();
    let mut hits: Vec<(u8, String, &'static str)> = Vec::new();
    for doc in loaded.policy.documents() {
        let Document::Resource(r) = doc else { continue };
        let name = &r.metadata.name;
        if !auth.is_admin && !accessible.iter().any(|a| &a.name == name) {
            continue;
        }
        let labels: Vec<String> = r
            .metadata
            .labels
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        if let Some(rank) = palette_rank(&needle, name, &labels) {
            hits.push((rank, name.clone(), spec_kind(&r.spec)));
        }
    }
    hits.sort();
    let out: Vec<serde_json::Value> = hits
        .into_iter()
        .take(PALETTE_RESOURCES)
        .map(|(_, name, kind)| {
            serde_json::json!({
                "name": name,
                "kind": kind,
                "href": format!("/console/resources/{}", path_segment(&name)),
            })
        })
        .collect();
    (
        [(CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::Value::Array(out)),
    )
        .into_response()
}

/// `GET /console/simulator`: a search box, clickable groups, bots and people,
/// and, once someone is chosen, what they can reach and could ask for. A GET,
/// since it changes nothing: the address can be bookmarked or linked
/// (`?person=...`, `?bot=...`, `?group=a&group=b`).
pub async fn simulator(
    State(state): State<AppState>,
    auth: Auth,
    RawQuery(raw): RawQuery,
) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let (mut picked_groups, person, bot, q) = parse_simulator_query(raw.as_deref());
    let (mut person, mut bot) = (person, bot);
    let current = state.policy.current();
    let (users, bots, mut names) = simulator_sources(&state).await;
    // The search box names one thing, or several groups, separated by commas.
    let mut not_found = None;
    if !q.is_empty() {
        let parts: Vec<&str> = q
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .collect();
        let find = |mut list: std::slice::Iter<'_, String>, p: &str| -> Option<String> {
            list.find(|x| x.eq_ignore_ascii_case(p)).cloned()
        };
        let people_names: Vec<String> = users.iter().map(|u| u.username.clone()).collect();
        let group_names: Vec<String> = names.iter().cloned().collect();
        if let [one] = parts.as_slice() {
            if let Some(n) = find(people_names.iter(), one) {
                person = n;
            } else if let Some(n) = find(bots.iter(), one) {
                bot = n;
            } else if let Some(n) = find(group_names.iter(), one) {
                picked_groups.push(n);
            } else {
                not_found = Some(format!(
                    "Nothing named {one}: try a person, a bot or an IdP group."
                ));
            }
        } else {
            for p in parts.iter().take(50) {
                match find(group_names.iter(), p) {
                    Some(n) => picked_groups.push(n),
                    None => {
                        not_found = Some(format!("{p} is not a known IdP group."));
                        break;
                    }
                }
            }
        }
    }
    names.extend(picked_groups.iter().cloned());

    // Choices. A group toggles in and out of the pick; a person or a bot
    // replaces it.
    let to =
        |pairs: &[(&str, &str)]| format!("{}#simulated", query::href("/console/simulator", pairs));
    let group_pick = |name: &str| {
        let on = picked_groups.iter().any(|g| g == name);
        let rest: Vec<(&str, &str)> = picked_groups
            .iter()
            .filter(|g| g.as_str() != name)
            .map(|g| ("group", g.as_str()))
            .chain((!on).then_some(("group", name)))
            .collect();
        let href = if rest.is_empty() {
            "/console/simulator".to_owned()
        } else {
            format!(
                "/console/simulator?{}",
                rest.iter()
                    .map(|(k, v)| format!("{k}={}", views::path_segment(v)))
                    .collect::<Vec<_>>()
                    .join("&")
            )
        };
        views::Pick {
            name: name.to_owned(),
            href,
            on,
        }
    };
    let groups: Vec<views::Pick> = names.iter().map(|n| group_pick(n)).collect();
    let bot_picks: Vec<views::Pick> = bots
        .iter()
        .map(|b| views::Pick {
            name: b.clone(),
            href: to(&[("bot", b)]),
            on: bot.eq_ignore_ascii_case(b),
        })
        .collect();
    let people: Vec<views::Pick> = users
        .iter()
        .take(PEOPLE_SHOWN)
        .map(|u| views::Pick {
            name: u.username.clone(),
            href: to(&[("person", &u.username)]),
            on: person.eq_ignore_ascii_case(&u.username),
        })
        .collect();
    // One kind of choice at a time.
    let chosen = usize::from(!picked_groups.is_empty())
        + usize::from(!person.is_empty())
        + usize::from(!bot.is_empty());
    let simulation = if let Some(e) = not_found {
        Some(Simulation {
            who: String::new(),
            error: Some(e),
            standing: vec![],
            requestable: vec![],
        })
    } else {
        match chosen {
            0 => None,
            1 => Some(simulate(
                &current.policy,
                &users,
                &picked_groups,
                &person,
                &bot,
            )),
            _ => Some(Simulation {
                who: String::new(),
                error: Some("Pick one: groups, a person or a bot.".into()),
                standing: vec![],
                requestable: vec![],
            }),
        }
    };
    html(
        SimulatorPage {
            chrome: chrome(&state, &auth, "simulator"),
            simulation,
            groups,
            bots: bot_picks,
            more_people: users.len().saturating_sub(PEOPLE_SHOWN),
            people,
            q,
        }
        .render(),
    )
}

/// What one choice can reach: a person (the groups the IdP puts them in now),
/// a bot, or groups.
fn simulate(
    policy: &limen_policy::Policy,
    users: &[store::UserRow],
    groups: &[String],
    person: &str,
    bot: &str,
) -> Simulation {
    let failed = |who: String, error: String| Simulation {
        who,
        error: Some(error),
        standing: vec![],
        requestable: vec![],
    };
    let (who, groups, bot) = if !person.is_empty() {
        let Some(u) = users
            .iter()
            .find(|u| u.username.eq_ignore_ascii_case(person))
        else {
            return failed(
                person.to_owned(),
                format!("No person named {person} has signed in."),
            );
        };
        let theirs = u.idp_groups.clone().unwrap_or_else(|| u.groups.clone());
        (
            if theirs.is_empty() {
                format!("{} (in no groups)", u.username)
            } else {
                format!("{} (in {})", u.username, theirs.join(", "))
            },
            theirs,
            None,
        )
    } else if !bot.is_empty() {
        (format!("The bot {bot}"), Vec::new(), Some(bot))
    } else {
        (
            format!("Members of {}", groups.join(" and ")),
            groups.to_vec(),
            None,
        )
    };
    match policy.what_can(&groups, bot) {
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
        Err(e) => failed(who, e),
    }
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
    fn palette_ranks_names_before_labels_and_hides_nonmatches() {
        let labels = vec!["env=prod".to_owned()];
        assert_eq!(palette_rank("", "bastion", &labels), Some(0));
        assert_eq!(palette_rank("bas", "bastion", &labels), Some(0));
        assert_eq!(palette_rank("tion", "bastion", &labels), Some(1));
        assert_eq!(palette_rank("prod", "bastion", &labels), Some(2));
        assert_eq!(palette_rank("nope", "bastion", &labels), None);
        // The needle arrives lowercased; the name and labels are folded here.
        assert_eq!(palette_rank("bas", "Bastion", &labels), Some(0));
        assert_eq!(
            palette_rank("env=prod", "x", &["ENV=PROD".to_owned()]),
            Some(2)
        );
    }

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
        let labels = ["note=a,b".to_owned(), "env=prod".to_owned()];
        let href = resource_ui::Filters {
            kind: Some("ssh"),
            q: "web",
            labels: &labels,
            sort: ResourceSort::Name,
            attention: false,
            pinned: false,
        }
        .href();
        let (_, query) = href.split_once('?').expect("query string");
        assert_eq!(label_filters(Some(query)), ["env=prod", "note=a,b"]);
    }
}
