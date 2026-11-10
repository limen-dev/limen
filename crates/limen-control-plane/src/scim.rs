//! SCIM 2.0 provisioning from the IdP (ADR-0048).
//!
//! Only what Okta's provisioning agent sends is built: users (list with a
//! `userName` filter, create, get, replace, patch, delete) and pushed groups
//! (list with a `displayName` filter, create, get, replace, patch, delete).
//! Unverified against a real Okta (#64).
//!
//! A SCIM record grants nothing: roles still come from the ID token at
//! sign-in. Provisioning creates a `users` row that has never signed in;
//! pushed group membership is copied to `users.idp_groups`, which the console
//! shows as access gained or lost at the next sign-in.

// Handlers return `Err(Response)` to bail out with a SCIM error body; the
// response type is large and these are cold error paths.
#![allow(clippy::result_large_err)]

use std::collections::BTreeSet;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use limen_audit::EventKind;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

use crate::services::ops::{self, Actor, DeleteRefused};
use crate::state::AppState;

/// Who SCIM acts as in locks and audit events.
pub const ACTOR: &str = "system:scim";
const ACTOR_AS: Actor<'static> = Actor {
    username: ACTOR,
    via: "scim",
};

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const MAX_BODY: usize = 256 * 1024;
const MAX_PAGE: i64 = 200;
const DEACTIVATED: &str = "deactivated in the identity provider (SCIM)";

type Reply = Result<Response, Response>;

/// The SCIM routes, served only when `--scim-token` is set.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(service_provider_config),
        )
        .route("/scim/v2/Users", get(list_users).post(create_user))
        .route(
            "/scim/v2/Users/{id}",
            get(get_user)
                .put(replace_user)
                .patch(patch_user)
                .delete(delete_user),
        )
        .route("/scim/v2/Groups", get(list_groups).post(create_group))
        .route(
            "/scim/v2/Groups/{id}",
            get(get_group)
                .put(replace_group)
                .patch(patch_group)
                .delete(delete_group),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(state.clone(), authenticate))
        .with_state(state)
}

// ---- replies ---------------------------------------------------------------------

fn reply(status: StatusCode, body: &Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/scim+json")],
        body.to_string(),
    )
        .into_response()
}

fn error(status: StatusCode, scim_type: Option<&str>, detail: &str) -> Response {
    let mut body = json!({
        "schemas": [ERROR_SCHEMA],
        "detail": detail,
        "status": status.as_u16().to_string(),
    });
    if let Some(t) = scim_type {
        body["scimType"] = json!(t);
    }
    reply(status, &body)
}

fn bad_request(detail: &str) -> Response {
    error(StatusCode::BAD_REQUEST, Some("invalidValue"), detail)
}

fn not_found(what: &str) -> Response {
    error(StatusCode::NOT_FOUND, None, &format!("{what} not found"))
}

fn server_error(doing: &str, e: &dyn std::fmt::Display) -> Response {
    tracing::error!(error = %e, "SCIM: {doing}");
    error(StatusCode::INTERNAL_SERVER_ERROR, None, "internal error")
}

fn status_error(s: &tonic::Status) -> Response {
    match s.code() {
        tonic::Code::InvalidArgument => bad_request(s.message()),
        tonic::Code::Unavailable => error(
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            "the change was not made: audit is unavailable",
        ),
        _ => server_error("a change failed", &s.message()),
    }
}

fn parse_body(body: &Bytes) -> Result<Value, Response> {
    serde_json::from_slice(body).map_err(|_| {
        error(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "the body is not JSON",
        )
    })
}

fn parse_id(id: &str, what: &str) -> Result<Uuid, Response> {
    Uuid::parse_str(id).map_err(|_| not_found(what))
}

// ---- authentication --------------------------------------------------------------

/// Compare by hash so the time does not depend on where the tokens differ.
fn token_matches(given: &str, wanted: &str) -> bool {
    use sha2::{Digest, Sha256};
    Sha256::digest(given.as_bytes()) == Sha256::digest(wanted.as_bytes())
}

async fn authenticate(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(wanted) = &state.config.scim_token else {
        return not_found("resource");
    };
    let given = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if !token_matches(given.trim(), wanted.expose().trim()) {
        metrics::counter!("limen_scim_requests_total", "outcome" => "unauthorized").increment(1);
        tracing::warn!(path = %req.uri().path(), "SCIM request with a missing or wrong token");
        return error(StatusCode::UNAUTHORIZED, None, "unauthorized");
    }
    metrics::counter!("limen_scim_requests_total", "outcome" => "ok").increment(1);
    next.run(req).await
}

// ---- discovery -------------------------------------------------------------------

async fn service_provider_config() -> Response {
    reply(
        StatusCode::OK,
        &json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": { "supported": true },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": true, "maxResults": MAX_PAGE },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "Bearer token",
                "description": "A static bearer token (Authorization: Bearer ...)",
            }],
        }),
    )
}

// ---- paging and filters ------------------------------------------------------------

#[derive(serde::Deserialize, Default)]
struct ListQuery {
    filter: Option<String>,
    #[serde(rename = "startIndex")]
    start_index: Option<i64>,
    count: Option<i64>,
}

impl ListQuery {
    fn window(&self) -> (i64, i64) {
        let start = self.start_index.unwrap_or(1).max(1);
        let count = self.count.unwrap_or(100).clamp(0, MAX_PAGE);
        (start, count)
    }
}

/// `attr eq "value"`, the only filter Okta sends. Returns the value.
fn eq_filter<'a>(filter: &'a str, attr: &str) -> Result<&'a str, Response> {
    let bad = || {
        error(
            StatusCode::BAD_REQUEST,
            Some("invalidFilter"),
            &format!("only `{attr} eq \"value\"` is supported"),
        )
    };
    let rest = filter.trim();
    // `get`, not indexing: the text is the caller's and may hold multi-byte
    // characters where a byte offset would fall inside one.
    if !rest
        .get(..attr.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(attr))
    {
        return Err(bad());
    }
    let rest = rest[attr.len()..].trim_start();
    let rest = match rest.get(..2) {
        Some(op) if op.eq_ignore_ascii_case("eq") => rest[2..].trim(),
        _ => return Err(bad()),
    };
    rest.strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .filter(|v| !v.contains('"'))
        .ok_or_else(bad)
}

fn list_reply(total: i64, start: i64, resources: &[Value]) -> Response {
    reply(
        StatusCode::OK,
        &json!({
            "schemas": [LIST_SCHEMA],
            "totalResults": total,
            "startIndex": start,
            "itemsPerPage": resources.len(),
            "Resources": resources,
        }),
    )
}

// ---- users -----------------------------------------------------------------------

struct UserRecord {
    scim_id: Uuid,
    username: String,
    active: bool,
}

impl UserRecord {
    fn json(&self) -> Value {
        json!({
            "schemas": [USER_SCHEMA],
            "id": self.scim_id.to_string(),
            "userName": self.username,
            "displayName": self.username,
            "emails": [{ "value": self.username, "type": "work", "primary": true }],
            "active": self.active,
            "meta": { "resourceType": "User" },
        })
    }
}

macro_rules! user_select {
    () => {
        "SELECT u.scim_id, u.username, (l.username IS NULL) AS active
     FROM users u
     LEFT JOIN user_locks l ON lower(l.username) = lower(u.username) AND l.released_at IS NULL"
    };
}

fn user_record(r: &sqlx::postgres::PgRow) -> Result<UserRecord, sqlx::Error> {
    Ok(UserRecord {
        scim_id: r.try_get("scim_id")?,
        username: r.try_get("username")?,
        active: r.try_get("active")?,
    })
}

async fn find_user(state: &AppState, id: Uuid) -> Result<Option<UserRecord>, Response> {
    sqlx::query(concat!(user_select!(), " WHERE u.scim_id = $1"))
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| server_error("reading a user", &e))?
        .as_ref()
        .map(user_record)
        .transpose()
        .map_err(|e| server_error("reading a user", &e))
}

async fn list_users(State(state): State<AppState>, Query(q): Query<ListQuery>) -> Reply {
    let (start, count) = q.window();
    let (rows, total) = match q.filter.as_deref() {
        Some(f) => {
            let name = eq_filter(f, "userName")?;
            let rows = sqlx::query(concat!(
                user_select!(),
                " WHERE lower(u.username) = lower($1) AND u.actor_type = 'user'"
            ))
            .bind(name)
            .fetch_all(&state.db)
            .await
            .map_err(|e| server_error("listing users", &e))?;
            let total = i64::try_from(rows.len()).unwrap_or(0);
            (rows, total)
        }
        None => {
            let rows = sqlx::query(concat!(
                user_select!(),
                " WHERE u.actor_type = 'user' ORDER BY u.username OFFSET $1 LIMIT $2"
            ))
            .bind(start - 1)
            .bind(count)
            .fetch_all(&state.db)
            .await
            .map_err(|e| server_error("listing users", &e))?;
            let total: i64 =
                sqlx::query_scalar("SELECT count(*) FROM users WHERE actor_type = 'user'")
                    .fetch_one(&state.db)
                    .await
                    .map_err(|e| server_error("counting users", &e))?;
            (rows, total)
        }
    };
    let resources: Vec<Value> = rows
        .iter()
        .map(user_record)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| server_error("listing users", &e))?
        .iter()
        .map(UserRecord::json)
        .collect();
    Ok(list_reply(total, start, &resources))
}

async fn get_user(State(state): State<AppState>, Path(id): Path<String>) -> Reply {
    let id = parse_id(&id, "user")?;
    match find_user(&state, id).await? {
        Some(u) => Ok(reply(StatusCode::OK, &u.json())),
        None => Err(not_found("user")),
    }
}

/// A `userName` Limen will hold: what a person's ID token could say.
fn clean_username(v: &Value) -> Result<String, Response> {
    let name = v
        .get("userName")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
        return Err(bad_request(
            "userName is required (at most 256 characters, no control characters)",
        ));
    }
    if limen_core::identity::is_bot(name) {
        return Err(bad_request("userName names a bot"));
    }
    if limen_core::identity::is_selftest(name) {
        return Err(bad_request("userName is in a reserved namespace"));
    }
    Ok(name.to_owned())
}

/// `active` as Okta writes it: a boolean (some servers send "true"/"False").
fn as_active(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) if s.eq_ignore_ascii_case("true") => Some(true),
        Value::String(s) if s.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

async fn create_user(State(state): State<AppState>, body: Bytes) -> Reply {
    let v = parse_body(&body)?;
    let username = clean_username(&v)?;
    let active = v.get("active").and_then(as_active).unwrap_or(true);

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| server_error("creating a user", &e))?;
    // Two creates of one name (Okta retries) queue here instead of racing to
    // the unique index.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext(lower($1)))")
        .bind(&username)
        .execute(&mut *tx)
        .await
        .map_err(|e| server_error("creating a user", &e))?;
    let existing = sqlx::query(
        "SELECT scim_id, actor_type, source FROM users WHERE lower(username) = lower($1) FOR UPDATE",
    )
    .bind(&username)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| server_error("creating a user", &e))?;
    let conflict = || {
        error(
            StatusCode::CONFLICT,
            Some("uniqueness"),
            "User already exists in the database.",
        )
    };
    let (scim_id, adopted) = if let Some(r) = existing {
        // SCIM already made them, or they are a bot: a conflict, and Okta then
        // looks them up by name. A person who signed in before SCIM was on is
        // taken over as they are.
        let actor: String = r.try_get("actor_type").unwrap_or_default();
        let source: String = r.try_get("source").unwrap_or_default();
        if actor != "user" || source == "scim" {
            return Err(conflict());
        }
        let id: Uuid = r
            .try_get("scim_id")
            .map_err(|e| server_error("creating a user", &e))?;
        (id, true)
    } else {
        let row = sqlx::query(
            "INSERT INTO users (username, subject, roles, groups, source, login_count,
                                first_login_at, last_login_at)
             VALUES ($1, NULL, '{}', '{}', 'scim', 0, now(), 'epoch')
             RETURNING scim_id",
        )
        .bind(&username)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(d) if d.is_unique_violation() => conflict(),
            _ => server_error("creating a user", &e),
        })?;
        let id: Uuid = row
            .try_get("scim_id")
            .map_err(|e| server_error("creating a user", &e))?;
        (id, false)
    };
    ops::audit_first(
        &state,
        EventKind::UserProvision,
        ACTOR_AS,
        None,
        json!({ "target_user": username, "scim_id": scim_id, "adopted": adopted }),
    )
    .await
    .map_err(|s| status_error(&s))?;
    tx.commit()
        .await
        .map_err(|e| server_error("creating a user", &e))?;
    if !active {
        deactivate(&state, &username).await?;
    }
    let user = find_user(&state, scim_id)
        .await?
        .ok_or_else(|| not_found("user"))?;
    Ok(reply(StatusCode::CREATED, &user.json()))
}

/// Disable the person and end their tracked logins at once.
async fn deactivate(state: &AppState, username: &str) -> Result<(), Response> {
    ops::lock_user(state, ACTOR_AS, username, DEACTIVATED)
        .await
        .map_err(|s| status_error(&s))?;
    crate::idp_check::end_logins_of(state, username, None, DEACTIVATED).await;
    Ok(())
}

/// Enable the person again, but only if SCIM is who disabled them.
async fn reactivate(state: &AppState, username: &str) -> Result<(), Response> {
    let lock = crate::db::active_lock(&state.db, username)
        .await
        .map_err(|e| server_error("reading a lock", &e))?;
    if lock.is_some_and(|l| l.locked_by == ACTOR) {
        ops::unlock_user(state, ACTOR_AS, username)
            .await
            .map_err(|s| status_error(&s))?;
    }
    Ok(())
}

async fn set_active(state: &AppState, user: &UserRecord, active: bool) -> Result<(), Response> {
    if active == user.active {
        return Ok(());
    }
    if active {
        reactivate(state, &user.username).await
    } else {
        deactivate(state, &user.username).await
    }
}

async fn replace_user(State(state): State<AppState>, Path(id): Path<String>, body: Bytes) -> Reply {
    let id = parse_id(&id, "user")?;
    let v = parse_body(&body)?;
    let user = find_user(&state, id)
        .await?
        .ok_or_else(|| not_found("user"))?;
    let name = clean_username(&v)?;
    if !name.eq_ignore_ascii_case(&user.username) {
        return Err(error(
            StatusCode::BAD_REQUEST,
            Some("mutability"),
            "userName cannot be changed: it is the name in the person's ID token",
        ));
    }
    if let Some(active) = v.get("active").and_then(as_active) {
        set_active(&state, &user, active).await?;
    }
    let user = find_user(&state, id)
        .await?
        .ok_or_else(|| not_found("user"))?;
    Ok(reply(StatusCode::OK, &user.json()))
}

/// The `active` a PATCH asks for, in either of the shapes in use: Okta's
/// `{"op":"replace","value":{"active":false}}` and the path form
/// `{"op":"replace","path":"active","value":false}`.
fn patched_active(v: &Value) -> Result<Option<bool>, Response> {
    let ops = v
        .get("Operations")
        .and_then(Value::as_array)
        .ok_or_else(|| bad_request("Operations is required"))?;
    let mut active = None;
    for op in ops {
        let kind = op
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_lowercase();
        if kind != "replace" && kind != "add" {
            continue;
        }
        let value = op.get("value");
        let path = op.get("path").and_then(Value::as_str);
        let got = match (path, value) {
            (Some(p), Some(val)) if p.eq_ignore_ascii_case("active") => as_active(val),
            (None, Some(Value::Object(o))) => o.get("active").and_then(as_active),
            _ => None,
        };
        if got.is_some() {
            active = got;
        }
    }
    Ok(active)
}

async fn patch_user(State(state): State<AppState>, Path(id): Path<String>, body: Bytes) -> Reply {
    let id = parse_id(&id, "user")?;
    let v = parse_body(&body)?;
    let user = find_user(&state, id)
        .await?
        .ok_or_else(|| not_found("user"))?;
    if let Some(active) = patched_active(&v)? {
        set_active(&state, &user, active).await?;
    }
    let user = find_user(&state, id)
        .await?
        .ok_or_else(|| not_found("user"))?;
    Ok(reply(StatusCode::OK, &user.json()))
}

async fn delete_user(State(state): State<AppState>, Path(id): Path<String>) -> Reply {
    let id = parse_id(&id, "user")?;
    let user = find_user(&state, id)
        .await?
        .ok_or_else(|| not_found("user"))?;
    deactivate(&state, &user.username).await?;
    match ops::delete_disabled_user(
        &state,
        ACTOR_AS,
        &user.username,
        "removed in the identity provider (SCIM)",
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(DeleteRefused::NotDisabled | DeleteRefused::Bot | DeleteRefused::NoRecord)) => {
            return Err(error(
                StatusCode::CONFLICT,
                None,
                "the user cannot be deleted",
            ));
        }
        Err(s) => return Err(status_error(&s)),
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---- groups ----------------------------------------------------------------------

async fn group_json(state: &AppState, id: Uuid, name: &str) -> Result<Value, Response> {
    let members = sqlx::query(
        "SELECT m.user_scim_id, u.username FROM scim_group_members m
         JOIN users u ON u.scim_id = m.user_scim_id
         WHERE m.group_id = $1 ORDER BY u.username",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| server_error("reading group members", &e))?;
    let members: Vec<Value> = members
        .iter()
        .filter_map(|r| {
            let uid: Uuid = r.try_get("user_scim_id").ok()?;
            let display: String = r.try_get("username").ok()?;
            Some(json!({ "value": uid.to_string(), "display": display }))
        })
        .collect();
    Ok(json!({
        "schemas": [GROUP_SCHEMA],
        "id": id.to_string(),
        "displayName": name,
        "members": members,
        "meta": { "resourceType": "Group" },
    }))
}

async fn find_group(state: &AppState, id: Uuid) -> Result<Option<(Uuid, String)>, Response> {
    let row = sqlx::query("SELECT id, display_name FROM scim_groups WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| server_error("reading a group", &e))?;
    row.map(|r| Ok((r.try_get("id")?, r.try_get("display_name")?)))
        .transpose()
        .map_err(|e: sqlx::Error| server_error("reading a group", &e))
}

async fn list_groups(State(state): State<AppState>, Query(q): Query<ListQuery>) -> Reply {
    let (start, count) = q.window();
    let (rows, total) = match q.filter.as_deref() {
        Some(f) => {
            let name = eq_filter(f, "displayName")?;
            let rows = sqlx::query(
                "SELECT id, display_name FROM scim_groups WHERE lower(display_name) = lower($1)",
            )
            .bind(name)
            .fetch_all(&state.db)
            .await
            .map_err(|e| server_error("listing groups", &e))?;
            let total = i64::try_from(rows.len()).unwrap_or(0);
            (rows, total)
        }
        None => {
            let rows = sqlx::query(
                "SELECT id, display_name FROM scim_groups ORDER BY display_name OFFSET $1 LIMIT $2",
            )
            .bind(start - 1)
            .bind(count)
            .fetch_all(&state.db)
            .await
            .map_err(|e| server_error("listing groups", &e))?;
            let total: i64 = sqlx::query_scalar("SELECT count(*) FROM scim_groups")
                .fetch_one(&state.db)
                .await
                .map_err(|e| server_error("counting groups", &e))?;
            (rows, total)
        }
    };
    let mut resources = Vec::new();
    for r in &rows {
        let id: Uuid = r.try_get("id").map_err(|e| server_error("groups", &e))?;
        let name: String = r
            .try_get("display_name")
            .map_err(|e| server_error("groups", &e))?;
        resources.push(group_json(&state, id, &name).await?);
    }
    Ok(list_reply(total, start, &resources))
}

async fn get_group(State(state): State<AppState>, Path(id): Path<String>) -> Reply {
    let id = parse_id(&id, "group")?;
    let (id, name) = find_group(&state, id)
        .await?
        .ok_or_else(|| not_found("group"))?;
    Ok(reply(StatusCode::OK, &group_json(&state, id, &name).await?))
}

fn clean_group_name(v: &Value) -> Result<String, Response> {
    let name = v
        .get("displayName")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
        return Err(bad_request(
            "displayName is required (at most 256 characters, no control characters)",
        ));
    }
    Ok(name.to_owned())
}

/// The member ids in a `members` array (`[{"value": "<user id>"}, ...]`).
fn member_ids(v: &Value) -> Result<Vec<Uuid>, Response> {
    v.as_array()
        .ok_or_else(|| bad_request("members must be a list"))?
        .iter()
        .map(|m| {
            m.get("value")
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| bad_request("a member needs a `value` that is a user id"))
        })
        .collect()
}

/// The people in a group, as SCIM ids.
async fn members_of(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    group: Uuid,
) -> Result<BTreeSet<Uuid>, Response> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT m.user_scim_id FROM scim_group_members m
             JOIN users u ON u.scim_id = m.user_scim_id WHERE m.group_id = $1",
    )
    .bind(group)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| server_error("reading group members", &e))?;
    Ok(ids.into_iter().collect())
}

/// Make `group`'s members exactly `wanted`; every id must be a known person.
async fn set_members(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    group: Uuid,
    wanted: &BTreeSet<Uuid>,
) -> Result<(), Response> {
    let ids: Vec<Uuid> = wanted.iter().copied().collect();
    let known: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE scim_id = ANY($1)")
        .bind(&ids)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| server_error("checking members", &e))?;
    if usize::try_from(known).unwrap_or(0) != ids.len() {
        return Err(bad_request("a member is not a known user"));
    }
    sqlx::query("DELETE FROM scim_group_members WHERE group_id = $1")
        .bind(group)
        .execute(&mut **tx)
        .await
        .map_err(|e| server_error("changing members", &e))?;
    sqlx::query(
        "INSERT INTO scim_group_members (group_id, user_scim_id)
         SELECT $1, unnest($2::uuid[])",
    )
    .bind(group)
    .bind(&ids)
    .execute(&mut **tx)
    .await
    .map_err(|e| server_error("changing members", &e))?;
    Ok(())
}

/// After a commit: end the logins of people who lost access they relied on.
/// Only for removals, deletions and renames; being added to a group never
/// takes anything away. The comparison uses the groups the IdP puts the person
/// in *now* (see `effective_groups`), not SCIM's pushed groups alone, so a
/// group SCIM never pushes (a baseline group, a bootstrap admin group) still
/// counts for the person.
async fn enforce(state: &AppState, people: &BTreeSet<Uuid>) {
    if people.is_empty() {
        return;
    }
    let ids: Vec<Uuid> = people.iter().copied().collect();
    let rows = sqlx::query(concat!(
        "SELECT u.username, ",
        crate::console::store::effective_groups!(),
        " AS groups FROM users u WHERE u.scim_id = ANY($1)"
    ))
    .bind(&ids)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    for r in &rows {
        let (Ok(name), Ok(Some(groups))) = (
            r.try_get::<String, _>("username"),
            r.try_get::<Option<Vec<String>>, _>("groups"),
        ) else {
            continue;
        };
        crate::idp_check::end_logins_of(
            state,
            &name,
            Some(&groups),
            "the identity provider changed their groups",
        )
        .await;
    }
}

async fn names_of(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    people: &BTreeSet<Uuid>,
) -> Vec<String> {
    let ids: Vec<Uuid> = people.iter().copied().collect();
    sqlx::query_scalar("SELECT username FROM users WHERE scim_id = ANY($1) ORDER BY username")
        .bind(&ids)
        .fetch_all(&mut **tx)
        .await
        .unwrap_or_default()
}

/// What changed in a group, for the audit event and for enforcement.
struct Change<'a> {
    action: &'a str,
    group: &'a str,
    added: BTreeSet<Uuid>,
    removed: BTreeSet<Uuid>,
    /// People whose access may have shrunk: those removed, and everyone in a
    /// group that was renamed or deleted.
    enforce: BTreeSet<Uuid>,
}

/// Audit a group change inside its transaction, then commit and enforce.
async fn finish_group_change(
    state: &AppState,
    mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
    change: Change<'_>,
) -> Result<(), Response> {
    let added_names = names_of(&mut tx, &change.added).await;
    let removed_names = names_of(&mut tx, &change.removed).await;
    ops::audit_first(
        state,
        EventKind::UserGroupsChange,
        ACTOR_AS,
        None,
        json!({ "group": change.group, "action": change.action,
                "added": added_names, "removed": removed_names }),
    )
    .await
    .map_err(|s| status_error(&s))?;
    tx.commit()
        .await
        .map_err(|e| server_error("changing a group", &e))?;
    enforce(state, &change.enforce).await;
    Ok(())
}

/// One step of a members change, applied in order under the group's row lock.
enum Step {
    Add(Vec<Uuid>),
    Remove(Vec<Uuid>),
    Replace(Vec<Uuid>),
    Clear,
}

fn apply_steps(members: &mut BTreeSet<Uuid>, steps: &[Step]) {
    for step in steps {
        match step {
            Step::Add(ids) => members.extend(ids.iter().copied()),
            Step::Remove(ids) => {
                for id in ids {
                    members.remove(id);
                }
            }
            Step::Replace(ids) => *members = ids.iter().copied().collect(),
            Step::Clear => members.clear(),
        }
    }
}

async fn create_group(State(state): State<AppState>, body: Bytes) -> Reply {
    let v = parse_body(&body)?;
    let name = clean_group_name(&v)?;
    let wanted: BTreeSet<Uuid> = match v.get("members") {
        Some(m) => member_ids(m)?.into_iter().collect(),
        None => BTreeSet::new(),
    };
    let id = Uuid::now_v7();
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| server_error("creating a group", &e))?;
    let inserted = sqlx::query(
        "INSERT INTO scim_groups (id, display_name) VALUES ($1, $2)
         ON CONFLICT (lower(display_name)) DO NOTHING",
    )
    .bind(id)
    .bind(&name)
    .execute(&mut *tx)
    .await
    .map_err(|e| server_error("creating a group", &e))?;
    if inserted.rows_affected() == 0 {
        return Err(error(
            StatusCode::CONFLICT,
            Some("uniqueness"),
            "Group already exists in the database.",
        ));
    }
    set_members(&mut tx, id, &wanted).await?;
    finish_group_change(
        &state,
        tx,
        Change {
            action: "create",
            group: &name,
            added: wanted,
            removed: BTreeSet::new(),
            enforce: BTreeSet::new(),
        },
    )
    .await?;
    Ok(reply(
        StatusCode::CREATED,
        &group_json(&state, id, &name).await?,
    ))
}

async fn replace_group(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Reply {
    let id = parse_id(&id, "group")?;
    let v = parse_body(&body)?;
    find_group(&state, id)
        .await?
        .ok_or_else(|| not_found("group"))?;
    let name = clean_group_name(&v)?;
    let wanted = match v.get("members") {
        Some(m) => member_ids(m)?,
        None => Vec::new(),
    };
    apply_group(
        &state,
        id,
        Some(&name),
        vec![Step::Replace(wanted)],
        "replace",
    )
    .await
}

/// Rename and/or change the members of a group, in one audited transaction
/// that holds the group's row, so concurrent changes to it queue up and none
/// is lost.
async fn apply_group(
    state: &AppState,
    id: Uuid,
    new_name: Option<&str>,
    steps: Vec<Step>,
    action: &str,
) -> Reply {
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| server_error("changing a group", &e))?;
    let current: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM scim_groups WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| server_error("changing a group", &e))?;
    let Some(current) = current else {
        return Err(not_found("group"));
    };
    let before = members_of(&mut tx, id).await?;
    let name = new_name.unwrap_or(&current).to_owned();
    if name != current {
        let renamed = sqlx::query(
            "UPDATE scim_groups SET display_name = $2 WHERE id = $1
             AND NOT EXISTS (SELECT 1 FROM scim_groups o
                             WHERE o.id <> $1 AND lower(o.display_name) = lower($2))",
        )
        .bind(id)
        .bind(&name)
        .execute(&mut *tx)
        .await
        .map_err(|e| server_error("renaming a group", &e))?;
        if renamed.rows_affected() == 0 {
            return Err(error(
                StatusCode::CONFLICT,
                Some("uniqueness"),
                "A group with that name already exists.",
            ));
        }
    }
    let mut after = before.clone();
    apply_steps(&mut after, &steps);
    if after != before {
        set_members(&mut tx, id, &after).await?;
    }
    let added: BTreeSet<Uuid> = after.difference(&before).copied().collect();
    let removed: BTreeSet<Uuid> = before.difference(&after).copied().collect();
    // A rename takes the old name away from everyone who had it.
    let enforce = if name == current {
        removed.clone()
    } else {
        before.clone()
    };
    finish_group_change(
        state,
        tx,
        Change {
            action,
            group: &name,
            added,
            removed,
            enforce,
        },
    )
    .await?;
    Ok(reply(StatusCode::OK, &group_json(state, id, &name).await?))
}

/// Read a PATCH into steps, without touching the database.
fn plan_patch(v: &Value) -> Result<(Option<String>, Vec<Step>), Response> {
    let ops_list = v
        .get("Operations")
        .and_then(Value::as_array)
        .ok_or_else(|| bad_request("Operations is required"))?;
    let mut name: Option<String> = None;
    let mut steps = Vec::new();
    for op in ops_list {
        let kind = op
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_lowercase();
        let path = op.get("path").and_then(Value::as_str).unwrap_or("");
        let value = op.get("value");
        let lower = path.to_lowercase();
        if lower == "displayname" {
            name = Some(clean_group_name(&json!({ "displayName": value }))?);
        } else if lower.is_empty() {
            // Okta's pathless form: {"op":"replace","value":{"displayName":...}}
            if let Some(obj) = value.filter(|x| x.is_object()) {
                if obj.get("displayName").is_some() {
                    name = Some(clean_group_name(obj)?);
                }
                if let Some(m) = obj.get("members") {
                    let ids = member_ids(m)?;
                    steps.push(if kind == "add" {
                        Step::Add(ids)
                    } else {
                        Step::Replace(ids)
                    });
                }
            }
        } else if lower == "members" {
            match (kind.as_str(), value) {
                ("add", Some(v)) => steps.push(Step::Add(member_ids(v)?)),
                ("replace", Some(v)) => steps.push(Step::Replace(member_ids(v)?)),
                ("remove", Some(v)) => steps.push(Step::Remove(member_ids(v)?)),
                ("remove", None) => steps.push(Step::Clear),
                _ => return Err(bad_request("unsupported members operation")),
            }
        } else if let Some(rest) = lower.strip_prefix("members[value eq ") {
            // members[value eq "<id>"]
            let id_text = rest.trim_end_matches(']').trim().trim_matches('"');
            let target = Uuid::parse_str(id_text)
                .map_err(|_| bad_request("a members filter needs a user id"))?;
            if kind == "remove" {
                steps.push(Step::Remove(vec![target]));
            } else {
                return Err(bad_request("unsupported members operation"));
            }
        }
        // Anything else (other attributes) is accepted and ignored.
    }
    Ok((name, steps))
}

async fn patch_group(State(state): State<AppState>, Path(id): Path<String>, body: Bytes) -> Reply {
    let id = parse_id(&id, "group")?;
    let v = parse_body(&body)?;
    find_group(&state, id)
        .await?
        .ok_or_else(|| not_found("group"))?;
    let (name, steps) = plan_patch(&v)?;
    apply_group(&state, id, name.as_deref(), steps, "patch").await
}

async fn delete_group(State(state): State<AppState>, Path(id): Path<String>) -> Reply {
    let id = parse_id(&id, "group")?;
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| server_error("deleting a group", &e))?;
    let name: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM scim_groups WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| server_error("deleting a group", &e))?;
    let Some(name) = name else {
        return Err(not_found("group"));
    };
    let before = members_of(&mut tx, id).await?;
    sqlx::query("DELETE FROM scim_groups WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| server_error("deleting a group", &e))?;
    finish_group_change(
        &state,
        tx,
        Change {
            action: "delete",
            group: &name,
            added: BTreeSet::new(),
            removed: before.clone(),
            enforce: before,
        },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_only_filter_is_an_equality_on_the_named_attribute() {
        assert_eq!(
            eq_filter("userName eq \"a@example.com\"", "userName").ok(),
            Some("a@example.com")
        );
        assert_eq!(
            eq_filter("USERNAME EQ \"a b\"", "userName").ok(),
            Some("a b")
        );
        for bad in [
            "userName co \"a\"",
            "displayName eq \"a\"",
            "userName eq a",
            "userName eq \"a\" or userName eq \"b\"",
            "",
            "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}",
            "userName\u{e9}eq \"a\"",
            "userName e",
            // Byte 8 falls inside a character: indexing there would panic.
            "a\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}",
        ] {
            assert!(eq_filter(bad, "userName").is_err(), "{bad}");
        }
    }

    #[test]
    fn a_patch_can_name_active_with_or_without_a_path() {
        let okta = json!({ "Operations": [{ "op": "replace", "value": { "active": false } }] });
        assert_eq!(patched_active(&okta).ok(), Some(Some(false)));
        let path =
            json!({ "Operations": [{ "op": "Replace", "path": "active", "value": "True" }] });
        assert_eq!(patched_active(&path).ok(), Some(Some(true)));
        let other =
            json!({ "Operations": [{ "op": "replace", "path": "name.givenName", "value": "x" }] });
        assert_eq!(patched_active(&other).ok(), Some(None));
        assert!(patched_active(&json!({})).is_err());
    }

    #[test]
    fn tokens_compare_whole() {
        assert!(token_matches("abc", "abc"));
        assert!(!token_matches("abc", "abd"));
        assert!(!token_matches("", "abc"));
    }
}
