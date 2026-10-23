//! Host-bound browser sessions and streaming HTTP forwarding (ADR-0022).

use std::error::Error;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;

use base64::Engine as _;
use http::header::{self, HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::BodyExt as _;
use hyper::body::{Bytes, Incoming};
use hyper_util::rt::TokioIo;
use limen_audit::{Context as AuditContext, EventKind};
use limen_ca::verify::{UserIdentity, verify_user};
use limen_policy::{AccessRequest, Principal, model::WebTarget};
use limen_proto::v1::auth_client::AuthClient;
use limen_proto::v1::{RedeemWebHandoffRequest, WebAppSession};
use limen_session::envelope::{self, Purpose};
use prost::Message as _;
use rustls_pki_types::CertificateDer;
use serde_json::json;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;
use url::Url;
use uuid::Uuid;

use crate::Proxy;

type BoxError = Box<dyn Error + Send + Sync>;
type ProxyResponse = Response<tonic::body::Body>;

const APP_COOKIE: &str = "__Host-limen_app";
const APP_LOGIN_COOKIE: &str = "__Host-limen_app_login";
const HANDOFF_PATH: &str = "/.limen/callback";
const MAX_URI_LEN: usize = 4096;

struct WebRoute {
    resource: String,
    target: WebTarget,
}

struct CountedIo<T> {
    inner: T,
    bytes_written: Arc<AtomicU64>,
}

impl<T> CountedIo<T> {
    fn new(inner: T, bytes_written: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            bytes_written,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for CountedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CountedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &result {
            this.bytes_written
                .fetch_add(*written as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Route when either HTTP authority or SNI names a configured app. This also
/// lets the handler reject a mismatched SNI/authority pair with 421.
pub(crate) fn candidate(proxy: &Proxy, req: &Request<Incoming>) -> bool {
    let Some(snapshot) = proxy.policy.latest() else {
        return false;
    };
    let host = request_host(req, web_public_port(proxy)).ok().flatten();
    let sni = req
        .extensions()
        .get::<limen_tunnel::PeerInfo>()
        .and_then(|peer| peer.server_name.as_deref());
    snapshot.policy.resources().any(|resource| {
        let Some(web) = &resource.spec.web else {
            return false;
        };
        host.as_deref()
            .is_some_and(|host| host.eq_ignore_ascii_case(&web.host))
            || sni.is_some_and(|name| name.eq_ignore_ascii_case(&web.host))
    })
}

#[allow(clippy::too_many_lines)] // Keep request authorization and audit ordering visible.
pub(crate) async fn handle(proxy: &Proxy, mut req: Request<Incoming>) -> ProxyResponse {
    let now = OffsetDateTime::now_utc();
    let snapshot = match proxy.policy.fresh(now) {
        Ok(snapshot) => snapshot,
        Err(e) => {
            tracing::warn!(error = %e, "web request refused without a fresh policy snapshot");
            return plain(StatusCode::SERVICE_UNAVAILABLE, "policy is unavailable");
        }
    };
    let peer = req.extensions().get::<limen_tunnel::PeerInfo>().cloned();
    let route = match resolve_route(
        &snapshot.policy,
        peer.as_ref(),
        &req,
        web_public_port(proxy),
    ) {
        Ok(Some(route)) => route,
        Ok(None) => return plain(StatusCode::MISDIRECTED_REQUEST, "web host mismatch"),
        Err(()) => {
            return audit_denied(
                proxy,
                None,
                None,
                "invalid_authority",
                StatusCode::MISDIRECTED_REQUEST,
                "web host mismatch",
                None,
                Some(req.method().as_str()),
                Some(req.uri().path()),
            )
            .await;
        }
    };
    let uri = req.uri().clone();
    if !safe_uri(&uri) || req.method() == Method::CONNECT {
        return audit_denied(
            proxy,
            None,
            None,
            "invalid_request_target",
            StatusCode::BAD_REQUEST,
            "invalid request target",
            Some(&route.resource),
            Some(req.method().as_str()),
            Some(uri.path()),
        )
        .await;
    }

    if uri.path() == HANDOFF_PATH {
        return redeem_handoff(proxy, &route, req).await;
    }

    let websocket = is_websocket_request(&req);
    if req.headers().contains_key(header::UPGRADE) && !websocket {
        return audit_denied(
            proxy,
            None,
            None,
            "unsupported_upgrade",
            StatusCode::NOT_IMPLEMENTED,
            "unsupported protocol upgrade",
            Some(&route.resource),
            Some(req.method().as_str()),
            Some(uri.path()),
        )
        .await;
    }
    if websocket && req.version() != http::Version::HTTP_11 {
        return audit_denied(
            proxy,
            None,
            None,
            "unsupported_upgrade",
            StatusCode::BAD_REQUEST,
            "WebSocket upgrades require HTTP/1.1",
            Some(&route.resource),
            Some(req.method().as_str()),
            Some(uri.path()),
        )
        .await;
    }

    let claims = match read_app_session(proxy, &req, &route) {
        Ok(Some((claims, identity))) => (claims, identity),
        Ok(None) => return login_redirect(proxy, &route, &uri, req.method()).await,
        Err(()) => {
            let denied = audit_denied(
                proxy,
                None,
                None,
                "invalid_app_session",
                StatusCode::FORBIDDEN,
                "sign-in required",
                Some(&route.resource),
                Some(req.method().as_str()),
                Some(uri.path()),
            )
            .await;
            return with_clear_cookie(denied);
        }
    };
    let (claims, identity) = claims;
    if identity.bot
        || claims.username != identity.username
        || claims.roles != identity.roles
        || claims.login_id != identity.login_id
        || claims.expires_at_unix > identity.not_after.unix_timestamp()
        || claims.resource != route.resource
        || claims.host != route.target.host
        || claims.expires_at_unix <= now.unix_timestamp()
        || (route.target.identity_headers
            && !identity_assertion_matches(&claims, &identity, &route.target.host))
    {
        return with_clear_cookie(
            audit_denied(
                proxy,
                Some(identity.username),
                None,
                "invalid_app_session",
                StatusCode::FORBIDDEN,
                "sign-in required",
                Some(&route.resource),
                Some(req.method().as_str()),
                Some(uri.path()),
            )
            .await,
        );
    }
    if let Some(reason) = snapshot
        .restrictions
        .blocks(&identity.username, &identity.login_id, "")
    {
        return audit_denied(
            proxy,
            Some(identity.username),
            None,
            reason,
            StatusCode::FORBIDDEN,
            "access denied",
            Some(&route.resource),
            Some(req.method().as_str()),
            Some(uri.path()),
        )
        .await;
    }
    let decision = snapshot.policy.evaluate(&AccessRequest {
        roles: &identity.roles,
        resource: &route.resource,
        principal: Principal::WebAccess,
    });
    if !decision.is_allowed()
        || !snapshot.policy.web_request_allowed(
            &identity.roles,
            &route.resource,
            req.method().as_str(),
            uri.path(),
        )
    {
        return audit_denied(
            proxy,
            Some(identity.username),
            None,
            "policy_denied",
            StatusCode::FORBIDDEN,
            "access denied",
            Some(&route.resource),
            Some(req.method().as_str()),
            Some(uri.path()),
        )
        .await;
    }

    let session_id = Uuid::now_v7();
    let started = Instant::now();
    let client_addr = peer
        .as_ref()
        .and_then(|p| p.remote_addr)
        .map(|addr| addr.ip().to_string());
    let request_data = json!({
        "action": "web",
        "resource": route.resource,
        "host": route.target.host,
        "method": req.method().as_str(),
        "path": uri.path(),
        "actor_type": "user",
        "websocket": websocket,
        "client_addr": client_addr,
        "policy_version": snapshot.version,
    });
    if let Err(e) = proxy
        .audit
        .emit(
            EventKind::WebRequest,
            AuditContext {
                user: Some(identity.username.clone()),
                session_id: Some(session_id),
            },
            request_data,
        )
        .await
    {
        tracing::error!(error = %e, session = %session_id, "failed to audit web request; refusing to forward it");
        return plain(StatusCode::SERVICE_UNAVAILABLE, "audit is unavailable");
    }

    let user_cert = claims.user_cert_der.clone();
    let client_upgrade = websocket.then(|| hyper::upgrade::on(&mut req));
    let (mut original_parts, incoming_body) = req.into_parts();
    let original_method = original_parts.method.clone();
    let original_uri = original_parts.uri.clone();
    original_parts.extensions = http::Extensions::new();
    let stream = match crate::sessions::open_web_stream(
        proxy,
        &identity,
        user_cert,
        &route.resource,
        &route.target.host,
        client_addr.clone(),
        session_id,
    )
    .await
    {
        Ok(stream) => stream,
        Err(denial) => {
            let status = if denial.audit {
                let _ = proxy
                    .audit
                    .emit(
                        EventKind::AuthDenied,
                        AuditContext {
                            user: Some(identity.username.clone()),
                            session_id: Some(session_id),
                        },
                        json!({
                            "action": "web",
                            "resource": route.resource,
                            "reason": denial.code.unwrap_or("worker_refused"),
                        }),
                    )
                    .await
                    .map_err(|e| tracing::error!(error = %e, "failed to audit worker web denial"));
                StatusCode::FORBIDDEN
            } else {
                tracing::warn!(error = %denial.reason, resource = %route.resource, "worker web session unavailable");
                StatusCode::BAD_GATEWAY
            };
            if emit_response(
                proxy,
                &identity.username,
                session_id,
                &route,
                &original_method,
                status,
                0,
                0,
                started,
                "worker_refused",
            )
            .await
            .is_err()
            {
                return plain(StatusCode::SERVICE_UNAVAILABLE, "audit is unavailable");
            }
            return plain(status, "web session unavailable");
        }
    };

    let upload = Arc::new(AtomicU64::new(0));
    let body = CountBody {
        inner: incoming_body,
        count: Arc::clone(&upload),
    };
    original_parts.version = http::Version::HTTP_11;
    original_parts.uri = match Uri::builder()
        .path_and_query(
            original_uri
                .path_and_query()
                .cloned()
                .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/")),
        )
        .build()
    {
        Ok(uri) => uri,
        Err(_) => return plain(StatusCode::BAD_REQUEST, "invalid request target"),
    };
    sanitize_request_headers(
        &mut original_parts.headers,
        &route.target,
        peer.as_ref(),
        websocket,
        &claims,
    );
    let upstream_request = Request::from_parts(original_parts, body);

    let (mut sender, connection) = match hyper::client::conn::http1::handshake::<
        _,
        CountBody<Incoming>,
    >(TokioIo::new(stream))
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(error = %e, resource = %route.resource, "web upstream HTTP connection failed");
            if emit_response(
                proxy,
                &identity.username,
                session_id,
                &route,
                &original_method,
                StatusCode::BAD_GATEWAY,
                upload.load(Ordering::Relaxed),
                0,
                started,
                "upstream_unavailable",
            )
            .await
            .is_err()
            {
                return plain(StatusCode::SERVICE_UNAVAILABLE, "audit is unavailable");
            }
            return plain(StatusCode::BAD_GATEWAY, "web app unavailable");
        }
    };
    tokio::spawn(async move {
        if let Err(e) = connection.with_upgrades().await {
            tracing::debug!(error = %e, "web upstream HTTP connection ended");
        }
    });
    let mut upstream_response = match sender.send_request(upstream_request).await {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!(error = %e, resource = %route.resource, "web upstream request failed");
            if emit_response(
                proxy,
                &identity.username,
                session_id,
                &route,
                &original_method,
                StatusCode::BAD_GATEWAY,
                upload.load(Ordering::Relaxed),
                0,
                started,
                "upstream_unavailable",
            )
            .await
            .is_err()
            {
                return plain(StatusCode::SERVICE_UNAVAILABLE, "audit is unavailable");
            }
            return plain(StatusCode::BAD_GATEWAY, "web app unavailable");
        }
    };
    sanitize_response_headers(upstream_response.headers_mut(), websocket);

    if websocket && upstream_response.status() == StatusCode::SWITCHING_PROTOCOLS {
        let status = upstream_response.status();
        if emit_response(
            proxy,
            &identity.username,
            session_id,
            &route,
            &original_method,
            status,
            upload.load(Ordering::Relaxed),
            0,
            started,
            "websocket_upgrade",
        )
        .await
        .is_err()
        {
            return plain(StatusCode::SERVICE_UNAVAILABLE, "audit is unavailable");
        }
        let upstream_upgrade = hyper::upgrade::on(&mut upstream_response);
        let Some(client_upgrade) = client_upgrade else {
            return plain(StatusCode::BAD_GATEWAY, "WebSocket upgrade failed");
        };
        let proxy = proxy.clone();
        let username = identity.username;
        let resource = route.resource;
        let host = route.target.host;
        let bytes_in = Arc::new(AtomicU64::new(0));
        let bytes_out = Arc::new(AtomicU64::new(0));
        tokio::spawn(async move {
            let result = async {
                let client = client_upgrade.await.map_err(|e| Box::new(e) as BoxError)?;
                let upstream = upstream_upgrade
                    .await
                    .map_err(|e| Box::new(e) as BoxError)?;
                let mut client = CountedIo::new(TokioIo::new(client), Arc::clone(&bytes_out));
                let mut upstream = CountedIo::new(TokioIo::new(upstream), Arc::clone(&bytes_in));
                tokio::io::copy_bidirectional(&mut client, &mut upstream)
                    .await
                    .map_err(|e| Box::new(e) as BoxError)
            }
            .await;
            let bytes_in = bytes_in.load(Ordering::Relaxed);
            let bytes_out = bytes_out.load(Ordering::Relaxed);
            let (bytes_in, bytes_out, reason) = match result {
                Ok(_) => (bytes_in, bytes_out, "closed"),
                Err(e) => {
                    tracing::debug!(error = %e, session = %session_id, "websocket stream ended with an error");
                    (bytes_in, bytes_out, "stream_error")
                }
            };
            let _ = proxy
                .audit
                .emit(
                    EventKind::WebSocket,
                    AuditContext {
                        user: Some(username),
                        session_id: Some(session_id),
                    },
                    json!({
                        "resource": resource,
                        "host": host,
                        "method": original_method.as_str(),
                        "path": original_uri.path(),
                        "bytes_in": bytes_in,
                        "bytes_out": bytes_out,
                        "duration_ms": started.elapsed().as_millis(),
                        "reason": reason,
                        "actor_type": "user",
                    }),
                )
                .await
                .map_err(|e| tracing::error!(error = %e, session = %session_id, "failed to audit web socket end"));
        });
        let (parts, _) = upstream_response.into_parts();
        return Response::from_parts(parts, empty_body());
    }

    let status = upstream_response.status();
    let (parts, body) = upstream_response.into_parts();
    let response_body = AuditResponseBody {
        inner: body,
        audit: proxy.audit.clone(),
        context: AuditContext {
            user: Some(identity.username),
            session_id: Some(session_id),
        },
        event: json!({
            "resource": route.resource,
            "host": route.target.host,
            "method": original_method.as_str(),
            "path": original_uri.path(),
            "actor_type": "user",
            "status": status.as_u16(),
            "bytes_in": upload.load(Ordering::Relaxed),
        }),
        status,
        session_id,
        request_started: started,
        upload,
        download: Arc::new(AtomicU64::new(0)),
        audit_rx: None,
        audit_started: false,
        done: false,
        pending_error: None,
    };
    Response::from_parts(parts, tonic::body::Body::new(response_body))
}

fn resolve_route(
    policy: &limen_policy::Policy,
    peer: Option<&limen_tunnel::PeerInfo>,
    req: &Request<Incoming>,
    public_port: u16,
) -> Result<Option<WebRoute>, ()> {
    let sni = peer.and_then(|peer| peer.server_name.as_deref());
    let host = request_host(req, public_port)?;
    let route = policy.resources().find_map(|resource| {
        let target = resource.spec.web.as_ref()?;
        let named_by_sni = sni.is_some_and(|name| name.eq_ignore_ascii_case(&target.host));
        let named_by_host = host
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case(&target.host));
        (named_by_sni || named_by_host).then(|| WebRoute {
            resource: resource.metadata.name.clone(),
            target: target.clone(),
        })
    });
    let Some(route) = route else {
        return Ok(None);
    };
    if !sni.is_some_and(|name| name.eq_ignore_ascii_case(&route.target.host))
        || !host
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case(&route.target.host))
    {
        return Err(());
    }
    Ok(Some(route))
}

fn request_host(req: &Request<Incoming>, public_port: u16) -> Result<Option<String>, ()> {
    let values: Vec<_> = req.headers().get_all(header::HOST).iter().collect();
    if values.len() > 1 {
        return Err(());
    }
    let header_authority = values
        .first()
        .map(|value| value.to_str().map_err(|_| ()))
        .transpose()?
        .map(|authority| parse_authority(authority, public_port))
        .transpose()?;
    let uri_authority = req
        .uri()
        .authority()
        .map(|authority| parse_authority(authority.as_str(), public_port))
        .transpose()?;
    if let (Some(header), Some(uri)) = (&header_authority, &uri_authority)
        && header != uri
    {
        return Err(());
    }
    Ok(header_authority.or(uri_authority))
}

fn web_public_port(proxy: &Proxy) -> u16 {
    proxy
        .config
        .console_public_url
        .as_deref()
        .and_then(|origin| Url::parse(origin).ok())
        .and_then(|origin| origin.port_or_known_default())
        .unwrap_or_else(|| proxy.config.listen.port())
}

fn parse_authority(authority: &str, public_port: u16) -> Result<String, ()> {
    let parsed = http::uri::Authority::try_from(authority).map_err(|_| ())?;
    if parsed.as_str().contains('@')
        || parsed.host().is_empty()
        || parsed
            .port_u16()
            .is_some_and(|port| port != 443 && port != public_port)
        || parsed.host().contains(':')
    {
        return Err(());
    }
    let host = parsed.host().to_ascii_lowercase();
    if host.ends_with('.') || !host.is_ascii() {
        return Err(());
    }
    Ok(host)
}

fn safe_uri(uri: &Uri) -> bool {
    let Some(path_and_query) = uri.path_and_query() else {
        return false;
    };
    let path = path_and_query.path();
    path_and_query.as_str().len() <= MAX_URI_LEN
        && path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains("//")
        && !path.contains(['\\', '%'])
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b))
        && path.split('/').all(|part| part != "." && part != "..")
        && path_and_query
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_graphic())
        && !path_and_query.as_str().contains('#')
}

fn is_websocket_request(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && req
            .headers()
            .get_all(header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}

fn valid_browser_nonce(nonce: &str) -> bool {
    nonce.len() <= 128
        && base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(nonce)
            .is_ok_and(|bytes| bytes.len() == 32)
}

async fn login_redirect(
    proxy: &Proxy,
    route: &WebRoute,
    uri: &Uri,
    method: &Method,
) -> ProxyResponse {
    if let Err(error) = proxy
        .audit
        .emit(
            EventKind::AuthDenied,
            AuditContext {
                user: None,
                session_id: None,
            },
            json!({
                "action": "web",
                "reason": "web_login_required",
                "actor_type": "unknown",
                "resource": route.resource,
                "method": method.as_str(),
                "path": uri.path(),
            }),
        )
        .await
    {
        tracing::error!(error = %error, "failed to audit web sign-in redirect");
        return plain(StatusCode::SERVICE_UNAVAILABLE, "audit is unavailable");
    }
    let Some(origin) = proxy.config.console_public_url.as_deref() else {
        return plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "browser sign-in is not configured",
        );
    };
    let Ok(mut destination) = Url::parse(origin) else {
        return plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "browser sign-in is not configured",
        );
    };
    if destination.scheme() != "https"
        || destination.host_str().is_none()
        || !destination.username().is_empty()
        || destination.password().is_some()
        || destination.query().is_some()
        || destination.fragment().is_some()
        || destination.path() != "/"
    {
        return plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "browser sign-in is not configured",
        );
    }
    destination.set_path("/console/web/login");
    let browser_nonce =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    destination
        .query_pairs_mut()
        .append_pair("resource", &route.resource)
        .append_pair("host", &route.target.host)
        .append_pair("browser_nonce", &browser_nonce)
        .append_pair(
            "return_path",
            uri.path_and_query()
                .map_or("/", http::uri::PathAndQuery::as_str),
        );
    let mut response = redirect_response(destination.as_str());
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{APP_LOGIN_COOKIE}={browser_nonce}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600"
        ))
        .expect("base64url browser nonce is a valid cookie value"),
    );
    response
}

fn read_app_session(
    proxy: &Proxy,
    req: &Request<Incoming>,
    route: &WebRoute,
) -> Result<Option<(WebAppSession, UserIdentity)>, ()> {
    let Some(cookie) = cookie_value(req.headers(), APP_COOKIE)? else {
        return Ok(None);
    };
    if cookie.len() > 8192 {
        return Err(());
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cookie)
        .map_err(|_| ())?;
    let signed = limen_proto::v1::Signed::decode(bytes.as_slice()).map_err(|_| ())?;
    verify_signed_session(proxy, &signed, route).map(Some)
}

fn verify_signed_session(
    proxy: &Proxy,
    signed: &limen_proto::v1::Signed,
    route: &WebRoute,
) -> Result<(WebAppSession, UserIdentity), ()> {
    let internal_ca = proxy.credentials().internal_ca().map_err(|_| ())?;
    let (_, payload) =
        envelope::verify(signed, Purpose::WebAppSession, &internal_ca).map_err(|_| ())?;
    let claims = WebAppSession::decode(payload).map_err(|_| ())?;
    let now = OffsetDateTime::now_utc();
    if claims.username.is_empty()
        || claims.login_id.is_empty()
        || claims.resource != route.resource
        || claims.host != route.target.host
        || claims.expires_at_unix <= now.unix_timestamp()
    {
        return Err(());
    }
    let user_ca = proxy.credentials().user_ca().map_err(|_| ())?;
    let identity = verify_user(
        &CertificateDer::from(claims.user_cert_der.as_slice()),
        &user_ca,
    )
    .map_err(|_| ())?;
    if identity.bot
        || claims.username != identity.username
        || claims.roles != identity.roles
        || claims.login_id != identity.login_id
        || claims.expires_at_unix > identity.not_after.unix_timestamp()
    {
        return Err(());
    }
    Ok((claims, identity))
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Result<Option<String>, ()> {
    let mut found = None;
    for header in &headers.get_all(header::COOKIE) {
        let value = header.to_str().map_err(|_| ())?;
        for pair in value.split(';') {
            let Some((key, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if key == name {
                if found.is_some() {
                    return Err(());
                }
                found = Some(value.to_owned());
            }
        }
    }
    Ok(found)
}

fn sanitize_request_headers(
    headers: &mut HeaderMap,
    target: &WebTarget,
    peer: Option<&limen_tunnel::PeerInfo>,
    websocket: bool,
    session: &WebAppSession,
) {
    sanitize_hop_headers(headers, websocket);
    let strip: Vec<_> = headers
        .keys()
        .filter(|name| {
            let name = name.as_str();
            name.starts_with("x-limen-")
                || name.starts_with("x-forwarded-")
                || name == "forwarded"
                || name == "x-real-ip"
        })
        .cloned()
        .collect();
    for name in strip {
        headers.remove(name);
    }
    if let Some(cookie) = filtered_cookie(headers) {
        headers.insert(header::COOKIE, cookie);
    } else {
        headers.remove(header::COOKIE);
    }
    headers.insert(
        header::HOST,
        HeaderValue::from_str(&target.host).expect("validated DNS host"),
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-host"),
        HeaderValue::from_str(&target.host).expect("validated DNS host"),
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("https"),
    );
    if let Some(addr) = peer.and_then(|p| p.remote_addr).map(|addr| addr.ip())
        && let Ok(value) = HeaderValue::from_str(&addr.to_string())
    {
        headers.insert(HeaderName::from_static("x-forwarded-for"), value);
    }
    if target.identity_headers {
        headers.insert(
            HeaderName::from_static("x-limen-user"),
            HeaderValue::from_str(&session.username).expect("validated user identity"),
        );
        headers.insert(
            HeaderName::from_static("x-limen-roles"),
            HeaderValue::from_str(&session.roles.join(",")).expect("validated role names"),
        );
        headers.insert(
            HeaderName::from_static("x-limen-identity"),
            HeaderValue::from_str(&session.identity_assertion)
                .expect("validated signed identity assertion"),
        );
    }
}

fn identity_assertion_matches(
    session: &WebAppSession,
    identity: &UserIdentity,
    host: &str,
) -> bool {
    let mut parts = session.identity_assertion.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let decode = |part: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .ok()
    };
    let (Some(header), Some(payload), Some(signature)) =
        (decode(header), decode(payload), decode(signature))
    else {
        return false;
    };
    let (Ok(header), Ok(payload)) = (
        serde_json::from_slice::<serde_json::Value>(&header),
        serde_json::from_slice::<serde_json::Value>(&payload),
    ) else {
        return false;
    };
    let now = OffsetDateTime::now_utc().unix_timestamp();
    header["alg"] == "ES256"
        && header["typ"] == "JWT"
        && header["kid"].as_str().is_some_and(|kid| !kid.is_empty())
        && signature.len() == 64
        && payload["iss"] == "urn:limen:control-plane"
        && payload["sub"] == identity.username
        && payload["aud"] == host
        && payload["login_id"] == identity.login_id
        && payload["roles"].as_array().is_some_and(|roles| {
            roles.len() == identity.roles.len()
                && roles
                    .iter()
                    .zip(&identity.roles)
                    .all(|(role, expected)| role.as_str() == Some(expected))
        })
        && payload["exp"]
            .as_i64()
            .is_some_and(|expires| expires > now && expires <= session.expires_at_unix)
}

fn filtered_cookie(headers: &HeaderMap) -> Option<HeaderValue> {
    let mut pairs = Vec::new();
    let cookie_headers = headers.get_all(header::COOKIE);
    for header in &cookie_headers {
        let value = header.to_str().ok()?;
        for pair in value
            .split(';')
            .map(str::trim)
            .filter(|pair| !pair.is_empty())
        {
            if pair
                .split_once('=')
                .is_some_and(|(name, _)| name == APP_COOKIE || name == APP_LOGIN_COOKIE)
            {
                continue;
            }
            pairs.push(pair);
        }
    }
    if pairs.is_empty() {
        None
    } else {
        HeaderValue::from_str(&pairs.join("; ")).ok()
    }
}

fn sanitize_response_headers(headers: &mut HeaderMap, websocket: bool) {
    sanitize_hop_headers(headers, websocket);
    let cookies: Vec<_> = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter(|value| {
            value.split_once('=').is_none_or(|(name, _)| {
                let name = name.trim();
                name != APP_COOKIE && name != APP_LOGIN_COOKIE
            })
        })
        .map(str::to_owned)
        .collect();
    headers.remove(header::SET_COOKIE);
    for cookie in cookies {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            headers.append(header::SET_COOKIE, value);
        }
    }
}

fn sanitize_hop_headers(headers: &mut HeaderMap, preserve_upgrade: bool) {
    let connection_tokens: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .filter(|name| {
            !preserve_upgrade || (*name != header::CONNECTION && *name != header::UPGRADE)
        })
        .collect();
    for name in [
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
    ] {
        headers.remove(name);
    }
    headers.remove(header::CONNECTION);
    headers.remove(HeaderName::from_static("keep-alive"));
    if !preserve_upgrade {
        headers.remove(header::UPGRADE);
    } else if headers.contains_key(header::UPGRADE) {
        headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    }
    for name in connection_tokens {
        headers.remove(name);
    }
}

#[allow(clippy::too_many_lines)] // Keep one-use redemption and fail-closed audit sequencing clear.
async fn redeem_handoff(proxy: &Proxy, route: &WebRoute, req: Request<Incoming>) -> ProxyResponse {
    let started = Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    if req.method() != Method::GET {
        return audit_denied(
            proxy,
            None,
            None,
            "invalid_handoff_method",
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed",
            Some(&route.resource),
            Some(method.as_str()),
            Some(uri.path()),
        )
        .await;
    }
    let token = req.uri().query().and_then(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| key == "handoff")
            .map(|(_, value)| value.into_owned())
    });
    let Some(token) = token.filter(|token| !token.is_empty() && token.len() <= 128) else {
        return audit_denied(
            proxy,
            None,
            None,
            "invalid_handoff",
            StatusCode::BAD_REQUEST,
            "invalid sign-in handoff",
            Some(&route.resource),
            Some(method.as_str()),
            Some(uri.path()),
        )
        .await;
    };
    let browser_nonce = match cookie_value(req.headers(), APP_LOGIN_COOKIE) {
        Ok(Some(nonce)) if valid_browser_nonce(&nonce) => nonce,
        _ => {
            return audit_denied(
                proxy,
                None,
                None,
                "invalid_handoff_browser",
                StatusCode::FORBIDDEN,
                "sign-in handoff is not valid for this browser",
                Some(&route.resource),
                Some(method.as_str()),
                Some(uri.path()),
            )
            .await;
        }
    };
    let mut client = AuthClient::new(proxy.cp_channel());
    let redeemed = client
        .redeem_web_handoff(RedeemWebHandoffRequest {
            token,
            resource: route.resource.clone(),
            host: route.target.host.clone(),
            browser_nonce,
        })
        .await;
    let response = match redeemed {
        Ok(response) => response.into_inner(),
        Err(status) => {
            tracing::warn!(code = ?status.code(), "web sign-in handoff could not be redeemed");
            return audit_denied(
                proxy,
                None,
                None,
                "handoff_redemption_failed",
                StatusCode::FORBIDDEN,
                "sign-in handoff expired; start again",
                Some(&route.resource),
                Some(method.as_str()),
                Some(uri.path()),
            )
            .await;
        }
    };
    let Some(signed) = response.session else {
        tracing::error!("control plane returned an empty web session handoff");
        return audit_denied(
            proxy,
            None,
            None,
            "empty_handoff_response",
            StatusCode::SERVICE_UNAVAILABLE,
            "sign-in unavailable",
            Some(&route.resource),
            Some(method.as_str()),
            Some(uri.path()),
        )
        .await;
    };
    let Ok((claims, identity)) = verify_signed_session(proxy, &signed, route) else {
        tracing::error!("control plane returned an invalid signed web session");
        return audit_denied(
            proxy,
            None,
            None,
            "invalid_handoff_response",
            StatusCode::SERVICE_UNAVAILABLE,
            "sign-in unavailable",
            Some(&route.resource),
            Some(method.as_str()),
            Some(uri.path()),
        )
        .await;
    };
    let cookie = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signed.encode_to_vec());
    if cookie.len() > 8192 || !valid_return_path(&response.return_path) {
        tracing::error!("control plane returned an invalid web session handoff");
        return audit_denied(
            proxy,
            Some(identity.username),
            None,
            "invalid_handoff_response",
            StatusCode::SERVICE_UNAVAILABLE,
            "sign-in unavailable",
            Some(&route.resource),
            Some(method.as_str()),
            Some(uri.path()),
        )
        .await;
    }
    let session_id = Uuid::now_v7();
    if let Err(error) = proxy
        .audit
        .emit(
            EventKind::WebRequest,
            AuditContext {
                user: Some(identity.username.clone()),
                session_id: Some(session_id),
            },
            json!({
                "action": "web",
                "resource": route.resource,
                "host": route.target.host,
                "method": method.as_str(),
                "path": uri.path(),
                "actor_type": "user",
                "handoff": true,
            }),
        )
        .await
    {
        tracing::error!(error = %error, session = %session_id, "failed to audit web handoff; refusing it");
        return plain(StatusCode::SERVICE_UNAVAILABLE, "audit is unavailable");
    }
    if emit_response(
        proxy,
        &identity.username,
        session_id,
        route,
        &method,
        StatusCode::SEE_OTHER,
        0,
        0,
        started,
        "handoff",
    )
    .await
    .is_err()
    {
        return plain(StatusCode::SERVICE_UNAVAILABLE, "audit is unavailable");
    }
    let mut destination = redirect_response(&response.return_path);
    let max_age = claims
        .expires_at_unix
        .saturating_sub(OffsetDateTime::now_utc().unix_timestamp())
        .clamp(1, 600);
    if let Ok(value) = HeaderValue::from_str(&format!(
        "{APP_COOKIE}={cookie}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}"
    )) {
        destination.headers_mut().append(header::SET_COOKIE, value);
        destination.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_static(
                "__Host-limen_app_login=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
            ),
        );
    } else {
        return plain(StatusCode::SERVICE_UNAVAILABLE, "sign-in unavailable");
    }
    destination.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    destination
}

fn valid_return_path(value: &str) -> bool {
    let Ok(uri) = Uri::try_from(value) else {
        return false;
    };
    uri.authority().is_none() && safe_uri(&uri)
}

#[allow(clippy::too_many_arguments)] // Carries the bounded fields for one denial event.
async fn audit_denied(
    proxy: &Proxy,
    user: Option<String>,
    session_id: Option<Uuid>,
    reason: &'static str,
    status: StatusCode,
    body: &'static str,
    resource: Option<&str>,
    method: Option<&str>,
    path: Option<&str>,
) -> ProxyResponse {
    let actor_type = if user.is_some() { "user" } else { "unknown" };
    let mut data = json!({"action": "web", "reason": reason, "actor_type": actor_type});
    if let Some(resource) = resource {
        data["resource"] = json!(resource);
    }
    if let Some(method) = method {
        data["method"] = json!(method);
    }
    if let Some(path) = path {
        data["path"] = json!(path);
    }
    if let Err(e) = proxy
        .audit
        .emit(
            EventKind::AuthDenied,
            AuditContext { user, session_id },
            data,
        )
        .await
    {
        tracing::error!(error = %e, "failed to audit denied web request");
        return plain(StatusCode::SERVICE_UNAVAILABLE, "audit is unavailable");
    }
    plain(status, body)
}

fn with_clear_cookie(mut response: ProxyResponse) -> ProxyResponse {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-limen_app=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
        ),
    );
    response
}

#[allow(clippy::too_many_arguments)] // Carries the outcome fields for one response event.
async fn emit_response(
    proxy: &Proxy,
    username: &str,
    session_id: Uuid,
    route: &WebRoute,
    method: &Method,
    status: StatusCode,
    bytes_in: u64,
    bytes_out: u64,
    started: Instant,
    reason: &str,
) -> Result<(), ()> {
    proxy
        .audit
        .emit(
            EventKind::WebResponse,
            AuditContext {
                user: Some(username.to_owned()),
                session_id: Some(session_id),
            },
            json!({
                "resource": route.resource,
                "host": route.target.host,
                "method": method.as_str(),
                "actor_type": "user",
                "status": status.as_u16(),
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
                "duration_ms": started.elapsed().as_millis(),
                "reason": reason,
            }),
        )
        .await
        .map(|_| ())
        .map_err(|e| {
            tracing::error!(error = %e, session = %session_id, "failed to audit web response");
        })
}

fn redirect_response(location: &str) -> ProxyResponse {
    let mut response = plain(StatusCode::SEE_OTHER, "");
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    match HeaderValue::from_str(location) {
        Ok(value) => {
            response.headers_mut().insert(header::LOCATION, value);
            response
        }
        Err(_) => plain(StatusCode::SERVICE_UNAVAILABLE, "sign-in unavailable"),
    }
}

fn plain(status: StatusCode, text: &'static str) -> ProxyResponse {
    let (parts, body) = (status, text).into_response().into_parts();
    Response::from_parts(parts, tonic::body::Body::new(body))
}

fn empty_body() -> tonic::body::Body {
    tonic::body::Body::new(http_body_util::Empty::<Bytes>::new().map_err(|never| match never {}))
}

use axum::response::IntoResponse as _;

struct CountBody<B> {
    inner: B,
    count: Arc<AtomicU64>,
}

impl<B> HttpBody for CountBody<B>
where
    B: HttpBody<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.count.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

struct AuditResponseBody {
    inner: Incoming,
    audit: limen_audit::Emitter,
    context: AuditContext,
    event: serde_json::Value,
    status: StatusCode,
    session_id: Uuid,
    request_started: Instant,
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
    audit_rx: Option<oneshot::Receiver<Result<(), String>>>,
    audit_started: bool,
    done: bool,
    pending_error: Option<BoxError>,
}

impl AuditResponseBody {
    fn start_audit(&mut self, reason: &'static str) {
        if self.audit_started {
            return;
        }
        self.audit_started = true;
        let (tx, rx) = oneshot::channel();
        self.audit_rx = Some(rx);
        let audit = self.audit.clone();
        let context = self.context.clone();
        let mut event = self.event.clone();
        let bytes_in = self.upload.load(Ordering::Relaxed);
        let bytes_out = self.download.load(Ordering::Relaxed);
        let status = self.status;
        let duration_ms = self.request_started.elapsed().as_millis();
        let session_id = self.session_id;
        tokio::spawn(async move {
            event["bytes_in"] = json!(bytes_in);
            event["bytes_out"] = json!(bytes_out);
            event["status"] = json!(status.as_u16());
            event["duration_ms"] = json!(duration_ms);
            event["reason"] = json!(reason);
            let result = audit
                .emit(EventKind::WebResponse, context, event)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string());
            if let Err(error) = &result {
                tracing::error!(%error, session = %session_id, "failed to audit web response");
            }
            let _ = tx.send(result);
        });
    }
}

impl HttpBody for AuditResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        if let Some(receiver) = &mut this.audit_rx {
            return match Pin::new(receiver).poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(Ok(()))) => {
                    this.audit_rx = None;
                    this.done = true;
                    if let Some(error) = this.pending_error.take() {
                        Poll::Ready(Some(Err(error)))
                    } else {
                        Poll::Ready(None)
                    }
                }
                Poll::Ready(Ok(Err(error))) => {
                    this.audit_rx = None;
                    this.done = true;
                    Poll::Ready(Some(Err(error.into())))
                }
                Poll::Ready(Err(_)) => {
                    this.audit_rx = None;
                    this.done = true;
                    Poll::Ready(Some(Err(std::io::Error::other(
                        "web response audit task stopped",
                    )
                    .into())))
                }
            };
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.download
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.pending_error = Some(Box::new(error));
                this.start_audit("upstream_stream_error");
                Pin::new(this).poll_frame(cx)
            }
            Poll::Ready(None) => {
                this.start_audit("complete");
                Pin::new(this).poll_frame(cx)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for AuditResponseBody {
    fn drop(&mut self) {
        if self.audit_started {
            return;
        }
        self.audit_started = true;
        let audit = self.audit.clone();
        let context = self.context.clone();
        let mut event = self.event.clone();
        let bytes_in = self.upload.load(Ordering::Relaxed);
        let bytes_out = self.download.load(Ordering::Relaxed);
        let status = self.status;
        let duration_ms = self.request_started.elapsed().as_millis();
        let session_id = self.session_id;
        tokio::spawn(async move {
            event["bytes_in"] = json!(bytes_in);
            event["bytes_out"] = json!(bytes_out);
            event["status"] = json!(status.as_u16());
            event["duration_ms"] = json!(duration_ms);
            event["reason"] = json!("client_disconnected");
            if let Err(e) = audit.emit(EventKind::WebResponse, context, event).await {
                tracing::error!(error = %e, session = %session_id, "failed to audit disconnected web response");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_is_normalized_and_rejects_other_ports() {
        assert_eq!(
            parse_authority("APP.APPS.TEST:38443", 38443).as_deref(),
            Ok("app.apps.test")
        );
        assert!(parse_authority("app.apps.test:38444", 38443).is_err());
        assert!(parse_authority("user@app.apps.test", 38443).is_err());
        assert!(parse_authority("app.apps.test.", 38443).is_err());
    }

    #[test]
    fn uri_paths_reject_ambiguous_encodings_and_normalization() {
        assert!(safe_uri(&Uri::from_static("/allowed?view=full")));
        for path in ["/%2e%2e/admin", "/a//b", "/a/../admin", "/a\\b", "//admin"] {
            assert!(
                !safe_uri(&Uri::try_from(path).expect("test URI parses")),
                "{path}"
            );
        }
    }

    #[test]
    fn request_sanitization_preserves_websocket_upgrade_and_trusted_identity() {
        let target = WebTarget {
            address: "web-target:8080".to_owned(),
            host: "app.apps.test".to_owned(),
            tls_ca_file: None,
            tls_server_name: None,
            health_path: None,
            insecure_dev: true,
            identity_headers: true,
        };
        let session = WebAppSession {
            username: "developer@example.com".to_owned(),
            roles: vec!["phase12-web".to_owned()],
            identity_assertion: "signed-assertion".to_owned(),
            ..WebAppSession::default()
        };
        let peer = limen_tunnel::PeerInfo {
            remote_addr: Some("127.0.0.1:1234".parse().expect("valid test address")),
            server_name: Some("app.apps.test".to_owned()),
            client_certs: Vec::new(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("app.apps.test"));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("__Host-limen_app=secret; app_session=kept"),
        );
        headers.insert(
            HeaderName::from_static("x-limen-user"),
            HeaderValue::from_static("spoofed"),
        );
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("spoofed"),
        );
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("Upgrade, X-Remove-Me"),
        );
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(
            HeaderName::from_static("x-remove-me"),
            HeaderValue::from_static("remove"),
        );

        sanitize_request_headers(&mut headers, &target, Some(&peer), true, &session);

        assert_eq!(headers[header::HOST], "app.apps.test");
        assert_eq!(headers[header::UPGRADE], "websocket");
        assert_eq!(headers[header::CONNECTION], "Upgrade");
        assert_eq!(headers["x-limen-user"], "developer@example.com");
        assert_eq!(headers["x-limen-roles"], "phase12-web");
        assert_eq!(headers["x-limen-identity"], "signed-assertion");
        assert_eq!(headers["x-forwarded-for"], "127.0.0.1");
        assert_eq!(headers[header::COOKIE], "app_session=kept");
        assert!(!headers.contains_key("x-remove-me"));
    }

    #[test]
    fn response_sanitization_keeps_app_cookies_but_not_limen_cookie() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_static("__Host-limen_app=spoofed; Path=/"),
        );
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_static("app_session=owned; Path=/"),
        );
        headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));

        sanitize_response_headers(&mut headers, true);

        let cookies: Vec<_> = headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().expect("valid test cookie header"))
            .collect();
        assert_eq!(cookies, ["app_session=owned; Path=/"]);
        assert_eq!(headers[header::CONNECTION], "Upgrade");
        assert_eq!(headers[header::UPGRADE], "websocket");
    }

    #[test]
    fn response_sanitization_removes_upgrade_from_regular_responses() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("Upgrade, X-Remove-Me"),
        );
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(
            HeaderName::from_static("x-remove-me"),
            HeaderValue::from_static("remove"),
        );

        sanitize_response_headers(&mut headers, false);

        assert!(!headers.contains_key(header::CONNECTION));
        assert!(!headers.contains_key(header::UPGRADE));
        assert!(!headers.contains_key("x-remove-me"));
    }
}
