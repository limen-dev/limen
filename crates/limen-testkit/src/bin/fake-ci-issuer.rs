//! A stand-in for a CI platform's OIDC issuer, for the local development stack
//! and the Phase 4 demo (ADR-0019). It serves discovery and signing keys like
//! GitHub Actions' token service does, and mints tokens on request.
//!
//! **Development only.** Anyone who can reach it can mint any token, so it must
//! never run anywhere real. Real tokens come from the CI platform.
//!
//! ```text
//! curl 'http://localhost:8130/github?repository=acme/infra&ref=refs/heads/main&environment=staging'
//! curl -X POST http://localhost:8130/mint -d '{"subject":"x","claims":{"project_path":"acme/r"}}'
//! ```

use std::collections::BTreeMap;

use axum::extract::Query;
use axum::routing::{get, post};
use axum::{Json, Router};
use limen_testkit::idp::{MockIdp, WorkloadToken};
use serde::Deserialize;

#[derive(Deserialize)]
struct GithubQuery {
    repository: String,
    #[serde(rename = "ref")]
    git_ref: String,
    environment: Option<String>,
    run_id: Option<String>,
    actor: Option<String>,
    audience: Option<String>,
    /// Pretend the token was minted this long ago.
    issued_secs_ago: Option<i64>,
}

#[derive(Deserialize)]
struct MintBody {
    subject: String,
    #[serde(default)]
    claims: BTreeMap<String, serde_json::Value>,
    audience: Option<String>,
    ttl_secs: Option<i64>,
    issued_secs_ago: Option<i64>,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listen = std::env::var("LIMEN_FAKE_CI_LISTEN").unwrap_or_else(|_| "0.0.0.0:8130".into());
    let issuer = std::env::var("LIMEN_FAKE_CI_ISSUER")
        .unwrap_or_else(|_| "http://fake-ci-issuer:8130".into());
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    let addr = listener.local_addr()?;
    let idp = MockIdp::new(&issuer, "limen", addr);

    let github = {
        let idp = idp.clone();
        get(move |Query(q): Query<GithubQuery>| async move {
            let mut token =
                WorkloadToken::github(&q.repository, &q.git_ref, q.environment.as_deref());
            if let Some(run) = q.run_id {
                token.claims.insert("run_id".into(), run.into());
            }
            if let Some(actor) = q.actor {
                token.claims.insert("actor".into(), actor.into());
            }
            if let Some(aud) = q.audience {
                token.audience = aud;
            }
            if let Some(ago) = q.issued_secs_ago {
                token.issued_secs_ago = ago;
            }
            idp.workload_token(&token)
        })
    };
    let mint = {
        let idp = idp.clone();
        post(move |Json(b): Json<MintBody>| async move {
            let mut token = WorkloadToken::github("x/x", "refs/heads/main", None);
            token.subject = b.subject;
            token.claims = b.claims;
            if let Some(aud) = b.audience {
                token.audience = aud;
            }
            if let Some(ttl) = b.ttl_secs {
                token.ttl_secs = ttl;
            }
            if let Some(ago) = b.issued_secs_ago {
                token.issued_secs_ago = ago;
            }
            idp.workload_token(&token)
        })
    };
    let app = Router::new()
        .merge(idp.router())
        .route("/github", github)
        .route("/mint", mint);
    eprintln!(
        "fake CI issuer for {issuer} listening on {listen}. DEVELOPMENT ONLY: it mints any token on request."
    );
    axum::serve(listener, app).await
}
