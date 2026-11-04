//! The Integrations page (#125): which outbound integrations this control plane replica is
//! configured with, and how the audit sinks are doing. Read only, admins only. Integrations are
//! deploy-time configuration (flags, environment, Terraform), so this page shows them and never
//! edits them.
//!
//! Nothing secret is shown. A URL that carries a credential (a user name, a query string, a
//! webhook path) is reduced to its origin, a key or secret is shown as "set", and an error
//! message from a sink is left in the log (it can echo what was sent).

use askama::Template;
use axum::extract::State;
use axum::response::Response;
use time::OffsetDateTime;

use super::pages::chrome;
use super::views::{Chrome, time_text};
use super::{Auth, html};
use crate::config::{CaBackend, Config, UsernameClaim};
use crate::pipeline::SinkSnapshot;
use crate::state::AppState;

/// One configured integration, and what to say about it.
pub struct IntegrationView {
    pub icon: &'static str,
    /// Colour class of the logo tile (`k-okta`, ...).
    pub brand: &'static str,
    pub name: &'static str,
    /// Where it points, reduced to what is safe to show.
    pub target: String,
    /// Further settings, each one line.
    pub details: Vec<String>,
    /// `ok`, `warn` or `bad`; empty for a plain "configured".
    pub class: &'static str,
    pub status: String,
}

/// One audit sink.
pub struct SinkView {
    pub icon: &'static str,
    pub brand: &'static str,
    pub name: &'static str,
    pub target: String,
    pub details: Vec<String>,
    pub pending: u64,
    pub last_ok: String,
    pub errors: u64,
    /// `warn` when S3 shipping is paused; empty otherwise.
    pub class: &'static str,
    pub status: String,
}

#[derive(Template)]
#[template(path = "integrations.html")]
pub struct Integrations {
    pub chrome: Chrome,
    pub identity: Vec<IntegrationView>,
    pub sinks: Vec<SinkView>,
    pub outbound: Vec<IntegrationView>,
}

/// `GET /console/integrations`
pub(super) async fn integrations(State(state): State<AppState>, auth: Auth) -> Response {
    if let Err(r) = auth.admin() {
        return r;
    }
    let config = &state.config;
    let snapshots = state.pipeline.sink_snapshots();
    html(
        Integrations {
            chrome: chrome(&state, &auth, "integrations"),
            identity: identity(config),
            sinks: sinks(config, &snapshots, state.pipeline.is_fenced()),
            outbound: outbound(config),
        }
        .render(),
    )
}

/// The identity provider and the certificate authority signer: what logins and certificates
/// depend on.
fn identity(config: &Config) -> Vec<IntegrationView> {
    let console = match (
        &config.console_public_url,
        &config.console_oidc_client_secret,
    ) {
        (Some(_), Some(_)) => format!(
            "Console client {} (secret set)",
            config.console_oidc_client_id
        ),
        (Some(_), None) => "Console client has no secret: the console can't sign anyone in".into(),
        (None, _) => "Console off (no public URL)".into(),
    };
    let mut idp = vec![
        format!("Client {}", config.oidc_client_id),
        format!("Scopes {}", config.oidc_scopes.join(" ")),
        format!(
            "User name from the {} claim",
            match config.oidc_username_claim {
                UsernameClaim::Email => "email",
                UsernameClaim::PreferredUsername => "preferred_username",
                UsernameClaim::Sub => "sub",
            }
        ),
        console,
    ];
    if let Some(internal) = &config.oidc_internal_url {
        idp.push(format!("Reached at {}", origin_of(internal)));
    }
    let signer = match config.ca_backend {
        CaBackend::File => IntegrationView {
            icon: "key-round",
            brand: "k-other",
            name: "Certificate authority keys",
            target: "Local key files".into(),
            details: vec!["Development only: production keeps the keys in KMS".into()],
            class: "warn",
            status: "files".into(),
        },
        CaBackend::Kms => IntegrationView {
            icon: "key-round",
            brand: "k-kms",
            name: "Certificate authority keys",
            target: "AWS KMS".into(),
            details: [
                ("Internal CA", &config.kms_internal_ca_key),
                ("User CA", &config.kms_user_ca_key),
                ("SSH user CA", &config.kms_ssh_user_ca_key),
                ("SSH host CA", &config.kms_ssh_host_ca_key),
            ]
            .into_iter()
            .map(|(label, key)| match key {
                Some(key) => format!("{label}: {key}"),
                None => format!("{label}: not set"),
            })
            .collect(),
            class: "",
            status: "KMS".into(),
        },
    };
    let (idp_icon, idp_brand) = idp_logo(&config.oidc_issuer);
    vec![
        IntegrationView {
            icon: idp_icon,
            brand: idp_brand,
            name: "Identity provider (OIDC)",
            target: origin_and_path(&config.oidc_issuer),
            details: idp,
            class: "",
            status: "configured".into(),
        },
        signer,
    ]
}

fn sinks(config: &Config, snapshots: &[(String, SinkSnapshot)], fenced: bool) -> Vec<SinkView> {
    snapshots
        .iter()
        .map(|(name, snap)| {
            let (label, (icon, brand), target, details): (
                &'static str,
                (&'static str, &'static str),
                String,
                Vec<String>,
            ) = match name.as_str() {
                crate::pipeline::CONSOLE => (
                    "Console store",
                    ("database", "k-postgres"),
                    "The control plane database".into(),
                    vec!["Feeds the Sessions, Audit trail and Dashboards pages".into()],
                ),
                crate::pipeline::JSONL => (
                    "JSONL file",
                    ("scroll-text", "k-other"),
                    config
                        .audit_file
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                    vec!["Meant for development".into()],
                ),
                crate::pipeline::S3 => (
                    "Amazon S3",
                    ("warehouse", "k-s3"),
                    format!(
                        "s3://{}/{}",
                        config.audit_s3_bucket.as_deref().unwrap_or_default(),
                        config.audit_s3_prefix
                    ),
                    s3_details(config),
                ),
                crate::pipeline::DATADOG => (
                    "Datadog Logs",
                    ("b-datadog", "k-datadog"),
                    config
                        .datadog_logs_url
                        .as_deref()
                        .map(origin_and_path)
                        .unwrap_or_default(),
                    vec![
                        "API key set".into(),
                        format!("Environment tag {}", config.environment),
                    ],
                ),
                _ => (
                    "Audit sink",
                    ("scroll-text", "k-other"),
                    String::new(),
                    Vec::new(),
                ),
            };
            let paused = fenced && name == crate::pipeline::S3;
            SinkView {
                icon,
                brand,
                name: label,
                target,
                details,
                pending: snap.pending,
                last_ok: snap.last_ok_unix.map_or_else(
                    || "not since this process started".into(),
                    |t| time_text(OffsetDateTime::from_unix_timestamp(t).ok()),
                ),
                errors: snap.errors,
                class: if paused { "warn" } else { "" },
                status: if paused {
                    "paused: this replica can't confirm it owns its id".into()
                } else {
                    String::new()
                },
            }
        })
        .collect()
}

fn s3_details(config: &Config) -> Vec<String> {
    let mut d = vec![format!("Flushed every {:?}", config.audit_s3_flush)];
    d.push(match &config.audit_s3_endpoint {
        Some(e) => format!("Endpoint {}", origin_of(e)),
        None => "AWS endpoint".into(),
    });
    if config.audit_s3_path_style {
        d.push("Path-style addressing".into());
    }
    d.push(match &config.audit_s3_kms_key {
        Some(key) => format!("Encrypted with KMS key {key}"),
        None => "Encrypted with the bucket's default".into(),
    });
    d
}

/// Trace export and the notices people get about access requests.
fn outbound(config: &Config) -> Vec<IntegrationView> {
    let mut rows = Vec::new();
    rows.push(match limen_core::telemetry::trace_export() {
        Some(t) => IntegrationView {
            icon: "b-opentelemetry",
            brand: "k-otel",
            name: "Trace export (OTLP)",
            target: origin_and_path(&t.endpoint),
            details: vec![
                format!("Sampling {}", t.sample_ratio),
                if t.ca_file {
                    "An extra CA file is trusted".into()
                } else {
                    "System trust store".into()
                },
                "Delivery is not reported: the exporter is best effort".into(),
            ],
            class: "",
            status: "exporting".into(),
        },
        None => IntegrationView {
            icon: "b-opentelemetry",
            brand: "k-other",
            name: "Trace export (OTLP)",
            target: "Off".into(),
            details: vec!["Set LIMEN_OTLP_ENDPOINT to export traces".into()],
            class: "",
            status: "off".into(),
        },
    });
    let secret_url = |name: &'static str, url: &Option<limen_core::secret::Secret<String>>| {
        url.as_ref().map(|u| {
            let slack = name.contains("Slack");
            IntegrationView {
                icon: if slack { "message-square" } else { "radio" },
                brand: if slack { "k-slack" } else { "k-webhook" },
                name,
                // A webhook's path is its credential, so only where it points is shown.
                target: origin_of(u.expose()),
                details: Vec::new(),
                class: "",
                status: "configured".into(),
            }
        })
    };
    let signed = config.notify_webhook_secret.is_some();
    for row in [
        secret_url("Access request webhook", &config.notify_webhook_url).map(|mut r| {
            r.details.push(
                if signed {
                    "Signed (secret set)"
                } else {
                    "Not signed"
                }
                .into(),
            );
            r
        }),
        secret_url("Access request Slack", &config.notify_slack_url),
        secret_url("Break-glass Slack", &config.break_glass_slack_url),
        secret_url("Break-glass webhook", &config.break_glass_webhook_url),
    ]
    .into_iter()
    .flatten()
    {
        rows.push(row);
    }
    rows
}

/// The logo for an identity provider, guessed from where its issuer lives. Anything unrecognised
/// (and any self-hosted provider that isn't Keycloak) gets the generic OIDC mark.
fn idp_logo(issuer: &str) -> (&'static str, &'static str) {
    let Ok(u) = url::Url::parse(issuer) else {
        return ("b-openid", "k-oidc");
    };
    let host = u.host_str().unwrap_or_default().to_ascii_lowercase();
    let on = |d: &str| host == d || host.ends_with(&format!(".{d}"));
    if on("okta.com") || on("oktapreview.com") {
        ("b-okta", "k-okta")
    } else if on("auth0.com") {
        ("b-auth0", "k-auth0")
    } else if host == "accounts.google.com" {
        ("b-google", "k-google")
    } else if u.path().contains("/realms/") {
        ("b-keycloak", "k-keycloak")
    } else {
        ("b-openid", "k-oidc")
    }
}

/// `scheme://host[:port]` of a URL, or a note that it isn't one. Never a user name, password, path
/// or query.
fn origin_of(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(u) if u.has_host() => u.origin().ascii_serialization(),
        _ => "(not a URL)".into(),
    }
}

/// Like [`origin_of`], keeping the path (an issuer or an intake path is not a secret) but never a
/// user name, password, query or fragment.
fn origin_and_path(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(u) if u.has_host() => {
            let path = u.path().trim_end_matches('/');
            format!("{}{path}", u.origin().ascii_serialization())
        }
        _ => "(not a URL)".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{idp_logo, origin_and_path, origin_of};

    #[test]
    fn identity_provider_logo_follows_the_issuer() {
        assert_eq!(idp_logo("https://acme.okta.com/oauth2/default").0, "b-okta");
        assert_eq!(idp_logo("https://acme.eu.auth0.com/").0, "b-auth0");
        assert_eq!(idp_logo("https://accounts.google.com").0, "b-google");
        assert_eq!(idp_logo("https://sso.acme.io/realms/limen").0, "b-keycloak");
        assert_eq!(idp_logo("https://evil-okta.com/").0, "b-openid");
        assert_eq!(idp_logo("nonsense").0, "b-openid");
    }

    #[test]
    fn urls_are_reduced_to_what_is_safe_to_show() {
        assert_eq!(
            origin_of("https://hooks.slack.com/services/T000/B000/SECRETSECRET"),
            "https://hooks.slack.com"
        );
        assert_eq!(
            origin_and_path(
                "https://user:pass@idp.example.com:8443/oauth2/default/?token=abc#frag"
            ),
            "https://idp.example.com:8443/oauth2/default"
        );
        assert_eq!(
            origin_and_path("https://http-intake.logs.datadoghq.eu/api/v2/logs?dd-api-key=SECRET"),
            "https://http-intake.logs.datadoghq.eu/api/v2/logs"
        );
        assert_eq!(origin_of("not a url"), "(not a URL)");
        assert_eq!(origin_of("mailto:someone@example.com"), "(not a URL)");
    }
}
