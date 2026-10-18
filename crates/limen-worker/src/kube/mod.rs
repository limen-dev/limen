//! Kubernetes access (ADR-0038): `kubectl` through Limen by impersonation.
//!
//! A kube worker serves one cluster. It holds a service account whose only
//! power is to impersonate (`users`, `groups`, and the `limen-session` extra),
//! and forwards each request the proxy opens a session for, as the user, with
//! the groups the grant names. Cluster RBAC bound to those groups decides what
//! the user may do. The worker never forwards a credential the client sent.

mod pump;
mod serve;
mod upstream;

use std::path::PathBuf;

use clap::Args;
use limen_policy::{AccessRequest, Principal};
use limen_session::grant::VerifiedGrant;
use time::OffsetDateTime;
use tonic::Status;

use crate::Worker;
pub(crate) use serve::serve;
pub(crate) use upstream::Upstream;

const IN_CLUSTER_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

/// Which cluster this worker serves and how it reaches the API server. With
/// none of these set the worker refuses Kubernetes sessions. Inside a pod
/// only `--kube-cluster` is needed: the API server address, CA, and service
/// account token come from the pod's environment.
#[derive(Debug, Clone, Args)]
#[allow(clippy::struct_field_names)] // the `kube_` prefix keeps clap IDs unique in the worker config
pub struct KubeConfig {
    /// Serve this cluster. Must equal `kubernetes.cluster_name` of the
    /// resources this worker may serve.
    #[arg(long = "kube-cluster", env = "LIMEN_KUBE_CLUSTER")]
    pub kube_cluster: Option<String>,

    /// API server URL, for example `https://10.0.0.1:443`. Default: in-cluster.
    #[arg(long = "kube-api-server", env = "LIMEN_KUBE_API_SERVER")]
    pub kube_api_server: Option<String>,

    /// CA certificate(s) that sign the API server's certificate.
    #[arg(long = "kube-ca-file", env = "LIMEN_KUBE_CA_FILE")]
    pub kube_ca_file: Option<PathBuf>,

    /// Service account token file. Re-read as it rotates.
    #[arg(long = "kube-token-file", env = "LIMEN_KUBE_TOKEN_FILE")]
    pub kube_token_file: Option<PathBuf>,
}

impl KubeConfig {
    /// The in-cluster defaults, where the flags are absent.
    pub(crate) fn resolve(&self) -> anyhow::Result<Option<Upstream>> {
        let Some(cluster) = &self.kube_cluster else {
            return Ok(None);
        };
        let api_server = match (
            &self.kube_api_server,
            std::env::var("KUBERNETES_SERVICE_HOST"),
        ) {
            (Some(url), _) => url.clone(),
            (None, Ok(host)) => {
                let port =
                    std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
                if host.contains(':') {
                    format!("https://[{host}]:{port}")
                } else {
                    format!("https://{host}:{port}")
                }
            }
            (None, Err(_)) => {
                anyhow::bail!("--kube-cluster needs --kube-api-server (or to run inside a pod)")
            }
        };
        let in_cluster = |name: &str| PathBuf::from(IN_CLUSTER_DIR).join(name);
        Upstream::new(
            cluster.clone(),
            &api_server,
            &self
                .kube_ca_file
                .clone()
                .unwrap_or_else(|| in_cluster("ca.crt")),
            self.kube_token_file
                .clone()
                .unwrap_or_else(|| in_cluster("token")),
        )
        .map(Some)
    }
}

/// A Kubernetes session the worker accepted.
#[derive(Debug)]
pub(crate) struct Admitted {
    pub session_id: String,
    pub username: String,
    pub actor_type: &'static str,
    pub groups: Vec<String>,
    pub resource: String,
    pub proxy_id: String,
    pub expires: OffsetDateTime,
    pub ci: Option<std::collections::BTreeMap<String, String>>,
}

/// The worker's own checks for a Kubernetes grant, on its own policy
/// snapshot. A proxy that signs a grant the policy does not allow is refused.
pub(crate) fn admit(
    worker: &Worker,
    verified: &VerifiedGrant,
    now: OffsetDateTime,
) -> Result<Admitted, Status> {
    let grant = &verified.grant;
    let upstream = worker
        .kube
        .as_ref()
        .ok_or_else(|| Status::failed_precondition("this worker does not serve Kubernetes"))?;
    if grant.groups.is_empty() {
        return Err(Status::permission_denied("the grant names no groups"));
    }
    // Never act as a built-in identity, whatever policy or a proxy says.
    if let Some(bad) = grant
        .groups
        .iter()
        .find(|g| g.is_empty() || g.starts_with("system:"))
    {
        return Err(Status::permission_denied(format!(
            "refusing to impersonate the group {bad:?}"
        )));
    }
    // A user name that is also a built-in identity (`system:kube-scheduler`,
    // `system:serviceaccount:…`) would inherit that identity's cluster RBAC.
    if grant.username.is_empty() || grant.username.starts_with("system:") {
        return Err(Status::permission_denied(
            "refusing to impersonate a user named like a built-in identity",
        ));
    }
    let snapshot = worker
        .policy
        .fresh(now)
        .map_err(|e| Status::unavailable(format!("can't decide: {e}")))?;
    if let Some(why) = snapshot
        .restrictions
        .blocks(&verified.user.username, &grant.session_id)
    {
        return Err(Status::permission_denied(why));
    }
    for group in &grant.groups {
        let decision = snapshot.policy.evaluate(&AccessRequest {
            roles: &verified.user.roles,
            resource: &grant.resource,
            principal: Principal::KubeGroup(group.clone()),
        });
        if !decision.is_allowed() {
            return Err(Status::permission_denied(format!(
                "worker policy check for group {group}: {decision:?}"
            )));
        }
    }
    let creds = worker.credentials();
    if !snapshot
        .policy
        .worker_may_serve(&grant.resource, &creds.labels)
    {
        return Err(Status::permission_denied(
            "this worker may not serve the resource",
        ));
    }
    let cluster = snapshot
        .policy
        .resource(&grant.resource)
        .and_then(|r| r.spec.kubernetes.as_ref())
        .map(|k| k.cluster_name.as_str())
        .ok_or_else(|| Status::failed_precondition("resource is not a Kubernetes cluster"))?;
    if cluster != upstream.cluster() {
        return Err(Status::failed_precondition(format!(
            "this worker serves the cluster {:?}, not {cluster:?}",
            upstream.cluster()
        )));
    }
    Ok(Admitted {
        session_id: grant.session_id.clone(),
        username: grant.username.clone(),
        actor_type: limen_core::identity::actor_type(&grant.username),
        groups: grant.groups.clone(),
        resource: grant.resource.clone(),
        proxy_id: grant.proxy_id.clone(),
        expires: OffsetDateTime::from_unix_timestamp(grant.session_expires_at_unix).unwrap_or(now),
        ci: verified.user.bot.then(|| verified.user.ci.clone()),
    })
}
