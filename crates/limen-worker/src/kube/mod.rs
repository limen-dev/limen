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
use limen_session::snapshot::Restrictions;
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
    /// The user's login, which groups their requests into one console session.
    pub login_id: String,
    pub actor_type: &'static str,
    pub groups: Vec<String>,
    pub resource: String,
    pub proxy_id: String,
    pub expires: OffsetDateTime,
    pub ci: Option<std::collections::BTreeMap<String, String>>,
    /// The access grants this session's roles depend on. When one ends, so does a stream.
    pub request_ids: Vec<String>,
}

impl Admitted {
    /// Why an open stream (a `watch`, `logs -f`, or an upgraded `exec`,
    /// `attach`, or `port-forward`) must stop at `now`: the session reached
    /// its deadline, an access grant it depends on ended, or the user was
    /// locked, logged out, or the session killed. `restrictions` is from the
    /// worker's latest snapshot, if it has one.
    pub(super) fn stop_reason(
        &self,
        restrictions: Option<&Restrictions>,
        now: OffsetDateTime,
    ) -> Option<&'static str> {
        if now >= self.expires {
            return Some("max_session_ttl reached");
        }
        let restrictions = restrictions?;
        if !self.request_ids.is_empty()
            && restrictions.grant_ended(&self.request_ids, now.unix_timestamp())
        {
            return Some("the access grant ended");
        }
        restrictions.blocks(&self.username, &self.login_id, &self.session_id)
    }
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
    if let Some(why) = snapshot.restrictions.blocks(
        &verified.user.username,
        &verified.user.login_id,
        &grant.session_id,
    ) {
        return Err(Status::permission_denied(why));
    }
    let effective = snapshot.roles_for(
        &verified.user.username,
        &verified.user.roles,
        &grant.resource,
        now,
    );
    let roles = effective.roles;
    for group in &grant.groups {
        let decision = snapshot.policy.evaluate(&AccessRequest {
            roles: &roles,
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
        login_id: grant.login_id.clone(),
        actor_type: limen_core::identity::actor_type(&grant.username),
        groups: grant.groups.clone(),
        resource: grant.resource.clone(),
        proxy_id: grant.proxy_id.clone(),
        expires: OffsetDateTime::from_unix_timestamp(grant.session_expires_at_unix).unwrap_or(now),
        ci: verified.user.bot.then(|| verified.user.ci.clone()),
        request_ids: effective.request_ids,
    })
}

#[cfg(test)]
mod tests {
    use limen_session::snapshot::{ActiveGrant, Restrictions};
    use time::{Duration, OffsetDateTime};

    use super::Admitted;

    fn admitted(now: OffsetDateTime, request_ids: &[&str]) -> Admitted {
        Admitted {
            session_id: "s-1".into(),
            username: "ada@example.com".into(),
            login_id: "l-1".into(),
            actor_type: "user",
            groups: vec![],
            resource: "eks-prod".into(),
            proxy_id: "p-1".into(),
            expires: now + Duration::hours(1),
            ci: None,
            request_ids: request_ids.iter().map(|&s| s.to_owned()).collect(),
        }
    }

    fn grant(id: &str, expires: OffsetDateTime) -> ActiveGrant {
        ActiveGrant {
            request_id: id.into(),
            username: "ada@example.com".into(),
            role: "eks-writer".into(),
            resource: "eks-prod".into(),
            expires_at_unix: expires.unix_timestamp(),
        }
    }

    #[test]
    fn a_stream_runs_while_nothing_has_ended() {
        let now = OffsetDateTime::now_utc();
        let held = Restrictions {
            grants: vec![grant("r-1", now + Duration::minutes(30))],
            ..Restrictions::default()
        };
        assert_eq!(admitted(now, &["r-1"]).stop_reason(Some(&held), now), None);
        assert_eq!(admitted(now, &[]).stop_reason(None, now), None);
    }

    #[test]
    fn a_stream_stops_at_its_deadline_even_without_a_snapshot() {
        let now = OffsetDateTime::now_utc();
        let a = admitted(now, &[]);
        assert_eq!(
            a.stop_reason(None, a.expires),
            Some("max_session_ttl reached")
        );
    }

    /// Upgraded streams (`exec`, `attach`, `port-forward`) use this check as
    /// well as streaming responses, so a revoked or expired grant ends them.
    #[test]
    fn a_stream_stops_when_its_grant_is_revoked_or_expires() {
        let now = OffsetDateTime::now_utc();
        let a = admitted(now, &["r-1"]);
        let revoked = Restrictions::default();
        assert_eq!(
            a.stop_reason(Some(&revoked), now),
            Some("the access grant ended")
        );
        let expired = Restrictions {
            grants: vec![grant("r-1", now)],
            ..Restrictions::default()
        };
        assert_eq!(
            a.stop_reason(Some(&expired), now),
            Some("the access grant ended")
        );
    }

    #[test]
    fn a_stream_stops_when_the_user_is_locked() {
        let now = OffsetDateTime::now_utc();
        let locked = Restrictions {
            locked_users: ["Ada@example.com".to_owned()].into(),
            ..Restrictions::default()
        };
        assert_eq!(
            admitted(now, &[]).stop_reason(Some(&locked), now),
            Some("user locked")
        );
    }
}
