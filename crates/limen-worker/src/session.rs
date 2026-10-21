//! Admitting a session the proxy opened over a tunnel (design §5).
//!
//! The first frame carries the proxy's signed grant. The worker checks it
//! independently (defense in depth: both proxy and worker must allow), gets
//! per-session SSH certificates from the control plane, then bridges the
//! frame stream to its SSH server (or database, Redis, or Kubernetes API).

use std::sync::Arc;

use limen_policy::{AccessRequest, Principal};
use limen_proto::v1::ssh_certificates_client::SshCertificatesClient;
use limen_proto::v1::tunnel_frame::Frame;
use limen_proto::v1::{
    IssueSessionCertificatesRequest, SessionClose, SessionOpened, Signed, TunnelFrame,
};
use limen_session::grant::verify_grant;
use russh::keys::{Algorithm, Certificate, PrivateKey, PublicKey};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Response, Status, Streaming};

use crate::ssh::{SshSessionConfig, serve};
use crate::{SessionGuard, Worker};
use crate::{amqp, kafka, redis};

type FrameStream =
    std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<TunnelFrame, Status>> + Send>>;

const FRAME_CHUNK: usize = 32 * 1024;

/// How long a session cut short (drain, TTL) waits for its output pump.
pub(crate) const PUMP_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Why a session ended when the worker ended it at its drain timeout.
pub(crate) const WORKER_DRAIN: &str = "worker_drain";

/// `guard` holds the session's slot under the worker's cap: dropped on any
/// early return, otherwise moved into the session task.
#[allow(clippy::too_many_lines)] // one arm per protocol
pub(crate) async fn open(
    worker: Worker,
    guard: SessionGuard,
    mut inbound: Streaming<TunnelFrame>,
) -> Result<Response<FrameStream>, Status> {
    let first = tokio::time::timeout(std::time::Duration::from_secs(10), inbound.message())
        .await
        .map_err(|_| Status::deadline_exceeded("no session open frame"))??;
    let Some(TunnelFrame {
        frame: Some(Frame::Open(open)),
    }) = first
    else {
        return Err(Status::invalid_argument(
            "the first frame must open the session",
        ));
    };
    let signed = open
        .grant
        .ok_or_else(|| Status::invalid_argument("missing grant"))?;
    let admitted = admit(&worker, &signed).await.map_err(|e| {
        tracing::warn!(error = %e, "session refused");
        e
    })?;

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<TunnelFrame, Status>>(64);
    let _ = tx
        .send(Ok(TunnelFrame {
            frame: Some(Frame::Opened(SessionOpened {})),
        }))
        .await;
    let (ours, theirs) = tokio::io::duplex(256 * 1024);
    let (mut theirs_read, mut theirs_write) = tokio::io::split(theirs);

    // Proxy → SSH server.
    tokio::spawn(async move {
        while let Some(Ok(frame)) = inbound.next().await {
            match frame.frame {
                Some(Frame::Data(bytes)) => {
                    if theirs_write.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
                Some(Frame::Close(_)) => break,
                _ => {}
            }
        }
        let _ = theirs_write.shutdown().await;
    });

    // SSH server → proxy, then the closing frame with the recording.
    let session_id = admitted.session_id();
    let expires = config_expiry(&signed);
    let audit = worker.audit.clone();
    let end = worker.end_sessions();
    let kube_worker = worker.clone();
    tokio::spawn(async move {
        let _guard = guard;
        let pump_tx = tx.clone();
        let pump = tokio::spawn(async move {
            let mut buf = vec![0u8; FRAME_CHUNK];
            loop {
                match theirs_read.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if pump_tx
                            .send(Ok(TunnelFrame {
                                frame: Some(Frame::Data(buf[..n].to_vec())),
                            }))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        });
        let until = (expires - OffsetDateTime::now_utc())
            .max(time::Duration::ZERO)
            .unsigned_abs();
        let serving = async {
            match admitted {
                Admitted::Ssh(config) => serve(ours, *config, audit, end).await,
                Admitted::Db(config) => {
                    // A drain that reaches its timeout ends database sessions too.
                    let mut end = end;
                    tokio::select! {
                        r = crate::db::serve(ours, *config, audit) => {
                            r.map(|()| crate::ssh::SessionOutcome::default())
                        }
                        _ = end.wait_for(|ended| *ended) => Ok(crate::ssh::SessionOutcome {
                            ended_by_drain: true,
                            ..Default::default()
                        }),
                    }
                }
                Admitted::Anchor(_) => {
                    let mut end = end;
                    let mut ours = ours;
                    let mut sink = [0u8; 256];
                    tokio::select! {
                        () = async {
                            while matches!(ours.read(&mut sink).await, Ok(n) if n > 0) {}
                        } => Ok(crate::ssh::SessionOutcome::default()),
                        _ = end.wait_for(|ended| *ended) => Ok(crate::ssh::SessionOutcome {
                            ended_by_drain: true,
                            ..Default::default()
                        }),
                    }
                }
                Admitted::Kafka(prepared) => {
                    let mut end = end;
                    tokio::select! {
                        r = Box::pin(kafka::serve(ours, *prepared, audit)) => r,
                        _ = end.wait_for(|ended| *ended) => Ok(crate::ssh::SessionOutcome {
                            ended_by_drain: true,
                            ..Default::default()
                        }),
                    }
                }
                Admitted::Mq(prepared) => {
                    let mut end = end;
                    tokio::select! {
                        r = Box::pin(amqp::serve(ours, *prepared, audit)) => r,
                        _ = end.wait_for(|ended| *ended) => Ok(crate::ssh::SessionOutcome {
                            ended_by_drain: true,
                            ..Default::default()
                        }),
                    }
                }
                Admitted::Redis(prepared) => {
                    let mut end = end;
                    tokio::select! {
                        r = redis::serve(ours, *prepared, audit) => r,
                        _ = end.wait_for(|ended| *ended) => Ok(crate::ssh::SessionOutcome {
                            ended_by_drain: true,
                            ..Default::default()
                        }),
                    }
                }
                Admitted::Kube(request) => {
                    // One HTTP request (and any stream it upgrades to). A
                    // drain that reaches its timeout ends it too.
                    let mut end = end;
                    tokio::select! {
                        () = crate::kube::serve(kube_worker, *request, ours) => {
                            Ok(crate::ssh::SessionOutcome::default())
                        }
                        _ = end.wait_for(|ended| *ended) => Ok(crate::ssh::SessionOutcome {
                            ended_by_drain: true,
                            ..Default::default()
                        }),
                    }
                }
                Admitted::Search(prepared) => {
                    let mut end = end;
                    tokio::select! {
                        r = crate::search::serve(ours, *prepared, audit) => r,
                        _ = end.wait_for(|ended| *ended) => Ok(crate::ssh::SessionOutcome {
                            ended_by_drain: true,
                            ..Default::default()
                        }),
                    }
                }
                Admitted::Mongo(prepared) => {
                    let mut end = end;
                    tokio::select! {
                        r = crate::mongo::serve(ours, *prepared, audit) => r,
                        _ = end.wait_for(|ended| *ended) => Ok(crate::ssh::SessionOutcome {
                            ended_by_drain: true,
                            ..Default::default()
                        }),
                    }
                }
            }
        };
        let (reason, outcome) = match tokio::time::timeout(until, serving).await {
            // The proxy's session.end carries this reason (`data.reason`).
            Ok(Ok(outcome)) if outcome.ended_by_drain => (WORKER_DRAIN.to_owned(), outcome),
            Ok(Ok(outcome)) => ("ended".to_owned(), outcome),
            Ok(Err(e)) => (format!("error: {e}"), crate::ssh::SessionOutcome::default()),
            Err(_) => (
                "max_session_ttl reached".to_owned(),
                crate::ssh::SessionOutcome::default(),
            ),
        };
        // The pump ends when the SSH server lets go of its stream. A session
        // that was cut short (drain, TTL) may not have let go: don't wait
        // for it forever.
        if reason == "ended" {
            let _ = pump.await;
        } else {
            let stop_pump = pump.abort_handle();
            if tokio::time::timeout(PUMP_WAIT, pump).await.is_err() {
                stop_pump.abort();
            }
        }
        tracing::info!(session = %session_id, %reason, recording = %outcome.recording_uri, "session ended");
        let _ = tx
            .send(Ok(TunnelFrame {
                frame: Some(Frame::Close(SessionClose {
                    reason,
                    recording_uri: outcome.recording_uri,
                    recording_sha256: outcome.recording_sha256,
                })),
            }))
            .await;
    });
    Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
}

fn config_expiry(signed: &Signed) -> OffsetDateTime {
    use prost::Message as _;
    limen_proto::v1::SessionGrant::decode(signed.payload.as_slice())
        .ok()
        .and_then(|g| OffsetDateTime::from_unix_timestamp(g.session_expires_at_unix).ok())
        .unwrap_or_else(OffsetDateTime::now_utc)
}

/// A session the worker agreed to serve.
enum Admitted {
    Ssh(Box<SshSessionConfig>),
    Db(Box<crate::db::DbSessionConfig>),
    Redis(Box<redis::Prepared>),
    Kube(Box<crate::kube::Admitted>),
    Mongo(Box<crate::mongo::Prepared>),
    Search(Box<crate::search::Prepared>),
    Mq(Box<amqp::Prepared>),
    Kafka(Box<kafka::Prepared>),
    /// The run's anchor (`limen mq|kafka connect`): authorized, serves nothing.
    Anchor(String),
}

impl Admitted {
    fn session_id(&self) -> String {
        match self {
            Admitted::Ssh(c) => c.session_id.clone(),
            Admitted::Db(c) => c.session_id.to_string(),
            Admitted::Redis(p) => p.session_id().to_owned(),
            Admitted::Kube(k) => k.session_id.clone(),
            Admitted::Mongo(p) => p.session_id(),
            Admitted::Search(p) => p.session_id(),
            Admitted::Mq(p) => p.session_id().to_owned(),
            Admitted::Kafka(p) => p.session_id().to_owned(),
            Admitted::Anchor(id) => id.clone(),
        }
    }
}

/// What the grant check established, shared by every protocol.
struct Checked {
    verified: limen_session::grant::VerifiedGrant,
    snapshot: limen_session::snapshot::Snapshot,
}

/// Every check a session must pass before the worker touches the target.
async fn admit(worker: &Worker, signed: &Signed) -> Result<Admitted, Status> {
    let creds = worker.credentials();
    let internal_ca = creds
        .internal_ca()
        .map_err(|e| Status::internal(e.to_string()))?;
    let user_ca = creds
        .user_ca()
        .map_err(|e| Status::internal(e.to_string()))?;
    let now = OffsetDateTime::now_utc();

    let verified = verify_grant(signed, &internal_ca, &user_ca, now)
        .map_err(|e| Status::permission_denied(e.to_string()))?;
    let grant = &verified.grant;
    if grant.worker_id != creds.id {
        return Err(Status::permission_denied("grant is for another worker"));
    }
    if !worker
        .nonces
        .check_and_insert(&grant.nonce, grant.establish_by_unix)
    {
        return Err(Status::permission_denied("grant already used"));
    }
    let kind = grant.kind.clone();
    // Our own policy decision, from our own snapshot.
    let snapshot = worker
        .policy
        .fresh(now)
        .map_err(|e| Status::unavailable(format!("can't decide: {e}")))?;
    let checked = Checked { verified, snapshot };
    match kind.as_str() {
        "ssh" => admit_ssh(worker, signed, &checked)
            .await
            .map(|c| Admitted::Ssh(Box::new(c))),
        "postgres" | "redshift" | "mysql" => admit_db(worker, &checked)
            .await
            .map(|c| Admitted::Db(Box::new(c))),
        "redis" => admit_redis(worker, &checked)
            .await
            .map(|c| Admitted::Redis(Box::new(c))),
        "kube" => {
            crate::kube::admit(worker, &checked.verified, now).map(|k| Admitted::Kube(Box::new(k)))
        }
        "opensearch" | "elasticsearch" => admit_search(worker, &checked)
            .await
            .map(|p| Admitted::Search(Box::new(p))),
        "mongodb" => admit_mongo(worker, &checked)
            .await
            .map(|c| Admitted::Mongo(Box::new(c))),
        "rabbitmq" | "kafka" if checked.verified.grant.database == limen_core::broker::ANCHOR => {
            // Same checks as a real session (policy, and a credential exists).
            let anchor = Admitted::Anchor(checked.verified.grant.session_id.clone());
            if kind == "kafka" {
                admit_kafka(worker, &checked, true).map(|_| anchor)
            } else {
                admit_mq(worker, &checked).map(|_| anchor)
            }
        }
        "rabbitmq" => admit_mq(worker, &checked).map(|c| Admitted::Mq(Box::new(c))),
        "kafka" => admit_kafka(worker, &checked, false).map(|c| Admitted::Kafka(Box::new(c))),
        other => Err(Status::unimplemented(format!(
            "{other} sessions arrive in a later phase"
        ))),
    }
}

/// The policy checks every kind shares: locks, the principal, and whether
/// this worker's labels may serve the resource.
fn check_policy(worker: &Worker, checked: &Checked, principal: Principal) -> Result<(), Status> {
    let creds = worker.credentials();
    let grant = &checked.verified.grant;
    let snapshot = &checked.snapshot;
    if let Some(why) = snapshot.restrictions.blocks(
        &checked.verified.user.username,
        &checked.verified.user.login_id,
        &grant.session_id,
    ) {
        return Err(Status::permission_denied(why));
    }
    let decision = snapshot.policy.evaluate(&AccessRequest {
        roles: &checked.verified.user.roles,
        resource: &grant.resource,
        principal,
    });
    if !decision.is_allowed() {
        return Err(Status::permission_denied(format!(
            "worker policy check: {decision:?}"
        )));
    }
    if !snapshot
        .policy
        .worker_may_serve(&grant.resource, &creds.labels)
    {
        return Err(Status::permission_denied(
            "this worker may not serve the resource",
        ));
    }
    Ok(())
}

fn admit_kafka(
    worker: &Worker,
    checked: &Checked,
    anchor: bool,
) -> Result<kafka::Prepared, Status> {
    let grant = &checked.verified.grant;
    check_policy(
        worker,
        checked,
        Principal::KafkaUser(grant.principal.clone()),
    )?;
    let target = checked
        .snapshot
        .policy
        .resource(&grant.resource)
        .and_then(|r| r.spec.kafka.clone())
        .ok_or_else(|| Status::failed_precondition("resource is not a Kafka resource"))?;
    // The CLI's listener table: which local port is which broker.
    let slot = if anchor {
        limen_core::broker::KafkaSlot::new(0, vec![1])
    } else {
        limen_core::broker::KafkaSlot::parse(&grant.database)
            .map_err(|e| Status::invalid_argument(e.to_string()))?
    };
    let grants = checked.snapshot.policy.kafka_grants(
        &checked.verified.user.roles,
        &grant.resource,
        &grant.principal,
    );
    let config = kafka::SessionConfig::new(
        grant.session_id.clone(),
        grant.username.clone(),
        grant.principal.clone(),
        grant.resource.clone(),
        target,
        slot,
    );
    kafka::prepare(&worker.broker, grants, config).map_err(|e| {
        // The detail names the account: it stays in the log.
        tracing::warn!(error = %e, resource = %grant.resource, "couldn't prepare the Kafka session");
        Status::unavailable(
            "couldn't prepare the Kafka session; ask an admin to check the worker's log",
        )
    })
}

fn admit_mq(worker: &Worker, checked: &Checked) -> Result<amqp::Prepared, Status> {
    let grant = &checked.verified.grant;
    check_policy(worker, checked, Principal::MqUser(grant.principal.clone()))?;
    let target = checked
        .snapshot
        .policy
        .resource(&grant.resource)
        .and_then(|r| r.spec.rabbitmq.clone())
        .ok_or_else(|| Status::failed_precondition("resource is not a RabbitMQ resource"))?;
    let grants = checked.snapshot.policy.mq_grants(
        &checked.verified.user.roles,
        &grant.resource,
        &grant.principal,
    );
    let config = amqp::SessionConfig {
        session_id: grant.session_id.clone(),
        username: grant.username.clone(),
        mq_user: grant.principal.clone(),
        resource: grant.resource.clone(),
        target,
    };
    amqp::prepare(&worker.broker, grants, config).map_err(|e| {
        // The detail names the account: it stays in the log.
        tracing::warn!(error = %e, resource = %grant.resource, "couldn't prepare the RabbitMQ session");
        Status::unavailable(
            "couldn't prepare the RabbitMQ session; ask an admin to check the worker's log",
        )
    })
}

/// The longest a Redis session may take to open its connection to the target.
const REDIS_PREPARE: std::time::Duration = std::time::Duration::from_secs(25);

async fn admit_redis(worker: &Worker, checked: &Checked) -> Result<redis::Prepared, Status> {
    let grant = &checked.verified.grant;
    check_policy(
        worker,
        checked,
        Principal::RedisUser(grant.principal.clone()),
    )?;
    let target = checked
        .snapshot
        .policy
        .resource(&grant.resource)
        .and_then(|r| r.spec.redis.clone())
        .ok_or_else(|| Status::failed_precondition("resource is not a Redis resource"))?;
    let grants = checked.snapshot.policy.redis_grants(
        &checked.verified.user.roles,
        &grant.resource,
        &grant.principal,
    );
    let config = redis::SessionConfig::new(
        grant.session_id.clone(),
        grant.username.clone(),
        grant.principal.clone(),
        grant.resource.clone(),
        target,
    );
    // Connect, TLS, login, and the command table each have their own limit;
    // this one bounds them together so the proxy isn't kept waiting.
    tokio::time::timeout(
        REDIS_PREPARE,
        redis::prepare(&worker.redis, grants, config),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out"))
    .and_then(|r| r)
    .map_err(|e| {
        // The detail names the server and the account: it stays in the log.
        tracing::warn!(error = %e, resource = %grant.resource, "couldn't open the Redis connection");
        Status::unavailable(
            "couldn't connect to the Redis server; ask an admin to check the worker's log",
        )
    })
}

/// The longest a search session may take to open its connection to the target.
const SEARCH_PREPARE: std::time::Duration = std::time::Duration::from_secs(30);

async fn admit_search(
    worker: &Worker,
    checked: &Checked,
) -> Result<crate::search::Prepared, Status> {
    let grant = &checked.verified.grant;
    check_policy(
        worker,
        checked,
        Principal::SearchRole(grant.principal.clone()),
    )?;
    let resource = checked
        .snapshot
        .policy
        .resource(&grant.resource)
        .ok_or_else(|| Status::failed_precondition("unknown resource"))?;
    let (engine, target) = match grant.kind.as_str() {
        "opensearch" => ("opensearch", resource.spec.opensearch.clone()),
        _ => ("elasticsearch", resource.spec.elasticsearch.clone()),
    };
    let target =
        target.ok_or_else(|| Status::failed_precondition("resource is not a search resource"))?;
    let grants = checked.snapshot.policy.search_grants(
        &checked.verified.user.roles,
        &grant.resource,
        &grant.principal,
    );
    let session_id = grant
        .session_id
        .parse()
        .map_err(|_| Status::invalid_argument("bad session id"))?;
    let config = crate::search::SessionConfig {
        session_id,
        username: checked.verified.user.username.clone(),
        resource: grant.resource.clone(),
        engine_role: grant.principal.clone(),
        engine,
        target: target.clone(),
    };
    let aws: Option<crate::search::target::AwsSource> = target.aws.then(|| {
        let worker = worker.clone();
        Arc::new(move || {
            let worker = worker.clone();
            Box::pin(async move { worker.aws_credentials().await })
                as std::pin::Pin<Box<dyn std::future::Future<Output = _> + Send>>
        }) as crate::search::target::AwsSource
    });
    tokio::time::timeout(
        SEARCH_PREPARE,
        crate::search::prepare(&worker.search, grants, config, aws),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out"))
    .and_then(|r| r)
    .map_err(|e| {
        // The detail names the server and the account: it stays in the log.
        tracing::warn!(error = %e, resource = %grant.resource, "couldn't open the search connection");
        Status::unavailable(
            "couldn't connect to the search server; ask an admin to check the worker's log",
        )
    })
}

/// The longest a MongoDB session may take to open its connection to the server.
const MONGO_PREPARE: std::time::Duration = std::time::Duration::from_secs(25);

async fn admit_mongo(worker: &Worker, checked: &Checked) -> Result<crate::mongo::Prepared, Status> {
    use limen_policy::model::MongoAuth;
    let grant = &checked.verified.grant;
    check_policy(
        worker,
        checked,
        Principal::MongoRole {
            role: grant.principal.clone(),
            database: grant.database.clone(),
        },
    )?;
    if !limen_policy::valid_mongo_role(&grant.principal) {
        return Err(Status::permission_denied("not a valid MongoDB role name"));
    }
    let spec = checked
        .snapshot
        .policy
        .resource(&grant.resource)
        .and_then(|r| r.spec.mongodb.clone())
        .ok_or_else(|| Status::failed_precondition("resource is not a MongoDB resource"))?;
    // The detail names the server and the account: it stays in the log.
    let unavailable = |what: &str, e: &dyn std::fmt::Display| {
        metrics::counter!("limen_mongo_connect_failures_total").increment(1);
        tracing::warn!(error = %e, resource = %grant.resource, "{what}");
        Status::unavailable(
            "couldn't connect to the MongoDB server; ask an admin to check the worker's log",
        )
    };
    let aws = if spec.auth == MongoAuth::Aws {
        Some(
            worker
                .aws_credentials()
                .await
                .map_err(|e| unavailable("couldn't get AWS credentials for MONGODB-AWS", &e))?,
        )
    } else {
        None
    };
    let (login, identity) = crate::mongo::credentials(&spec, &grant.principal, aws)
        .await
        .map_err(|e| {
            metrics::counter!("limen_mongo_connect_failures_total").increment(1);
            tracing::error!(resource = %grant.resource, error = %e, "can't load the MongoDB role's credential");
            Status::failed_precondition("the worker has no credential for this MongoDB role")
        })?;
    let target = crate::db::Target::from_mongo(&spec, worker.allow_insecure_db_targets(), identity)
        .await
        .map_err(Status::failed_precondition)?;
    let auth_source = spec.auth_source.clone().unwrap_or_else(|| {
        match spec.auth {
            MongoAuth::Scram | MongoAuth::ScramSha1 => "admin",
            MongoAuth::X509 | MongoAuth::Aws => "$external",
        }
        .to_owned()
    });
    let session_id = grant
        .session_id
        .parse()
        .map_err(|_| Status::invalid_argument("bad session id"))?;
    let access = crate::mongo::Access::new(
        std::sync::Arc::clone(&checked.snapshot.policy),
        checked.verified.user.roles.clone(),
        &grant.resource,
        &grant.principal,
    );
    let config = crate::mongo::SessionConfig::new(
        session_id,
        grant.username.clone(),
        grant.resource.clone(),
        grant.principal.clone(),
        &spec,
    );
    tokio::time::timeout(
        MONGO_PREPARE,
        crate::mongo::prepare(config, &target, &login, &auth_source, access),
    )
    .await
    .map_err(|_| unavailable("MongoDB connection timed out", &"timed out"))?
    .map_err(|e| unavailable("couldn't open the MongoDB connection", &e))
}

async fn admit_db(
    worker: &Worker,
    checked: &Checked,
) -> Result<crate::db::DbSessionConfig, Status> {
    use crate::db::{DbSessionConfig, Engine, Target, secret};
    let grant = &checked.verified.grant;
    check_policy(
        worker,
        checked,
        Principal::DbRole {
            role: grant.principal.clone(),
            database: grant.database.clone(),
        },
    )?;
    let resource = checked
        .snapshot
        .policy
        .resource(&grant.resource)
        .ok_or_else(|| Status::failed_precondition("unknown resource"))?;
    let (engine, spec) = match grant.kind.as_str() {
        "postgres" => (Engine::Postgres, resource.spec.postgres.as_ref()),
        "redshift" => (Engine::Redshift, resource.spec.redshift.as_ref()),
        _ => (Engine::Mysql, resource.spec.mysql.as_ref()),
    };
    let spec = spec.ok_or_else(|| Status::failed_precondition("resource is not a database"))?;
    if !limen_policy::valid_db_role(&grant.principal) {
        return Err(Status::permission_denied("not a limen_* role"));
    }
    let target = Target::from_spec(spec, worker.allow_insecure_db_targets())
        .await
        .map_err(Status::failed_precondition)?;
    let (login_user, password) = if spec.iam_auth {
        iam_login(worker, engine, spec, grant).await?
    } else {
        let dir = spec.password_dir.as_deref().ok_or_else(|| {
            Status::failed_precondition("the resource has no password_dir (secret mode)")
        })?;
        let password = secret::role_password(dir, &grant.principal)
            .await
            .map_err(|e| {
                tracing::error!(resource = %grant.resource, error = %e, "can't load the database role's password");
                Status::failed_precondition("the worker has no credential for this database role")
            })?;
        (grant.principal.clone(), password)
    };
    let session_id = grant
        .session_id
        .parse()
        .map_err(|_| Status::invalid_argument("bad session id"))?;
    Ok(DbSessionConfig {
        session_id,
        username: checked.verified.user.username.clone(),
        resource: grant.resource.clone(),
        engine,
        role: grant.principal.clone(),
        login_user,
        database: grant.database.clone(),
        target,
        password,
        normalize_literals: spec.normalize_literals,
        registry: Arc::clone(&worker.db_registry),
    })
}

/// The login for an IAM-authenticated database: `(user, password)`.
/// Unverified against the real AWS services (ADR-0033).
async fn iam_login(
    worker: &Worker,
    engine: crate::db::Engine,
    spec: &limen_policy::model::DbTarget,
    grant: &limen_proto::v1::SessionGrant,
) -> Result<(String, limen_core::secret::Secret<String>), Status> {
    use crate::db::iam;
    let region = spec.region.as_deref().ok_or_else(|| {
        Status::failed_precondition("IAM authentication needs the resource's region")
    })?;
    let unavailable = |e: String| {
        tracing::error!(resource = %grant.resource, error = %e, "IAM database authentication failed");
        Status::unavailable("couldn't get AWS credentials for the database")
    };
    let creds = worker.aws_credentials().await.map_err(unavailable)?;
    let now = OffsetDateTime::now_utc();
    match engine {
        crate::db::Engine::Postgres | crate::db::Engine::Mysql => Ok((
            grant.principal.clone(),
            iam::rds_auth_token(&creds, region, &spec.endpoint, &grant.principal, now),
        )),
        crate::db::Engine::Redshift => {
            let kind = match (&spec.workgroup, &spec.cluster_identifier) {
                (Some(workgroup), _) => iam::RedshiftKind::Serverless { workgroup },
                (None, Some(cluster_identifier)) => {
                    iam::RedshiftKind::Provisioned { cluster_identifier }
                }
                (None, None) => {
                    return Err(Status::failed_precondition(
                        "a Redshift resource with IAM needs cluster_identifier or workgroup",
                    ));
                }
            };
            let login = iam::redshift_login(
                &iam::Endpoints::from_env(),
                &creds,
                region,
                kind,
                &grant.principal,
                &grant.database,
                now,
            )
            .await
            .map_err(unavailable)?;
            Ok((login.user, login.password))
        }
    }
}

async fn admit_ssh(
    worker: &Worker,
    signed: &Signed,
    checked: &Checked,
) -> Result<SshSessionConfig, Status> {
    let grant = &checked.verified.grant;
    let snapshot = &checked.snapshot;
    check_policy(
        worker,
        checked,
        Principal::SshLogin(grant.principal.clone()),
    )?;
    let target = snapshot
        .policy
        .resource(&grant.resource)
        .and_then(|r| r.spec.ssh.clone())
        .ok_or_else(|| Status::failed_precondition("resource is not an SSH resource"))?;
    let pinned = target
        .host_key
        .as_deref()
        .ok_or_else(|| {
            Status::failed_precondition(
                "resource has no pinned host_key; refusing to connect to an unverified host",
            )
        })
        .and_then(|k| {
            PublicKey::from_openssh(k)
                .map_err(|e| Status::failed_precondition(format!("pinned host_key: {e}")))
        })?;

    // Keys for this session only. The control plane certifies them.
    let (user_key, host_key) = {
        // Scoped: the thread-local RNG must not be held across an await.
        let mut rng = rand::rng();
        (
            PrivateKey::random(&mut rng, Algorithm::Ed25519)
                .map_err(|e| Status::internal(e.to_string()))?,
            PrivateKey::random(&mut rng, Algorithm::Ed25519)
                .map_err(|e| Status::internal(e.to_string()))?,
        )
    };
    let channel = worker
        .control_plane()
        .map_err(|e| Status::internal(e.to_string()))?;
    let certs = SshCertificatesClient::new(channel)
        .issue_session_certificates(IssueSessionCertificatesRequest {
            grant: Some(signed.clone()),
            user_public_key: user_key
                .public_key()
                .to_openssh()
                .map_err(|e| Status::internal(e.to_string()))?,
            host_public_key: host_key
                .public_key()
                .to_openssh()
                .map_err(|e| Status::internal(e.to_string()))?,
        })
        .await
        .map_err(|s| {
            if s.code() == tonic::Code::PermissionDenied {
                s
            } else {
                Status::unavailable(format!("control plane: {}", s.message()))
            }
        })?
        .into_inner();
    let user_cert = Certificate::from_openssh(&certs.user_certificate)
        .map_err(|e| Status::internal(e.to_string()))?;
    let host_cert = Certificate::from_openssh(&certs.host_certificate)
        .map_err(|e| Status::internal(e.to_string()))?;

    Ok(SshSessionConfig {
        recording_path: worker
            .recordings_dir()
            .join(format!("{}.cast", grant.session_id)),
        session_id: grant.session_id.clone(),
        username: grant.username.clone(),
        login: grant.principal.clone(),
        resource: grant.resource.clone(),
        target_address: target.address,
        target_host_key: pinned,
        user_key: Arc::new(user_key),
        user_cert,
        host_key,
        host_cert,
    })
}
