//! The worker's own connection to the cluster (ADR-0037): dial, ask what the
//! broker supports, log in with SASL, and, for slots other than bootstrap, find
//! out which broker is which. Requests here use header v1 and the
//! non-flexible versions, like everything else the worker speaks.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context as _, bail};
use limen_core::secret::Secret;
use limen_policy::{BrokerTarget, KafkaSasl};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::auth::{self, Scram, ScramHash};
use super::proto::{self, Broker, MetadataResponse};
use super::wire::{Reader, Writer, api, error};
use crate::broker::{BoxedStream, Credential, Settings, host_of};
use crate::db::sigv4::Credentials;

/// The largest reply the worker reads for itself.
const MAX_SETUP_REPLY: usize = 16 * 1024 * 1024;
/// How long one setup exchange may take.
const STEP: Duration = Duration::from_secs(10);
/// How long a cached list of brokers is trusted.
const BROKER_CACHE: Duration = Duration::from_secs(10);

/// A logged-in connection and what the broker told us about itself.
pub struct Upstream {
    pub stream: BoxedStream,
    /// The broker's `(min, max)` for each API key.
    pub versions: BTreeMap<i16, (i16, i16)>,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream").finish_non_exhaustive()
    }
}

/// Write one request message and read one response body.
async fn call<S>(
    stream: &mut S,
    correlation: i32,
    key: i16,
    version: i16,
    body: &[u8],
) -> anyhow::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let head = Writer::new()
        .i16(key)
        .i16(version)
        .i32(correlation)
        .string("limen")
        .finish();
    let size = i32::try_from(head.len() + body.len()).context("request too large")?;
    let mut msg = Vec::with_capacity(4 + head.len() + body.len());
    msg.extend_from_slice(&size.to_be_bytes());
    msg.extend_from_slice(&head);
    msg.extend_from_slice(body);
    stream.write_all(&msg).await?;
    stream.flush().await?;
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let len = usize::try_from(i32::from_be_bytes(len)).context("negative response size")?;
    if !(4..=MAX_SETUP_REPLY).contains(&len) {
        bail!("the broker sent a response of {len} bytes");
    }
    let mut resp = vec![0u8; len];
    stream.read_exact(&mut resp).await?;
    let got = i32::from_be_bytes([resp[0], resp[1], resp[2], resp[3]]);
    if got != correlation {
        bail!("the broker answered request {got}, not {correlation}");
    }
    Ok(resp.split_off(4))
}

async fn step<T>(
    what: &str,
    f: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    tokio::time::timeout(STEP, f)
        .await
        .map_err(|_| anyhow::anyhow!("timed out: {what}"))?
        .with_context(|| what.to_owned())
}

/// The mechanism a target logs in with.
#[must_use]
pub fn mechanism(target: &BrokerTarget) -> KafkaSasl {
    target.sasl.unwrap_or(if target.aws {
        KafkaSasl::AwsMskIam
    } else {
        KafkaSasl::Plain
    })
}

/// Connect to `address` (`host:port`) and log in as `user`.
///
/// # Errors
/// If the broker can't be reached, doesn't support what the worker speaks, or
/// refuses the login. The detail names the account; it is for the log, not the user.
pub async fn connect(
    settings: &Settings,
    target: &BrokerTarget,
    credential: &Credential,
    address: &str,
    user: &str,
) -> anyhow::Result<Upstream> {
    let mut stream = settings.dial(address, target.tls, Some(credential)).await?;
    let mut correlation = 0;
    let mut next = || {
        correlation += 1;
        correlation
    };
    let versions = step("ApiVersions", async {
        let body = call(&mut stream, next(), api::API_VERSIONS, 0, &[]).await?;
        proto::parse_api_versions_v0(&body)
            .map_err(|_| anyhow::anyhow!("the broker refused or garbled ApiVersions"))
    })
    .await?;
    let mech = mechanism(target);
    if mech != KafkaSasl::None {
        login(
            &mut stream,
            &versions,
            mech,
            settings,
            target,
            credential,
            address,
            user,
            &mut next,
        )
        .await?;
    }
    Ok(Upstream { stream, versions })
}

#[allow(clippy::too_many_arguments)]
async fn login<S>(
    stream: &mut S,
    versions: &BTreeMap<i16, (i16, i16)>,
    mech: KafkaSasl,
    settings: &Settings,
    target: &BrokerTarget,
    credential: &Credential,
    address: &str,
    user: &str,
    next: &mut impl FnMut() -> i32,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _ = settings;
    let name = match mech {
        KafkaSasl::Plain => "PLAIN",
        KafkaSasl::ScramSha256 => ScramHash::Sha256.mechanism(),
        KafkaSasl::ScramSha512 => ScramHash::Sha512.mechanism(),
        KafkaSasl::AwsMskIam => "AWS_MSK_IAM",
        KafkaSasl::None => return Ok(()),
    };
    let handshake_max = versions.get(&api::SASL_HANDSHAKE).map_or(0, |v| v.1);
    if handshake_max < 1 {
        bail!("the broker is too old for SASL through the worker (SaslHandshake v1)");
    }
    let body = step("SaslHandshake", async {
        call(
            stream,
            next(),
            api::SASL_HANDSHAKE,
            1,
            &Writer::new().string(name).finish(),
        )
        .await
    })
    .await?;
    let mut r = Reader::new(&body);
    let code = r
        .i16()
        .map_err(|_| anyhow::anyhow!("garbled SaslHandshake reply"))?;
    if code != error::NONE {
        let offered = r
            .array(Reader::string)
            .ok()
            .flatten()
            .unwrap_or_default()
            .join(", ");
        bail!("the broker refused SASL mechanism {name} (error {code}); it offers: {offered}");
    }
    let auth_version = if versions
        .get(&api::SASL_AUTHENTICATE)
        .is_some_and(|v| v.1 >= 1)
    {
        1
    } else {
        0
    };
    let mut authenticate = async |token: Vec<u8>| -> anyhow::Result<Vec<u8>> {
        step("SaslAuthenticate", async {
            let reply = call(
                stream,
                next(),
                api::SASL_AUTHENTICATE,
                auth_version,
                &Writer::new().bytes(&token).finish(),
            )
            .await?;
            let mut r = Reader::new(&reply);
            let code = r
                .i16()
                .map_err(|_| anyhow::anyhow!("garbled SaslAuthenticate reply"))?;
            let message = r
                .nullable_string()
                .map_err(|_| anyhow::anyhow!("garbled SaslAuthenticate reply"))?;
            let bytes = r
                .nullable_bytes()
                .map_err(|_| anyhow::anyhow!("garbled SaslAuthenticate reply"))?
                .unwrap_or_default()
                .to_vec();
            if code != error::NONE {
                bail!(
                    "the broker refused the login (error {code}): {}",
                    message.unwrap_or_default()
                );
            }
            Ok(bytes)
        })
        .await
    };
    let secret_of = || -> anyhow::Result<&Secret<String>> {
        credential
            .password
            .as_ref()
            .context("the worker has no password for this broker user (--broker-credentials-file)")
    };
    match mech {
        KafkaSasl::Plain => {
            authenticate(auth::plain(user, secret_of()?.expose())).await?;
        }
        KafkaSasl::ScramSha256 | KafkaSasl::ScramSha512 => {
            let hash = if mech == KafkaSasl::ScramSha256 {
                ScramHash::Sha256
            } else {
                ScramHash::Sha512
            };
            let mut scram = Scram::new(hash, user, secret_of()?.clone(), &Scram::new_nonce());
            let server_first = authenticate(scram.first()).await?;
            let client_final = scram.respond(&server_first)?;
            let server_final = authenticate(client_final).await?;
            scram.verify(&server_final)?;
        }
        KafkaSasl::AwsMskIam => {
            let host = host_of(address);
            let region = target
                .region
                .clone()
                .or_else(|| auth::msk_region(host).map(str::to_owned))
                .context("an MSK resource needs `region` (or a broker name that carries it)")?;
            let creds = aws_credentials(&region).await?;
            let payload = auth::msk_iam_payload(&creds, &region, host, OffsetDateTime::now_utc());
            authenticate(payload.expose().clone()).await?;
        }
        KafkaSasl::None => {}
    }
    Ok(())
}

/// The worker's own AWS credentials, from the default chain.
async fn aws_credentials(region: &str) -> anyhow::Result<Credentials> {
    use aws_credential_types::provider::ProvideCredentials as _;
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region.to_owned()))
        .load()
        .await;
    let provider = config
        .credentials_provider()
        .context("the worker has no AWS credentials")?;
    let c = provider
        .provide_credentials()
        .await
        .context("loading the worker's AWS credentials")?;
    Ok(Credentials {
        access_key: c.access_key_id().to_owned(),
        secret_key: Secret::new(c.secret_access_key().to_owned()),
        session_token: c.session_token().map(|t| Secret::new(t.to_owned())),
    })
}

/// Ask a connected broker for the cluster's brokers.
///
/// # Errors
/// If the exchange fails or the answer isn't a `Metadata` v1 response.
pub async fn brokers_of(up: &mut Upstream) -> anyhow::Result<Vec<Broker>> {
    // An empty topic list: brokers only.
    let body = step("Metadata", async {
        call(
            &mut up.stream,
            1000,
            api::METADATA,
            1,
            &Writer::new().i32(0).finish(),
        )
        .await
    })
    .await?;
    Ok(MetadataResponse::decode(1, &body)
        .map_err(|_| anyhow::anyhow!("garbled Metadata reply"))?
        .brokers)
}

/// The brokers of the cluster `target` names, from a short-lived connection
/// to its bootstrap address. Cached for a few seconds, per resource and user.
///
/// # Errors
/// If the bootstrap broker can't be reached or logged in to.
pub async fn cluster_brokers(
    settings: &Settings,
    resource: &str,
    user: &str,
    target: &BrokerTarget,
    credential: &Credential,
) -> anyhow::Result<Vec<Broker>> {
    let key = format!("{resource}/{user}");
    if let Some(cached) = settings.cached_brokers(&key, BROKER_CACHE) {
        return Ok(cached
            .into_iter()
            .map(|(node_id, host, port)| Broker {
                node_id,
                host,
                port,
                rack: None,
            })
            .collect());
    }
    let mut up = connect(settings, target, credential, &target.endpoint, user).await?;
    let brokers = brokers_of(&mut up).await?;
    settings.cache_brokers(
        key,
        brokers
            .iter()
            .map(|b| (b.node_id, b.host.clone(), b.port))
            .collect(),
    );
    Ok(brokers)
}
