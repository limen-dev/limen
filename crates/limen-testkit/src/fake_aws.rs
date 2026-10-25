//! A stand-in for the AWS describe APIs discovery uses (ADR-0027): EC2, RDS,
//! Redshift, `ElastiCache`, EKS and STS, answering with the response shapes
//! the AWS documentation shows. **It proves the worker reads those shapes and
//! signs its requests; it does not prove the real services behave the same.**
//! It refuses any request that is not signed, and records the actions it saw
//! so tests can check that discovery only reads.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use base64::Engine as _;
use std::fmt::Write as _;

#[derive(Debug, Clone)]
pub struct Instance {
    pub id: String,
    pub ip: String,
    pub state: String,
    pub tags: BTreeMap<String, String>,
    /// Printed in the console output, as cloud-init does.
    pub host_key: Option<String>,
}

#[derive(Debug, Default)]
pub struct World {
    pub instances: Vec<Instance>,
    /// Actions seen, as `Action` or `GET /path`.
    pub seen: Vec<String>,
    /// Make EC2 fail, to prove a failed scan counts nothing as missing.
    pub fail_ec2: bool,
    pub account: String,
}

pub type Shared = Arc<Mutex<World>>;

fn form(body: &[u8]) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(body).into_owned().collect()
}

fn xml(body: String) -> impl IntoResponse {
    (StatusCode::OK, [("content-type", "text/xml")], body)
}

fn tag_set(tags: &BTreeMap<String, String>) -> String {
    use std::fmt::Write as _;
    tags.iter().fold(String::new(), |mut s, (k, v)| {
        let _ = write!(s, "<item><key>{k}</key><value>{v}</value></item>");
        s
    })
}

async fn query(
    State(w): State<Shared>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let signed = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.starts_with("AWS4-HMAC-SHA256 Credential="))
        && headers.contains_key("x-amz-date");
    if !signed {
        return (
            StatusCode::FORBIDDEN,
            "<Error><Code>MissingAuthenticationToken</Code><Message>unsigned</Message></Error>",
        )
            .into_response();
    }
    let p = form(&body);
    let action = p.get("Action").cloned().unwrap_or_default();
    let mut world = w.lock().expect("lock");
    world.seen.push(action.clone());
    let account = world.account.clone();
    match action.as_str() {
        "GetCallerIdentity" => xml(format!(
            "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><GetCallerIdentityResult><Account>{account}</Account><Arn>arn:aws:iam::{account}:role/x</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>"
        ))
        .into_response(),
        "AssumeRole" => xml(
            "<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIAEXAMPLE</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>".to_owned(),
        )
        .into_response(),
        "DescribeInstances" => {
            if world.fail_ec2 {
                return (StatusCode::SERVICE_UNAVAILABLE, "<Response><Errors><Error><Code>RequestLimitExceeded</Code><Message>slow down</Message></Error></Errors></Response>").into_response();
            }
            let items = world.instances.iter().fold(String::new(), |mut acc, i| {
                let _ = write!(acc,
                        "<item><reservationId>r-1</reservationId><instancesSet><item><instanceId>{}</instanceId><instanceState><code>16</code><name>{}</name></instanceState><privateDnsName>ip-{}.ec2.internal</privateDnsName><privateIpAddress>{}</privateIpAddress><tagSet>{}</tagSet></item></instancesSet></item>",
                        i.id, i.state, i.ip.replace('.', "-"), i.ip, tag_set(&i.tags)
                    );
                acc
            });
            xml(format!(
                "<DescribeInstancesResponse xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\"><reservationSet>{items}</reservationSet></DescribeInstancesResponse>"
            ))
            .into_response()
        }
        "GetConsoleOutput" => {
            let id = p.get("InstanceId").cloned().unwrap_or_default();
            let output = world
                .instances
                .iter()
                .find(|i| i.id == id)
                .and_then(|i| i.host_key.clone())
                .map_or_else(
                    || "booting...\n".to_owned(),
                    |k| format!("cloud-init: ok\n-----BEGIN SSH HOST KEY KEYS-----\necdsa-sha2-nistp256 AAAAEcdsaIgnoreMe root@host\n{k} root@host\n-----END SSH HOST KEY KEYS-----\n"),
                );
            let b64 = base64::engine::general_purpose::STANDARD.encode(output);
            xml(format!("<GetConsoleOutputResponse><instanceId>{id}</instanceId><output>{b64}</output></GetConsoleOutputResponse>")).into_response()
        }
        "DescribeDBInstances" => xml(
            "<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances>\
             <DBInstance><DBInstanceIdentifier>orders-db</DBInstanceIdentifier><Engine>postgres</Engine><DBInstanceStatus>available</DBInstanceStatus><Endpoint><Address>orders-db.abc.eu-west-1.rds.amazonaws.com</Address><Port>5432</Port></Endpoint><IAMDatabaseAuthenticationEnabled>true</IAMDatabaseAuthenticationEnabled><TagList><Tag><Key>env</Key><Value>prod</Value></Tag></TagList></DBInstance>\
             <DBInstance><DBInstanceIdentifier>aurora-1</DBInstanceIdentifier><DBClusterIdentifier>aurora</DBClusterIdentifier><Engine>aurora-postgresql</Engine><DBInstanceStatus>available</DBInstanceStatus><Endpoint><Address>aurora-1.abc.rds.amazonaws.com</Address><Port>5432</Port></Endpoint></DBInstance>\
             </DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>".to_owned(),
        )
        .into_response(),
        "DescribeDBClusters" => xml(
            "<DescribeDBClustersResponse><DescribeDBClustersResult><DBClusters>\
             <DBCluster><DBClusterIdentifier>aurora</DBClusterIdentifier><Engine>aurora-postgresql</Engine><Status>available</Status><Endpoint>aurora.cluster-abc.eu-west-1.rds.amazonaws.com</Endpoint><Port>5432</Port><IAMDatabaseAuthenticationEnabled>true</IAMDatabaseAuthenticationEnabled><TagList><Tag><Key>env</Key><Value>prod</Value></Tag></TagList></DBCluster>\
             </DBClusters></DescribeDBClustersResult></DescribeDBClustersResponse>".to_owned(),
        )
        .into_response(),
        "DescribeClusters" => xml(
            "<DescribeClustersResponse><DescribeClustersResult><Clusters>\
             <Cluster><ClusterIdentifier>warehouse</ClusterIdentifier><ClusterStatus>available</ClusterStatus><Endpoint><Address>warehouse.abc.eu-west-1.redshift.amazonaws.com</Address><Port>5439</Port></Endpoint><Tags><Tag><Key>env</Key><Value>prod</Value></Tag></Tags></Cluster>\
             </Clusters></DescribeClustersResult></DescribeClustersResponse>".to_owned(),
        )
        .into_response(),
        "DescribeReplicationGroups" => xml(
            "<DescribeReplicationGroupsResponse><DescribeReplicationGroupsResult><ReplicationGroups>\
             <ReplicationGroup><ReplicationGroupId>sessions</ReplicationGroupId><Status>available</Status><ClusterEnabled>false</ClusterEnabled><TransitEncryptionEnabled>true</TransitEncryptionEnabled><ARN>arn:aws:elasticache:eu-west-1:111122223333:replicationgroup:sessions</ARN><NodeGroups><NodeGroup><PrimaryEndpoint><Address>sessions.abc.euw1.cache.amazonaws.com</Address><Port>6379</Port></PrimaryEndpoint></NodeGroup></NodeGroups></ReplicationGroup>\
             <ReplicationGroup><ReplicationGroupId>sharded</ReplicationGroupId><Status>available</Status><ClusterEnabled>true</ClusterEnabled></ReplicationGroup>\
             </ReplicationGroups></DescribeReplicationGroupsResult></DescribeReplicationGroupsResponse>".to_owned(),
        )
        .into_response(),
        "ListTagsForResource" => xml(
            "<ListTagsForResourceResponse><ListTagsForResourceResult><TagList><Tag><Key>env</Key><Value>prod</Value></Tag></TagList></ListTagsForResourceResult></ListTagsForResourceResponse>".to_owned(),
        )
        .into_response(),
        _ => (StatusCode::BAD_REQUEST, "<Error><Code>InvalidAction</Code><Message>no such action</Message></Error>").into_response(),
    }
}

async fn eks(State(w): State<Shared>, headers: HeaderMap, uri: Uri) -> axum::response::Response {
    if !headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.starts_with("AWS4-HMAC-SHA256"))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    w.lock()
        .expect("lock")
        .seen
        .push(format!("GET {}", uri.path()));
    let body = match uri.path() {
        "/clusters" => serde_json::json!({ "clusters": ["prod-eks"] }),
        "/clusters/prod-eks" => {
            serde_json::json!({ "cluster": { "name": "prod-eks", "status": "ACTIVE", "tags": { "env": "prod" } } })
        }
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    axum::Json(body).into_response()
}

/// Start the stand-in. Returns its URL and the shared state tests change.
///
/// # Panics
/// If it can't bind a local port.
pub async fn start(account: &str) -> (String, Shared) {
    let world: Shared = Arc::new(Mutex::new(World {
        account: account.to_owned(),
        ..World::default()
    }));
    let app = Router::new()
        .route("/", post(query))
        .route("/clusters", get(eks))
        .route("/clusters/{name}", get(eks))
        .with_state(Arc::clone(&world));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), world)
}
