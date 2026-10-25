//! What to ask each AWS service, and how to read the answer (ADR-0027). The
//! parsers take the root of a response so they can be tested on recorded
//! answers. **They are written from AWS's documented response shapes and
//! tested against stand-ins, not against the real services.**

use std::collections::BTreeMap;

use base64::Engine as _;
use limen_policy::discovery::{DiscoveryMatch, Found, Source};

use super::aws::{Aws, indexed};
use super::xml::Node;
use crate::db::sigv4::Credentials;

/// Most pages of one listing: a bound, not an expectation.
const MAX_PAGES: usize = 50;
/// Most console-output fetches per scan.
const MAX_CONSOLE_FETCHES: usize = 100;

/// Tags as a map, from `<Tag><Key/><Value/></Tag>` or `<item><key/><value/></item>`.
fn tags_of(list: Option<&Node>, element: &str, key: &str, value: &str) -> BTreeMap<String, String> {
    list.map(|l| {
        l.all(element)
            .filter_map(|t| {
                Some((
                    t.text_of(key)?.to_owned(),
                    t.text_of(value).unwrap_or_default().to_owned(),
                ))
            })
            .collect()
    })
    .unwrap_or_default()
}

/// Only the tags the matcher uses: its filter, its name template, its label
/// tags. The rest never leave the worker.
fn used_tags(m: &DiscoveryMatch, all: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut wanted: Vec<String> = m.tags.keys().cloned().collect();
    wanted.extend(m.labels_from_tags.iter().cloned());
    if let Some(t) = &m.name_template {
        wanted.extend(
            t.split("{{")
                .skip(1)
                .filter_map(|p| p.split("}}").next())
                .filter_map(|p| p.trim().strip_prefix("tag."))
                .map(str::to_owned),
        );
    } else if m.source == Source::Ec2 {
        wanted.push("Name".into());
    }
    all.iter()
        .filter(|(k, _)| wanted.contains(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn filter_matches(m: &DiscoveryMatch, tags: &BTreeMap<String, String>) -> bool {
    m.tags.iter().all(|(k, vs)| {
        tags.get(k)
            .is_some_and(|a| vs.iter().any(|v| v == "*" || v == a))
    })
}

fn found(
    m: &DiscoveryMatch,
    account: &str,
    region: &str,
    id: &str,
    target: String,
    all_tags: &BTreeMap<String, String>,
    facts: &[(&str, String)],
) -> Option<Found> {
    if !filter_matches(m, all_tags) {
        return None;
    }
    Some(Found {
        source: m.source,
        account: account.to_owned(),
        region: region.to_owned(),
        provider_id: id.to_owned(),
        target,
        tags: used_tags(m, all_tags),
        facts: facts
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect(),
    })
}

// ---- EC2 -------------------------------------------------------------------------------

/// Running instances in a `DescribeInstances` answer.
#[must_use]
pub fn parse_instances(
    root: &Node,
    m: &DiscoveryMatch,
    account: &str,
    region: &str,
) -> Vec<(Found, String)> {
    let use_dns = m
        .ssh
        .as_ref()
        .is_some_and(|s| s.address == limen_policy::discovery::SshAddress::PrivateDns);
    let port = m.ssh.as_ref().map_or(22, |s| s.port);
    let mut out = Vec::new();
    let Some(sets) = root.child("reservationSet") else {
        return out;
    };
    for res in sets.all("item") {
        for i in res
            .child("instancesSet")
            .into_iter()
            .flat_map(|s| s.all("item"))
        {
            if i.text_at(&["instanceState", "name"]) != Some("running") {
                continue;
            }
            let Some(id) = i.text_of("instanceId") else {
                continue;
            };
            let host = if use_dns {
                i.text_of("privateDnsName")
            } else {
                i.text_of("privateIpAddress")
            };
            let Some(host) = host else { continue };
            let tags = tags_of(i.child("tagSet"), "item", "key", "value");
            if let Some(f) = found(m, account, region, id, format!("{host}:{port}"), &tags, &[]) {
                out.push((f, id.to_owned()));
            }
        }
    }
    out
}

/// The best SSH host key in an instance's console output: cloud-init prints
/// the public keys between two marker lines.
#[must_use]
pub fn host_key_from_console(output_b64: &str) -> Option<String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(output_b64.trim())
        .ok()?;
    let text = String::from_utf8_lossy(&raw);
    let block = text
        .split("-----BEGIN SSH HOST KEY KEYS-----")
        .nth(1)?
        .split("-----END SSH HOST KEY KEYS-----")
        .next()?;
    let keys: Vec<&str> = block
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("ssh-") || l.starts_with("ecdsa-"))
        .collect();
    // Ed25519 first, then ECDSA, then whatever else.
    let pick = ["ssh-ed25519", "ecdsa-sha2-nistp256"]
        .iter()
        .find_map(|p| keys.iter().find(|k| k.starts_with(p)))
        .or_else(|| keys.first())?;
    // `type base64 comment` → `type base64`.
    Some(
        pick.split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" "),
    )
}

async fn scan_ec2(
    aws: &Aws,
    creds: &Credentials,
    m: &DiscoveryMatch,
    account: &str,
    region: &str,
) -> Result<Vec<Found>, String> {
    let mut found: Vec<(Found, String)> = Vec::new();
    let mut token: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let mut params = vec![
            ("Filter.1.Name".to_owned(), "instance-state-name".to_owned()),
            ("Filter.1.Value.1".to_owned(), "running".to_owned()),
        ];
        for (n, (k, vs)) in (2..).zip(&m.tags) {
            if vs.iter().any(|v| v == "*") {
                params.push((format!("Filter.{n}.Name"), "tag-key".into()));
                params.push((format!("Filter.{n}.Value.1"), k.clone()));
            } else {
                params.push((format!("Filter.{n}.Name"), format!("tag:{k}")));
                params.extend(indexed(&format!("Filter.{n}.Value"), vs));
            }
        }
        if let Some(t) = &token {
            params.push(("NextToken".into(), t.clone()));
        }
        let root = aws
            .query(
                creds,
                "ec2",
                region,
                "2016-11-15",
                "DescribeInstances",
                &params,
            )
            .await?;
        found.extend(parse_instances(&root, m, account, region));
        token = root.text_of("nextToken").map(str::to_owned);
        if token.is_none() {
            break;
        }
    }
    // Host keys: the worker refuses hosts it can't verify, and DescribeInstances
    // doesn't say. The instance's console output does, on images that print it.
    for (f, id) in found.iter_mut().take(MAX_CONSOLE_FETCHES) {
        let root = aws
            .query(
                creds,
                "ec2",
                region,
                "2016-11-15",
                "GetConsoleOutput",
                &[
                    ("InstanceId".into(), id.clone()),
                    ("Latest".into(), "true".into()),
                ],
            )
            .await;
        // One instance's missing output is not a failed scan.
        if let Ok(root) = root
            && let Some(key) = root.text_of("output").and_then(host_key_from_console)
        {
            f.facts.insert("host_key".into(), key);
        }
    }
    Ok(found.into_iter().map(|(f, _)| f).collect())
}

// ---- RDS / Aurora -------------------------------------------------------------------------

#[must_use]
pub fn parse_rds(
    instances: &Node,
    clusters: &Node,
    m: &DiscoveryMatch,
    account: &str,
    region: &str,
) -> Vec<Found> {
    let mut out = Vec::new();
    let tag_list = |n: &Node| tags_of(n.child("TagList"), "Tag", "Key", "Value");
    let endpoint = |n: &Node, addr: &[&str], port: &[&str]| {
        Some(format!(
            "{}:{}",
            n.text_at(addr)?,
            n.text_at(port).unwrap_or("5432")
        ))
    };
    let list = |root: &Node, result: &str, set: &str, item: &'static str| -> Vec<Node> {
        root.path(&[result, set])
            .map(|s| s.all(item).cloned().collect())
            .unwrap_or_default()
    };
    for c in list(
        clusters,
        "DescribeDBClustersResult",
        "DBClusters",
        "DBCluster",
    ) {
        if c.text_of("Status").is_some_and(|s| s != "available") {
            continue;
        }
        let (Some(id), Some(engine)) = (c.text_of("DBClusterIdentifier"), c.text_of("Engine"))
        else {
            continue;
        };
        let default_port = if engine.contains("mysql") {
            "3306"
        } else {
            "5432"
        };
        let Some(target) = c
            .text_of("Endpoint")
            .map(|h| format!("{h}:{}", c.text_of("Port").unwrap_or(default_port)))
        else {
            continue;
        };
        let iam = c
            .text_of("IAMDatabaseAuthenticationEnabled")
            .unwrap_or("false")
            .to_owned();
        out.extend(found(
            m,
            account,
            region,
            id,
            target,
            &tag_list(&c),
            &[("engine", engine.to_owned()), ("iam_auth", iam)],
        ));
    }
    for i in list(
        instances,
        "DescribeDBInstancesResult",
        "DBInstances",
        "DBInstance",
    ) {
        // Members of a cluster are reached through the cluster endpoint.
        if i.text_of("DBClusterIdentifier").is_some()
            || i.text_of("DBInstanceStatus")
                .is_some_and(|s| s != "available")
        {
            continue;
        }
        let (Some(id), Some(engine)) = (i.text_of("DBInstanceIdentifier"), i.text_of("Engine"))
        else {
            continue;
        };
        let Some(target) = endpoint(&i, &["Endpoint", "Address"], &["Endpoint", "Port"]) else {
            continue;
        };
        let iam = i
            .text_of("IAMDatabaseAuthenticationEnabled")
            .unwrap_or("false")
            .to_owned();
        out.extend(found(
            m,
            account,
            region,
            id,
            target,
            &tag_list(&i),
            &[("engine", engine.to_owned()), ("iam_auth", iam)],
        ));
    }
    out
}

async fn paged(
    aws: &Aws,
    creds: &Credentials,
    service: &str,
    region: &str,
    version: &str,
    action: &str,
    extra: &[(String, String)],
) -> Result<Vec<Node>, String> {
    let mut pages = Vec::new();
    let mut marker: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let mut params = extra.to_vec();
        if let Some(mk) = &marker {
            params.push(("Marker".into(), mk.clone()));
        }
        let root = aws
            .query(creds, service, region, version, action, &params)
            .await?;
        // The marker sits inside the *Result element.
        marker = root
            .children
            .iter()
            .find_map(|c| c.text_of("Marker"))
            .map(str::to_owned);
        pages.push(root);
        if marker.is_none() {
            break;
        }
    }
    Ok(pages)
}

// ---- Redshift -------------------------------------------------------------------------------

#[must_use]
pub fn parse_redshift(root: &Node, m: &DiscoveryMatch, account: &str, region: &str) -> Vec<Found> {
    let mut out = Vec::new();
    let Some(clusters) = root.path(&["DescribeClustersResult", "Clusters"]) else {
        return out;
    };
    for c in clusters.all("Cluster") {
        if c.text_of("ClusterStatus").is_some_and(|s| s != "available") {
            continue;
        }
        let Some(id) = c.text_of("ClusterIdentifier") else {
            continue;
        };
        let Some(host) = c.text_at(&["Endpoint", "Address"]) else {
            continue;
        };
        let target = format!(
            "{host}:{}",
            c.text_at(&["Endpoint", "Port"]).unwrap_or("5439")
        );
        let tags = tags_of(c.child("Tags"), "Tag", "Key", "Value");
        out.extend(found(m, account, region, id, target, &tags, &[]));
    }
    out
}

// ---- ElastiCache ---------------------------------------------------------------------------

/// Replication groups with a primary endpoint. Cluster-mode groups are not
/// served (Phase 7), so they are skipped, not half-described.
#[must_use]
pub fn parse_replication_groups(root: &Node) -> Vec<Node> {
    root.path(&["DescribeReplicationGroupsResult", "ReplicationGroups"])
        .map(|s| s.all("ReplicationGroup").cloned().collect())
        .unwrap_or_default()
}

#[must_use]
pub fn elasticache_found(
    g: &Node,
    tags: &BTreeMap<String, String>,
    m: &DiscoveryMatch,
    account: &str,
    region: &str,
) -> Option<Found> {
    if g.text_of("Status").is_some_and(|s| s != "available")
        || g.text_of("ClusterEnabled") == Some("true")
    {
        return None;
    }
    let id = g.text_of("ReplicationGroupId")?;
    let primary = g
        .path(&["NodeGroups"])?
        .all("NodeGroup")
        .next()?
        .child("PrimaryEndpoint")?;
    let target = format!(
        "{}:{}",
        primary.text_of("Address")?,
        primary.text_of("Port").unwrap_or("6379")
    );
    let iam = g
        .child("UserGroupIds")
        .is_some_and(|u| !u.children.is_empty());
    found(
        m,
        account,
        region,
        id,
        target,
        tags,
        &[
            ("replication_group", id.to_owned()),
            (
                "tls",
                g.text_of("TransitEncryptionEnabled")
                    .unwrap_or("false")
                    .to_owned(),
            ),
            ("iam_auth", iam.to_string()),
        ],
    )
}

async fn scan_elasticache(
    aws: &Aws,
    creds: &Credentials,
    m: &DiscoveryMatch,
    account: &str,
    region: &str,
) -> Result<Vec<Found>, String> {
    let mut out = Vec::new();
    for page in paged(
        aws,
        creds,
        "elasticache",
        region,
        "2015-02-02",
        "DescribeReplicationGroups",
        &[],
    )
    .await?
    {
        for g in parse_replication_groups(&page) {
            let tags = match g.text_of("ARN") {
                Some(arn) => {
                    let root = aws
                        .query(
                            creds,
                            "elasticache",
                            region,
                            "2015-02-02",
                            "ListTagsForResource",
                            &[("ResourceName".into(), arn.to_owned())],
                        )
                        .await?;
                    tags_of(
                        root.path(&["ListTagsForResourceResult", "TagList"]),
                        "Tag",
                        "Key",
                        "Value",
                    )
                }
                None => BTreeMap::new(),
            };
            out.extend(elasticache_found(&g, &tags, m, account, region));
        }
    }
    Ok(out)
}

// ---- EKS -----------------------------------------------------------------------------------

async fn scan_eks(
    aws: &Aws,
    creds: &Credentials,
    m: &DiscoveryMatch,
    account: &str,
    region: &str,
) -> Result<Vec<Found>, String> {
    let mut names: Vec<String> = Vec::new();
    let mut token: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let mut q = vec![("maxResults".to_owned(), "100".to_owned())];
        if let Some(t) = &token {
            q.push(("nextToken".into(), t.clone()));
        }
        let v = aws.rest_get(creds, "eks", region, "/clusters", &q).await?;
        names.extend(
            v["clusters"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|n| n.as_str().map(str::to_owned)),
        );
        token = v["nextToken"].as_str().map(str::to_owned);
        if token.is_none() {
            break;
        }
    }
    let mut out = Vec::new();
    for name in names {
        let path = format!("/clusters/{name}");
        let v = aws.rest_get(creds, "eks", region, &path, &[]).await?;
        out.extend(eks_found(&v, m, account, region));
    }
    Ok(out)
}

#[must_use]
pub fn eks_found(
    v: &serde_json::Value,
    m: &DiscoveryMatch,
    account: &str,
    region: &str,
) -> Option<Found> {
    let c = v.get("cluster")?;
    if c["status"].as_str() != Some("ACTIVE") {
        return None;
    }
    let name = c["name"].as_str()?;
    let tags: BTreeMap<String, String> = c["tags"]
        .as_object()
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default();
    found(m, account, region, name, name.to_owned(), &tags, &[])
}

// ---- entry point -----------------------------------------------------------------------------

/// Scan one matcher in one account and region.
pub async fn scan(
    aws: &Aws,
    creds: &Credentials,
    m: &DiscoveryMatch,
    account: &str,
    region: &str,
) -> Result<Vec<Found>, String> {
    match m.source {
        Source::Ec2 => scan_ec2(aws, creds, m, account, region).await,
        Source::Rds => {
            let instances = paged(
                aws,
                creds,
                "rds",
                region,
                "2014-10-31",
                "DescribeDBInstances",
                &[],
            )
            .await?;
            let clusters = paged(
                aws,
                creds,
                "rds",
                region,
                "2014-10-31",
                "DescribeDBClusters",
                &[],
            )
            .await?;
            let mut out = Vec::new();
            for (i, c) in instances
                .iter()
                .zip(clusters.iter().chain(std::iter::repeat(&Node::default())))
            {
                out.extend(parse_rds(i, c, m, account, region));
            }
            // More cluster pages than instance pages.
            for c in clusters.iter().skip(instances.len()) {
                out.extend(parse_rds(&Node::default(), c, m, account, region));
            }
            Ok(out)
        }
        Source::Redshift => {
            let mut out = Vec::new();
            for page in paged(
                aws,
                creds,
                "redshift",
                region,
                "2012-12-01",
                "DescribeClusters",
                &[],
            )
            .await?
            {
                out.extend(parse_redshift(&page, m, account, region));
            }
            Ok(out)
        }
        Source::Elasticache => scan_elasticache(aws, creds, m, account, region).await,
        Source::Eks => scan_eks(aws, creds, m, account, region).await,
    }
}
