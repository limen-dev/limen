//! Kinds of infrastructure resources Limen brokers access to.

use serde::{Deserialize, Serialize};

/// The protocol family of a resource. Determines which worker type serves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Ssh,
    Postgres,
    Mysql,
    Redshift,
    Redis,
    Kubernetes,
    Mongodb,
    Opensearch,
    Elasticsearch,
    Rabbitmq,
    Kafka,
    Web,
    Tcp,
}

impl ResourceKind {
    pub const ALL: [ResourceKind; 13] = [
        ResourceKind::Ssh,
        ResourceKind::Postgres,
        ResourceKind::Mysql,
        ResourceKind::Redshift,
        ResourceKind::Redis,
        ResourceKind::Kubernetes,
        ResourceKind::Mongodb,
        ResourceKind::Opensearch,
        ResourceKind::Elasticsearch,
        ResourceKind::Rabbitmq,
        ResourceKind::Kafka,
        ResourceKind::Web,
        ResourceKind::Tcp,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceKind::Ssh => "ssh",
            ResourceKind::Postgres => "postgres",
            ResourceKind::Mysql => "mysql",
            ResourceKind::Redshift => "redshift",
            ResourceKind::Redis => "redis",
            ResourceKind::Kubernetes => "kubernetes",
            ResourceKind::Mongodb => "mongodb",
            ResourceKind::Opensearch => "opensearch",
            ResourceKind::Elasticsearch => "elasticsearch",
            ResourceKind::Rabbitmq => "rabbitmq",
            ResourceKind::Kafka => "kafka",
            ResourceKind::Web => "web",
            ResourceKind::Tcp => "tcp",
        }
    }
}

/// How people reach a kind of resource, and whether that works yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    /// The `limen` command, with `{name}` standing for the resource name.
    pub command: &'static str,
    /// The roadmap phase that delivers it, such as `Phase 6`. `None` once it ships.
    pub planned: Option<&'static str>,
}

impl ResourceKind {
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == name)
    }

    /// The command that opens this kind, and the phase that delivers it. SSH,
    /// the SQL databases, Redis, Kubernetes, and MongoDB are served; the other kinds can be
    /// written in policy and listed, but nothing serves them yet (ADR-0018,
    /// ADR-0022).
    #[must_use]
    pub fn access(self) -> Access {
        let (command, planned) = match self {
            ResourceKind::Ssh => ("limen ssh {name}", None),
            ResourceKind::Postgres | ResourceKind::Mysql | ResourceKind::Redshift => {
                ("limen db connect {name}", None)
            }
            ResourceKind::Redis => ("limen redis connect {name}", None),
            ResourceKind::Kubernetes => ("limen kube login {name}", None),
            ResourceKind::Mongodb => ("limen mongo connect {name}", None),
            ResourceKind::Opensearch | ResourceKind::Elasticsearch => {
                ("limen search connect {name}", None)
            }
            ResourceKind::Rabbitmq => ("limen mq connect {name}", Some("Phase 11")),
            ResourceKind::Kafka => ("limen kafka connect {name}", Some("Phase 11")),
            ResourceKind::Web => ("limen web open {name}", Some("Phase 12")),
            ResourceKind::Tcp => ("limen tcp {name}", Some("Phase 12")),
        };
        Access { command, planned }
    }

    /// Whether anything serves this kind today.
    #[must_use]
    pub fn is_available(self) -> bool {
        self.access().planned.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_names_a_command_and_parses_back() {
        for kind in ResourceKind::ALL {
            assert_eq!(ResourceKind::parse(kind.as_str()), Some(kind));
            let access = kind.access();
            assert!(access.command.starts_with("limen ") && access.command.contains("{name}"));
        }
        assert_eq!(ResourceKind::parse("nope"), None);
    }

    #[test]
    fn ssh_the_sql_databases_redis_kubernetes_mongodb_and_search_are_available_today() {
        let available: Vec<_> = ResourceKind::ALL
            .into_iter()
            .filter(|k| k.is_available())
            .collect();
        assert_eq!(
            available,
            [
                ResourceKind::Ssh,
                ResourceKind::Postgres,
                ResourceKind::Mysql,
                ResourceKind::Redshift,
                ResourceKind::Redis,
                ResourceKind::Kubernetes,
                ResourceKind::Mongodb,
                ResourceKind::Opensearch,
                ResourceKind::Elasticsearch
            ]
        );
    }

    #[test]
    fn serde_name_matches_as_str() {
        for kind in ResourceKind::ALL {
            let json = serde_json::to_string(&kind).expect("serialize");
            assert_eq!(json, format!("\"{}\"", kind.as_str()));
        }
    }
}
