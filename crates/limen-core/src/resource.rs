//! Kinds of infrastructure resources Limen brokers access to.

use serde::{Deserialize, Serialize};

/// The protocol family of a resource. Determines which worker type serves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Ssh,
    Postgres,
    Mysql,
    Redis,
    Kubernetes,
}

impl ResourceKind {
    pub const ALL: [ResourceKind; 5] = [
        ResourceKind::Ssh,
        ResourceKind::Postgres,
        ResourceKind::Mysql,
        ResourceKind::Redis,
        ResourceKind::Kubernetes,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceKind::Ssh => "ssh",
            ResourceKind::Postgres => "postgres",
            ResourceKind::Mysql => "mysql",
            ResourceKind::Redis => "redis",
            ResourceKind::Kubernetes => "kubernetes",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_name_matches_as_str() {
        for kind in ResourceKind::ALL {
            let json = serde_json::to_string(&kind).expect("serialize");
            assert_eq!(json, format!("\"{}\"", kind.as_str()));
        }
    }
}
