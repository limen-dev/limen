//! Identity: OIDC login and mapping IdP groups to Limen roles.
//!
//! The OIDC flows (PKCE and device code) arrive in Phase 1 (see ADR-0006).
//! The [`IdentityProvider`] seam is where SAML could plug in later.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Verified identity after a successful IdP login.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Stable subject identifier from the IdP (`sub`).
    pub subject: String,
    /// Human-readable username, usually the email address.
    pub username: String,
    pub groups: BTreeSet<String>,
}

/// Kinds of identity provider. Only OIDC is implemented in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IdentityProvider {
    Oidc,
}

/// Maps IdP group names to Limen role names.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupRoleMapping(BTreeMap<String, BTreeSet<String>>);

impl GroupRoleMapping {
    pub fn map(&mut self, group: impl Into<String>, role: impl Into<String>) {
        self.0.entry(group.into()).or_default().insert(role.into());
    }

    /// Roles granted to an identity. Unknown groups grant nothing.
    #[must_use]
    pub fn roles_for(&self, identity: &Identity) -> BTreeSet<String> {
        identity
            .groups
            .iter()
            .filter_map(|g| self.0.get(g))
            .flatten()
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_groups_and_ignores_unknown() {
        let mut mapping = GroupRoleMapping::default();
        mapping.map("okta-dba", "db-admin");
        mapping.map("okta-dba", "db-readonly");
        mapping.map("okta-sre", "ssh-prod");
        let identity = Identity {
            subject: "00u1".into(),
            username: "admin@example.com".into(),
            groups: ["okta-dba".to_owned(), "okta-marketing".to_owned()].into(),
        };
        let roles: Vec<_> = mapping.roles_for(&identity).into_iter().collect();
        assert_eq!(roles, ["db-admin", "db-readonly"]);
    }
}
