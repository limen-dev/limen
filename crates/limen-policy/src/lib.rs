//! Policy model and evaluator.
//!
//! Phase 0 fixes the shape of a decision. Role and resource YAML, label
//! selectors, and signed snapshots arrive in Phase 1 (see ADR-0008).

use limen_core::resource::ResourceKind;
use serde::{Deserialize, Serialize};

/// Result of evaluating an access request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Decision {
    Allow {
        matched_roles: Vec<String>,
    },
    Deny {
        reason: DenyReason,
    },
    /// Reserved for just-in-time and approval workflows. Not produced in v1.
    /// Enforcement points must treat it as a denial.
    RequiresApproval {
        reason: String,
    },
}

impl Decision {
    /// True only for an explicit allow. Every other variant, including ones
    /// added later, denies access.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    NoMatchingRole,
    PolicySnapshotStale,
    InvalidRequest,
}

/// Minimal access request used by the Phase 0 evaluator.
#[derive(Debug, Clone)]
pub struct AccessRequest<'a> {
    pub user: &'a str,
    pub roles: &'a [String],
    pub kind: ResourceKind,
    pub resource: &'a str,
}

/// Evaluator with no roles loaded. It denies everything, which is the
/// baseline every later policy builds on.
#[derive(Debug, Default)]
pub struct EmptyPolicy;

impl EmptyPolicy {
    #[must_use]
    pub fn evaluate(&self, _request: &AccessRequest<'_>) -> Decision {
        Decision::Deny {
            reason: DenyReason::NoMatchingRole,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_policy_denies_every_kind() {
        let roles = vec!["admin".to_owned()];
        for kind in ResourceKind::ALL {
            let request = AccessRequest {
                user: "alice",
                roles: &roles,
                kind,
                resource: "anything",
            };
            let decision = EmptyPolicy.evaluate(&request);
            assert!(!decision.is_allowed());
        }
    }

    #[test]
    fn requires_approval_is_not_allowed() {
        let decision = Decision::RequiresApproval {
            reason: "jit".into(),
        };
        assert!(!decision.is_allowed());
    }
}
