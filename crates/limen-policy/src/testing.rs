//! `kind: policy_test` (ADR-0028): cases that say who must, or must not, reach
//! what. They run offline through the same decision code as enforcement, so a
//! green suite means the policy does what the cases say. The runtime ignores
//! them.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::model::{Metadata, Version};
use crate::{AccessRequest, Decision, Policy, PolicyError, Principal, invalid, validate_name};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTestDoc {
    pub version: Version,
    pub metadata: Metadata,
    pub spec: PolicyTestSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTestSpec {
    pub cases: Vec<TestCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestCase {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub who: Who,
    pub resource: String,
    pub principal: TestPrincipal,
    pub expect: Expect,
    /// With `expect: allow`: the role the decision must go through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_role: Option<String>,
}

/// The identity a case speaks for, written by what policy sees, never by user
/// name: cases don't depend on who is in the user table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Who {
    /// IdP groups. The roles come from the role mappings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// A bot, by name. Its roles come from its document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bot: Option<String>,
    /// Roles held directly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expect {
    /// Standing access: the identity holds a role that grants it.
    Allow,
    /// Not granted, but the identity could ask for it (ADR-0025).
    Request,
    /// No way in at all, not even by asking.
    Deny,
}

impl Expect {
    fn as_str(self) -> &'static str {
        match self {
            Expect::Allow => "allow",
            Expect::Request => "request",
            Expect::Deny => "deny",
        }
    }
}

/// Exactly one field (or `database` with its role) names the principal.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestPrincipal {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mongo_role: Option<String>,
    /// With `db_role` or `mongo_role`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kube_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redis_user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mq_user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kafka_user: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub web: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub tcp: bool,
}

impl TestPrincipal {
    /// The principal this names, or what is wrong with it.
    pub fn resolve(&self) -> Result<Principal, String> {
        let named = [
            self.login.is_some(),
            self.db_role.is_some(),
            self.mongo_role.is_some(),
            self.kube_group.is_some(),
            self.redis_user.is_some(),
            self.search_role.is_some(),
            self.mq_user.is_some(),
            self.kafka_user.is_some(),
            self.web,
            self.tcp,
        ]
        .into_iter()
        .filter(|b| *b)
        .count();
        if named != 1 {
            return Err("principal must name exactly one of login, db_role, mongo_role, kube_group, redis_user, search_role, mq_user, kafka_user, web, tcp".into());
        }
        if self.database.is_some() && self.db_role.is_none() && self.mongo_role.is_none() {
            return Err("database goes with db_role or mongo_role".into());
        }
        if let Some(role) = &self.db_role {
            let database = self.database.clone().ok_or("db_role needs a database")?;
            return Ok(Principal::DbRole {
                role: role.clone(),
                database,
            });
        }
        if let Some(role) = &self.mongo_role {
            let database = self.database.clone().ok_or("mongo_role needs a database")?;
            return Ok(Principal::MongoRole {
                role: role.clone(),
                database,
            });
        }
        Ok(if let Some(l) = &self.login {
            Principal::SshLogin(l.clone())
        } else if let Some(g) = &self.kube_group {
            Principal::KubeGroup(g.clone())
        } else if let Some(u) = &self.redis_user {
            Principal::RedisUser(u.clone())
        } else if let Some(r) = &self.search_role {
            Principal::SearchRole(r.clone())
        } else if let Some(u) = &self.mq_user {
            Principal::MqUser(u.clone())
        } else if let Some(u) = &self.kafka_user {
            Principal::KafkaUser(u.clone())
        } else if self.web {
            Principal::WebAccess
        } else {
            Principal::TcpAccess
        })
    }
}

pub(crate) fn validate_test(doc: &PolicyTestDoc) -> Result<(), PolicyError> {
    let name = &doc.metadata.name;
    validate_name("policy_test", name, name)?;
    if doc.spec.cases.is_empty() {
        return Err(invalid("policy_test", name, "cases must not be empty"));
    }
    for (i, case) in doc.spec.cases.iter().enumerate() {
        let who = &case.who;
        if who.groups.is_empty() && who.bot.is_none() && who.roles.is_empty() {
            return Err(invalid(
                "policy_test",
                name,
                format!("case {}: who needs groups, a bot, or roles", i + 1),
            ));
        }
        if let Err(e) = case.principal.resolve() {
            return Err(invalid("policy_test", name, format!("case {}: {e}", i + 1)));
        }
        if case.via_role.is_some() && case.expect != Expect::Allow {
            return Err(invalid(
                "policy_test",
                name,
                format!("case {}: via_role goes with expect: allow", i + 1),
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseResult {
    pub test: String,
    pub case: usize,
    pub name: String,
    pub expected: String,
    pub got: String,
    pub passed: bool,
    /// Why, when it failed.
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub untested_resources: Vec<String>,
    pub untested_roles: Vec<String>,
    pub resources: usize,
    pub roles: usize,
    /// Cases that say something must be denied.
    pub deny_cases: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub results: Vec<CaseResult>,
    pub coverage: Coverage,
}

impl Report {
    #[must_use]
    pub fn failed(&self) -> usize {
        self.results.iter().filter(|r| !r.passed).count()
    }

    #[must_use]
    pub fn ok(&self) -> bool {
        self.failed() == 0
    }
}

impl Policy {
    /// The roles a `who` holds, and the roles it could request.
    fn roles_of(&self, who: &Who) -> Result<(Vec<String>, Vec<String>), String> {
        let mut held: BTreeSet<String> = who.roles.iter().cloned().collect();
        let groups = who.groups.iter().map(String::as_str);
        held.extend(self.roles_for_groups(groups.clone(), &[]));
        if let Some(bot) = &who.bot {
            let doc = self.bot(bot).ok_or_else(|| format!("no bot named {bot}"))?;
            held.extend(doc.spec.roles.iter().cloned());
        }
        let eligible: Vec<String> = self
            .requestable_roles_for_groups(groups)
            .into_iter()
            .filter(|r| !held.contains(r))
            .collect();
        Ok((held.into_iter().collect(), eligible))
    }

    /// Run every `policy_test` document in this policy.
    #[must_use]
    pub fn run_tests(&self) -> Report {
        let mut report = Report::default();
        let mut touched_roles: BTreeSet<String> = BTreeSet::new();
        let mut touched_resources: BTreeSet<String> = BTreeSet::new();
        for (test, doc) in &self.policy_tests {
            for (i, case) in doc.spec.cases.iter().enumerate() {
                let label = case
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("{} on {}", who_text(&case.who), case.resource));
                let mut result = CaseResult {
                    test: test.clone(),
                    case: i + 1,
                    name: label,
                    expected: case.expect.as_str().to_owned(),
                    got: String::new(),
                    passed: false,
                    detail: String::new(),
                };
                if case.expect == Expect::Deny {
                    report.coverage.deny_cases += 1;
                }
                touched_resources.insert(case.resource.clone());
                match self.run_case(case, &mut touched_roles) {
                    Ok((got, detail)) => {
                        result.passed = got == result.expected && detail.is_empty();
                        result.got = got;
                        result.detail = detail;
                    }
                    Err(e) => {
                        "error".clone_into(&mut result.got);
                        result.detail = e;
                    }
                }
                report.results.push(result);
            }
        }
        report.coverage.resources = self.resources.len();
        report.coverage.roles = self.roles.len();
        report.coverage.untested_resources = self
            .resources
            .keys()
            .filter(|r| !touched_resources.contains(*r))
            .cloned()
            .collect();
        report.coverage.untested_roles = self
            .roles
            .keys()
            .filter(|r| !touched_roles.contains(*r))
            .cloned()
            .collect();
        report
    }

    /// `(outcome, problem)`. An empty problem means the case's own extra
    /// conditions (`via_role`) held too.
    fn run_case(
        &self,
        case: &TestCase,
        touched_roles: &mut BTreeSet<String>,
    ) -> Result<(String, String), String> {
        if self.resource(&case.resource).is_none() {
            // A "deny" on a typo would pass for the wrong reason.
            return Err(format!("no resource named {}", case.resource));
        }
        let principal = case.principal.resolve()?;
        let (held, eligible) = self.roles_of(&case.who)?;
        touched_roles.extend(held.iter().cloned());
        touched_roles.extend(eligible.iter().cloned());
        let decision = self.evaluate_eligible(
            &AccessRequest {
                roles: &held,
                resource: &case.resource,
                principal,
            },
            &eligible,
        );
        Ok(match decision {
            Decision::Allow { matched_roles } => {
                let problem = case
                    .via_role
                    .as_ref()
                    .filter(|via| !matched_roles.contains(via))
                    .map(|via| format!("allowed through {}, not {via}", matched_roles.join(", ")))
                    .unwrap_or_default();
                ("allow".to_owned(), problem)
            }
            Decision::RequiresApproval { .. } => ("request".to_owned(), String::new()),
            Decision::Deny { .. } => ("deny".to_owned(), String::new()),
        })
    }
}

fn who_text(who: &Who) -> String {
    let mut parts = Vec::new();
    if !who.groups.is_empty() {
        parts.push(format!("groups {}", who.groups.join(",")));
    }
    if let Some(b) = &who.bot {
        parts.push(format!("bot {b}"));
    }
    if !who.roles.is_empty() {
        parts.push(format!("roles {}", who.roles.join(",")));
    }
    parts.join(" and ")
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde `skip_serializing_if` takes a reference
fn is_false(b: &bool) -> bool {
    !*b
}
