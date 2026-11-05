#![no_main]
//! The policy evaluator, on arbitrary requests against the example policy.
use std::sync::OnceLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use limen_policy::{AccessRequest, Decision, Policy, Principal};

const ROLES: &str = include_str!("../../examples/policy/shared/roles.yaml");
const MAPPINGS: &str = include_str!("../../examples/policy/shared/mappings.yaml");
const RESOURCES: &str = concat!(
    include_str!("../../examples/policy/stacks/ssh/resources.yaml"),
    "\n---\n",
    include_str!("../../examples/policy/stacks/database/resources.yaml"),
    "\n---\n",
    include_str!("../../examples/policy/stacks/redis/resources.yaml"),
    "\n---\n",
    include_str!("../../examples/policy/stacks/mongo/resources.yaml"),
    "\n---\n",
    include_str!("../../examples/policy/stacks/messaging/resources.yaml"),
    "\n---\n",
    include_str!("../../examples/policy/stacks/search/resources.yaml"),
);

fn policy() -> &'static Policy {
    static POLICY: OnceLock<Policy> = OnceLock::new();
    POLICY.get_or_init(|| {
        Policy::parse_yaml([
            ("roles", ROLES),
            ("mappings", MAPPINGS),
            ("resources", RESOURCES),
        ])
        .expect("the example policy is valid")
    })
}

#[derive(Arbitrary, Debug)]
struct Input {
    roles: Vec<String>,
    eligible: Vec<String>,
    resource: String,
    principal: String,
    database: String,
    method: String,
    path: String,
}

fuzz_target!(|input: Input| {
    let policy = policy();
    // Names the policy knows are worth more than random text: try each as the resource too.
    let known: Vec<String> = policy
        .resources()
        .map(|r| r.metadata.name.clone())
        .collect();
    let known_roles: Vec<String> = policy.roles().map(|r| r.metadata.name.clone()).collect();

    let principal = Principal::parse(&input.principal, &input.database);
    for resource in known
        .iter()
        .map(String::as_str)
        .chain([input.resource.as_str()])
    {
        for roles in [&input.roles, &known_roles] {
            let _ = policy.web_request_allowed(roles, resource, &input.method, &input.path);
            let _ = policy.redis_grants(roles, resource, &input.principal);
            let _ = policy.mq_grants(roles, resource, &input.principal);
            let _ = policy.kafka_grants(roles, resource, &input.principal);
            let _ = policy.mongo_grants(roles, resource, &input.principal);
            let _ = policy.kube_groups(roles, resource);
            let Ok(principal) = &principal else { continue };
            let req = AccessRequest {
                roles,
                resource,
                principal: principal.clone(),
            };
            let decision = policy.evaluate(&req);
            // Deny by default: no roles, no access.
            if roles.is_empty() {
                assert!(!decision.is_allowed());
            }
            // A request for approval never turns an allow into something else.
            let eligible = policy.evaluate_eligible(&req, &input.eligible);
            if decision.is_allowed() {
                assert_eq!(decision, eligible);
            } else {
                assert!(!matches!(eligible, Decision::Allow { .. }));
            }
        }
    }
    let _ = policy.accessible(&input.roles);
    let _ = policy.roles_for_groups(input.roles.iter().map(String::as_str), &input.eligible);
    let _ = policy.requestable_resources(&input.roles, &input.eligible);
    let _ = policy.what_can(&input.roles, Some(&input.resource));
    let _ = policy.cert_ttl(
        &input.roles,
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(3600),
    );
});
