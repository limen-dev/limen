//! `grant_scopes`: what each login, role or user may do on a resource, for the console's command
//! builder. The principals must be exactly those `accessible` gives.
#![allow(clippy::unwrap_used)]

use crate::{GrantScope, Policy};

const RESOURCES: &str = r"
kind: resource
version: v1
metadata: { name: orders, labels: { env: prod } }
spec: { postgres: { endpoint: 'db.internal:5432' } }
---
kind: resource
version: v1
metadata: { name: docs, labels: { env: prod } }
spec: { mongodb: { endpoint: 'm:27017', credentials_dir: /c, tls_ca_file: /ca.pem } }
---
kind: resource
version: v1
metadata: { name: cache, labels: { env: prod } }
spec: { redis: { endpoint: 'h:6379' } }
---
kind: resource
version: v1
metadata: { name: logs, labels: { env: prod } }
spec: { opensearch: { endpoint: 'h:9200' } }
---
kind: resource
version: v1
metadata: { name: jobs, labels: { env: prod } }
spec: { rabbitmq: { endpoint: 'h:5672' } }
---
kind: resource
version: v1
metadata: { name: events, labels: { env: prod } }
spec: { kafka: { endpoint: 'h:9092' } }
---
kind: resource
version: v1
metadata: { name: wiki, labels: { env: prod } }
spec: { web: { address: 'h:80', host: 'wiki.example.com', insecure_dev: true } }
";

const ROLES: &str = r"
kind: role
version: v1
metadata: { name: dev }
spec:
  allow:
    - resources: { kind: [postgres], labels: { env: [prod] } }
      db: { roles: [limen_read, limen_write], databases: [orders, billing] }
    - resources: { kind: [postgres], labels: { env: [prod] } }
      db: { roles: [limen_read], databases: [reports] }
    - resources: { kind: [mongodb], labels: { env: [prod] } }
      mongo: { roles: [reader], databases: ['*'] }
    - resources: { kind: [redis], labels: { env: [prod] } }
      redis: { users: [reader], keys: ['s:*'], databases: [1, 2] }
    - resources: { kind: [redis], labels: { env: [prod] } }
      redis: { users: [plain] }
    - resources: { kind: [opensearch], labels: { env: [prod] } }
      search: { roles: [viewer], indices: ['app-*'] }
    - resources: { kind: [rabbitmq], labels: { env: [prod] } }
      mq: { users: [worker], vhosts: [jobs, billing-*], classes: [read, write, configure] }
    - resources: { kind: [rabbitmq], labels: { env: [prod] } }
      mq: { users: [plainmq] }
    - resources: { kind: [kafka], labels: { env: [prod] } }
      kafka: { users: [consumer], topics: ['orders.*'], groups: ['app-*'] }
    - resources: { kind: [web], labels: { env: [prod] } }
      web: { methods: [GET], path_prefixes: [/docs] }
  deny:
    - resources: { kind: [postgres], labels: { env: [prod] } }
      db: { roles: [limen_write], databases: ['*'] }
";

fn policy() -> Policy {
    Policy::parse_yaml([("r.yaml", RESOURCES), ("roles.yaml", ROLES)]).expect("fixture")
}

fn scopes(resource: &str) -> Vec<GrantScope> {
    policy().grant_scopes(&["dev".to_owned()], resource)
}

fn one(resource: &str, principal: &str) -> GrantScope {
    scopes(resource)
        .into_iter()
        .find(|s| s.principal == principal)
        .unwrap_or_else(|| panic!("no {principal} on {resource}"))
}

#[test]
fn database_roles_merge_their_databases_and_a_denied_role_is_gone() {
    let s = scopes("orders");
    let names: Vec<&str> = s.iter().map(|s| s.principal.as_str()).collect();
    assert_eq!(names, ["limen_read"], "limen_write is denied");
    assert_eq!(s[0].databases, ["billing", "orders", "reports"]);
}

#[test]
fn the_principals_are_exactly_the_ones_accessible_gives() {
    let policy = policy();
    let roles = ["dev".to_owned()];
    for res in policy.accessible(&roles) {
        let got: Vec<String> = policy
            .grant_scopes(&roles, &res.name)
            .into_iter()
            .map(|s| s.principal)
            .collect();
        assert_eq!(got, res.principals, "{}", res.name);
    }
}

#[test]
fn a_wildcard_database_swallows_the_rest_of_the_list() {
    assert_eq!(one("docs", "reader").databases, ["*"]);
}

#[test]
fn redis_keys_and_databases_default_to_any_key_and_database_zero() {
    let reader = one("cache", "reader");
    assert_eq!(reader.patterns, ["s:*"]);
    assert_eq!(reader.numbers, [1, 2]);
    let plain = one("cache", "plain");
    assert_eq!(plain.patterns, ["*"]);
    assert_eq!(plain.numbers, [0]);
}

#[test]
fn search_has_classes_and_indices_with_read_the_default() {
    let v = one("logs", "viewer");
    assert_eq!(v.classes, ["read"]);
    assert_eq!(v.patterns, ["app-*"]);
}

#[test]
fn rabbitmq_defaults_to_the_root_vhost_and_read_write() {
    let w = one("jobs", "worker");
    assert_eq!(w.vhosts, ["billing-*", "jobs"]);
    assert_eq!(w.classes, ["configure", "read", "write"]);
    let p = one("jobs", "plainmq");
    assert_eq!(p.vhosts, ["/"]);
    assert_eq!(p.classes, ["read", "write"]);
    assert_eq!(p.patterns, ["*"]);
}

#[test]
fn kafka_has_classes_topics_and_groups() {
    let c = one("events", "consumer");
    assert_eq!(c.classes, ["read"]);
    assert_eq!(c.patterns, ["orders.*"]);
    assert_eq!(c.groups, ["app-*"]);
}

#[test]
fn a_web_grant_lists_methods_and_path_prefixes() {
    let a = one("wiki", "access");
    assert_eq!(a.classes, ["GET"]);
    assert_eq!(a.patterns, ["/docs"]);
}

#[test]
fn unknown_resources_and_no_roles_give_nothing() {
    let none = Vec::<GrantScope>::new();
    assert_eq!(scopes("nope"), none);
    assert_eq!(policy().grant_scopes(&[], "orders"), none);
    assert_eq!(policy().grant_scopes(&["ghost".to_owned()], "orders"), none);
}
