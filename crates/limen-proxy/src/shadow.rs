//! Reporting shadow deny rules (ADR-0046). A shadow rule must never refuse
//! a request, so nothing here can fail one: a lost report is logged and
//! counted, and the request goes on. If the audit sink is down, the request's
//! own audit event fails first and the usual failure mode applies.

use limen_audit::{Context, Emitter, EventKind};
use limen_policy::shadow::ShadowMatch;
use serde_json::{Value, json};
use uuid::Uuid;

/// One `policy.shadow_deny` event per matching rule. `request` says what was
/// asked (resource, principal, and for the web the method and path).
pub(crate) async fn report(
    audit: &Emitter,
    hits: &[ShadowMatch],
    user: &str,
    session_id: Option<Uuid>,
    policy_version: i64,
    request: &Value,
) {
    for hit in hits {
        let mut data = request.clone();
        data["role"] = json!(hit.role);
        data["rule"] = json!(hit.rule);
        data["policy_version"] = json!(policy_version);
        let sent = audit
            .emit(
                EventKind::PolicyShadowDeny,
                Context {
                    user: Some(user.to_owned()),
                    session_id,
                },
                data,
            )
            .await;
        metrics::counter!(
            "limen_policy_shadow_denies_total",
            "role" => hit.role.clone(),
            "rule" => hit.rule.clone()
        )
        .increment(1);
        if let Err(e) = sent {
            metrics::counter!("limen_policy_shadow_events_dropped_total").increment(1);
            tracing::warn!(error = %e, role = %hit.role, rule = %hit.rule, "could not audit a shadow deny; the request goes on");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use limen_audit::FailureMode;
    use limen_audit::sink::MemorySink;

    use super::*;

    fn hit() -> ShadowMatch {
        ShadowMatch {
            role: "dev".into(),
            rule: "no-root".into(),
            index: 0,
        }
    }

    #[tokio::test]
    async fn a_report_carries_the_rule_and_the_request() {
        let sink = Arc::new(MemorySink::default());
        let audit = Emitter::new("proxy", "p1", sink.clone(), FailureMode::FailClosed);
        report(
            &audit,
            &[hit()],
            "ana",
            None,
            7,
            &json!({ "action": "ssh", "resource": "web-prod", "login": "root" }),
        )
        .await;
        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::PolicyShadowDeny);
        assert_eq!(events[0].user.as_deref(), Some("ana"));
        assert_eq!(events[0].data["rule"], "no-root");
        assert_eq!(events[0].data["role"], "dev");
        assert_eq!(events[0].data["login"], "root");
        assert_eq!(events[0].data["policy_version"], 7);
    }

    /// The report has no way to refuse the request: with the sink broken and
    /// the failure mode closed, it still returns, having written nothing.
    #[tokio::test]
    async fn a_broken_sink_does_not_stop_the_request() {
        let sink = Arc::new(MemorySink::default());
        sink.set_failing(true);
        let audit = Emitter::new("proxy", "p1", sink.clone(), FailureMode::FailClosed);
        report(&audit, &[hit(), hit()], "ana", None, 7, &json!({})).await;
        assert_eq!(sink.events().len(), 0);
    }
}
