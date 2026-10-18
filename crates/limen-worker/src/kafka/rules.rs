//! What a Kafka session may do (ADR-0037), in the shape of Kafka's ACLs:
//! *read*, *write*, and *admin* on topic patterns, and consumer group
//! patterns. Each decision is made by one grant: grants don't combine.

use limen_policy::{KafkaClass, KafkaGrant};

use crate::broker::{glob, matches_any};

/// Internal topics (`__consumer_offsets`, `__transaction_state`) are named
/// with a leading underscore; `*` never opens them.
const INTERNAL: &str = "_";

#[derive(Debug, Clone)]
pub struct Rules {
    grants: Vec<KafkaGrant>,
}

fn class_name(c: KafkaClass) -> &'static str {
    match c {
        KafkaClass::Read => "read",
        KafkaClass::Write => "write",
        KafkaClass::Admin => "admin",
    }
}

fn topic_ok(grant: &KafkaGrant, topic: &str) -> bool {
    if grant.topics.is_empty() {
        return !topic.starts_with(INTERNAL);
    }
    matches_any(&grant.topics, topic, INTERNAL)
}

fn group_ok(grant: &KafkaGrant, group: &str) -> bool {
    grant.groups.is_empty() || grant.groups.iter().any(|p| glob(p, group))
}

impl Rules {
    #[must_use]
    pub fn new(grants: Vec<KafkaGrant>) -> Self {
        Self { grants }
    }

    /// May the session do `class` on `topic` (in `group`, for offsets)?
    ///
    /// # Errors
    /// The reason, for the user and the audit trail.
    pub fn topic(&self, class: KafkaClass, topic: &str, group: Option<&str>) -> Result<(), String> {
        let with_class: Vec<&KafkaGrant> = self
            .grants
            .iter()
            .filter(|g| g.effective_classes().contains(&class))
            .collect();
        if with_class.is_empty() {
            return Err(format!(
                "your role doesn't grant the {} permission",
                class_name(class)
            ));
        }
        let mut topic_matched = false;
        for g in with_class {
            if topic_ok(g, topic) {
                topic_matched = true;
                if group.is_none_or(|grp| group_ok(g, grp)) {
                    return Ok(());
                }
            }
        }
        Err(if topic_matched {
            "your role doesn't cover that consumer group".to_owned()
        } else {
            format!(
                "your role doesn't grant {} on topic {topic:?}",
                class_name(class)
            )
        })
    }

    /// May the session use consumer group `group`? (Joining, committing,
    /// and finding its coordinator need `read`.)
    ///
    /// # Errors
    /// The reason, for the user and the audit trail.
    pub fn group(&self, group: &str) -> Result<(), String> {
        let mut has_read = false;
        for g in &self.grants {
            if g.effective_classes().contains(&KafkaClass::Read) {
                has_read = true;
                if group_ok(g, group) {
                    return Ok(());
                }
            }
        }
        Err(if has_read {
            format!("your role doesn't cover consumer group {group:?}")
        } else {
            "your role doesn't grant the read permission".to_owned()
        })
    }

    /// Does any grant give `class`?
    #[must_use]
    pub fn has_class(&self, class: KafkaClass) -> bool {
        self.grants
            .iter()
            .any(|g| g.effective_classes().contains(&class))
    }

    /// May the topic's name appear in answers? Any class that reaches the
    /// topic is enough: describing needs no more than that.
    #[must_use]
    pub fn visible(&self, topic: &str) -> bool {
        self.grants.iter().any(|g| topic_ok(g, topic))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(classes: &[KafkaClass], topics: &[&str], groups: &[&str]) -> KafkaGrant {
        KafkaGrant {
            users: vec!["u".into()],
            classes: classes.to_vec(),
            topics: topics.iter().map(|s| (*s).to_owned()).collect(),
            groups: groups.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn the_default_grant_reads_any_topic_but_not_internal_ones() {
        let r = Rules::new(vec![grant(&[], &[], &[])]);
        assert!(r.topic(KafkaClass::Read, "orders", None).is_ok());
        assert!(
            r.topic(KafkaClass::Read, "__consumer_offsets", None)
                .is_err()
        );
        let err = r
            .topic(KafkaClass::Write, "orders", None)
            .expect_err("no write");
        assert!(err.contains("write"), "{err}");
        assert!(r.group("anything").is_ok());
        assert!(r.visible("orders") && !r.visible("__transaction_state"));
    }

    #[test]
    fn patterns_limit_topics_and_groups() {
        let r = Rules::new(vec![grant(
            &[KafkaClass::Read],
            &["orders.*"],
            &["reports-*"],
        )]);
        assert!(
            r.topic(KafkaClass::Read, "orders.new", Some("reports-1"))
                .is_ok()
        );
        assert!(r.topic(KafkaClass::Read, "payments", None).is_err());
        let err = r
            .topic(KafkaClass::Read, "orders.new", Some("other"))
            .expect_err("group");
        assert!(err.contains("consumer group"), "{err}");
        assert!(r.group("reports-7").is_ok());
        assert!(r.group("other").is_err());
        assert!(r.visible("orders.x") && !r.visible("payments"));
    }

    #[test]
    fn a_star_does_not_open_internal_topics_but_an_underscore_pattern_does() {
        let star = Rules::new(vec![grant(&[KafkaClass::Read], &["*"], &[])]);
        assert!(star.topic(KafkaClass::Read, "orders", None).is_ok());
        assert!(
            star.topic(KafkaClass::Read, "__consumer_offsets", None)
                .is_err()
        );
        let under = Rules::new(vec![grant(&[KafkaClass::Read], &["_*"], &[])]);
        assert!(
            under
                .topic(KafkaClass::Read, "__consumer_offsets", None)
                .is_ok()
        );
    }

    #[test]
    fn grants_do_not_combine() {
        let r = Rules::new(vec![
            grant(&[KafkaClass::Read], &["a.*"], &[]),
            grant(&[KafkaClass::Write], &["b.*"], &[]),
        ]);
        assert!(r.topic(KafkaClass::Read, "a.x", None).is_ok());
        assert!(r.topic(KafkaClass::Write, "b.x", None).is_ok());
        assert!(r.topic(KafkaClass::Read, "b.x", None).is_err());
        assert!(r.topic(KafkaClass::Write, "a.x", None).is_err());
        assert!(r.has_class(KafkaClass::Write) && !r.has_class(KafkaClass::Admin));
    }
}
