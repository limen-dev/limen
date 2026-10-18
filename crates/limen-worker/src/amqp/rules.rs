//! Which AMQP methods a client may send, and what each one names (ADR-0037).
//!
//! The classes follow `RabbitMQ`'s own permission model: *configure*
//! (declare, delete, bind, purge), *write* (publish), *read* (consume, get,
//! acknowledge). A grant adds vhosts and name patterns. Anything the worker
//! doesn't know is refused, so a method added by a newer client stays closed
//! until someone decides about it.

use std::collections::HashSet;

use limen_policy::{MqClass, MqGrant};
use serde_json::{Value, json};

use super::codec::{Args, Malformed, ids};
use crate::broker::matches_any;

/// Names `*` never opens: the broker's own, such as the firehose tracer
/// `amq.rabbitmq.trace`.
const RESERVED: &str = "amq.rabbitmq.";
/// Direct reply-to is how RPC clients get answers; it is always theirs.
const REPLY_TO: &str = "amq.rabbitmq.reply-to";

/// What one client method asks for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Inspected {
    /// The audit name of the operation.
    pub action: &'static str,
    /// The permission it needs, if it needs one.
    pub needs: Option<MqClass>,
    /// Names that must be covered by the grant's patterns.
    pub names: Vec<String>,
    pub exchange: Option<String>,
    pub queue: Option<String>,
    pub routing_key: Option<String>,
    /// The destination of an exchange-to-exchange binding.
    pub destination: Option<String>,
    /// Written to the audit trail (acknowledgements and channel housekeeping are not).
    pub audited: bool,
    /// `Basic.publish`: a content header and body follow.
    pub publish: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectError {
    Malformed,
    /// A method the worker doesn't relay.
    Unsupported,
}

impl From<Malformed> for InspectError {
    fn from(_: Malformed) -> Self {
        InspectError::Malformed
    }
}

fn housekeeping(action: &'static str) -> Inspected {
    Inspected {
        action,
        ..Inspected::default()
    }
}

fn unaudited(action: &'static str, needs: MqClass) -> Inspected {
    Inspected {
        action,
        needs: Some(needs),
        ..Inspected::default()
    }
}

/// Decode what a client method on a channel asks for.
///
/// # Errors
/// If the arguments are cut short, or the method isn't one the worker relays.
#[allow(clippy::too_many_lines)] // one flat table, clearer than split
pub fn inspect(class: u16, method: u16, args: &[u8]) -> Result<Inspected, InspectError> {
    let mut a = Args::new(args);
    Ok(match (class, method) {
        // Channel housekeeping: the worker handles open, close, and flow.
        (ids::CHANNEL, 10) => housekeeping("channel_open"),
        (ids::CHANNEL, 20 | 21) => housekeeping("channel_flow"),
        (ids::CHANNEL, 40) => housekeeping("channel_close"),
        (ids::CHANNEL, 41) => housekeeping("channel_close_ok"),

        (ids::EXCHANGE, 10) => {
            a.u16()?;
            let exchange = a.shortstr()?;
            let kind = a.shortstr()?;
            Inspected {
                action: "declare_exchange",
                needs: Some(MqClass::Configure),
                names: vec![exchange.clone()],
                exchange: Some(exchange),
                // The exchange type is a name, not data.
                routing_key: Some(kind).filter(|k| !k.is_empty()),
                audited: true,
                ..Inspected::default()
            }
        }
        (ids::EXCHANGE, 20) => {
            a.u16()?;
            let exchange = a.shortstr()?;
            Inspected {
                action: "delete_exchange",
                needs: Some(MqClass::Configure),
                names: vec![exchange.clone()],
                exchange: Some(exchange),
                audited: true,
                ..Inspected::default()
            }
        }
        (ids::EXCHANGE, 30 | 40) => {
            a.u16()?;
            let destination = a.shortstr()?;
            let source = a.shortstr()?;
            let key = a.shortstr()?;
            Inspected {
                action: if method == 30 {
                    "bind_exchange"
                } else {
                    "unbind_exchange"
                },
                needs: Some(MqClass::Configure),
                names: vec![destination.clone(), source.clone()],
                exchange: Some(source),
                destination: Some(destination),
                routing_key: Some(key),
                audited: true,
                ..Inspected::default()
            }
        }

        (ids::QUEUE, 10) => {
            a.u16()?;
            let queue = a.shortstr()?;
            Inspected {
                action: "declare_queue",
                needs: Some(MqClass::Configure),
                // An empty name asks the server to choose one.
                names: vec![queue.clone()],
                queue: Some(queue),
                audited: true,
                ..Inspected::default()
            }
        }
        (ids::QUEUE, 20 | 50) => {
            a.u16()?;
            let queue = a.shortstr()?;
            let exchange = a.shortstr()?;
            let key = a.shortstr()?;
            Inspected {
                action: if method == 20 {
                    "bind_queue"
                } else {
                    "unbind_queue"
                },
                needs: Some(MqClass::Configure),
                names: vec![queue.clone(), exchange.clone()],
                queue: Some(queue),
                exchange: Some(exchange),
                routing_key: Some(key),
                audited: true,
                ..Inspected::default()
            }
        }
        (ids::QUEUE, 30 | 40) => {
            a.u16()?;
            let queue = a.shortstr()?;
            Inspected {
                action: if method == 30 {
                    "purge_queue"
                } else {
                    "delete_queue"
                },
                needs: Some(MqClass::Configure),
                names: vec![queue.clone()],
                queue: Some(queue),
                audited: true,
                ..Inspected::default()
            }
        }

        (ids::BASIC, 10) => unaudited("qos", MqClass::Read),
        (ids::BASIC, 20) => {
            a.u16()?;
            let queue = a.shortstr()?;
            Inspected {
                action: "consume",
                needs: Some(MqClass::Read),
                names: vec![queue.clone()],
                queue: Some(queue),
                audited: true,
                ..Inspected::default()
            }
        }
        (ids::BASIC, 30) => unaudited("cancel", MqClass::Read),
        (ids::BASIC, 40) => {
            a.u16()?;
            let exchange = a.shortstr()?;
            let key = a.shortstr()?;
            // The default exchange delivers to the queue named by the routing key.
            let target = if exchange.is_empty() {
                key.clone()
            } else {
                exchange.clone()
            };
            Inspected {
                action: "publish",
                needs: Some(MqClass::Write),
                names: vec![target],
                exchange: Some(exchange),
                routing_key: Some(key),
                audited: true,
                publish: true,
                ..Inspected::default()
            }
        }
        (ids::BASIC, 70) => {
            a.u16()?;
            let queue = a.shortstr()?;
            Inspected {
                action: "get",
                needs: Some(MqClass::Read),
                names: vec![queue.clone()],
                queue: Some(queue),
                audited: true,
                ..Inspected::default()
            }
        }
        (ids::BASIC, 80) => unaudited("ack", MqClass::Read),
        (ids::BASIC, 90) => unaudited("reject", MqClass::Read),
        (ids::BASIC, 100 | 110) => unaudited("recover", MqClass::Read),
        (ids::BASIC, 120) => unaudited("nack", MqClass::Read),

        (ids::CONFIRM, 10) => unaudited("confirm_select", MqClass::Write),
        (ids::TX, 10) => unaudited("tx_select", MqClass::Write),
        (ids::TX, 20) => unaudited("tx_commit", MqClass::Write),
        (ids::TX, 30) => unaudited("tx_rollback", MqClass::Write),

        _ => return Err(InspectError::Unsupported),
    })
}

/// The grants a session runs under.
#[derive(Debug, Clone)]
pub struct Rules {
    grants: Vec<MqGrant>,
}

impl Rules {
    #[must_use]
    pub fn new(grants: Vec<MqGrant>) -> Self {
        Self { grants }
    }

    /// Does any grant open this vhost?
    #[must_use]
    pub fn vhost_allowed(&self, vhost: &str) -> bool {
        self.grants.iter().any(|g| vhost_matches(g, vhost))
    }

    /// Check one operation. `owned` holds the server-named queues this
    /// session created, which it may use whatever the patterns say.
    ///
    /// # Errors
    /// The reason, for the user and the audit trail.
    pub fn check(
        &self,
        vhost: &str,
        insp: &Inspected,
        owned: &HashSet<String>,
    ) -> Result<(), String> {
        let Some(needs) = insp.needs else {
            return Ok(());
        };
        let in_vhost: Vec<&MqGrant> = self
            .grants
            .iter()
            .filter(|g| vhost_matches(g, vhost))
            .collect();
        if in_vhost.is_empty() {
            return Err(format!("vhost {vhost:?} is not allowed for your role"));
        }
        let with_class: Vec<&&MqGrant> = in_vhost
            .iter()
            .filter(|g| g.effective_classes().contains(&needs))
            .collect();
        if with_class.is_empty() {
            return Err(format!(
                "{} needs the {} permission, which your role doesn't grant on vhost {vhost:?}",
                insp.action,
                class_name(needs)
            ));
        }
        // One grant must cover every name: grants don't combine.
        let mut first_uncovered: Option<&str> = None;
        for g in with_class {
            match insp.names.iter().find(|n| !name_ok(g, n, owned)) {
                None => return Ok(()),
                Some(n) => {
                    first_uncovered.get_or_insert(n);
                }
            }
        }
        Err(format!(
            "{} is not allowed on {:?}: your role doesn't cover that name",
            insp.action,
            first_uncovered.unwrap_or_default()
        ))
    }
}

fn class_name(c: MqClass) -> &'static str {
    match c {
        MqClass::Read => "read",
        MqClass::Write => "write",
        MqClass::Configure => "configure",
    }
}

fn vhost_matches(grant: &MqGrant, vhost: &str) -> bool {
    grant
        .effective_vhosts()
        .iter()
        .any(|p| crate::broker::glob(p, vhost))
}

fn name_ok(grant: &MqGrant, name: &str, owned: &HashSet<String>) -> bool {
    // An empty name is the server's choice, or "the queue declared last on
    // this channel", which was checked when it was declared.
    if name.is_empty() || owned.contains(name) {
        return true;
    }
    if name == REPLY_TO || name.starts_with("amq.rabbitmq.reply-to.") {
        return true;
    }
    if grant.names.is_empty() {
        return !name.starts_with(RESERVED);
    }
    matches_any(&grant.names, name, RESERVED)
}

/// The `mq.operation` event for an allowed operation.
#[must_use]
pub fn audit_data(
    insp: &Inspected,
    resource: &str,
    mq_user: &str,
    vhost: &str,
    channel: u16,
    size: Option<u64>,
) -> Value {
    let mut data = json!({
        "action": insp.action,
        "resource": resource,
        "mq_user": mq_user,
        "vhost": vhost,
        "channel": channel,
    });
    for (key, value) in [
        ("exchange", &insp.exchange),
        ("queue", &insp.queue),
        ("routing_key", &insp.routing_key),
        ("destination", &insp.destination),
    ] {
        if let Some(v) = value {
            data[key] = json!(v);
        }
    }
    if let Some(size) = size {
        data["size"] = json!(size);
    }
    data
}

/// The `auth.denied` event for a refused operation.
#[must_use]
pub fn denied_data(
    insp: &Inspected,
    resource: &str,
    mq_user: &str,
    vhost: &str,
    channel: u16,
    reason: &str,
) -> Value {
    let mut data = audit_data(insp, resource, mq_user, vhost, channel, None);
    data["operation"] = data["action"].take();
    data["action"] = json!("mq");
    data["reason"] = json!(reason);
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amqp::codec::Out;

    fn grant(vhosts: &[&str], classes: &[MqClass], names: &[&str]) -> MqGrant {
        MqGrant {
            users: vec!["u".into()],
            vhosts: vhosts.iter().map(|s| (*s).to_owned()).collect(),
            classes: classes.to_vec(),
            names: names.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn publish(exchange: &str, key: &str) -> Inspected {
        let args = Out::new()
            .u16(0)
            .shortstr(exchange)
            .shortstr(key)
            .u8(0)
            .finish();
        inspect(ids::BASIC, 40, &args).expect("publish")
    }

    fn consume(queue: &str) -> Inspected {
        let args = Out::new()
            .u16(0)
            .shortstr(queue)
            .shortstr("tag")
            .u8(0)
            .u32(0)
            .finish();
        inspect(ids::BASIC, 20, &args).expect("consume")
    }

    fn declare_queue(queue: &str) -> Inspected {
        let args = Out::new().u16(0).shortstr(queue).u8(0).u32(0).finish();
        inspect(ids::QUEUE, 10, &args).expect("declare")
    }

    fn none() -> HashSet<String> {
        HashSet::new()
    }

    #[test]
    fn publish_names_the_exchange_or_for_the_default_exchange_the_queue() {
        let p = publish("orders", "new");
        assert_eq!(p.names, ["orders"]);
        assert_eq!(p.routing_key.as_deref(), Some("new"));
        assert!(p.audited && p.publish);
        let d = publish("", "work-queue");
        assert_eq!(
            d.names,
            ["work-queue"],
            "the default exchange routes by queue name"
        );
    }

    #[test]
    fn methods_decode_to_what_they_name() {
        let bind = inspect(
            ids::QUEUE,
            20,
            &Out::new()
                .u16(0)
                .shortstr("q")
                .shortstr("x")
                .shortstr("k")
                .u8(0)
                .u32(0)
                .finish(),
        )
        .expect("bind");
        assert_eq!(
            (bind.action, bind.names),
            ("bind_queue", vec!["q".to_owned(), "x".to_owned()])
        );
        let ebind = inspect(
            ids::EXCHANGE,
            30,
            &Out::new()
                .u16(0)
                .shortstr("dst")
                .shortstr("src")
                .shortstr("k")
                .u8(0)
                .u32(0)
                .finish(),
        )
        .expect("exchange.bind");
        assert_eq!(ebind.destination.as_deref(), Some("dst"));
        assert_eq!(ebind.exchange.as_deref(), Some("src"));
        let get = inspect(
            ids::BASIC,
            70,
            &Out::new().u16(0).shortstr("q").u8(1).finish(),
        )
        .expect("get");
        assert_eq!((get.action, get.needs), ("get", Some(MqClass::Read)));
        // Acknowledgements are checked but not logged.
        let ack = inspect(ids::BASIC, 80, &[0; 9]).expect("ack");
        assert!(!ack.audited && ack.needs == Some(MqClass::Read));
    }

    #[test]
    fn what_the_worker_does_not_know_is_unsupported() {
        for (c, m) in [
            (ids::BASIC, 60),
            (ids::CONNECTION, 70),
            (ids::QUEUE, 99),
            (200, 1),
            (ids::TX, 40),
        ] {
            assert_eq!(
                inspect(c, m, &[]),
                Err(InspectError::Unsupported),
                "{c}.{m}"
            );
        }
    }

    #[test]
    fn truncated_arguments_are_malformed() {
        assert_eq!(
            inspect(ids::BASIC, 40, &[0, 0, 7, b'a']),
            Err(InspectError::Malformed)
        );
        assert_eq!(inspect(ids::QUEUE, 10, &[]), Err(InspectError::Malformed));
    }

    #[test]
    fn the_default_grant_reads_and_writes_on_slash_but_does_not_configure() {
        let r = Rules::new(vec![grant(&[], &[], &[])]);
        assert!(r.vhost_allowed("/"));
        assert!(!r.vhost_allowed("other"));
        assert!(r.check("/", &publish("x", "k"), &none()).is_ok());
        assert!(r.check("/", &consume("q"), &none()).is_ok());
        let err = r
            .check("/", &declare_queue("q"), &none())
            .expect_err("configure");
        assert!(err.contains("configure"), "{err}");
        let err = r
            .check("other", &publish("x", "k"), &none())
            .expect_err("vhost");
        assert!(err.contains("vhost"), "{err}");
    }

    #[test]
    fn names_limit_what_can_be_touched() {
        let r = Rules::new(vec![grant(
            &["/"],
            &[MqClass::Read, MqClass::Write],
            &["orders.*", "events"],
        )]);
        assert!(r.check("/", &publish("orders.new", ""), &none()).is_ok());
        assert!(r.check("/", &publish("events", "k"), &none()).is_ok());
        assert!(r.check("/", &publish("payments", ""), &none()).is_err());
        // Default exchange: the routing key is the queue.
        assert!(r.check("/", &publish("", "orders.q"), &none()).is_ok());
        assert!(r.check("/", &publish("", "payments.q"), &none()).is_err());
        assert!(r.check("/", &consume("orders.q"), &none()).is_ok());
        assert!(r.check("/", &consume("billing"), &none()).is_err());
    }

    #[test]
    fn a_star_never_opens_the_brokers_own_names_but_standard_exchanges_work() {
        let r = Rules::new(vec![grant(
            &[],
            &[MqClass::Read, MqClass::Write, MqClass::Configure],
            &["*"],
        )]);
        assert!(r.check("/", &publish("amq.topic", "k"), &none()).is_ok());
        assert!(
            r.check("/", &consume("amq.rabbitmq.trace"), &none())
                .is_err()
        );
        let bind = inspect(
            ids::QUEUE,
            20,
            &Out::new()
                .u16(0)
                .shortstr("mine")
                .shortstr("amq.rabbitmq.trace")
                .shortstr("#")
                .u8(0)
                .u32(0)
                .finish(),
        )
        .expect("bind");
        assert!(
            r.check("/", &bind, &none()).is_err(),
            "no tapping the firehose"
        );
        let open = Rules::new(vec![grant(&[], &[MqClass::Read], &[])]);
        assert!(
            open.check("/", &consume("amq.rabbitmq.trace"), &none())
                .is_err()
        );
        let explicit = Rules::new(vec![grant(&[], &[MqClass::Read], &["amq.rabbitmq.*"])]);
        assert!(
            explicit
                .check("/", &consume("amq.rabbitmq.trace"), &none())
                .is_ok()
        );
    }

    #[test]
    fn rpc_reply_queues_and_the_sessions_own_queues_are_always_usable() {
        let r = Rules::new(vec![grant(
            &[],
            &[MqClass::Read, MqClass::Write],
            &["orders.*"],
        )]);
        assert!(
            r.check("/", &consume("amq.rabbitmq.reply-to"), &none())
                .is_ok()
        );
        assert!(
            r.check("/", &publish("", "amq.rabbitmq.reply-to.g2dkABC"), &none())
                .is_ok()
        );
        assert!(r.check("/", &consume("amq.gen-Xyz"), &none()).is_err());
        let owned: HashSet<String> = ["amq.gen-Xyz".to_owned()].into();
        assert!(r.check("/", &consume("amq.gen-Xyz"), &owned).is_ok());
        // "" is the queue declared last on the channel.
        assert!(r.check("/", &consume(""), &none()).is_ok());
    }

    #[test]
    fn grants_do_not_combine() {
        let r = Rules::new(vec![
            grant(&[], &[MqClass::Read], &["a.*"]),
            grant(&[], &[MqClass::Write], &["b.*"]),
        ]);
        assert!(r.check("/", &consume("a.q"), &none()).is_ok());
        assert!(r.check("/", &publish("b.x", ""), &none()).is_ok());
        assert!(
            r.check("/", &consume("b.q"), &none()).is_err(),
            "read is only on a.*"
        );
        assert!(
            r.check("/", &publish("a.x", ""), &none()).is_err(),
            "write is only on b.*"
        );
    }

    #[test]
    fn server_named_queues_need_configure_but_no_name() {
        let r = Rules::new(vec![grant(&[], &[MqClass::Configure], &["orders.*"])]);
        assert!(r.check("/", &declare_queue(""), &none()).is_ok());
        assert!(r.check("/", &declare_queue("billing"), &none()).is_err());
    }

    #[test]
    fn housekeeping_needs_no_permission() {
        let r = Rules::new(vec![grant(&[], &[MqClass::Read], &[])]);
        let open = inspect(ids::CHANNEL, 10, &[0]).expect("open");
        assert!(r.check("/", &open, &none()).is_ok());
        assert!(!open.audited);
    }

    #[test]
    fn events_carry_names_and_sizes_never_bodies() {
        let p = publish("orders", "new");
        let data = audit_data(&p, "mq-staging", "limen-app", "/", 3, Some(42));
        assert_eq!(data["action"], "publish");
        assert_eq!(data["exchange"], "orders");
        assert_eq!(data["routing_key"], "new");
        assert_eq!(data["size"], 42);
        assert_eq!(data["channel"], 3);
        let denied = denied_data(&p, "mq-staging", "limen-app", "/", 3, "nope");
        assert_eq!(denied["action"], "mq");
        assert_eq!(denied["operation"], "publish");
        assert_eq!(denied["reason"], "nope");
    }
}
