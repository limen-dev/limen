//! Telling people a request needs them (ADR-0025). Notifiers **notify and
//! link to the console; they never carry an approval**: whoever approves does
//! it inside an authenticated Limen session, so the approver's identity is
//! always proven by the IdP login. By default a message names the request id
//! and a console link only, so resource names don't leave Limen.
//!
//! Delivery is best effort and never blocks or fails the action: a bounded
//! queue feeds one task that retries a few times, and a full queue drops the
//! message and counts it. The audit trail, not the notifier, is the record.

use std::time::Duration;

use aws_lc_rs::hmac;
use serde_json::json;
use tokio::sync::mpsc;

use limen_core::secret::Secret;

/// How many messages wait for delivery before new ones are dropped.
const QUEUE: usize = 256;
const ATTEMPTS: u32 = 3;
const TIMEOUT: Duration = Duration::from_secs(5);

/// Where a message goes.
#[derive(Debug, Clone)]
pub enum Target {
    /// A signed JSON POST (`X-Limen-Signature: sha256=<hmac>`).
    Webhook {
        url: Secret<String>,
        secret: Option<Secret<String>>,
    },
    /// A Slack incoming webhook. The URL is the credential.
    Slack { url: Secret<String> },
}

impl Target {
    fn name(&self) -> &'static str {
        match self {
            Target::Webhook { .. } => "webhook",
            Target::Slack { .. } => "slack",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct NotifyConfig {
    pub targets: Vec<Target>,
    /// Extra targets for break-glass grants, on top of `targets`.
    pub break_glass_targets: Vec<Target>,
    /// Put the requester, role, resource, and reason in the message.
    pub include_details: bool,
}

impl NotifyConfig {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty() && self.break_glass_targets.is_empty()
    }
}

/// What happened, as far as a notifier is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A request is waiting for approvers.
    Requested,
    Approved,
    Denied,
    /// A break-glass grant was made. Critical.
    BreakGlass,
    /// An admin ended a grant early.
    Revoked,
    /// Access review items are waiting for their reviewer.
    ReviewDue,
}

impl Event {
    fn name(self) -> &'static str {
        match self {
            Event::Requested => "access.requested",
            Event::Approved => "access.approved",
            Event::Denied => "access.denied",
            Event::BreakGlass => "access.break_glass",
            Event::Revoked => "access.revoked",
            Event::ReviewDue => "review.due",
        }
    }

    fn headline(self) -> &'static str {
        match self {
            Event::Requested => "needs approval",
            Event::Approved => "was approved",
            Event::Denied => "was denied",
            Event::BreakGlass => "BREAK-GLASS access was granted",
            Event::Revoked => "was revoked",
            Event::ReviewDue => "has items waiting for a reviewer",
        }
    }
}

/// The facts a message may carry. `details` are shown only if configured.
#[derive(Debug, Clone)]
pub struct Notice {
    pub event: Event,
    pub request_id: String,
    pub link: Option<String>,
    pub requester: String,
    pub role: String,
    pub resource: String,
    pub reason: String,
    pub duration_secs: u64,
}

/// Cheap to clone; sends nothing if no target is configured.
#[derive(Debug, Clone)]
pub struct Notifier {
    queue: Option<mpsc::Sender<Job>>,
    config: std::sync::Arc<NotifyConfig>,
}

#[derive(Debug)]
struct Job {
    target: Target,
    body: String,
    signed: bool,
}

impl Notifier {
    /// A notifier that does nothing.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            queue: None,
            config: std::sync::Arc::default(),
        }
    }

    /// Start the delivery task. Needs a Tokio runtime.
    pub fn start(config: NotifyConfig) -> anyhow::Result<Self> {
        if config.is_empty() {
            return Ok(Self::disabled());
        }
        let http = reqwest::Client::builder()
            // A webhook that redirects is either misconfigured or hostile.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .build()?;
        let (tx, rx) = mpsc::channel(QUEUE);
        tokio::spawn(deliver(http, rx));
        Ok(Self {
            queue: Some(tx),
            config: std::sync::Arc::new(config),
        })
    }

    /// Queue a message for every target that wants it. Never blocks.
    pub fn send(&self, notice: &Notice) {
        let Some(queue) = &self.queue else { return };
        let critical = notice.event == Event::BreakGlass;
        let targets = self
            .config
            .targets
            .iter()
            .chain(self.config.break_glass_targets.iter().filter(|_| critical));
        for target in targets {
            let (body, signed) = match target {
                Target::Webhook { secret, .. } => (
                    webhook_body(notice, self.config.include_details),
                    secret.is_some(),
                ),
                Target::Slack { .. } => (slack_body(notice, self.config.include_details), false),
            };
            let job = Job {
                target: target.clone(),
                body,
                signed,
            };
            if queue.try_send(job).is_err() {
                metrics::counter!("limen_notifications_total", "notifier" => target.name(), "outcome" => "dropped")
                    .increment(1);
                tracing::warn!(
                    notifier = target.name(),
                    "notification queue is full; dropping a message"
                );
            }
        }
    }
}

fn webhook_body(n: &Notice, details: bool) -> String {
    let mut v = json!({
        "version": 1,
        "event": n.event.name(),
        "severity": if n.event == Event::BreakGlass { "critical" } else { "info" },
        "request_id": n.request_id,
        "link": n.link,
        "time": time::OffsetDateTime::now_utc().unix_timestamp(),
    });
    if details {
        v["requester"] = json!(n.requester);
        v["role"] = json!(n.role);
        v["resource"] = json!(n.resource);
        v["reason"] = json!(n.reason);
        v["duration_secs"] = json!(n.duration_secs);
    }
    v.to_string()
}

fn slack_body(n: &Notice, details: bool) -> String {
    let link = n
        .link
        .as_deref()
        .map_or_else(String::new, |l| format!(" <{l}|Open in Limen>"));
    let text = if details {
        format!(
            "Access request `{}` {}: {} wants `{}` on `{}` for {}s. Reason: {}.{link}",
            n.request_id,
            n.event.headline(),
            slack_escape(&n.requester),
            slack_escape(&n.role),
            slack_escape(&n.resource),
            n.duration_secs,
            slack_escape(&n.reason),
        )
    } else {
        format!(
            "Access request `{}` {}.{link}",
            n.request_id,
            n.event.headline()
        )
    };
    let text = if n.event == Event::BreakGlass {
        format!(":rotating_light: {text}")
    } else {
        text
    };
    json!({ "text": text }).to_string()
}

/// Slack treats `&`, `<` and `>` as markup, and a reason is free text.
fn slack_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

async fn deliver(http: reqwest::Client, mut rx: mpsc::Receiver<Job>) {
    while let Some(job) = rx.recv().await {
        let notifier = job.target.name();
        let mut outcome = "failed";
        for attempt in 1..=ATTEMPTS {
            match post(&http, &job).await {
                Ok(()) => {
                    outcome = "sent";
                    break;
                }
                Err(e) => {
                    // The URL is a credential: never in the log.
                    tracing::warn!(notifier, attempt, error = %e.without_url(), "notification failed");
                    tokio::time::sleep(Duration::from_millis(250 * u64::from(attempt))).await;
                }
            }
        }
        metrics::counter!("limen_notifications_total", "notifier" => notifier, "outcome" => outcome)
            .increment(1);
    }
}

async fn post(http: &reqwest::Client, job: &Job) -> Result<(), reqwest::Error> {
    let (url, secret) = match &job.target {
        Target::Webhook { url, secret } => (url.expose(), secret.as_ref()),
        Target::Slack { url } => (url.expose(), None),
    };
    let mut request = http
        .post(url.as_str())
        .header("content-type", "application/json")
        .body(job.body.clone());
    if job.signed
        && let Some(secret) = secret
    {
        let timestamp = time::OffsetDateTime::now_utc().unix_timestamp().to_string();
        request = request.header("x-limen-timestamp", &timestamp).header(
            "x-limen-signature",
            format!(
                "sha256={}",
                signature(secret.expose().as_bytes(), &timestamp, &job.body)
            ),
        );
    }
    request.send().await?.error_for_status().map(|_| ())
}

/// `HMAC-SHA256(secret, timestamp "." body)` as lower-case hex. Receivers
/// check the timestamp is recent to reject replays.
#[must_use]
pub fn signature(secret: &[u8], timestamp: &str, body: &str) -> String {
    use std::fmt::Write as _;
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(timestamp.as_bytes());
    ctx.update(b".");
    ctx.update(body.as_bytes());
    ctx.sign()
        .as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Reject a notifier URL that would send credentials in clear or reach
/// somewhere surprising: `https`, or `http` to loopback for development.
pub fn validate_url(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("not a URL: {e}"))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if parsed.host_str().is_some_and(is_loopback) => Ok(()),
        "http" => Err("plain http is only allowed to localhost; use https".into()),
        other => Err(format!("unsupported scheme {other:?}")),
    }
}

fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notice(event: Event) -> Notice {
        Notice {
            event,
            request_id: "0198".into(),
            link: Some("https://limen.example/console/access/0198".into()),
            requester: "alice@example.com".into(),
            role: "prod-db-readonly".into(),
            resource: "orders-prod".into(),
            reason: "INC-123 <script>".into(),
            duration_secs: 1800,
        }
    }

    #[test]
    fn by_default_a_message_names_the_request_and_a_link_only() {
        let hook: serde_json::Value =
            serde_json::from_str(&webhook_body(&notice(Event::Requested), false)).expect("json");
        assert_eq!(hook["request_id"], "0198");
        assert_eq!(hook["link"], "https://limen.example/console/access/0198");
        for leaked in ["requester", "resource", "role", "reason"] {
            assert!(hook.get(leaked).is_none(), "{leaked} leaked: {hook}");
        }
        let slack = slack_body(&notice(Event::Requested), false);
        for leaked in ["alice", "orders-prod", "prod-db-readonly", "INC-123"] {
            assert!(!slack.contains(leaked), "{leaked} leaked: {slack}");
        }
        assert!(slack.contains("0198") && slack.contains("Open in Limen"));
    }

    #[test]
    fn details_are_opt_in_and_slack_markup_is_escaped() {
        let hook: serde_json::Value =
            serde_json::from_str(&webhook_body(&notice(Event::Requested), true)).expect("json");
        assert_eq!(hook["resource"], "orders-prod");
        let slack = slack_body(&notice(Event::Requested), true);
        assert!(slack.contains("INC-123 &lt;script&gt;"), "{slack}");
        assert!(!slack.contains("<script>"));
    }

    #[test]
    fn break_glass_is_critical() {
        let hook: serde_json::Value =
            serde_json::from_str(&webhook_body(&notice(Event::BreakGlass), false)).expect("json");
        assert_eq!(hook["severity"], "critical");
        assert!(slack_body(&notice(Event::BreakGlass), false).contains("rotating_light"));
    }

    #[test]
    fn signature_matches_an_independent_hmac() {
        // RFC 4231 test case 2 for HMAC-SHA256, through the same primitive,
        // with the signed string being "Jefe" over "what do ya want for nothing?".
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"Jefe");
        let tag = hmac::sign(&key, b"what do ya want for nothing?");
        let hex = tag.as_ref().iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        });
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // And the framing: timestamp, a dot, the body.
        let a = signature(b"k", "100", "{}");
        assert_eq!(a.len(), 64);
        assert_ne!(a, signature(b"k", "101", "{}"), "the timestamp is signed");
        assert_ne!(a, signature(b"k", "100", "{ }"), "the body is signed");
        assert_ne!(a, signature(b"other", "100", "{}"), "the key matters");
    }

    #[test]
    fn urls_must_be_https_or_loopback() {
        assert!(validate_url("https://hooks.slack.com/services/T/B/x").is_ok());
        assert!(validate_url("http://127.0.0.1:9000/hook").is_ok());
        assert!(validate_url("http://localhost/hook").is_ok());
        assert!(validate_url("http://[::1]/hook").is_ok());
        assert!(validate_url("http://example.com/hook").is_err());
        assert!(validate_url("ftp://example.com/").is_err());
        assert!(validate_url("not a url").is_err());
    }

    #[tokio::test]
    async fn a_disabled_notifier_accepts_messages_and_does_nothing() {
        Notifier::disabled().send(&notice(Event::Requested));
        assert!(
            Notifier::start(NotifyConfig::default())
                .expect("start")
                .queue
                .is_none()
        );
    }
}
