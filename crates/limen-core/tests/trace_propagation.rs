//! W3C trace context across a component boundary: a span in one "process"
//! hands its `traceparent` over, and the span the other side opens joins the
//! same trace.

use clap::Parser;
use limen_core::telemetry::{LogArgs, current_traceparent, set_parent_from_traceparent};

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    log: LogArgs,
}

fn trace_id(traceparent: &str) -> &str {
    traceparent.split('-').nth(1).expect("trace id")
}

#[test]
fn child_span_joins_the_parents_trace() {
    // Nothing listens here: export fails quietly, ids are still generated.
    let cli = Cli::parse_from(["x", "--otlp-endpoint", "http://127.0.0.1:1"]);
    let _guard = cli.log.init("limen-propagation-test");

    assert!(current_traceparent().is_none(), "no span, no traceparent");

    let proxy_span = limen_core::trace_span!("session");
    let sent = proxy_span
        .in_scope(current_traceparent)
        .expect("a traceparent inside an exported span");
    assert_eq!(sent.len(), 55, "{sent}");
    assert!(sent.starts_with("00-"), "{sent}");

    let worker_span = limen_core::trace_span!("session");
    set_parent_from_traceparent(&worker_span, &sent);
    let received = worker_span.in_scope(current_traceparent).expect("worker");
    assert_eq!(trace_id(&received), trace_id(&sent), "same trace");
    assert_ne!(received, sent, "but its own span");

    // Garbage is ignored: the span keeps its own trace.
    for bad in ["", "garbage", &"x".repeat(55), &sent[..54]] {
        let span = limen_core::trace_span!("session");
        set_parent_from_traceparent(&span, bad);
        let own = span.in_scope(current_traceparent).expect("own");
        assert_ne!(trace_id(&own), trace_id(&sent), "{bad:?}");
    }

    // A span that is not exported has no context to hand over.
    let plain = tracing::info_span!("plain");
    assert!(plain.in_scope(current_traceparent).is_none());
}
