//! `--trace-sample-ratio`: at 0 no new trace is sampled, but a trace the
//! caller already sampled is kept, so a session is never half-traced.

use clap::Parser;
use limen_core::telemetry::{LogArgs, current_traceparent, set_parent_from_traceparent};

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    log: LogArgs,
}

fn flags(traceparent: &str) -> &str {
    traceparent.rsplit('-').next().expect("flags")
}

#[test]
fn ratio_zero_drops_new_traces_but_follows_a_sampled_parent() {
    let cli = Cli::parse_from([
        "x",
        "--otlp-endpoint",
        "http://127.0.0.1:1",
        "--trace-sample-ratio",
        "0",
    ]);
    let _guard = cli.log.init("limen-sampling-test");

    let root = limen_core::trace_span!("session");
    // Unsampled spans have no recording context to hand over, or hand over
    // the not-sampled flag; either way nothing is exported.
    let own = root.in_scope(current_traceparent);
    assert!(own.as_deref().is_none_or(|t| flags(t) == "00"), "{own:?}");

    let sampled_parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let child = limen_core::trace_span!("session");
    set_parent_from_traceparent(&child, sampled_parent);
    let kept = child.in_scope(current_traceparent).expect("kept");
    assert_eq!(flags(&kept), "01", "the parent's decision wins: {kept}");
}

#[test]
fn ratio_must_be_between_zero_and_one() {
    for bad in ["-0.1", "1.5", "lots"] {
        assert!(
            Cli::try_parse_from(["x", "--trace-sample-ratio", bad]).is_err(),
            "{bad}"
        );
    }
    assert!(Cli::try_parse_from(["x", "--trace-sample-ratio", "0.25"]).is_ok());
}
