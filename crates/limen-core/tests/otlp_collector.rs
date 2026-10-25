//! Sends one span to a real collector. Runs only when `LIMEN_TEST_OTLP_ENDPOINT`
//! is set (for example `http://localhost:4318` for Jaeger or an OpenTelemetry
//! collector); otherwise it prints SKIPPED. Check the backend for service
//! `limen-collector-test`.

use clap::Parser;
use limen_core::telemetry::LogArgs;

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    log: LogArgs,
}

#[test]
fn sends_a_span_to_a_real_collector() {
    let Ok(endpoint) = std::env::var("LIMEN_TEST_OTLP_ENDPOINT") else {
        eprintln!("SKIPPED: set LIMEN_TEST_OTLP_ENDPOINT to run against a collector");
        return;
    };
    let cli = Cli::parse_from(["x", "--otlp-endpoint", &endpoint]);
    let guard = cli.log.init("limen-collector-test");
    {
        let span = limen_core::trace_span!("collector.check", kind = "ssh");
        let _in = span.enter();
    }
    drop(guard);
}
