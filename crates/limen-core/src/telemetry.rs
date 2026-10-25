//! Process-wide tracing setup shared by all binaries: structured logs, and
//! optional OTLP trace export (ADR-0011, ADR-0040).
//!
//! Only spans created with [`trace_span!`] are exported. Ordinary log events
//! and spans never leave the process through OTLP, so a field added to a log
//! line cannot leak into a trace backend by accident.

use clap::{Args, ValueEnum};
use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{Protocol, SpanExporter, WithExportConfig as _, WithHttpConfig as _};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer as _, fmt};

/// `tracing` target of every span that is exported over OTLP.
pub const TRACE_TARGET: &str = "limen::trace";

/// The W3C `traceparent` of the current span, when it is being exported.
///
/// Carries only trace and span ids and the sampled flag, never `tracestate`
/// or baggage, so nothing else crosses a component boundary with it.
#[must_use]
pub fn current_traceparent() -> Option<String> {
    use opentelemetry::propagation::TextMapPropagator as _;
    use opentelemetry::trace::TraceContextExt as _;
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;

    let cx = tracing::Span::current().context();
    if !cx.span().span_context().is_valid() {
        return None;
    }
    let mut carrier = std::collections::HashMap::new();
    TraceContextPropagator::new().inject_context(&cx, &mut carrier);
    carrier.remove("traceparent")
}

/// Make `span` a child of the remote span named by `traceparent`.
///
/// Ignores an empty, oversized or malformed value: a peer can only choose
/// which trace this span is filed under, nothing else.
pub fn set_parent_from_traceparent(span: &tracing::Span, traceparent: &str) {
    use opentelemetry::propagation::TextMapPropagator as _;
    use opentelemetry::trace::TraceContextExt as _;
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;

    // A version 00 traceparent is exactly 55 bytes.
    if traceparent.len() != 55 {
        return;
    }
    let carrier =
        std::collections::HashMap::from([("traceparent".to_owned(), traceparent.to_owned())]);
    let cx = TraceContextPropagator::new().extract(&carrier);
    if cx.span().span_context().is_valid() {
        let _ = span.set_parent(cx);
    }
}

/// Open a span that is exported over OTLP when tracing is on.
///
/// Attach only identifiers and outcomes (session id, resource kind, result).
/// Never a user name, claim, token, statement, path, or payload: traces go to
/// a third-party backend (ADR-0040).
#[macro_export]
macro_rules! trace_span {
    ($name:expr $(, $($fields:tt)*)?) => {
        ::tracing::info_span!(target: $crate::telemetry::TRACE_TARGET, $name $(, $($fields)*)?)
    };
}

/// Logging flags shared by every server binary, so they are configured the same way.
///
/// Levels: `error` is a failure that needs an operator, `warn` a degraded or
/// rejected-but-handled condition, `info` lifecycle events, `debug` per-request
/// detail, `trace` wire-level detail. `RUST_LOG`, when set, overrides `--log-level`.
/// Never log a credential: wrap it in `limen_core::secret::Secret`.
#[derive(Debug, Clone, Args)]
pub struct LogArgs {
    /// Log verbosity (a `tracing` filter such as `info` or `info,h2=debug`).
    #[arg(long, env = "LIMEN_LOG_LEVEL", default_value = "info")]
    pub log_level: String,

    /// Log output format.
    #[arg(long, env = "LIMEN_LOG_FORMAT", value_enum)]
    pub log_format: Option<LogFormat>,

    /// Deprecated alias for `--log-format json`.
    #[arg(long, env = "LIMEN_LOG_JSON", hide = true)]
    pub log_json: bool,

    /// Export traces over OTLP/HTTP to this collector base URL, for example
    /// `http://localhost:4318` (a Datadog Agent or OpenTelemetry collector).
    /// Unset: no traces are exported.
    #[arg(long, env = "LIMEN_OTLP_ENDPOINT")]
    pub otlp_endpoint: Option<String>,

    /// PEM file with the CA that signed the collector's certificate, for an
    /// `https://` endpoint on a private CA. Added to the system roots.
    #[arg(long, env = "LIMEN_OTLP_CA_FILE")]
    pub otlp_ca_file: Option<std::path::PathBuf>,

    /// Share of new traces to export, 0 to 1. A trace that a peer already
    /// sampled (the proxy's session, seen by the worker) is always kept.
    /// Lower it where the control plane's steady stream of calls costs too much.
    #[arg(
        long,
        env = "LIMEN_TRACE_SAMPLE_RATIO",
        default_value_t = 1.0,
        value_parser = parse_ratio
    )]
    pub trace_sample_ratio: f64,

    /// Deployment environment tag on exported traces (`deployment.environment`).
    /// Shares `LIMEN_ENVIRONMENT` with the control plane's `--environment`.
    #[arg(
        long = "trace-environment",
        env = "LIMEN_ENVIRONMENT",
        default_value = "dev"
    )]
    pub trace_environment: String,
}

impl LogArgs {
    /// The effective format: `--log-format` wins over the legacy `--log-json`.
    #[must_use]
    pub fn format(&self) -> LogFormat {
        self.log_format.unwrap_or(if self.log_json {
            LogFormat::Json
        } else {
            LogFormat::Text
        })
    }

    /// Install the global subscriber from these flags, exporting traces when
    /// `--otlp-endpoint` is set. Keep the guard alive until exit: dropping it
    /// flushes pending spans.
    pub fn init(&self, service: &'static str) -> TelemetryGuard {
        let provider = self
            .otlp_endpoint
            .as_deref()
            .filter(|e| !e.is_empty())
            .and_then(|endpoint| {
                match build_provider(
                    endpoint,
                    service,
                    &self.trace_environment,
                    self.trace_sample_ratio,
                    self.otlp_ca_file.as_deref(),
                ) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        // Tracing is best effort: never stop the service for it.
                        eprintln!("tracing disabled: cannot set up the OTLP exporter: {e}");
                        None
                    }
                }
            });
        install(
            self.format(),
            &self.log_level,
            provider.as_ref().map(|p| p.tracer(service)),
        );
        TelemetryGuard { provider }
    }
}

/// Flushes and stops trace export on drop.
#[must_use = "dropping the guard stops trace export"]
pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

impl std::fmt::Debug for TelemetryGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelemetryGuard")
            .field("exporting", &self.provider.is_some())
            .finish()
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(p) = self.provider.take() {
            let _ = p.shutdown();
        }
    }
}

fn parse_ratio(raw: &str) -> Result<f64, String> {
    match raw.parse::<f64>() {
        Ok(r) if (0.0..=1.0).contains(&r) => Ok(r),
        _ => Err(format!("{raw:?} is not a number from 0 to 1")),
    }
}

fn build_provider(
    endpoint: &str,
    service: &'static str,
    environment: &str,
    sample_ratio: f64,
    ca_file: Option<&std::path::Path>,
) -> Result<SdkTracerProvider, Box<dyn std::error::Error>> {
    let builder = SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(traces_url(endpoint));
    let exporter = match ca_file {
        Some(path) => builder.with_http_client(client_trusting(path)?),
        None => builder,
    }
    .build()?;
    let resource = Resource::builder()
        .with_service_name(service)
        .with_attributes([
            KeyValue::new("service.version", crate::VERSION),
            KeyValue::new("deployment.environment", environment.to_owned()),
            // Tells replicas of one service apart.
            KeyValue::new("service.instance.id", uuid::Uuid::new_v4().to_string()),
        ])
        .build();
    Ok(SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            sample_ratio,
        ))))
        .build())
}

/// A blocking HTTP client that also trusts the CA in `path`.
fn client_trusting(
    path: &std::path::Path,
) -> Result<reqwest::blocking::Client, Box<dyn std::error::Error>> {
    let pem = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let ca = reqwest::Certificate::from_pem(&pem)
        .map_err(|e| format!("{} is not a PEM certificate: {e}", path.display()))?;
    // A blocking client cannot be built (or dropped) on an async runtime thread.
    std::thread::Builder::new()
        .spawn(move || {
            reqwest::blocking::Client::builder()
                .add_root_certificate(ca)
                .build()
        })?
        .join()
        .map_err(|_| "the HTTP client thread panicked")?
        .map_err(Into::into)
}

/// The collector's trace path under a base URL like `http://host:4318`.
fn traces_url(base: &str) -> String {
    let base = base.trim_end_matches('/');
    if base.ends_with("/v1/traces") {
        base.to_owned()
    } else {
        format!("{base}/v1/traces")
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    /// Human-readable, for local development.
    #[default]
    Text,
    /// One JSON object per line, for production log shipping.
    Json,
}

/// Install the global tracing subscriber. Respects `RUST_LOG`, defaulting to `info`.
///
/// Calling it more than once is harmless: later calls are ignored.
pub fn init(format: LogFormat) {
    init_with_default(format, "info");
}

/// Like [`init`], with a different default filter when `RUST_LOG` is unset.
pub fn init_with_default(format: LogFormat, default_filter: &str) {
    install(format, default_filter, None);
}

type Tracer = opentelemetry_sdk::trace::Tracer;

fn install(format: LogFormat, default_filter: &str, tracer: Option<Tracer>) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    let logs = match format {
        LogFormat::Text => fmt::layer().with_writer(std::io::stderr).boxed(),
        LogFormat::Json => fmt::layer()
            .json()
            .flatten_event(true)
            .with_writer(std::io::stderr)
            .boxed(),
    }
    .with_filter(filter);
    // Spans only, and only ours: see the module docs.
    let otel = tracer.map(|t| {
        use tracing_subscriber::filter::Targets;
        // `Targets` answers per callsite, so tracing caches the decision
        // exactly. Nothing logs events with this target; `trace_span!` is the
        // only way in.
        let ours = Targets::new().with_target(TRACE_TARGET, tracing::Level::TRACE);
        tracing_opentelemetry::layer()
            .with_tracer(t)
            .with_filter(ours)
    });
    let _ = tracing_subscriber::registry()
        .with(logs)
        .with(otel)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        log: LogArgs,
    }

    #[test]
    fn traces_url_appends_the_path_once() {
        assert_eq!(traces_url("http://a:4318"), "http://a:4318/v1/traces");
        assert_eq!(traces_url("http://a:4318/"), "http://a:4318/v1/traces");
        assert_eq!(traces_url("http://a/v1/traces"), "http://a/v1/traces");
    }

    #[test]
    fn tracing_is_off_by_default() {
        let cli = Cli::parse_from(["x"]);
        assert!(cli.log.otlp_endpoint.is_none());
    }

    #[test]
    fn defaults_to_info_text() {
        let cli = Cli::parse_from(["x"]);
        assert_eq!(cli.log.log_level, "info");
        assert_eq!(cli.log.format(), LogFormat::Text);
    }

    #[test]
    fn format_flag_beats_legacy_json_flag() {
        let cli = Cli::parse_from(["x", "--log-json"]);
        assert_eq!(cli.log.format(), LogFormat::Json);
        let cli = Cli::parse_from(["x", "--log-json", "--log-format", "text"]);
        assert_eq!(cli.log.format(), LogFormat::Text);
    }
}
