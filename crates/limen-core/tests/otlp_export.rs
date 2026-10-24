//! OTLP export against a stand-in collector (a socket that records the POST).
//! Not verified against a real collector or Datadog Agent.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use clap::Parser;
use limen_core::telemetry::LogArgs;

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    log: LogArgs,
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[test]
fn exports_only_trace_spans_with_resource_attributes() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let collector = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        conn.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let mut raw = Vec::new();
        let mut buf = [0u8; 8192];
        // Read until the headers and the whole body have arrived.
        loop {
            let n = conn.read(&mut buf).expect("read");
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
                let len = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if raw.len() >= end + 4 + len {
                    break;
                }
            }
        }
        conn.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .ok();
        raw
    });

    let cli = Cli::parse_from([
        "x",
        "--otlp-endpoint",
        &format!("http://127.0.0.1:{port}"),
        "--trace-environment",
        "test",
    ]);
    let guard = cli.log.init("limen-test");
    {
        let span = limen_core::trace_span!("session.open", kind = "ssh");
        let _in = span.enter();
        tracing::info!(note = "event-must-not-export", "a log event");
    }
    let plain = tracing::info_span!("plain-span-must-not-export");
    drop(plain.enter());
    drop(guard); // flushes

    let raw = collector.join().expect("collector");
    let text = String::from_utf8_lossy(&raw);
    assert!(text.starts_with("POST /v1/traces "), "{text}");
    assert!(contains(&raw, "session.open"));
    assert!(contains(&raw, "limen-test"));
    assert!(contains(&raw, "deployment.environment"));
    assert!(!contains(&raw, "event-must-not-export"));
    assert!(!contains(&raw, "plain-span-must-not-export"));
}
