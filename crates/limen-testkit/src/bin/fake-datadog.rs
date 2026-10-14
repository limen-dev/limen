//! Fake Datadog Logs intake for the local dev stack. Accepts any API key
//! unless `FAKE_DD_API_KEY` is set.

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let intake = std::sync::Arc::new(limen_testkit::fake_datadog::Intake::default());
    if let Ok(key) = std::env::var("FAKE_DD_API_KEY") {
        *intake
            .api_key
            .lock()
            .map_err(|_| std::io::Error::other("lock"))? = Some(key);
    }
    let addr = std::env::var("FAKE_DD_LISTEN").unwrap_or_else(|_| "0.0.0.0:8126".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    eprintln!("fake Datadog intake listening on {addr}");
    axum::serve(listener, limen_testkit::fake_datadog::router(intake)).await
}
