//! Static files, embedded in the binary. The console serves nothing from
//! disk and loads nothing from other origins.

use axum::extract::Path;
use axum::http::StatusCode;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};

const FILES: &[(&str, &str, &[u8])] = &[
    (
        "console.css",
        "text/css; charset=utf-8",
        include_bytes!("../../assets/console.css"),
    ),
    (
        "player-init.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../../assets/player-init.js"),
    ),
    (
        "logo-mark.svg",
        "image/svg+xml",
        include_bytes!("../../assets/logo-mark.svg"),
    ),
    (
        "asciinema-player.min.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../../assets/vendor/asciinema-player.min.js"),
    ),
    (
        "asciinema-player.css",
        "text/css; charset=utf-8",
        include_bytes!("../../assets/vendor/asciinema-player.css"),
    ),
];

pub async fn serve(Path(name): Path<String>) -> Response {
    match FILES.iter().find(|(n, _, _)| *n == name) {
        Some((_, content_type, body)) => (
            [
                (CONTENT_TYPE, *content_type),
                // Changes ship with a new release; an hour keeps pages quick.
                (CACHE_CONTROL, "public, max-age=3600"),
            ],
            *body,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
