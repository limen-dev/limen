//! Static files, embedded in the binary. The console serves nothing from
//! disk and loads nothing from other origins.

use axum::extract::{Path, Query};
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
        "console.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../../assets/console.js"),
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
        "logo-mark-dark.svg",
        "image/svg+xml",
        include_bytes!("../../assets/logo-mark-dark.svg"),
    ),
    (
        "icons.svg",
        "image/svg+xml",
        include_bytes!("../../assets/icons.svg"),
    ),
    (
        "inter-latin-wght-normal.woff2",
        "font/woff2",
        include_bytes!("../../assets/vendor/fonts/inter-latin-wght-normal.woff2"),
    ),
    (
        "jetbrains-mono-latin-wght-normal.woff2",
        "font/woff2",
        include_bytes!("../../assets/vendor/fonts/jetbrains-mono-latin-wght-normal.woff2"),
    ),
    (
        "review-init.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../../assets/review-init.js"),
    ),
    (
        "watch-init.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../../assets/watch-init.js"),
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

/// A fingerprint of every embedded file. Pages reference assets as
/// `…?v=<this>`, so a release that changes any file changes every URL and no
/// browser pairs new HTML with an old stylesheet.
pub fn version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for (name, _, body) in FILES {
            hasher.update(name.as_bytes());
            hasher.update(body);
        }
        hasher
            .finalize()
            .iter()
            .take(6)
            .fold(String::new(), |mut s, b| {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
                s
            })
    })
}

#[derive(serde::Deserialize)]
pub struct Versioned {
    v: Option<String>,
}

pub async fn serve(Path(name): Path<String>, Query(q): Query<Versioned>) -> Response {
    match FILES.iter().find(|(n, _, _)| *n == name) {
        Some((_, content_type, body)) => (
            [
                (CONTENT_TYPE, *content_type),
                // A URL carrying the current fingerprint never changes meaning.
                // Anything else (fonts named from CSS) is rechecked hourly.
                (
                    CACHE_CONTROL,
                    if q.v.as_deref() == Some(version()) {
                        "public, max-age=31536000, immutable"
                    } else {
                        "public, max-age=3600"
                    },
                ),
            ],
            *body,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    const CSS: &str = include_str!("../../assets/console.css");
    const WATCH: &str = include_str!("../../templates/watch.html");

    /// The text of the last `prefers-reduced-motion` block, which must be the global one.
    fn global_reduced_motion_block() -> &'static str {
        let at = CSS
            .rfind("@media (prefers-reduced-motion: reduce) {\n")
            .expect("console.css has a reduced-motion block");
        &CSS[at..]
    }

    #[test]
    fn reduced_motion_ends_every_animation_and_transition() {
        let block = global_reduced_motion_block();
        for needle in [
            "animation-duration: .01ms !important",
            "animation-iteration-count: 1 !important",
            "transition-duration: .01ms !important",
            "scroll-behavior: auto !important",
            "@view-transition { navigation: none; }",
            "::before",
            "::after",
        ] {
            assert!(
                block.contains(needle),
                "the reduced-motion block lost `{needle}`"
            );
        }
        // The vendored player is excluded, with its own pseudo-elements' parents.
        assert!(block.contains(":not(.ap-player, .ap-player *)"));
    }

    #[test]
    fn the_sidebar_scroll_cue_is_defined_for_both_themes() {
        // One shadow colour per theme block (light, dark, and dark by system preference).
        assert_eq!(CSS.matches("--nav-shadow:").count(), 3);
        // The cue exists for the sidebar and for the phone strip.
        assert!(CSS.matches("no-repeat local").count() >= 4);
    }

    #[test]
    fn view_transitions_come_before_the_reduced_motion_override() {
        let on = CSS
            .find("@view-transition { navigation: auto; }")
            .expect("page changes cross-fade");
        let off = CSS
            .rfind("@view-transition { navigation: none; }")
            .expect("reduced motion turns them off");
        assert!(on < off, "the override must come later in the cascade");
        // The sidebar stays put while the content fades.
        assert!(CSS.contains("view-transition-name: sidebar"));
    }

    #[test]
    fn the_watch_state_is_announced() {
        assert!(WATCH.contains("id=\"watch-state\" role=\"status\""));
    }
}
