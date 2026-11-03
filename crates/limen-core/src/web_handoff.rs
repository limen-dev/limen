//! Checks for the values a browser carries through the web app sign-in
//! (`return_path`, `browser_nonce`). The control plane and the proxy both
//! apply them, so they live here and cannot drift apart.

use base64::Engine as _;

/// Longest accepted return path, query included.
pub const MAX_RETURN_PATH: usize = 4096;

/// A browser nonce is 32 random bytes, base64url without padding.
#[must_use]
pub fn valid_browser_nonce(nonce: &str) -> bool {
    nonce.len() <= 128
        && base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(nonce)
            .is_ok_and(|bytes| bytes.len() == 32)
}

/// A same-host absolute path with an optional query: no scheme or authority,
/// no `//`, no dot segments, no escapes or backslashes in the path, no
/// fragment, and only printable ASCII.
#[must_use]
pub fn valid_return_path(path: &str) -> bool {
    if path.len() > MAX_RETURN_PATH || !path.bytes().all(|b| b.is_ascii_graphic()) {
        return false;
    }
    let (route, query) = path
        .split_once('?')
        .map_or((path, None), |(r, q)| (r, Some(q)));
    route.starts_with('/')
        && !route.contains("//")
        && route
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b))
        && route
            .split('/')
            .all(|segment| segment != "." && segment != "..")
        && query.is_none_or(|q| !q.bytes().any(|b| b"#\"<>\\^`{|}".contains(&b)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_paths_stay_on_the_app_host() {
        for ok in [
            "/",
            "/app",
            "/a/b-c_d.e~f",
            "/app?next=/x&y=1",
            "/app?next=//x",
            "/a?",
        ] {
            assert!(valid_return_path(ok), "{ok} should be accepted");
        }
        for bad in [
            "",
            "app",
            "//evil.example",
            "///evil.example",
            "/a//b",
            "https://evil.example/",
            "http://evil.example",
            "javascript:alert(1)",
            "?x=1",
            "/\\evil.example",
            "/a\\b",
            "/a/../b",
            "/a/./b",
            "/..",
            "/a%2e%2e/b",
            "/a%2Fb",
            "/a#frag",
            "/a?x#frag",
            "/a?x=\"y",
            "/a b",
            "/a\tb",
            "/a\nb",
            "/caf\u{e9}",
            "/%0d%0aSet-Cookie:x=1",
        ] {
            assert!(!valid_return_path(bad), "{bad:?} should be rejected");
        }
        assert!(valid_return_path(&format!(
            "/{}",
            "a".repeat(MAX_RETURN_PATH - 1)
        )));
        assert!(!valid_return_path(&format!(
            "/{}",
            "a".repeat(MAX_RETURN_PATH)
        )));
    }

    #[test]
    fn browser_nonces_are_exactly_32_url_safe_bytes() {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        assert!(valid_browser_nonce(&engine.encode([7u8; 32])));
        assert!(!valid_browser_nonce(&engine.encode([7u8; 31])));
        assert!(!valid_browser_nonce(&engine.encode([7u8; 33])));
        assert!(!valid_browser_nonce(""));
        assert!(!valid_browser_nonce(&"A".repeat(200)));
        // Padding and the standard alphabet are not the format we issue.
        assert!(!valid_browser_nonce(&format!(
            "{}=",
            engine.encode([7u8; 32])
        )));
        assert!(!valid_browser_nonce(
            &base64::engine::general_purpose::STANDARD.encode([0xfbu8; 32])
        ));
    }
}
