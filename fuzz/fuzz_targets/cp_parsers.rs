#![no_main]
//! The control plane's pure text parsers: the audit search language, secret masking, the
//! console's date filters, notifier URLs, durations and policy source names.
use libfuzzer_sys::fuzz_target;
use time::OffsetDateTime;

use limen_control_plane::access::notify::validate_url;
use limen_control_plane::config::{parse_duration, parse_duration_or_zero};
use limen_control_plane::console::query_fuzz;
use limen_control_plane::policy_store::validate_source;
use limen_control_plane::search::{mask, query};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let now = OffsetDateTime::UNIX_EPOCH;
    if let Ok(q) = query::parse(text, now) {
        let _ = q.is_empty();
    }
    let _ = query::like_pattern(text);
    let masked = mask::mask(text);
    assert_eq!(mask::changed(text), masked != text);
    query_fuzz::dates(text);
    let _ = validate_url(text);
    let _ = parse_duration(text);
    let _ = parse_duration_or_zero(text);
    let _ = validate_source(text);
});
