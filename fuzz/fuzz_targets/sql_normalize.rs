#![no_main]
//! SQL audit text: `split` and `normalize` on any text, and a string literal's
//! content must not survive `normalize` (ADR-0033 amendment, 2026-11-12).
use libfuzzer_sys::fuzz_target;
use limen_worker::db::sqltext::{Flavor, normalize, split};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    for flavor in [Flavor::Postgres, Flavor::Mysql] {
        // Must not panic, whatever the text.
        let _ = split(&text, flavor);
        let _ = normalize(&text, flavor);

        // A quoted body made of the input, without anything that ends or
        // escapes the quote, is a literal in both dialects.
        let body: String = text
            .chars()
            .filter(|c| !matches!(c, '\'' | '\\' | '\0') && !c.is_control())
            .collect();
        let body = format!("zq9{body}");
        let out = normalize(&format!("select '{body}'"), flavor);
        assert!(!out.contains(&body), "{flavor:?}: {body:?} -> {out:?}");
    }
});
