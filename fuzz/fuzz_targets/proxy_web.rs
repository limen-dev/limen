#![no_main]
//! The proxy's web-app request checks on any bytes: the `Host` authority, the request URI,
//! `Cookie` headers and identity text going into a header value.
use libfuzzer_sys::fuzz_target;

use limen_proxy::web_fuzz;

fuzz_target!(|data: &[u8]| {
    web_fuzz::request_parts(data, 8443);
});
