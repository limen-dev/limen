#![no_main]
//! Kafka: the request header and the field reader, on any bytes.
use libfuzzer_sys::fuzz_target;

use limen_worker::kafka::wire::{Reader, parse_request_header};

fuzz_target!(|data: &[u8]| {
    let _ = parse_request_header(data);
    let mut r = Reader::new(data);
    let _ = r.nullable_string();
    let _ = r.nullable_bytes();
    let _ = r.array(|r| r.string());
    let mut r = Reader::new(data);
    let _ = r.skip_array(|r| r.skip_nullable_bytes());
});
