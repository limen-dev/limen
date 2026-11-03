#![no_main]
//! AMQP 0-9-1: frame parsing and the field reader, on any bytes.
use libfuzzer_sys::fuzz_target;

use limen_worker::amqp::codec::{Args, parse_frame};

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    while let Ok(Some((frame, used))) = parse_frame(rest, 1 << 16) {
        assert!(used > 0 && used <= rest.len(), "a frame that consumes nothing or too much");
        let _ = frame.as_method();
        let _ = frame.body_size();
        rest = &rest[used..];
    }
    let mut r = Args::new(data);
    let _ = r.shortstr();
    let _ = r.table_strings(&["user", "mechanism"]);
    let mut r = Args::new(data);
    let _ = r.longstr();
});
