#![no_main]
//! RESP: the frame scanners, the command parser and the value parser, on any bytes.
use libfuzzer_sys::fuzz_target;

use limen_worker::redis::codec::{FrameScanner, RequestScanner, parse_command, parse_value};

fuzz_target!(|data: &[u8]| {
    // The scanners see a buffer that only grows; feed it in two steps.
    let mid = data.len() / 2;
    for scan in [0, 1] {
        let (mut frames, mut requests) = (FrameScanner::new(), RequestScanner::new());
        for end in [mid, data.len()] {
            let buf = &data[..end];
            let found = if scan == 0 {
                frames.advance(buf)
            } else {
                requests.advance(buf)
            };
            if let Ok(Some(n)) = found {
                assert!(n <= buf.len(), "a frame longer than the buffer");
                let _ = parse_command(&buf[..n]);
                let _ = parse_value(&buf[..n]);
            }
        }
    }
    let _ = parse_command(data);
    let _ = parse_value(data);
});
