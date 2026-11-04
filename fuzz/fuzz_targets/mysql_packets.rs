#![no_main]
//! MySQL: packet framing and the hello, error and handshake parsers, on any bytes.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

fn rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
    })
}

fuzz_target!(|data: &[u8]| {
    rt().block_on(limen_worker::db::fuzz_mysql::packets(data));
});
