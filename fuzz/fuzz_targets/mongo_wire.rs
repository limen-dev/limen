#![no_main]
//! MongoDB: message framing, OP_MSG and OP_QUERY bodies, and the BSON reader, on any bytes.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

use limen_worker::mongo::bson::Doc;
use limen_worker::mongo::wire::{parse_op_msg, parse_op_query, read_message};

fn rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
    })
}

fuzz_target!(|data: &[u8]| {
    let mut stream = data;
    rt().block_on(async {
        while let Ok(Some(_)) = read_message(&mut stream).await {}
    });
    let _ = parse_op_msg(data);
    let _ = parse_op_query(data);
    if let Ok(doc) = Doc::new(data) {
        let _ = doc.validate();
        for item in doc.iter() {
            let _ = item;
        }
    }
});
