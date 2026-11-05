#![no_main]
//! The small parsers the policy loads values through, on any text.
use libfuzzer_sys::fuzz_target;

use limen_policy::discovery::render_name;
use limen_policy::duration::DurationStr;
use limen_policy::{
    Principal, compile_ticket_pattern, valid_db_role, valid_mongo_database, valid_mongo_role,
};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = DurationStr::parse(text);
    let _ = Principal::parse(text, "db");
    let _ = compile_ticket_pattern(text);
    let _ = valid_db_role(text);
    let _ = valid_mongo_role(text);
    let _ = valid_mongo_database(text);
    let _ = render_name(text, |key| Some(key.to_owned()));
    let _ = render_name(text, |_| None);
});
