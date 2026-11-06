#![no_main]
//! Policy documents: YAML parsing, then validation and compiling, on any text.
use libfuzzer_sys::fuzz_target;

use limen_policy::Policy;

const ROLES: &str = include_str!("../../examples/policy/shared/roles.yaml");
const RESOURCES: &str = include_str!("../../examples/policy/stacks/ssh/resources.yaml");

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = Policy::parse_yaml_documents([("fuzz", text)]);
    if let Ok(policy) = Policy::parse_yaml([("fuzz", text)]) {
        let _ = policy.digest();
        let _ = policy.warnings();
        let _ = policy.effective_access();
    }
    // Next to valid documents, so cross-document checks (duplicates, references) run too.
    if let Ok(policy) =
        Policy::parse_yaml([("roles", ROLES), ("resources", RESOURCES), ("fuzz", text)])
    {
        let _ = policy.digest();
        let _ = policy.warnings();
        let _ = policy.who_can("anything");
    }
});
