use super::*;

#[test]
fn every_kind_has_a_draft_2020_12_schema() {
    for kind in KINDS {
        let schema = spec_schema(kind).expect(kind);
        assert_eq!(
            schema["$schema"], "https://json-schema.org/draft/2020-12/schema",
            "{kind}"
        );
        assert_eq!(schema["title"], format!("{kind} spec"));
    }
    assert!(spec_schema("nope").is_none());
}

#[test]
fn the_schema_follows_the_parser() {
    let resource = spec_schema("resource").expect("resource");
    // Strict parsing: unknown fields are refused.
    assert_eq!(resource["additionalProperties"], false, "{resource:#}");
    assert!(
        resource["properties"]["postgres"].is_object(),
        "{resource:#}"
    );
    // A mapping's spec is a list.
    assert_eq!(
        spec_schema("role_mapping").expect("mapping")["type"],
        "array"
    );
    // Durations and labels read as the parser reads them.
    let discovery = spec_schema("discovery").expect("discovery").to_string();
    assert!(discovery.contains("[smhd]"), "{discovery}");
}

/// `docs/policy-schema/<kind>.json` is what `GetSchema` serves, for clients that
/// can't reach a server (a plan in a pull request). Regenerate it with
/// `UPDATE_SCHEMA=1 cargo test -p limen-policy committed_schemas_are_current`.
#[test]
fn committed_schemas_are_current() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/policy-schema");
    let update = std::env::var_os("UPDATE_SCHEMA").is_some();
    for kind in KINDS {
        let path = format!("{dir}/{kind}.json");
        let generated =
            serde_json::to_string_pretty(&spec_schema(kind).expect(kind)).expect("json") + "\n";
        if update {
            std::fs::create_dir_all(dir).expect("mkdir docs/policy-schema");
            std::fs::write(&path, &generated).expect("write");
            continue;
        }
        let committed = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            committed == generated,
            "{path} is stale; regenerate it with UPDATE_SCHEMA=1 cargo test -p limen-policy committed_schemas_are_current"
        );
    }
}
