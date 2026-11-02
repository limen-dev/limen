//! The JSON Schema (draft 2020-12) of each kind's `spec`, generated from the
//! types that parse it, so the two can't disagree (ADR-0042 §2). Served by
//! the management API's `GetSchema` and committed under `docs/policy-schema/`.

use schemars::JsonSchema;
use schemars::generate::SchemaSettings;
use serde_json::Value;

/// Every kind with a schema, in the order the docs list them.
pub const KINDS: [&str; 8] = [
    "role",
    "role_mapping",
    "resource",
    "bot",
    "discovery",
    "policy_test",
    "resource_profile",
    "policy_writer",
];

/// The schema of `kind`'s `spec`, or `None` for an unknown kind.
#[must_use]
pub fn spec_schema(kind: &str) -> Option<Value> {
    fn of<T: JsonSchema>(kind: &str) -> Value {
        let mut schema = SchemaSettings::draft2020_12()
            .into_generator()
            .into_root_schema_for::<T>();
        schema.insert("title".into(), format!("{kind} spec").into());
        schema.to_value()
    }
    Some(match kind {
        "role" => of::<crate::model::RoleSpec>(kind),
        "role_mapping" => of::<Vec<crate::model::GroupMapping>>(kind),
        "resource" => of::<crate::model::ResourceSpec>(kind),
        "bot" => of::<crate::bot::BotSpec>(kind),
        "discovery" => of::<crate::discovery::DiscoverySpec>(kind),
        "policy_test" => of::<crate::testing::PolicyTestSpec>(kind),
        "resource_profile" => of::<crate::delegation::ProfileSpec>(kind),
        "policy_writer" => of::<crate::delegation::WriterSpec>(kind),
        _ => return None,
    })
}

#[cfg(test)]
mod tests;
