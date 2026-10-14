//! The users the integration tests (and the dev stack's demos) talk about.
//! The dev stack's own copy of the same people is `deploy/compose/dev-users.toml`;
//! keep the emails in step. Their groups differ on purpose: tests use their
//! own mock IdP groups (`admins`, `ops`) matching the policies they apply.

pub const ALICE: &str = "alice@example.com";
pub const BOB: &str = "bob@example.com";
pub const CAROL: &str = "carol@example.com";

/// The same emails as one URL path segment.
pub const ALICE_ENC: &str = "alice%40example.com";
pub const BOB_ENC: &str = "bob%40example.com";
pub const CAROL_ENC: &str = "carol%40example.com";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_forms_match() {
        for (plain, enc) in [(ALICE, ALICE_ENC), (BOB, BOB_ENC), (CAROL, CAROL_ENC)] {
            assert_eq!(plain.replace('@', "%40"), enc);
        }
    }

    /// The dev stack and the tests must agree about who exists.
    #[test]
    fn dev_users_file_has_the_same_people() {
        let toml = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/compose/dev-users.toml"
        ))
        .expect("dev-users.toml");
        for email in [ALICE, BOB, CAROL] {
            assert!(
                toml.contains(email),
                "{email} is missing from dev-users.toml"
            );
        }
    }
}
