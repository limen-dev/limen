//! Optional display names for proxies and workers.
//!
//! The component ID stays the identity (certificate CN, policy, revocation).
//! A name is for people: the console, audit data, logs. It is approved by
//! the join token (exactly or by a pattern), validated and made unique among
//! live components by the control plane, and recorded in the certificate as
//! the label [`NAME_LABEL`], so the component can't change it later.

use std::collections::BTreeMap;

/// The certificate label that carries a component's name.
pub const NAME_LABEL: &str = "limen.io/name";

/// Longest name (a DNS label's length).
pub const MAX_NAME_LEN: usize = 63;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NameError {
    #[error(
        "invalid name {0:?}: use 1 to {MAX_NAME_LEN} characters of a-z, 0-9 and -, not starting or ending with -"
    )]
    InvalidName(String),
    #[error(
        "invalid name pattern {0:?}: use 1 to {MAX_NAME_LEN} characters of a-z, 0-9 and -, with at most one *, not starting or ending with -"
    )]
    InvalidPattern(String),
}

/// Check a name: 1 to 63 characters of `[a-z0-9-]`, not starting or ending
/// with `-`. Uppercase is refused, not lowered.
pub fn validate_name(name: &str) -> Result<(), NameError> {
    if is_valid_name(name) {
        Ok(())
    } else {
        Err(NameError::InvalidName(name.to_owned()))
    }
}

fn name_char(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'
}

fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name.bytes().all(name_char)
        && !name.starts_with('-')
        && !name.ends_with('-')
}

/// The names a join token approves: one exact name, or a pattern with a
/// single `*` that matches zero or more characters of `[a-z0-9-]`.
///
/// `prod-a-*` accepts `prod-a-1` and `prod-a-x-2`, and refuses `prod-b-1`,
/// `prod-a` (no `-` after it) and `prod-a-` (not a valid name). A name must
/// always be valid on its own as well as match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamePattern(String);

impl NamePattern {
    /// Parse a pattern: 1 to 63 characters of `[a-z0-9-*]`, at most one
    /// `*`, not starting or ending with `-`. Without `*`, it is an exact name.
    pub fn parse(pattern: &str) -> Result<Self, NameError> {
        let bad = || NameError::InvalidPattern(pattern.to_owned());
        if pattern.is_empty()
            || pattern.len() > MAX_NAME_LEN
            || !pattern.bytes().all(|b| name_char(b) || b == b'*')
            || pattern.bytes().filter(|&b| b == b'*').count() > 1
            || pattern.starts_with('-')
            || pattern.ends_with('-')
        {
            return Err(bad());
        }
        Ok(Self(pattern.to_owned()))
    }

    /// The exact name, when the pattern has no `*`.
    #[must_use]
    pub fn exact(&self) -> Option<&str> {
        (!self.0.contains('*')).then_some(self.0.as_str())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `name` is valid and matches.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        if !is_valid_name(name) {
            return false;
        }
        match self.0.split_once('*') {
            None => self.0 == name,
            Some((prefix, suffix)) => {
                name.len() >= prefix.len() + suffix.len()
                    && name.starts_with(prefix)
                    && name.ends_with(suffix)
            }
        }
    }
}

impl std::fmt::Display for NamePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A component's name, from its certified labels.
#[must_use]
pub fn from_labels(labels: &BTreeMap<String, String>) -> Option<&str> {
    labels.get(NAME_LABEL).map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        for ok in ["a", "prod-a-worker-1", "w--1", "0", &"a".repeat(63)] {
            assert_eq!(validate_name(ok), Ok(()), "{ok:?}");
        }
    }

    #[test]
    fn invalid_names_are_refused_not_normalized() {
        for bad in [
            "",
            " ",
            " a",
            "Prod-a",
            "WORKER",
            "-a",
            "a-",
            "-",
            "a_b",
            "a.b",
            "a*",
            "wörker",
            "a b",
            &"a".repeat(64),
        ] {
            assert!(validate_name(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn pattern_syntax() {
        for ok in ["*", "prod-a-*", "*-worker", "prod-*-1", "exact-name"] {
            assert!(NamePattern::parse(ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "",
            "**",
            "a*b*",
            "-*",
            "*-",
            "Prod-*",
            "a_*",
            "prod-a-*\u{e9}",
            &format!("{}*", "a".repeat(63)),
        ] {
            assert!(NamePattern::parse(bad).is_err(), "{bad:?} must be refused");
        }
        assert_eq!(
            NamePattern::parse("exact-name").expect("p").exact(),
            Some("exact-name")
        );
        assert_eq!(NamePattern::parse("prod-*").expect("p").exact(), None);
    }

    #[test]
    fn star_matches_zero_or_more_name_characters() {
        let p = NamePattern::parse("prod-a-*").expect("pattern");
        assert!(p.matches("prod-a-1"));
        assert!(p.matches("prod-a-x-2"));
        assert!(!p.matches("prod-b-1"));
        // `prod-a` lacks the `-`; `prod-a-` is not a valid name.
        assert!(!p.matches("prod-a"));
        assert!(!p.matches("prod-a-"));
        assert!(!p.matches("PROD-A-1"));

        let mid = NamePattern::parse("prod-*-1").expect("pattern");
        assert!(mid.matches("prod-a-1"));
        assert!(mid.matches("prod--1"), "zero characters");
        assert!(!mid.matches("prod-1"), "prefix and suffix may not overlap");

        let any = NamePattern::parse("*").expect("pattern");
        assert!(any.matches("anything-1"));
        assert!(!any.matches("Bad"));

        let exact = NamePattern::parse("edge-1").expect("pattern");
        assert!(exact.matches("edge-1"));
        assert!(!exact.matches("edge-12"));
    }

    #[test]
    fn name_label_is_a_legal_label_and_identity_uri() {
        let mut labels = crate::labels::Labels::default();
        labels
            .insert(NAME_LABEL, "prod-a-worker-1")
            .expect("legal label key");
        let uri = crate::identity::IdentityUri::Label {
            key: NAME_LABEL.into(),
            value: "prod-a-worker-1".into(),
        };
        assert_eq!(
            crate::identity::IdentityUri::parse(&uri.to_uri()),
            Some(uri)
        );
        let map: BTreeMap<String, String> = labels.into();
        assert_eq!(from_labels(&map), Some("prod-a-worker-1"));
    }
}
