//! Resource labels. Roles select resources by matching on labels, so keys and
//! values are validated strictly to keep policy evaluation unambiguous.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

const MAX_KEY_LEN: usize = 63;
const MAX_VALUE_LEN: usize = 255;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LabelError {
    #[error("label key must be 1..={MAX_KEY_LEN} chars of [a-z0-9._/-], got {0:?}")]
    InvalidKey(String),
    #[error("label value for {key:?} must be at most {MAX_VALUE_LEN} printable ASCII chars")]
    InvalidValue { key: String },
}

/// A validated, ordered set of labels.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    try_from = "BTreeMap<String, String>",
    into = "BTreeMap<String, String>"
)]
pub struct Labels(BTreeMap<String, String>);

impl Labels {
    pub fn insert(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), LabelError> {
        let (key, value) = (key.into(), value.into());
        validate(&key, &value)?;
        self.0.insert(key, value);
        Ok(())
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

fn validate(key: &str, value: &str) -> Result<(), LabelError> {
    let key_ok = !key.is_empty()
        && key.len() <= MAX_KEY_LEN
        && key.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'/' | b'-')
        });
    if !key_ok {
        return Err(LabelError::InvalidKey(key.to_owned()));
    }
    let value_ok =
        value.len() <= MAX_VALUE_LEN && value.bytes().all(|b| b.is_ascii_graphic() || b == b' ');
    if !value_ok {
        return Err(LabelError::InvalidValue {
            key: key.to_owned(),
        });
    }
    Ok(())
}

impl TryFrom<BTreeMap<String, String>> for Labels {
    type Error = LabelError;

    fn try_from(map: BTreeMap<String, String>) -> Result<Self, Self::Error> {
        for (k, v) in &map {
            validate(k, v)?;
        }
        Ok(Self(map))
    }
}

impl From<Labels> for BTreeMap<String, String> {
    fn from(labels: Labels) -> Self {
        labels.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_labels() {
        let mut labels = Labels::default();
        labels.insert("env", "prod").expect("valid");
        labels
            .insert("team.example.com/owner", "payments")
            .expect("valid");
        assert_eq!(labels.get("env"), Some("prod"));
    }

    #[test]
    fn rejects_invalid_keys_and_values() {
        let mut labels = Labels::default();
        assert!(matches!(
            labels.insert("Env", "prod"),
            Err(LabelError::InvalidKey(_))
        ));
        assert!(matches!(
            labels.insert("", "x"),
            Err(LabelError::InvalidKey(_))
        ));
        assert!(matches!(
            labels.insert("env", "a\nb"),
            Err(LabelError::InvalidValue { .. })
        ));
    }

    #[test]
    fn deserialization_validates() {
        let err = serde_json::from_str::<Labels>(r#"{"BAD KEY":"x"}"#);
        assert!(err.is_err());
        let ok: Labels = serde_json::from_str(r#"{"env":"dev"}"#).expect("valid");
        assert_eq!(ok.get("env"), Some("dev"));
    }
}
