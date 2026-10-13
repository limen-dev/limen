//! How identities are encoded in certificates.
//!
//! Limen certificates carry identity as URI subject alternative names, so a
//! certificate can be verified offline without a lookup:
//!
//! - `limen://user/<username>`: the human user (user CA only)
//! - `limen://role/<role>`: one per role granted at login
//! - `limen://login/<uuid>`: the login session that produced the cert
//! - `limen://component/<kind>/<id>`: a control plane, proxy, or worker (internal CA only)
//!
//! Path segments are percent-encoded, so `alice@example.com` survives intact.

use std::fmt;

use serde::{Deserialize, Serialize};

pub const SCHEME: &str = "limen";

/// Built-in role that grants administrative APIs. The colon is reserved for
/// built-in roles, and user-defined role names can't contain it.
pub const ADMIN_ROLE: &str = "limen:admin";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentKind {
    ControlPlane,
    Proxy,
    Worker,
}

impl ComponentKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ComponentKind::ControlPlane => "control_plane",
            ComponentKind::Proxy => "proxy",
            ComponentKind::Worker => "worker",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "control_plane" => Some(ComponentKind::ControlPlane),
            "proxy" => Some(ComponentKind::Proxy),
            "worker" => Some(ComponentKind::Worker),
            _ => None,
        }
    }
}

impl fmt::Display for ComponentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One identity-bearing SAN URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityUri {
    User(String),
    Role(String),
    Login(String),
    Component { kind: ComponentKind, id: String },
}

impl IdentityUri {
    #[must_use]
    pub fn to_uri(&self) -> String {
        match self {
            IdentityUri::User(u) => format!("{SCHEME}://user/{}", encode(u)),
            IdentityUri::Role(r) => format!("{SCHEME}://role/{}", encode(r)),
            IdentityUri::Login(l) => format!("{SCHEME}://login/{}", encode(l)),
            IdentityUri::Component { kind, id } => {
                format!("{SCHEME}://component/{kind}/{}", encode(id))
            }
        }
    }

    /// Parse a SAN URI. Anything that isn't a well-formed Limen URI returns `None`.
    #[must_use]
    pub fn parse(uri: &str) -> Option<Self> {
        let rest = uri.strip_prefix("limen://")?;
        let mut parts = rest.split('/');
        let kind = parts.next()?;
        let first = decode(parts.next()?)?;
        match (kind, parts.next(), parts.next()) {
            ("user", None, _) => Some(IdentityUri::User(first)),
            ("role", None, _) => Some(IdentityUri::Role(first)),
            ("login", None, _) => Some(IdentityUri::Login(first)),
            ("component", Some(id), None) => Some(IdentityUri::Component {
                kind: ComponentKind::parse(&first)?,
                id: decode(id)?,
            }),
            _ => None,
        }
    }
}

fn encode(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'@' | b':') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn decode(s: &str) -> Option<String> {
    if s.is_empty() {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_all_variants() {
        let cases = [
            IdentityUri::User("alice@example.com".into()),
            IdentityUri::User("bob smith/evil".into()),
            IdentityUri::Role("limen:admin".into()),
            IdentityUri::Login("0192f1d2-0000-7000-8000-000000000000".into()),
            IdentityUri::Component {
                kind: ComponentKind::Worker,
                id: "w-1".into(),
            },
        ];
        for case in cases {
            let uri = case.to_uri();
            assert_eq!(IdentityUri::parse(&uri), Some(case), "{uri}");
        }
    }

    #[test]
    fn slash_in_value_cannot_forge_another_kind() {
        let uri = IdentityUri::User("x/role/limen:admin".into()).to_uri();
        assert_eq!(uri, "limen://user/x%2Frole%2Flimen:admin");
        assert!(matches!(
            IdentityUri::parse(&uri),
            Some(IdentityUri::User(_))
        ));
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "https://user/a",
            "limen://user/",
            "limen://user/a/b",
            "limen://component/nope/x",
            "limen://x/y",
            "limen://user/%zz",
        ] {
            assert_eq!(IdentityUri::parse(bad), None, "{bad}");
        }
    }
}
