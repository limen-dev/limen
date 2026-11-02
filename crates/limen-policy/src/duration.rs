//! Durations written as `90s`, `10m`, `8h`, or `1d`.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DurationStr(pub Duration);

impl DurationStr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let split = s
            .find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| format!("missing unit in duration {s:?}"))?;
        let (num, unit) = s.split_at(split);
        let n: u64 = num.parse().map_err(|_| format!("invalid duration {s:?}"))?;
        let secs = match unit {
            "s" => Some(n),
            "m" => n.checked_mul(60),
            "h" => n.checked_mul(3600),
            "d" => n.checked_mul(86_400),
            _ => return Err(format!("unknown unit in duration {s:?}; use s, m, h, or d")),
        }
        .ok_or_else(|| format!("duration {s:?} overflows"))?;
        if secs == 0 {
            return Err("duration must be positive".into());
        }
        Ok(Self(Duration::from_secs(secs)))
    }
}

impl fmt::Display for DurationStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0.as_secs();
        if s.is_multiple_of(86_400) {
            write!(f, "{}d", s / 86_400)
        } else if s.is_multiple_of(3600) {
            write!(f, "{}h", s / 3600)
        } else if s.is_multiple_of(60) {
            write!(f, "{}m", s / 60)
        } else {
            write!(f, "{s}s")
        }
    }
}

/// A string such as `90s`, `10m`, `8h`, or `1d`, as [`DurationStr::parse`] reads.
impl schemars::JsonSchema for DurationStr {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Duration".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^\\s*[0-9]+[smhd]\\s*$",
            "description": "A positive duration: a whole number and a unit, s, m, h, or d, such as `90s` or `8h`."
        })
    }
}

impl Serialize for DurationStr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DurationStr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_displays() {
        for (input, secs, shown) in [
            ("90s", 90, "90s"),
            ("10m", 600, "10m"),
            ("8h", 28_800, "8h"),
            ("2d", 172_800, "2d"),
            ("120s", 120, "2m"),
        ] {
            let d = DurationStr::parse(input).expect(input);
            assert_eq!(d.0.as_secs(), secs);
            assert_eq!(d.to_string(), shown);
        }
    }

    #[test]
    fn rejects_bad_input() {
        for bad in ["", "10", "m", "10x", "-5m", "0s", "99999999999999999999d"] {
            assert!(DurationStr::parse(bad).is_err(), "{bad}");
        }
    }
}
