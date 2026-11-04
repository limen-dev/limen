//! Short durations written as `30s`, `15m`, or `1h`, for command-line flags.

use std::time::Duration;

/// Parse a whole number and a unit, `s`, `m`, or `h`. Zero is allowed.
///
/// A value too large to hold is an error. (`Duration::from_mins` and
/// `from_hours` panic on overflow, which a typo in a flag must not trigger.)
pub fn parse_short(s: &str) -> Result<Duration, String> {
    let split = s
        .find(|c: char| !c.is_ascii_digit())
        .ok_or("missing unit (use s, m, or h)")?;
    let (digits, unit) = s.split_at(split);
    let n: u64 = digits.parse().map_err(|_| "not a number")?;
    let factor = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => return Err("use s, m, or h".into()),
    };
    n.checked_mul(factor)
        .map(Duration::from_secs)
        .ok_or_else(|| "that duration is too large".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units() {
        assert_eq!(parse_short("90s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_short("30m"), Ok(Duration::from_mins(30)));
        assert_eq!(parse_short("2h"), Ok(Duration::from_hours(2)));
        assert_eq!(parse_short("0s"), Ok(Duration::ZERO));
    }

    #[test]
    fn refuses_bad_input() {
        for bad in ["", "5", "m", "5d", "-5m", "5 m", "5M", "1.5h"] {
            assert!(parse_short(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn refuses_what_would_overflow_instead_of_panicking() {
        assert!(parse_short("18446744073709551615h").is_err());
        assert!(parse_short("18446744073709551615m").is_err());
        assert!(parse_short("99999999999999999999999s").is_err());
        assert_eq!(
            parse_short("18446744073709551615s"),
            Ok(Duration::from_secs(u64::MAX))
        );
    }
}
