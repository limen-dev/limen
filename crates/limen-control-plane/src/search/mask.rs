//! Hiding secret shapes before text is indexed (ADR-0026). **Best effort, not
//! a guarantee**: it catches the common shapes (passwords in assignments and
//! SQL, bearer tokens, JWTs, cloud and Git hosting tokens, private keys,
//! passwords in URLs), nothing more. The originals stay wherever they already
//! are, under the sinks' controls; this only keeps the search index from being
//! a second, easier place to find them.

use std::sync::OnceLock;

use regex_lite::Regex;

struct Rule {
    pattern: Regex,
    replacement: &'static str,
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let rule = |p: &str, replacement: &'static str| Rule {
            pattern: Regex::new(p).expect("valid mask pattern"),
            replacement,
        };
        vec![
            // A private key block, or whatever follows its header if it is cut short.
            rule(
                r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)",
                "[masked:private-key]",
            ),
            // Authorization headers and bearer tokens (before the assignments, so
            // `Authorization: Bearer x` keeps no part of x).
            rule(r"(?i)\b(bearer|basic)(\s+)[A-Za-z0-9._~+/=-]{8,}", "${1}${2}[masked]"),
            // user:password@host in a URL.
            rule(r"(://[^/\s:@]+:)[^@\s/]+@", "${1}[masked]@"),
            // password=..., token: "...", api_key=...
            rule(
                r#"(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|authorization)(["']?\s*[=:]\s*)('[^']*'|"[^"]*"|[^\s,;&'")]+)"#,
                "${1}${2}[masked]",
            ),
            // SQL: PASSWORD 'x', IDENTIFIED BY 'x'.
            rule(
                r#"(?i)\b(password|passwd|identified\s+by)(\s+)('[^']*'|"[^"]*")"#,
                "${1}${2}[masked]",
            ),
            // JSON web tokens.
            rule(
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*",
                "[masked:jwt]",
            ),
            // AWS access key ids.
            rule(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b", "[masked:aws-key]"),
            // GitHub and Slack tokens.
            rule(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "[masked:token]"),
            rule(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", "[masked:token]"),
            rule(r"\bxox[abprs]-[A-Za-z0-9-]{10,}", "[masked:token]"),
        ]
    })
}

/// `text` with secret shapes replaced.
#[must_use]
pub fn mask(text: &str) -> String {
    let mut out = text.to_owned();
    for rule in rules() {
        if let std::borrow::Cow::Owned(replaced) = rule.pattern.replace_all(&out, rule.replacement)
        {
            out = replaced;
        }
    }
    out
}

/// Whether anything in `text` was masked.
#[must_use]
pub fn changed(text: &str) -> bool {
    mask(text) != text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masked(s: &str) -> String {
        mask(s)
    }

    #[test]
    fn assignments_keep_the_name_and_lose_the_value() {
        assert_eq!(
            masked("mysql --password=hunter2 -h db"),
            "mysql --password=[masked] -h db"
        );
        assert_eq!(masked("export TOKEN=abc123def"), "export TOKEN=[masked]");
        assert!(!masked(r#"curl -d '{"api_key": "k-9"}'"#).contains("k-9"));
        assert!(!masked("db_password: s3cr3t").contains("s3cr3t"));
        // Variable names that end in the word count too.
        assert_eq!(
            masked("export DB_PASSWORD=swordfish"),
            "export DB_PASSWORD=[masked]"
        );
        assert!(!masked("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG").contains("wJalr"));
        assert!(!masked("PWD='quoted secret'").contains("quoted"));
    }

    #[test]
    fn sql_passwords_are_hidden() {
        let s =
            masked("CREATE USER bob WITH PASSWORD 'p@ss w0rd'; ALTER ROLE x IDENTIFIED BY \"y\"");
        assert!(!s.contains("p@ss") && !s.contains("\"y\""), "{s}");
        assert!(s.contains("CREATE USER bob"));
    }

    #[test]
    fn tokens_keys_and_urls_are_hidden() {
        for secret in [
            "Authorization: Bearer abcdefgh12345678",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl",
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
            "xoxb-1234567890-abcdefghij",
            "postgres://app:topsecret@db.internal/orders",
        ] {
            let s = masked(secret);
            assert!(s.contains("[masked"), "{secret} -> {s}");
            for leak in [
                "abcdefgh12345678",
                "c2lnbmF0dXJl",
                "IOSFODNN7EXAMPLE",
                "0123456789abcdef",
                "1234567890-abcdefghij",
                "topsecret",
            ] {
                assert!(!s.contains(leak), "{leak} survived in {s}");
            }
        }
        // The host and user of a URL stay: they are what you search for.
        assert_eq!(
            masked("psql postgres://app:pw@db.internal/orders"),
            "psql postgres://app:[masked]@db.internal/orders"
        );
    }

    #[test]
    fn private_key_blocks_go_even_when_cut_short() {
        let whole = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----\nrest";
        assert_eq!(masked(whole), "[masked:private-key]\nrest");
        let cut = "cat key\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow";
        assert_eq!(masked(cut), "cat key\n[masked:private-key]");
    }

    #[test]
    fn ordinary_text_is_left_alone() {
        for plain in [
            "SELECT * FROM orders WHERE id = 5",
            "auth failed for user bob",
            "systemctl restart nginx",
            "tokenizer",
            "kubectl get pods -n payments",
        ] {
            assert_eq!(masked(plain), plain);
            assert!(!changed(plain));
        }
    }

    #[test]
    fn hostile_input_does_not_make_the_masker_spin() {
        let hostile = "a".repeat(200_000) + "=" + &"b".repeat(200_000);
        let started = std::time::Instant::now();
        let _ = masked(&hostile);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}
