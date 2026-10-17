//! Statement text for the audit trail (ADR-0033 section 5).
//!
//! Only the `sqlparser` *tokenizer* is used, to split a message into
//! statements, name each statement's type, and replace literals. Nothing here
//! decides whether a statement is allowed (ADR-0012): that is the database's
//! grants.

use sqlparser::dialect::{Dialect, MySqlDialect, PostgreSqlDialect};
use sqlparser::tokenizer::{Token, Tokenizer};

/// The SQL flavour of a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Postgres,
    Mysql,
}

impl Flavor {
    fn dialect(self) -> &'static dyn Dialect {
        match self {
            Flavor::Postgres => &PostgreSqlDialect {},
            Flavor::Mysql => &MySqlDialect {},
        }
    }
}

/// One statement of a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// `select`, `insert`, ... `other` for an unrecognized first word,
    /// `unknown` when the text couldn't be tokenized.
    pub kind: &'static str,
    pub text: String,
}

const KINDS: &[&str] = &[
    "select",
    "insert",
    "update",
    "delete",
    "merge",
    "create",
    "alter",
    "drop",
    "truncate",
    "grant",
    "revoke",
    "copy",
    "call",
    "do",
    "set",
    "reset",
    "show",
    "begin",
    "commit",
    "rollback",
    "savepoint",
    "release",
    "explain",
    "analyze",
    "vacuum",
    "lock",
    "prepare",
    "execute",
    "deallocate",
    "declare",
    "fetch",
    "close",
    "listen",
    "notify",
    "unlisten",
    "comment",
    "refresh",
    "reindex",
    "cluster",
    "discard",
    "checkpoint",
    "load",
    "import",
    "with",
    "values",
    "use",
    "describe",
    "desc",
    "replace",
    "rename",
    "optimize",
    "flush",
    "kill",
    "handler",
    "unlock",
    "xa",
    "table",
    "abort",
    "end",
    "security",
    "unload",
];

fn kind_of(tokens: &[Token]) -> &'static str {
    let first = tokens
        .iter()
        .find(|t| !matches!(t, Token::Whitespace(_) | Token::SemiColon));
    match first {
        Some(Token::Word(w)) => {
            let lower = w.value.to_ascii_lowercase();
            if w.quote_style.is_some() {
                return "other";
            }
            match lower.as_str() {
                "start" => "begin",
                "desc" => "describe",
                other => KINDS
                    .iter()
                    .copied()
                    .find(|k| *k == other)
                    .unwrap_or("other"),
            }
        }
        Some(Token::LParen) => "select",
        Some(_) => "other",
        None => "empty",
    }
}

fn render(tokens: &[Token]) -> String {
    tokens.iter().map(ToString::to_string).collect()
}

/// Split a simple-protocol message into statements. The common single
/// statement is returned exactly as written; several are re-rendered from
/// their tokens.
#[must_use]
pub fn split(sql: &str, flavor: Flavor) -> Vec<Statement> {
    let Ok(tokens) = Tokenizer::new(flavor.dialect(), sql).tokenize() else {
        return vec![Statement {
            kind: "unknown",
            text: sql.to_owned(),
        }];
    };
    let mut parts: Vec<&[Token]> = Vec::new();
    let mut start = 0;
    for (i, t) in tokens.iter().enumerate() {
        if matches!(t, Token::SemiColon) {
            parts.push(&tokens[start..i]);
            start = i + 1;
        }
    }
    parts.push(&tokens[start..]);
    let blank = |p: &[Token]| p.iter().all(|t| matches!(t, Token::Whitespace(_)));
    let real: Vec<&[Token]> = parts.into_iter().filter(|p| !blank(p)).collect();
    match real.as_slice() {
        [] => vec![Statement {
            kind: "empty",
            text: sql.trim().to_owned(),
        }],
        [only] => vec![Statement {
            kind: kind_of(only),
            text: sql.trim().to_owned(),
        }],
        many => many
            .iter()
            .map(|p| Statement {
                kind: kind_of(p),
                text: render(p).trim().to_owned(),
            })
            .collect(),
    }
}

/// Replace literals with `?` (`audit.normalize_literals`). Text that can't be
/// tokenized is withheld entirely rather than logged with its literals.
#[must_use]
pub fn normalize(sql: &str, flavor: Flavor) -> String {
    let Ok(tokens) = Tokenizer::new(flavor.dialect(), sql).tokenize() else {
        return "[unparseable statement; text withheld]".to_owned();
    };
    tokens
        .iter()
        .map(|t| match t {
            Token::Number(..)
            | Token::SingleQuotedString(_)
            | Token::DoubleQuotedString(_)
            | Token::TripleSingleQuotedString(_)
            | Token::TripleDoubleQuotedString(_)
            | Token::DollarQuotedString(_)
            | Token::EscapedStringLiteral(_)
            | Token::UnicodeStringLiteral(_)
            | Token::NationalStringLiteral(_)
            | Token::HexStringLiteral(_)
            | Token::SingleQuotedByteStringLiteral(_)
            | Token::DoubleQuotedByteStringLiteral(_) => "?".to_owned(),
            other => other.to_string(),
        })
        .collect()
}

/// Rows affected from a PostgreSQL `CommandComplete` tag, such as
/// `INSERT 0 5` or `SELECT 3`.
#[must_use]
pub fn rows_from_tag(tag: &str) -> Option<u64> {
    tag.rsplit(' ').next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_statement_is_kept_as_written() {
        let s = split("  SELECT  1 ;", Flavor::Postgres);
        assert_eq!(
            s,
            vec![Statement {
                kind: "select",
                text: "SELECT  1 ;".into()
            }]
        );
    }

    #[test]
    fn splits_several_and_names_each_type() {
        let s = split(
            "insert into t values (1); update t set a = 2; ;",
            Flavor::Postgres,
        );
        let kinds: Vec<_> = s.iter().map(|s| s.kind).collect();
        assert_eq!(kinds, ["insert", "update"]);
        assert!(s[0].text.starts_with("insert into t"), "{:?}", s[0]);
    }

    #[test]
    fn semicolons_inside_strings_and_dollar_quotes_do_not_split() {
        let s = split(
            "select ';'; do $$ begin perform 1; end $$",
            Flavor::Postgres,
        );
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].kind, "select");
        assert_eq!(s[1].kind, "do");
    }

    #[test]
    fn classifies_other_shapes() {
        let kind = |q: &str| split(q, Flavor::Postgres)[0].kind;
        assert_eq!(kind("WITH x AS (select 1) select * from x"), "with");
        assert_eq!(kind("(select 1)"), "select");
        assert_eq!(kind("start transaction"), "begin");
        assert_eq!(kind("-- c\nDROP TABLE t"), "drop");
        assert_eq!(kind("frobnicate"), "other");
        assert_eq!(kind(""), "empty");
        assert_eq!(kind("\"select\" 1"), "other");
    }

    #[test]
    fn untokenizable_text_is_unknown_and_kept() {
        let s = split("select 'unterminated", Flavor::Postgres);
        assert_eq!(s[0].kind, "unknown");
        assert_eq!(s[0].text, "select 'unterminated");
    }

    #[test]
    fn normalizes_literals_but_not_identifiers() {
        let n = normalize(
            "select \"Name\" from users where id = 42 and email = 'a@b.c' and x = $$s$$",
            Flavor::Postgres,
        );
        assert_eq!(
            n,
            "select \"Name\" from users where id = ? and email = ? and x = ?"
        );
        assert!(normalize("select 'oops", Flavor::Postgres).contains("withheld"));
    }

    #[test]
    fn mysql_double_quotes_are_strings() {
        assert_eq!(normalize("select \"secret\"", Flavor::Mysql), "select ?");
    }

    #[test]
    fn rows_from_tags() {
        assert_eq!(rows_from_tag("INSERT 0 5"), Some(5));
        assert_eq!(rows_from_tag("SELECT 3"), Some(3));
        assert_eq!(rows_from_tag("BEGIN"), None);
    }
}
