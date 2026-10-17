//! MySQL, Aurora MySQL, and MariaDB: users instead of roles.
//!
//! The admin usually can't read `mysql.user`, so the grants a user has are read
//! by logging in *as that user* and running `SHOW GRANTS`, which needs no
//! privilege. That doubles as the password check. In IAM mode there is no
//! password to log in with, so the admin's `SHOW GRANTS FOR` is used (RDS's
//! master-level admin may run it). Users are `'name'@'%'`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use limen_core::secret::Secret;
use limen_policy::model::{DbAccess, DbGrantSpec};

use super::{Reconciler, existing_or_new_password, quote_literal, secret};
use crate::db::mysqlclient::Client;
use crate::db::pgclient::QueryError;

/// A MySQL identifier in backticks.
#[must_use]
pub fn quote_ident(name: &str) -> String {
    format!("`{}`", name.replace('`', "``"))
}

fn account(user: &str) -> String {
    format!("{}@'%'", quote_literal(user))
}

/// What `SHOW GRANTS` said about one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Grant {
    /// `GRANT <role> TO user`
    Role(String),
    Privileges {
        /// Sorted, upper case. Column-level privileges keep their column list.
        privileges: BTreeSet<String>,
        /// `*.*`, `db.*`, or `db.table`, without backticks.
        scope: String,
        grant_option: bool,
    },
}

/// Parse one row of `SHOW GRANTS`.
pub(super) fn parse_grant(line: &str) -> Option<Grant> {
    let rest = line.strip_prefix("GRANT ")?;
    let Some((privileges, after)) = rest.split_once(" ON ") else {
        // GRANT `role`@`%` TO `user`@`%`
        let role = rest.split(" TO ").next()?.trim();
        return Some(Grant::Role(role.to_owned()));
    };
    let (scope, tail) = after.split_once(" TO ")?;
    // Split the privileges at commas that are outside parentheses.
    let (mut parts, mut depth, mut current) = (BTreeSet::new(), 0, String::new());
    for ch in privileges.chars() {
        match ch {
            '(' => {
                depth += 1;
                current.push(ch);
            }
            ')' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                parts.insert(current.trim().to_ascii_uppercase());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        parts.insert(current.trim().to_ascii_uppercase());
    }
    Some(Grant::Privileges {
        privileges: parts,
        scope: scope.replace('`', ""),
        grant_option: tail.contains("WITH GRANT OPTION"),
    })
}

fn wanted(access: DbAccess) -> BTreeSet<String> {
    let list: &[&str] = match access {
        DbAccess::Read => &["SELECT"],
        DbAccess::Write => &["SELECT", "INSERT", "UPDATE", "DELETE"],
    };
    list.iter().map(|s| (*s).to_owned()).collect()
}

/// The statements that turn `have` into exactly `want` (empty when equal).
pub(super) fn grant_fixes(
    user: &str,
    have: &[Grant],
    want: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<(String, Vec<String>)> {
    let who = account(user);
    let mut fixes = Vec::new();
    let mut seen = BTreeSet::new();
    for g in have {
        match g {
            Grant::Role(role) => fixes.push((
                format!("role membership {role}"),
                vec![format!("REVOKE {role} FROM {who}")],
            )),
            Grant::Privileges {
                privileges,
                scope,
                grant_option,
            } => {
                if scope == "*.*" {
                    if privileges.iter().any(|p| p != "USAGE") || *grant_option {
                        fixes.push((
                            "global privileges".to_owned(),
                            vec![format!(
                                "REVOKE ALL PRIVILEGES, GRANT OPTION ON *.* FROM {who}"
                            )],
                        ));
                    }
                    continue;
                }
                seen.insert(scope.clone());
                let Some(need) = want.get(scope) else {
                    fixes.push((
                        format!("privileges on {scope} that policy doesn't grant"),
                        revoke(&who, scope, privileges, *grant_option),
                    ));
                    continue;
                };
                if privileges != need || *grant_option {
                    let mut sql = revoke(&who, scope, privileges, *grant_option);
                    sql.push(grant(&who, scope, need));
                    fixes.push((format!("privileges on {scope} differ from policy"), sql));
                }
            }
        }
    }
    for (scope, need) in want {
        if !seen.contains(scope) {
            fixes.push((
                format!(
                    "{} on {scope}",
                    need.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
                vec![grant(&who, scope, need)],
            ));
        }
    }
    fixes
}

fn scope_sql(scope: &str) -> String {
    match scope.split_once('.') {
        Some((db, "*")) => format!("{}.*", quote_ident(db)),
        Some((db, table)) => format!("{}.{}", quote_ident(db), quote_ident(table)),
        None => quote_ident(scope),
    }
}

fn revoke(
    who: &str,
    scope: &str,
    privileges: &BTreeSet<String>,
    grant_option: bool,
) -> Vec<String> {
    let on = scope_sql(scope);
    let mut sql: Vec<String> = if privileges.iter().any(|p| p.contains('(')) {
        // Column privileges are revoked as listed.
        privileges
            .iter()
            .map(|p| format!("REVOKE {p} ON {on} FROM {who}"))
            .collect()
    } else {
        vec![format!("REVOKE ALL PRIVILEGES ON {on} FROM {who}")]
    };
    if grant_option {
        sql.push(format!("REVOKE GRANT OPTION ON {on} FROM {who}"));
    }
    sql
}

fn grant(who: &str, scope: &str, privileges: &BTreeSet<String>) -> String {
    format!(
        "GRANT {} ON {} TO {who}",
        privileges.iter().cloned().collect::<Vec<_>>().join(", "),
        scope_sql(scope)
    )
}

impl Reconciler<'_> {
    pub(super) async fn run_mysql(&mut self) -> Result<(), String> {
        let roles = self.plan.roles.clone();
        for spec in &roles {
            if !limen_policy::valid_db_role(&spec.role) {
                return Err(format!("{:?} is not a limen_* role", spec.role));
            }
            self.mysql_user(&spec.role, &spec.grants).await?;
        }
        Ok(())
    }

    async fn mysql_user(&mut self, user: &str, grants: &[DbGrantSpec]) -> Result<(), String> {
        let db = self.plan.admin_database.clone();
        let who = account(user);
        let require = if self.plan.target.uses_tls() {
            " REQUIRE SSL"
        } else {
            ""
        };
        let want: BTreeMap<String, BTreeSet<String>> = grants
            .iter()
            .map(|g| (format!("{}.*", g.database), wanted(g.access)))
            .collect();

        // 1. The account and its credential.
        let can_read_grants;
        if self.plan.iam {
            // Authentication is the plugin's; the admin must be able to read grants.
            let known = self.admin_grants(user).await;
            if matches!(known, Err(ref e) if e.contains("1141") || e.contains("no such grant")) {
                self.act(
                    &db,
                    user,
                    "create_role",
                    "created with AWSAuthenticationPlugin".into(),
                    vec![format!("CREATE USER {who} IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS'{require}")],
                )
                .await?;
                can_read_grants = self.apply;
            } else {
                can_read_grants = known.is_ok();
            }
        } else {
            let dir = self
                .plan
                .password_dir
                .clone()
                .ok_or("secret mode needs password_dir")?;
            let path = PathBuf::from(&dir).join(user);
            let current = secret::read(&path.display().to_string()).await.ok();
            let logs_in = match &current {
                Some(pw) => {
                    Client::connect(&self.plan.target, user, pw, "", "limen-bootstrap-check")
                        .await
                        .is_ok()
                }
                None => false,
            };
            if logs_in {
                can_read_grants = true;
            } else {
                // Missing, or the password differs: make the account exist with
                // the password in the file (generating the file first if there
                // is none, so a crash loses nothing).
                let password = if self.apply {
                    match &current {
                        Some(pw) => pw.clone(),
                        None => existing_or_new_password(&path).await?,
                    }
                } else {
                    Secret::new(String::new())
                };
                let lit = quote_literal(password.expose());
                let why = if current.is_some() {
                    "the user is missing or its password doesn't match the file"
                } else {
                    "no password file"
                };
                self.act(
                    &db,
                    user,
                    "ensure_user",
                    format!("{why}; password in {}", path.display()),
                    vec![
                        format!("CREATE USER IF NOT EXISTS {who} IDENTIFIED BY {lit}{require}"),
                        format!("ALTER USER {who} IDENTIFIED BY {lit}{require}"),
                    ],
                )
                .await?;
                can_read_grants = self.apply;
            }
        }

        // 2. Its grants, as the account itself (or the admin in IAM mode).
        let have = if can_read_grants {
            self.read_grants(user).await?
        } else {
            Vec::new()
        };
        for (what, sql) in grant_fixes(user, &have, &want) {
            let kind = if what.starts_with("role") || what.starts_with("global") {
                "revoke_membership"
            } else {
                "grant"
            };
            self.act(&db, user, kind, what, sql).await?;
        }
        Ok(())
    }

    async fn admin_grants(&mut self, user: &str) -> Result<Vec<String>, String> {
        let db = self.plan.admin_database.clone();
        let rows = self
            .client(&db)
            .await?
            .query(&format!("SHOW GRANTS FOR {}", account(user)))
            .await
            .map_err(|e| match e {
                QueryError::Server { code, message } => format!("{message} ({code})"),
                other @ QueryError::Other(_) => other.to_string(),
            })?;
        Ok(rows
            .into_iter()
            .filter_map(|r| r.into_iter().next().flatten())
            .collect())
    }

    async fn read_grants(&mut self, user: &str) -> Result<Vec<Grant>, String> {
        let lines = if self.plan.iam {
            self.admin_grants(user).await?
        } else {
            let dir = self
                .plan
                .password_dir
                .clone()
                .ok_or("secret mode needs password_dir")?;
            let pw = secret::read(&PathBuf::from(&dir).join(user).display().to_string()).await?;
            let mut c =
                Client::connect(&self.plan.target, user, &pw, "", "limen-bootstrap-check").await?;
            let rows = c.query("SHOW GRANTS").await.map_err(|e| e.to_string());
            c.close().await;
            rows?
                .into_iter()
                .filter_map(|r| r.into_iter().next().flatten())
                .collect()
        };
        Ok(lines.iter().filter_map(|l| parse_grant(l)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn privs(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_what_show_grants_prints() {
        assert_eq!(
            parse_grant("GRANT USAGE ON *.* TO `limen_ro`@`%`"),
            Some(Grant::Privileges {
                privileges: privs(&["USAGE"]),
                scope: "*.*".into(),
                grant_option: false
            })
        );
        assert_eq!(
            parse_grant("GRANT SELECT, INSERT ON `orders`.* TO `u`@`%` WITH GRANT OPTION"),
            Some(Grant::Privileges {
                privileges: privs(&["INSERT", "SELECT"]),
                scope: "orders.*".into(),
                grant_option: true
            })
        );
        assert_eq!(
            parse_grant("GRANT SELECT (`id`, `x`), INSERT ON `billing`.`invoices` TO `u`@`%`"),
            Some(Grant::Privileges {
                privileges: privs(&["INSERT", "SELECT (`ID`, `X`)"]),
                scope: "billing.invoices".into(),
                grant_option: false
            })
        );
        assert_eq!(
            parse_grant("GRANT `r`@`%` TO `u`@`%`"),
            Some(Grant::Role("`r`@`%`".into()))
        );
        assert_eq!(parse_grant("nonsense"), None);
    }

    #[test]
    fn nothing_to_fix_when_grants_match() {
        let want = BTreeMap::from([("orders.*".to_owned(), privs(&["SELECT"]))]);
        let have = vec![
            parse_grant("GRANT USAGE ON *.* TO `u`@`%`").expect("g"),
            parse_grant("GRANT SELECT ON `orders`.* TO `u`@`%`").expect("g"),
        ];
        assert_eq!(grant_fixes("limen_ro", &have, &want).len(), 0);
    }

    #[test]
    fn fixes_missing_extra_and_foreign_grants() {
        let want = BTreeMap::from([("orders.*".to_owned(), privs(&["SELECT"]))]);
        let have = vec![
            parse_grant("GRANT USAGE ON *.* TO `u`@`%`").expect("g"),
            parse_grant("GRANT SELECT, INSERT ON `orders`.* TO `u`@`%`").expect("g"),
            parse_grant("GRANT SELECT ON `billing`.* TO `u`@`%`").expect("g"),
            parse_grant("GRANT `admin`@`%` TO `u`@`%`").expect("g"),
        ];
        let fixes = grant_fixes("limen_ro", &have, &want);
        let all: String = fixes
            .iter()
            .flat_map(|(_, s)| s.clone())
            .collect::<Vec<_>>()
            .join(" | ");
        assert!(
            all.contains("REVOKE ALL PRIVILEGES ON `orders`.* FROM 'limen_ro'@'%'"),
            "{all}"
        );
        assert!(
            all.contains("GRANT SELECT ON `orders`.* TO 'limen_ro'@'%'"),
            "{all}"
        );
        assert!(
            all.contains("REVOKE ALL PRIVILEGES ON `billing`.* FROM"),
            "{all}"
        );
        assert!(all.contains("REVOKE `admin`@`%` FROM"), "{all}");
        let missing = grant_fixes("limen_ro", &[], &want);
        assert_eq!(missing.len(), 1);
        assert!(missing[0].1[0].starts_with("GRANT SELECT ON `orders`.*"));
    }

    #[test]
    fn identifiers_are_quoted() {
        assert_eq!(quote_ident("a`b"), "`a``b`");
        assert_eq!(account("limen_x"), "'limen_x'@'%'");
    }
}
