//! Role bootstrap (ADR-0015, ADR-0033 section 6): make the database match
//! the `bootstrap` section of the resource, idempotently.
//!
//! Reconcile compares what exists with what policy declares and changes only
//! the difference, so a second run issues no DDL. It only ever touches roles
//! with the reserved `limen_` prefix. Every change is audited (`db.bootstrap`)
//! *before* it is made; a change that can't be audited is not made.
//!
//! Passwords (secret mode) live in `<password_dir>/<role>`. They never appear
//! in an event, a log line, or [`Action::detail`].

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use limen_audit::{Context, Emitter, EventKind};
use limen_core::secret::Secret;
use limen_policy::model::{DbAccess, DbRoleSpec, DbTarget};
use serde_json::json;

use super::pgclient::{Client, QueryError, Row};
use super::target::Target;
use super::{Engine, mysqlclient, secret};

mod mysql;

/// Everything needed to reconcile one resource.
#[derive(Debug)]
pub struct Plan {
    pub resource: String,
    pub engine: Engine,
    pub target: Target,
    pub admin_user: String,
    pub admin_password: Secret<String>,
    /// The database the admin connects to for role-level work.
    pub admin_database: String,
    pub roles: Vec<DbRoleSpec>,
    /// Secret mode: where role passwords live. `None` with `iam`.
    pub password_dir: Option<String>,
    pub iam: bool,
}

impl Plan {
    /// Build a plan from a resource, or say why it can't be reconciled.
    pub async fn from_spec(
        resource: &str,
        engine: Engine,
        spec: &DbTarget,
        allow_insecure: bool,
    ) -> Result<Self, String> {
        let admin_user = spec
            .admin_user
            .clone()
            .ok_or("bootstrap needs admin_user (a dedicated login, never the master user)")?;
        if spec.admin_secret_arn.is_some() && spec.admin_password_file.is_none() {
            return Err(
                "admin_secret_arn (Secrets Manager) is not supported yet; use admin_password_file"
                    .into(),
            );
        }
        let file = spec
            .admin_password_file
            .as_deref()
            .ok_or("bootstrap needs admin_password_file")?;
        let admin_password = secret::read(file).await?;
        let admin_database = spec
            .default_database
            .clone()
            .or_else(|| {
                spec.bootstrap
                    .iter()
                    .flat_map(|r| &r.grants)
                    .map(|g| g.database.clone())
                    .next()
            })
            .ok_or("bootstrap needs default_database or at least one grant")?;
        if !spec.iam_auth && spec.password_dir.is_none() {
            return Err("secret mode needs password_dir".into());
        }
        Ok(Self {
            resource: resource.to_owned(),
            engine,
            target: Target::from_spec(spec, allow_insecure).await?,
            admin_user,
            admin_password,
            admin_database,
            roles: spec.bootstrap.clone(),
            password_dir: spec.password_dir.clone(),
            iam: spec.iam_auth,
        })
    }
}

/// One change (or, in check mode, one difference).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    pub database: String,
    pub role: String,
    /// `create_role`, `alter_role`, `revoke_membership`, `reset_password`,
    /// `grant`, `default_privileges`.
    pub kind: &'static str,
    /// Human text. Never holds a secret.
    pub detail: String,
    /// Whether it was made (false in check mode or on failure).
    pub applied: bool,
    pub error: Option<String>,
}

#[derive(Debug, Default)]
pub struct Report {
    pub actions: Vec<Action>,
}

impl Report {
    #[must_use]
    pub fn failed(&self) -> Vec<&Action> {
        self.actions.iter().filter(|a| a.error.is_some()).collect()
    }
}

/// Quote an identifier. PostgreSQL doubles embedded quotes.
#[must_use]
pub fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Quote a string literal (requires `standard_conforming_strings = on`,
/// which `reconcile` checks).
#[must_use]
pub fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn same_set(a: &str, b: &str) -> bool {
    a.chars().collect::<BTreeSet<_>>() == b.chars().collect::<BTreeSet<_>>()
}

/// A connection to either engine, with the few calls bootstrap needs.
enum AnyClient {
    Pg(Client),
    My(mysqlclient::Client),
}

impl AnyClient {
    async fn query(&mut self, sql: &str) -> Result<Vec<Row>, QueryError> {
        match self {
            AnyClient::Pg(c) => c.query(sql).await,
            AnyClient::My(c) => c.query(sql).await,
        }
    }

    async fn execute(&mut self, sql: &str) -> Result<(), QueryError> {
        self.query(sql).await.map(|_| ())
    }

    async fn scalar(&mut self, sql: &str) -> Result<Option<String>, QueryError> {
        Ok(self
            .query(sql)
            .await?
            .into_iter()
            .next()
            .and_then(|r| r.into_iter().next())
            .flatten())
    }

    async fn close(self) {
        match self {
            AnyClient::Pg(c) => c.close().await,
            AnyClient::My(c) => c.close().await,
        }
    }
}

struct Reconciler<'a> {
    plan: &'a Plan,
    apply: bool,
    emitter: Option<&'a Emitter>,
    clients: HashMap<String, AnyClient>,
    report: Report,
}

/// Reconcile a PostgreSQL-protocol resource. `apply: false` only reports.
///
/// # Errors
/// If the admin can't connect, or an event can't be written.
pub async fn reconcile(
    plan: &Plan,
    emitter: Option<&Emitter>,
    apply: bool,
) -> Result<Report, String> {
    let mut r = Reconciler {
        plan,
        apply,
        emitter,
        clients: HashMap::new(),
        report: Report::default(),
    };
    let result = if plan.engine == Engine::Mysql {
        r.run_mysql().await
    } else {
        r.run().await
    };
    for (_, c) in r.clients.drain() {
        c.close().await;
    }
    result.map(|()| r.report)
}

impl Reconciler<'_> {
    async fn client(&mut self, database: &str) -> Result<&mut AnyClient, String> {
        if !self.clients.contains_key(database) {
            let (target, user, password) = (
                &self.plan.target,
                &self.plan.admin_user,
                &self.plan.admin_password,
            );
            let c = if self.plan.engine == Engine::Mysql {
                mysqlclient::Client::connect(target, user, password, database, "limen-bootstrap")
                    .await
                    .map(AnyClient::My)
            } else {
                Client::connect(target, user, password, database, "limen-bootstrap")
                    .await
                    .map(AnyClient::Pg)
            }
            .map_err(|e| format!("connecting to {database} as {user}: {e}"))?;
            self.clients.insert(database.to_owned(), c);
        }
        Ok(self.clients.get_mut(database).expect("just inserted"))
    }

    async fn query(
        &mut self,
        database: &str,
        sql: &str,
    ) -> Result<Vec<Vec<Option<String>>>, String> {
        self.client(database)
            .await?
            .query(sql)
            .await
            .map_err(|e| e.to_string())
    }

    async fn scalar(&mut self, database: &str, sql: &str) -> Result<Option<String>, String> {
        self.client(database)
            .await?
            .scalar(sql)
            .await
            .map_err(|e: QueryError| e.to_string())
    }

    /// Record, audit, and (when applying) make one change. A failure to
    /// audit stops the whole run; a failure of the SQL is recorded and the
    /// run goes on.
    async fn act(
        &mut self,
        database: &str,
        role: &str,
        kind: &'static str,
        detail: String,
        sql: Vec<String>,
    ) -> Result<(), String> {
        if let Some(emitter) = self.emitter {
            emitter
                .emit(
                    EventKind::DbBootstrap,
                    Context::default(),
                    json!({
                        "resource": self.plan.resource,
                        "database": database,
                        "db_role": role,
                        "action": kind,
                        "detail": detail,
                        "mode": if self.apply { "apply" } else { "check" },
                    }),
                )
                .await
                .map_err(|e| format!("audit unavailable, not changing anything: {e}"))?;
        }
        let mut action = Action {
            database: database.to_owned(),
            role: role.to_owned(),
            kind,
            detail,
            applied: false,
            error: None,
        };
        if self.apply {
            let result = async {
                let client = self.client(database).await?;
                for statement in &sql {
                    client.execute(statement).await.map_err(|e| e.to_string())?;
                }
                Ok::<(), String>(())
            }
            .await;
            match result {
                Ok(()) => action.applied = true,
                Err(e) => action.error = Some(e),
            }
        }
        self.report.actions.push(action);
        Ok(())
    }

    async fn run(&mut self) -> Result<(), String> {
        let admin_db = self.plan.admin_database.clone();
        let scs = self
            .scalar(&admin_db, "SHOW standard_conforming_strings")
            .await?;
        if scs.as_deref() != Some("on") {
            return Err(
                "standard_conforming_strings is off; refusing to build SQL literals".into(),
            );
        }
        let roles = self.plan.roles.clone();
        for spec in &roles {
            if !limen_policy::valid_db_role(&spec.role) {
                return Err(format!("{:?} is not a limen_* role", spec.role));
            }
            let exists = self.role(&spec.role).await?;
            for grant in &spec.grants {
                self.grants(&spec.role, grant, exists).await?;
            }
        }
        Ok(())
    }

    /// Create the role or repair its attributes, membership, and password.
    /// Returns whether it exists afterwards (in check mode, whether it did).
    async fn role(&mut self, role: &str) -> Result<bool, String> {
        let db = self.plan.admin_database.clone();
        let q = quote_ident(role);
        let lit = quote_literal(role);
        let flags = self
            .query(
                &db,
                &format!("SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls FROM pg_roles WHERE rolname = {lit}"),
            )
            .await?;
        let Some(row) = flags.first() else {
            return self.create_role(role).await.map(|()| self.apply);
        };
        let is = |i: usize| row.get(i).and_then(|v| v.as_deref()) == Some("t");
        let (login, risky) = (is(0), is(1) || is(2) || is(3) || is(4) || is(5));
        if !login || risky {
            self.act(
                &db,
                role,
                "alter_role",
                "role had login off, or superuser, createdb, createrole, replication, or bypassrls on".into(),
                vec![format!("ALTER ROLE {q} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS")],
            )
            .await?;
        }
        // Membership in other roles is how SET ROLE escalates (ADR-0033
        // section 4). Only `rds_iam` is allowed, and only with IAM auth.
        let members = self
            .query(
                &db,
                &format!("SELECT r.rolname FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = {lit}"),
            )
            .await?;
        for m in members
            .iter()
            .filter_map(|r| r.first().and_then(Clone::clone))
        {
            let allowed = self.plan.iam && self.plan.engine == Engine::Postgres && m == "rds_iam";
            if !allowed {
                self.act(
                    &db,
                    role,
                    "revoke_membership",
                    format!("role was a member of {m}"),
                    vec![format!("REVOKE {} FROM {q}", quote_ident(&m))],
                )
                .await?;
            }
        }
        if self.plan.iam {
            let has = self
                .scalar(&db, &format!("SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = {lit} AND r.rolname = 'rds_iam'"))
                .await?;
            if has.is_none() && self.plan.engine == Engine::Postgres {
                self.act(
                    &db,
                    role,
                    "alter_role",
                    "role lacked rds_iam".into(),
                    vec![format!("GRANT rds_iam TO {q}")],
                )
                .await?;
            }
        } else {
            self.check_password(role).await?;
        }
        Ok(true)
    }

    async fn create_role(&mut self, role: &str) -> Result<(), String> {
        let db = self.plan.admin_database.clone();
        let q = quote_ident(role);
        let attrs = "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS";
        if self.plan.iam {
            let mut sql = vec![format!("CREATE ROLE {q} {attrs}")];
            if self.plan.engine == Engine::Postgres {
                sql.push(format!("GRANT rds_iam TO {q}"));
            }
            return self
                .act(
                    &db,
                    role,
                    "create_role",
                    "created with IAM authentication".into(),
                    sql,
                )
                .await;
        }
        let dir = self
            .plan
            .password_dir
            .clone()
            .ok_or("secret mode needs password_dir")?;
        let path = PathBuf::from(&dir).join(role);
        let password = if self.apply {
            existing_or_new_password(&path).await?
        } else {
            Secret::new(String::new())
        };
        self.act(
            &db,
            role,
            "create_role",
            format!("created; password in {}", path.display()),
            vec![format!(
                "CREATE ROLE {q} {attrs} PASSWORD {}",
                quote_literal(password.expose())
            )],
        )
        .await
    }

    /// Secret mode: the file must hold the password the database has.
    async fn check_password(&mut self, role: &str) -> Result<(), String> {
        let db = self.plan.admin_database.clone();
        let dir = self
            .plan
            .password_dir
            .clone()
            .ok_or("secret mode needs password_dir")?;
        let path = PathBuf::from(&dir).join(role);
        let current = secret::read(&path.display().to_string()).await.ok();
        let works = match &current {
            Some(pw) => Client::connect(&self.plan.target, role, pw, &db, "limen-bootstrap-check")
                .await
                .is_ok(),
            None => false,
        };
        if works {
            return Ok(());
        }
        let password = if self.apply {
            let fresh = Secret::new(random_password());
            write_secret(&path, fresh.expose()).await?;
            fresh
        } else {
            Secret::new(String::new())
        };
        let why = if current.is_some() {
            "the password file doesn't match the database"
        } else {
            "no password file"
        };
        self.act(
            &db,
            role,
            "reset_password",
            format!("{why}; new password in {}", path.display()),
            vec![format!(
                "ALTER ROLE {} PASSWORD {}",
                quote_ident(role),
                quote_literal(password.expose())
            )],
        )
        .await
    }

    async fn grants(
        &mut self,
        role: &str,
        grant: &limen_policy::model::DbGrantSpec,
        role_exists: bool,
    ) -> Result<(), String> {
        let db = grant.database.clone();
        let q = quote_ident(role);
        let lit = quote_literal(role);
        let schemas: Vec<String> = if grant.schemas.is_empty() {
            vec!["public".to_owned()]
        } else {
            grant.schemas.clone()
        };
        let write = grant.access == DbAccess::Write;
        let (want, excess): (&[&str], &[&str]) = if write {
            (
                &["SELECT", "INSERT", "UPDATE", "DELETE"],
                &["TRUNCATE", "REFERENCES", "TRIGGER"],
            )
        } else {
            (
                &["SELECT"],
                &[
                    "INSERT",
                    "UPDATE",
                    "DELETE",
                    "TRUNCATE",
                    "REFERENCES",
                    "TRIGGER",
                ],
            )
        };
        // Without the role (check mode before creation) there is nothing to
        // compare: every grant is missing.
        let connect_ok = role_exists
            && self
                .scalar(
                    &db,
                    &format!(
                        "SELECT has_database_privilege({lit}, {}, 'CONNECT')",
                        quote_literal(&db)
                    ),
                )
                .await?
                .as_deref()
                == Some("t");
        if !connect_ok {
            self.act(
                &db,
                role,
                "grant",
                format!("CONNECT on database {db}"),
                vec![format!(
                    "GRANT CONNECT ON DATABASE {} TO {q}",
                    quote_ident(&db)
                )],
            )
            .await?;
        }
        for schema in &schemas {
            let qs = quote_ident(schema);
            let usage = role_exists
                && self
                    .scalar(
                        &db,
                        &format!(
                            "SELECT has_schema_privilege({lit}, {}, 'USAGE')",
                            quote_literal(schema)
                        ),
                    )
                    .await?
                    .as_deref()
                    == Some("t");
            if !usage {
                self.act(
                    &db,
                    role,
                    "grant",
                    format!("USAGE on schema {schema}"),
                    vec![format!("GRANT USAGE ON SCHEMA {qs} TO {q}")],
                )
                .await?;
            }
            let kinds = "'r','p','v','m','f'";
            let in_schema = format!(
                "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = {} AND c.relkind IN ({kinds})",
                quote_literal(schema)
            );
            let cond = |privs: &[&str], missing: bool| {
                privs
                    .iter()
                    .map(|p| {
                        let f = format!("has_table_privilege({lit}, c.oid, '{p}')");
                        if missing { format!("NOT {f}") } else { f }
                    })
                    .collect::<Vec<_>>()
                    .join(" OR ")
            };
            let (missing, extra) = if role_exists {
                let m = self
                    .scalar(
                        &db,
                        &format!("SELECT count(*) {in_schema} AND ({})", cond(want, true)),
                    )
                    .await?;
                let e = self
                    .scalar(
                        &db,
                        &format!("SELECT count(*) {in_schema} AND ({})", cond(excess, false)),
                    )
                    .await?;
                (m.as_deref() != Some("0"), e.as_deref() != Some("0"))
            } else {
                (true, false)
            };
            if missing || extra {
                let privileges = want.join(", ");
                let mut sql = Vec::new();
                if extra {
                    sql.push(format!("REVOKE ALL ON ALL TABLES IN SCHEMA {qs} FROM {q}"));
                }
                sql.push(format!(
                    "GRANT {privileges} ON ALL TABLES IN SCHEMA {qs} TO {q}"
                ));
                if write {
                    sql.push(format!(
                        "GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA {qs} TO {q}"
                    ));
                }
                self.act(
                    &db,
                    role,
                    "grant",
                    format!("{privileges} on tables in {db}.{schema}"),
                    sql,
                )
                .await?;
            }
            self.default_privileges(role, &db, schema, write, role_exists)
                .await?;
        }
        Ok(())
    }

    /// Tables created later by the admin get the same grants.
    async fn default_privileges(
        &mut self,
        role: &str,
        db: &str,
        schema: &str,
        write: bool,
        role_exists: bool,
    ) -> Result<(), String> {
        let admin = self.plan.admin_user.clone();
        let (q, qs, qa) = (quote_ident(role), quote_ident(schema), quote_ident(&admin));
        let current = |kind: &str| {
            format!(
                "SELECT split_part(split_part(acl::text, '=', 2), '/', 1) FROM pg_default_acl d JOIN pg_namespace n ON n.oid = d.defaclnamespace JOIN pg_roles o ON o.oid = d.defaclrole, unnest(d.defaclacl) AS acl WHERE o.rolname = {} AND n.nspname = {} AND d.defaclobjtype = '{kind}' AND split_part(acl::text, '=', 1) = {}",
                quote_literal(&admin),
                quote_literal(schema),
                quote_literal(role),
            )
        };
        let (tables_now, sequences_now) = if role_exists {
            (
                self.scalar(db, &current("r")).await?,
                self.scalar(db, &current("S")).await?,
            )
        } else {
            (None, None)
        };
        let tables_want = if write { "arwd" } else { "r" };
        if !tables_now
            .as_deref()
            .is_some_and(|c| same_set(c, tables_want))
        {
            let list = if write {
                "SELECT, INSERT, UPDATE, DELETE"
            } else {
                "SELECT"
            };
            self.act(
                db,
                role,
                "default_privileges",
                format!("future tables of {admin} in {db}.{schema} get {list}"),
                vec![
                    format!("ALTER DEFAULT PRIVILEGES FOR ROLE {qa} IN SCHEMA {qs} REVOKE ALL ON TABLES FROM {q}"),
                    format!("ALTER DEFAULT PRIVILEGES FOR ROLE {qa} IN SCHEMA {qs} GRANT {list} ON TABLES TO {q}"),
                ],
            )
            .await?;
        }
        if write && !sequences_now.as_deref().is_some_and(|c| same_set(c, "rwU")) {
            self.act(
                db,
                role,
                "default_privileges",
                format!("future sequences of {admin} in {db}.{schema} get USAGE, SELECT, UPDATE"),
                vec![
                    format!("ALTER DEFAULT PRIVILEGES FOR ROLE {qa} IN SCHEMA {qs} REVOKE ALL ON SEQUENCES FROM {q}"),
                    format!("ALTER DEFAULT PRIVILEGES FOR ROLE {qa} IN SCHEMA {qs} GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO {q}"),
                ],
            )
            .await?;
        }
        Ok(())
    }
}

/// 256 random bits, hex.
fn random_password() -> String {
    use std::fmt::Write as _;
    rand::random::<[u8; 32]>()
        .iter()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// The password already in `path`, or a new one written there first, so a
/// crash between writing and `CREATE ROLE` loses nothing.
async fn existing_or_new_password(path: &Path) -> Result<Secret<String>, String> {
    if let Ok(existing) = secret::read(&path.display().to_string()).await {
        return Ok(existing);
    }
    let fresh = random_password();
    write_secret(path, &fresh).await?;
    Ok(Secret::new(fresh))
}

/// Write a secret file atomically with mode 0600 (its directory 0700).
async fn write_secret(path: &Path, value: &str) -> Result<(), String> {
    let dir = path.parent().ok_or("password path has no directory")?;
    tokio::fs::create_dir_all(dir)
        .await
        .map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".tmp-{}", uuid::Uuid::now_v7().simple()));
    let result = async {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            let value = value.to_owned();
            let tmp2 = tmp.clone();
            tokio::task::spawn_blocking(move || {
                use std::io::Write as _;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&tmp2)?;
                f.write_all(value.as_bytes())?;
                f.sync_all()
            })
            .await
            .map_err(std::io::Error::other)??;
        }
        #[cfg(not(unix))]
        tokio::fs::write(&tmp, value).await?;
        tokio::fs::rename(&tmp, path).await
    }
    .await;
    if let Err(e) = result {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(format!("writing {}: {e}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_defeats_injection() {
        assert_eq!(quote_ident("limen_ro"), "\"limen_ro\"");
        assert_eq!(quote_ident("a\"b"), "\"a\"\"b\"");
        assert_eq!(quote_literal("o'brien"), "'o''brien'");
        assert_eq!(
            quote_literal("x'; DROP ROLE y; --"),
            "'x''; DROP ROLE y; --'"
        );
    }

    #[test]
    fn privilege_strings_compare_as_sets() {
        assert!(same_set("rwda", "arwd"));
        assert!(same_set("rwU", "Urw"));
        assert!(!same_set("r", "arwd"));
    }

    #[test]
    fn generated_passwords_are_long_and_distinct() {
        let (a, b) = (random_password(), random_password());
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn secret_files_are_private_and_never_overwritten_by_existing_or_new() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("secrets").join("limen_x");
        let first = existing_or_new_password(&path).await.expect("first");
        let second = existing_or_new_password(&path).await.expect("second");
        assert_eq!(first.expose(), second.expose());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
