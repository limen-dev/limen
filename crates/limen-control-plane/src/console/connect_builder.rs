//! The command builder on a resource page: which login, role or user you can act as, what that
//! lets you open, and the exact `limen` command for the choice. Pure and tested.
//!
//! Rules this module keeps:
//! - Only flags the CLI documents are emitted (`docs/cli-reference.md`; a test checks each one
//!   against it), and only for the kinds that take them.
//! - Every value that reaches a command line is plain (`[A-Za-z0-9_.-]`, and `/` in a vhost, not
//!   starting with `-`), so a copied command never needs quoting or reads as an option.
//! - A value the person's access doesn't allow produces no command, only a sentence saying so.
//! - The access shown is what the held roles grant. The proxy and workers still decide every
//!   request; this only shows what is on offer.

use limen_policy::GrantScope;

/// What the person typed or picked, straight from the query string. Nothing here is trusted.
#[derive(Debug, Default, Clone)]
pub struct Picks {
    pub who: Option<String>,
    pub database: Option<String>,
    pub vhost: Option<String>,
    pub port: Option<String>,
}

/// One choice in a dropdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opt {
    pub value: String,
    pub label: String,
    pub selected: bool,
}

/// One input of the builder: a dropdown, or a text box when the access is a pattern or a wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// The query parameter.
    pub name: &'static str,
    pub label: String,
    /// Empty for a text box.
    pub options: Vec<Opt>,
    pub value: String,
    pub placeholder: String,
    pub hint: String,
}

impl Field {
    #[must_use]
    pub fn is_select(&self) -> bool {
        !self.options.is_empty()
    }
}

/// A fact about what the chosen identity may do, for the reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    pub label: &'static str,
    pub text: String,
}

/// What the page shows under the Connect card.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Builder {
    pub fields: Vec<Field>,
    /// The command for the current choices; `None` while a choice is missing or refused.
    pub command: Option<String>,
    /// Why there is no command: a missing choice (a hint) or a refused one (a problem).
    pub note: Option<String>,
    pub refused: bool,
    pub facts: Vec<Fact>,
}

/// How a kind's command takes its choices. `None` for kinds the plain command covers.
struct Spec {
    who_flag: Option<&'static str>,
    who_label: &'static str,
    database: bool,
    vhost: bool,
    listen: bool,
}

fn spec(kind: &str) -> Option<Spec> {
    let s = |who_flag, who_label, database, vhost, listen| {
        Some(Spec {
            who_flag,
            who_label,
            database,
            vhost,
            listen,
        })
    };
    match kind {
        "postgres" | "mysql" | "redshift" => {
            s(Some("--db-role"), "Database role", true, false, true)
        }
        "mongodb" => s(Some("--role"), "MongoDB role", true, false, true),
        "redis" => s(Some("--user"), "Redis user", false, false, true),
        "opensearch" | "elasticsearch" => s(Some("--role"), "Engine role", false, false, true),
        "rabbitmq" => s(Some("--user"), "Broker user", false, true, true),
        "kafka" => s(Some("--user"), "Broker user", false, false, true),
        // Kubernetes, web apps, TCP and SSH have nothing to choose on the command.
        _ => None,
    }
}

/// The flag that names who you act as, for the kinds that take one. The quick commands on the
/// Connect card use it too.
#[must_use]
pub fn who_flag(kind: &str) -> Option<&'static str> {
    spec(kind).and_then(|s| s.who_flag)
}

/// A value that may go on a command line as it is.
#[must_use]
pub fn plain_value(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && !v.starts_with('-')
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// A virtual host as it may go on a command line: `/` is the default vhost's whole name.
fn plain_vhost(v: &str) -> bool {
    v == "/"
        || (!v.is_empty()
            && v.len() <= 64
            && !v.starts_with('-')
            && v.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '/')))
}

/// `*` is the only wildcard, as in policy.
fn glob(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or("");
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    let mut tail = parts.collect::<Vec<_>>();
    let Some(last) = tail.pop() else {
        return rest.is_empty();
    };
    for mid in tail {
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    rest.ends_with(last) && rest.len() >= last.len()
}

fn allows(patterns: &[String], value: &str) -> bool {
    patterns.iter().any(|p| p == "*" || glob(p, value))
}

fn listed(items: &[String], any: &str) -> String {
    if items.iter().any(|i| i == "*") {
        any.to_owned()
    } else {
        items.join(", ")
    }
}

fn blank(v: Option<&String>) -> &str {
    v.map_or("", |s| s.trim())
}

/// The builder for `kind`, given what the viewer's roles grant and what they picked. `None` when
/// the page needs nothing beyond the plain command (SSH, TCP, and anything without a grant).
#[must_use]
pub fn build(kind: &str, name: &str, scopes: &[GrantScope], picks: &Picks) -> Option<Builder> {
    if matches!(kind, "kubernetes" | "web") {
        return facts_only(kind, scopes);
    }
    let spec = spec(kind)?;
    // A name that can't go on a command line is left out; if that leaves nothing the plain
    // command on the Connect card is all there is.
    let usable: Vec<&GrantScope> = scopes
        .iter()
        .filter(|s| plain_value(&s.principal))
        .collect();
    if usable.is_empty() {
        return None;
    }
    let mut b = Builder::default();
    let several = usable.len() > 1;
    let who = blank(picks.who.as_ref());
    let chosen: Option<&GrantScope> = if several {
        usable.iter().find(|s| s.principal == who).copied()
    } else {
        usable.first().copied()
    };
    if several {
        let mut options = vec![Opt {
            value: String::new(),
            label: "Choose…".to_owned(),
            selected: chosen.is_none() && who.is_empty(),
        }];
        options.extend(usable.iter().map(|s| Opt {
            value: s.principal.clone(),
            label: s.principal.clone(),
            selected: chosen.is_some_and(|c| c.principal == s.principal),
        }));
        b.fields.push(Field {
            name: "who",
            label: spec.who_label.to_owned(),
            options,
            value: String::new(),
            placeholder: String::new(),
            hint: String::new(),
        });
    }
    let mut command = crate::console::views::connect_for(kind, name).command;
    if several && !who.is_empty() && chosen.is_none() {
        return Some(refuse(
            b,
            format!(
                "Your access doesn't include {} as a {}.",
                shown(who),
                spec.who_label.to_lowercase()
            ),
        ));
    }
    let Some(scope) = chosen else {
        b.note = Some(format!(
            "Choose a {} to see the command.",
            spec.who_label.to_lowercase()
        ));
        return Some(b);
    };
    if several && let Some(flag) = spec.who_flag {
        add_flag(&mut command, flag, &scope.principal);
    }
    let results = [
        spec.database
            .then(|| ("--database", database_field(&scope.databases, picks))),
        spec.vhost
            .then(|| ("--vhost", vhost_field(&scope.vhosts, picks))),
        spec.listen.then(|| ("--listen", port_field(picks))),
    ];
    for (flag, result) in results.into_iter().flatten() {
        match result {
            Ok((field, value)) => {
                b.fields.push(field);
                if let Some(v) = value {
                    add_flag(&mut command, flag, &v);
                }
            }
            Err((field, why)) => {
                b.fields.push(field);
                return Some(refuse(b, why));
            }
        }
    }
    b.facts = facts(kind, scope);
    b.command = Some(command);
    Some(b)
}

/// A refused value, cut short, for the sentence that says it was refused. The template escapes it.
fn add_flag(command: &mut String, flag: &str, value: &str) {
    command.push(' ');
    command.push_str(flag);
    command.push(' ');
    command.push_str(value);
}

fn shown(v: &str) -> String {
    v.chars().take(40).collect()
}

fn refuse(mut b: Builder, why: String) -> Builder {
    b.command = None;
    b.note = Some(why);
    b.refused = true;
    b
}

type FieldResult = Result<(Field, Option<String>), (Field, String)>;

fn text_field(
    name: &'static str,
    label: &str,
    value: &str,
    placeholder: &str,
    hint: &str,
) -> Field {
    Field {
        name,
        label: label.to_owned(),
        options: Vec::new(),
        value: value.to_owned(),
        placeholder: placeholder.to_owned(),
        hint: hint.to_owned(),
    }
}

fn select_field(
    name: &'static str,
    label: &str,
    empty: &str,
    values: &[String],
    current: &str,
) -> Field {
    let mut options = vec![Opt {
        value: String::new(),
        label: empty.to_owned(),
        selected: current.is_empty(),
    }];
    options.extend(values.iter().map(|v| Opt {
        value: v.clone(),
        label: v.clone(),
        selected: v == current,
    }));
    Field {
        name,
        label: label.to_owned(),
        options,
        value: current.to_owned(),
        placeholder: String::new(),
        hint: String::new(),
    }
}

fn database_field(allowed: &[String], picks: &Picks) -> FieldResult {
    let value = blank(picks.database.as_ref());
    let any = allowed.iter().any(|d| d == "*");
    let field = if any {
        text_field(
            "database",
            "Database",
            value,
            "default database",
            "This role may open any database. Leave empty for the resource's default.",
        )
    } else {
        select_field("database", "Database", "Default", allowed, value)
    };
    if value.is_empty() {
        return Ok((field, None));
    }
    if !plain_value(value) {
        return Err((
            field,
            "A database name here has letters, digits, _ . - only.".to_owned(),
        ));
    }
    if !any && !allowed.iter().any(|d| d == value) {
        return Err((field, format!("This role may not open {}.", shown(value))));
    }
    Ok((field, Some(value.to_owned())))
}

fn vhost_field(allowed: &[String], picks: &Picks) -> FieldResult {
    let value = blank(picks.vhost.as_ref());
    let patterned = allowed.iter().any(|v| v.contains('*'));
    let field = if patterned {
        text_field(
            "vhost",
            "Virtual host",
            value,
            "/",
            &format!("Allowed: {}.", listed(allowed, "any")),
        )
    } else {
        select_field("vhost", "Virtual host", "Default (/)", allowed, value)
    };
    if value.is_empty() {
        return Ok((field, None));
    }
    if !plain_vhost(value) {
        return Err((
            field,
            "A virtual host here has letters, digits, _ . - and / only.".to_owned(),
        ));
    }
    if !allows(allowed, value) {
        return Err((
            field,
            format!("This user may not use the virtual host {}.", shown(value)),
        ));
    }
    Ok((field, Some(value.to_owned())))
}

fn port_field(picks: &Picks) -> FieldResult {
    let value = blank(picks.port.as_ref());
    let field = text_field(
        "port",
        "Local port",
        value,
        "any free port",
        "The port the tunnel listens on, on this machine only.",
    );
    if value.is_empty() {
        return Ok((field, None));
    }
    match value.parse::<u16>() {
        Ok(p) if p >= 1024 && value.chars().all(|c| c.is_ascii_digit()) => {
            Ok((field, Some(format!("127.0.0.1:{p}"))))
        }
        _ => Err((
            field,
            "A local port is a number from 1024 to 65535.".to_owned(),
        )),
    }
}

/// What the chosen identity may do, in the words of the kind.
fn facts(kind: &str, s: &GrantScope) -> Vec<Fact> {
    let mut out = Vec::new();
    let mut add = |label, text: String| out.push(Fact { label, text });
    match kind {
        "postgres" | "mysql" | "redshift" | "mongodb" => {
            add("Databases", listed(&s.databases, "any database"));
        }
        "redis" => {
            add(
                "Logical databases",
                s.numbers
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            add("Keys", listed(&s.patterns, "any key"));
        }
        "opensearch" | "elasticsearch" => {
            add("May do", s.classes.join(", "));
            add(
                "Indices",
                listed(&s.patterns, "any index that isn't hidden"),
            );
        }
        "rabbitmq" => {
            add("May do", s.classes.join(", "));
            add("Virtual hosts", listed(&s.vhosts, "any"));
            add(
                "Exchanges and queues",
                listed(&s.patterns, "any except amq.*"),
            );
        }
        "kafka" => {
            add("May do", s.classes.join(", "));
            add("Topics", listed(&s.patterns, "any that isn't internal"));
            add("Consumer groups", listed(&s.groups, "any"));
        }
        _ => {}
    }
    out
}

/// Kubernetes and web apps: nothing to pick on the command, but what the access is.
fn facts_only(kind: &str, scopes: &[GrantScope]) -> Option<Builder> {
    if scopes.is_empty() {
        return None;
    }
    let mut b = Builder::default();
    if kind == "kubernetes" {
        let groups: Vec<String> = scopes.iter().map(|s| s.principal.clone()).collect();
        b.facts.push(Fact {
            label: "Groups you can act as in the cluster",
            text: groups.join(", "),
        });
    } else {
        let all = |f: fn(&GrantScope) -> &Vec<String>| {
            let mut v: Vec<String> = scopes.iter().flat_map(|s| f(s).clone()).collect();
            v.sort();
            v.dedup();
            v
        };
        b.facts.push(Fact {
            label: "Methods",
            text: listed(&all(|s| &s.classes), "any"),
        });
        b.facts.push(Fact {
            label: "Paths",
            text: listed(&all(|s| &s.patterns), "any"),
        });
    }
    Some(b)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn scope(p: &str) -> GrantScope {
        GrantScope {
            principal: p.to_owned(),
            ..GrantScope::default()
        }
    }

    fn db(p: &str, dbs: &[&str]) -> GrantScope {
        GrantScope {
            databases: dbs.iter().map(|d| (*d).to_owned()).collect(),
            ..scope(p)
        }
    }

    fn picks(who: &str, database: &str, vhost: &str, port: &str) -> Picks {
        let some = |s: &str| (!s.is_empty()).then(|| s.to_owned());
        Picks {
            who: some(who),
            database: some(database),
            vhost: some(vhost),
            port: some(port),
        }
    }

    fn cmd(b: &Builder) -> String {
        b.command.clone().expect("a command")
    }

    #[test]
    fn globs_use_only_star() {
        assert!(glob("app-*", "app-x"));
        assert!(glob("app-*", "app-"));
        assert!(!glob("app-*", "ap"));
        assert!(glob("*-x", "a-x"));
        assert!(!glob("*-x", "x"));
        assert!(glob("a*b*c", "aXbYc"));
        assert!(!glob("a*b*c", "aXcYb"));
        assert!(glob("exact", "exact"));
        assert!(!glob("exact", "exactly"));
        assert!(glob("*", "anything"));
    }

    #[test]
    fn one_database_role_needs_no_flag_and_several_need_a_choice() {
        let one = build(
            "postgres",
            "orders",
            &[db("app", &["orders"])],
            &Picks::default(),
        )
        .unwrap();
        assert_eq!(cmd(&one), "limen db connect orders");
        let two = [db("ro", &["orders"]), db("rw", &["orders"])];
        let b = build("postgres", "orders", &two, &Picks::default()).unwrap();
        assert!(b.command.is_none() && !b.refused);
        assert!(
            b.note
                .as_deref()
                .unwrap()
                .contains("Choose a database role")
        );
        let b = build("postgres", "orders", &two, &picks("rw", "", "", "")).unwrap();
        assert_eq!(cmd(&b), "limen db connect orders --db-role rw");
    }

    #[test]
    fn a_database_is_offered_from_the_role_and_refused_otherwise() {
        let s = [db("ro", &["orders", "billing"])];
        let b = build("postgres", "orders", &s, &picks("", "billing", "", "")).unwrap();
        assert_eq!(cmd(&b), "limen db connect orders --database billing");
        let f = b.fields.iter().find(|f| f.name == "database").unwrap();
        assert!(f.is_select());
        assert!(f.options.iter().any(|o| o.value == "billing" && o.selected));
        let b = build("postgres", "orders", &s, &picks("", "secret", "", "")).unwrap();
        assert!(b.command.is_none() && b.refused);
        assert!(b.note.unwrap().contains("may not open secret"));
    }

    #[test]
    fn a_wildcard_database_is_a_text_box_checked_for_plain_names() {
        let s = [db("ro", &["*"])];
        let b = build("mongodb", "orders", &s, &picks("", "anything", "", "")).unwrap();
        assert_eq!(cmd(&b), "limen mongo connect orders --database anything");
        assert!(
            !b.fields
                .iter()
                .find(|f| f.name == "database")
                .unwrap()
                .is_select()
        );
        for bad in ["a b", "x;y", "$(id)", "--x", "a/b", "é"] {
            let b = build("mongodb", "orders", &s, &picks("", bad, "", "")).unwrap();
            assert!(b.command.is_none() && b.refused, "{bad}");
        }
    }

    #[test]
    fn each_kind_uses_its_own_flag() {
        let two = |kind: &str| {
            let s = [scope("a"), scope("b")];
            cmd(&build(kind, "orders", &s, &picks("b", "", "", "")).unwrap())
        };
        assert_eq!(two("redis"), "limen redis connect orders --user b");
        assert_eq!(two("mongodb"), "limen mongo connect orders --role b");
        assert_eq!(two("opensearch"), "limen search connect orders --role b");
        assert_eq!(two("elasticsearch"), "limen search connect orders --role b");
        assert_eq!(two("rabbitmq"), "limen mq connect orders --user b");
        assert_eq!(two("kafka"), "limen kafka connect orders --user b");
        assert_eq!(two("mysql"), "limen db connect orders --db-role b");
    }

    #[test]
    fn someone_you_cannot_act_as_is_refused() {
        let s = [scope("a"), scope("b")];
        let b = build("redis", "orders", &s, &picks("root", "", "", "")).unwrap();
        assert!(b.command.is_none() && b.refused);
        assert!(b.note.unwrap().contains("doesn't include root"));
    }

    #[test]
    fn a_vhost_is_checked_against_the_patterns() {
        let mut u = scope("worker");
        u.vhosts = vec!["billing-*".to_owned(), "jobs".to_owned()];
        let s = [u];
        let b = build("rabbitmq", "orders", &s, &picks("", "", "billing-eu", "")).unwrap();
        assert_eq!(cmd(&b), "limen mq connect orders --vhost billing-eu");
        let b = build("rabbitmq", "orders", &s, &picks("", "", "other", "")).unwrap();
        assert!(b.refused);
        let b = build("rabbitmq", "orders", &s, &picks("", "", "billing-a b", "")).unwrap();
        assert!(b.refused);
    }

    #[test]
    fn a_literal_vhost_list_is_a_dropdown_and_the_root_vhost_is_plain() {
        let mut u = scope("worker");
        u.vhosts = vec!["/".to_owned()];
        let b = build("rabbitmq", "orders", &[u.clone()], &picks("", "", "/", "")).unwrap();
        assert_eq!(cmd(&b), "limen mq connect orders --vhost /");
        assert!(
            b.fields
                .iter()
                .find(|f| f.name == "vhost")
                .unwrap()
                .is_select()
        );
    }

    #[test]
    fn a_local_port_is_a_number_from_1024() {
        let s = [scope("a")];
        let b = build("redis", "orders", &s, &picks("", "", "", "6380")).unwrap();
        assert_eq!(
            cmd(&b),
            "limen redis connect orders --listen 127.0.0.1:6380"
        );
        for bad in [
            "80", "70000", "x", "-1", "63 80", "6380;ls", "0x10", "+6380",
        ] {
            let b = build("redis", "orders", &s, &picks("", "", "", bad)).unwrap();
            assert!(b.command.is_none() && b.refused, "{bad}");
        }
    }

    #[test]
    fn names_that_cannot_go_on_a_command_line_are_never_offered() {
        let bad = [scope("a b"), scope("--x"), scope("$(id)")];
        assert!(build("redis", "orders", &bad, &Picks::default()).is_none());
        let mixed = [scope("a b"), scope("ok")];
        let b = build("redis", "orders", &mixed, &Picks::default()).unwrap();
        // Only one usable name is left, so there is nothing to choose and no flag.
        assert_eq!(cmd(&b), "limen redis connect orders");
    }

    #[test]
    fn what_each_kind_may_do_is_shown() {
        let mut s = scope("viewer");
        s.classes = vec!["read".to_owned()];
        s.patterns = vec!["app-*".to_owned()];
        let b = build("opensearch", "orders", &[s], &Picks::default()).unwrap();
        let text: Vec<String> = b
            .facts
            .iter()
            .map(|f| format!("{}={}", f.label, f.text))
            .collect();
        assert_eq!(text, ["May do=read", "Indices=app-*"]);
        let mut k = scope("c");
        k.classes = vec!["read".to_owned()];
        k.patterns = vec!["*".to_owned()];
        k.groups = vec!["*".to_owned()];
        let b = build("kafka", "orders", &[k], &Picks::default()).unwrap();
        assert_eq!(b.facts[1].text, "any that isn't internal");
        assert_eq!(b.facts[2].text, "any");
    }

    #[test]
    fn kubernetes_and_web_show_access_and_no_inputs() {
        let b = build(
            "kubernetes",
            "orders",
            &[scope("dev"), scope("view")],
            &Picks::default(),
        )
        .unwrap();
        assert!(b.fields.is_empty() && b.command.is_none());
        assert_eq!(b.facts[0].text, "dev, view");
        let mut w = scope("access");
        w.classes = vec!["GET".to_owned()];
        w.patterns = vec!["/docs".to_owned()];
        let b = build("web", "orders", &[w], &Picks::default()).unwrap();
        assert_eq!(b.facts[0].text, "GET");
        assert_eq!(b.facts[1].text, "/docs");
    }

    #[test]
    fn ssh_tcp_and_unknown_kinds_have_no_builder() {
        let s = [scope("a")];
        for kind in ["ssh", "tcp", "other"] {
            assert!(build(kind, "orders", &s, &Picks::default()).is_none());
        }
        assert!(build("redis", "orders", &[], &Picks::default()).is_none());
        assert!(build("kubernetes", "orders", &[], &Picks::default()).is_none());
    }

    /// Every flag a command can carry exists on its subcommand in the generated CLI reference, so
    /// a renamed flag fails here, not in front of a developer.
    #[test]
    fn every_flag_exists_in_the_cli_reference() {
        let reference = include_str!("../../../../docs/cli-reference.md");
        let section = |sub: &str| {
            let head = format!("#### `limen {sub}`");
            let start = reference.find(&head).expect(sub);
            let rest = &reference[start + head.len()..];
            rest[..rest.find("\n#### ").unwrap_or(rest.len())].to_owned()
        };
        let mut s = scope("a");
        s.databases = vec!["*".to_owned()];
        s.vhosts = vec!["*".to_owned()];
        let two = [
            s.clone(),
            GrantScope {
                principal: "b".to_owned(),
                ..s
            },
        ];
        for (kind, sub) in [
            ("postgres", "db connect"),
            ("mongodb", "mongo connect"),
            ("redis", "redis connect"),
            ("opensearch", "search connect"),
            ("rabbitmq", "mq connect"),
            ("kafka", "kafka connect"),
        ] {
            let b = build(kind, "orders", &two, &picks("b", "d", "v", "6380")).unwrap();
            let c = cmd(&b);
            assert!(c.starts_with(&format!("limen {sub} ")), "{c}");
            let text = section(sub);
            for flag in c.split(' ').filter(|w| w.starts_with("--")) {
                assert!(
                    text.contains(&format!("`{flag} ")) || text.contains(&format!("`{flag}`")),
                    "{flag} not on `{sub}`"
                );
            }
        }
    }
}
