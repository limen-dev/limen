//! Pins and saved views: what may be stored, and where a redirect may go. Pure rules, so each has
//! a unit test. The data is a person's own preferences; the pages a saved view points at check
//! access themselves when they are opened, so nothing here grants anything.

/// Console pages a view may be saved for. The address must be exactly the page, or the page with a
/// query: `/console/resourcesX` and `/console/resources/web-1` are not views.
const VIEW_PAGES: [&str; 4] = [
    "/console/resources",
    "/console/sessions",
    "/console/audit",
    "/console/dashboards",
];

/// Longest address kept.
const MAX_TARGET: usize = 500;
/// Longest label kept, in characters.
const MAX_LABEL: usize = 60;

fn plain(s: &str) -> bool {
    !s.chars().any(char::is_control)
}

/// Whether `target` is a saved-view address: one of [`VIEW_PAGES`], optionally with a query, no
/// fragment, no control characters, bounded.
#[must_use]
pub fn valid_view_target(target: &str) -> bool {
    if target.len() > MAX_TARGET || !plain(target) || target.contains('#') {
        return false;
    }
    VIEW_PAGES.iter().any(|page| {
        target
            .strip_prefix(page)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('?'))
    })
}

/// Who may open the page a view is for. Saving a view is refused for anyone below it, so a
/// person's list never holds a link they can't use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Power {
    Anyone,
    /// Admins and auditors: the audit trail.
    ReadsRecord,
    Admin,
}

#[must_use]
pub fn required_power(target: &str) -> Power {
    let is = |page: &str| {
        target
            .strip_prefix(page)
            .is_some_and(|r| r.is_empty() || r.starts_with('?'))
    };
    if is("/console/dashboards") {
        Power::Admin
    } else if is("/console/audit") {
        Power::ReadsRecord
    } else {
        Power::Anyone
    }
}

/// A label for a saved view: trimmed, control characters dropped, cut to [`MAX_LABEL`] characters.
/// Empty becomes `fallback`.
#[must_use]
pub fn clean_label(label: &str, fallback: &str) -> String {
    let cleaned: String = label
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_LABEL)
        .collect();
    if cleaned.is_empty() {
        fallback.to_owned()
    } else {
        cleaned
    }
}

/// Where to go back to after pinning: only a console address on this origin. Anything else (another
/// site, a protocol-relative `//host`, a header-splitting newline) goes to the Overview.
#[must_use]
pub fn local_back(back: &str) -> String {
    if back.starts_with("/console/")
        && !back.starts_with("//")
        && back.len() <= MAX_TARGET
        && plain(back)
        && !back.contains('\\')
    {
        back.to_owned()
    } else {
        "/console/".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_view_is_a_listed_page_with_or_without_a_query() {
        assert!(valid_view_target("/console/resources"));
        assert!(valid_view_target(
            "/console/resources?kind=ssh&label=env%3Dprod"
        ));
        assert!(valid_view_target("/console/sessions?filter=active"));
        assert!(valid_view_target("/console/dashboards?p=denials"));
        for bad in [
            "/console/resources/web-1",
            "/console/resourcesX",
            "/console/users",
            "/console/logout",
            "https://evil.example/console/resources",
            "//evil.example",
            "/console/resources?x=1#frag",
            "/console/resources?x=\n1",
            "",
        ] {
            assert!(!valid_view_target(bad), "{bad:?}");
        }
        assert!(!valid_view_target(&format!(
            "/console/resources?q={}",
            "a".repeat(600)
        )));
    }

    #[test]
    fn dashboards_are_for_admins_and_the_audit_trail_for_readers_of_the_record() {
        assert_eq!(required_power("/console/dashboards?p=x"), Power::Admin);
        assert_eq!(
            required_power("/console/audit?kind=auth.denied"),
            Power::ReadsRecord
        );
        assert_eq!(required_power("/console/resources?kind=ssh"), Power::Anyone);
        assert_eq!(required_power("/console/sessions"), Power::Anyone);
        // A page whose name merely starts the same is not that page.
        assert_eq!(required_power("/console/auditx"), Power::Anyone);
    }

    #[test]
    fn labels_are_trimmed_cut_and_never_empty() {
        assert_eq!(clean_label("  Prod ssh  ", "Saved view"), "Prod ssh");
        assert_eq!(clean_label("", "Saved view"), "Saved view");
        assert_eq!(clean_label("\n\t ", "Saved view"), "Saved view");
        assert_eq!(clean_label("a\u{0}b\nc", "x"), "abc");
        assert_eq!(clean_label(&"é".repeat(100), "x").chars().count(), 60);
    }

    #[test]
    fn only_console_addresses_are_redirect_targets() {
        assert_eq!(
            local_back("/console/resources?kind=ssh"),
            "/console/resources?kind=ssh"
        );
        for bad in [
            "https://evil.example/",
            "//evil.example/console/",
            "/\\evil.example",
            "/console/\r\nSet-Cookie: x=1",
            "/elsewhere",
            "",
        ] {
            assert_eq!(local_back(bad), "/console/", "{bad:?}");
        }
    }
}
