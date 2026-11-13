//! The pure parts of the resources pages: how the list is sorted and filtered, and the links that
//! carry those choices. No database and no request, so every rule here has a unit test.

use time::OffsetDateTime;

use super::views::{Health, SortOption};

/// How the resources list is ordered. The default is by name; the other three need what only
/// admins see (everyone's sessions, worker health), except `Recent`, which for everyone else is
/// ordered by their own sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceSort {
    Name,
    Recent,
    Busiest,
    Attention,
}

impl ResourceSort {
    /// An unknown value, or one the viewer may not use, is the default: a link never errors.
    #[must_use]
    pub fn parse(value: Option<&str>, admin: bool) -> Self {
        match value {
            Some("recent") => Self::Recent,
            Some("busiest") if admin => Self::Busiest,
            Some("attention") if admin => Self::Attention,
            _ => Self::Name,
        }
    }

    #[must_use]
    pub fn value(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Recent => "recent",
            Self::Busiest => "busiest",
            Self::Attention => "attention",
        }
    }

    /// The sort menu for this viewer, with this one marked.
    #[must_use]
    pub fn options(self, admin: bool) -> Vec<SortOption> {
        let all = [
            (Self::Name, "Name", true),
            (Self::Recent, "Recently used", true),
            (Self::Busiest, "Busiest", admin),
            (Self::Attention, "Needs attention first", admin),
        ];
        all.into_iter()
            .filter(|(_, _, shown)| *shown)
            .map(|(sort, label, _)| SortOption {
                value: sort.value(),
                label,
                selected: sort == self,
            })
            .collect()
    }
}

/// What the list orders by: one row's facts, without the page's view types.
#[derive(Debug, Clone)]
pub struct SortKey<'a> {
    pub name: &'a str,
    pub last_used: Option<OffsetDateTime>,
    pub active: i64,
    pub total: i64,
    pub health: Option<Health>,
    /// Errors in the last 24 hours (admins; zero otherwise).
    pub errors: i64,
}

/// Rank for "needs attention first": offline, then no worker, then reachable but erroring, then
/// fine.
fn attention_rank(health: Option<Health>, errors: i64) -> u8 {
    match health {
        Some(Health::Offline) => 0,
        Some(Health::NoWorker) => 1,
        Some(Health::Up) | None if errors > 0 => 2,
        Some(Health::Up) | None => 3,
    }
}

/// Sort `keys` in place. Every order ends in the name, so the result is stable between loads.
pub fn sort_keys(keys: &mut [SortKey<'_>], sort: ResourceSort) {
    match sort {
        ResourceSort::Name => keys.sort_by(|a, b| a.name.cmp(b.name)),
        // Latest first; never used last.
        ResourceSort::Recent => keys.sort_by(|a, b| {
            b.last_used
                .cmp(&a.last_used)
                .then_with(|| a.name.cmp(b.name))
        }),
        ResourceSort::Busiest => keys.sort_by(|a, b| {
            b.active
                .cmp(&a.active)
                .then_with(|| b.total.cmp(&a.total))
                .then_with(|| a.name.cmp(b.name))
        }),
        ResourceSort::Attention => keys.sort_by(|a, b| {
            attention_rank(a.health, a.errors)
                .cmp(&attention_rank(b.health, b.errors))
                .then_with(|| b.errors.cmp(&a.errors))
                .then_with(|| a.name.cmp(b.name))
        }),
    }
}

/// The filters of one resources page, as a link.
pub struct Filters<'a> {
    pub kind: Option<&'a str>,
    pub q: &'a str,
    pub labels: &'a [String],
    pub sort: ResourceSort,
    pub attention: bool,
    pub pinned: bool,
}

impl Filters<'_> {
    /// A `/console/resources` link for this combination, so every filter is shareable. The default
    /// sort and an off switch are left out, so an unfiltered page is the plain address.
    #[must_use]
    pub fn href(&self) -> String {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        if let Some(k) = self.kind {
            ser.append_pair("kind", k);
        }
        if !self.q.is_empty() {
            ser.append_pair("q", self.q);
        }
        for l in self.labels {
            ser.append_pair("label", l);
        }
        if self.sort != ResourceSort::Name {
            ser.append_pair("sort", self.sort.value());
        }
        if self.attention {
            ser.append_pair("attention", "1");
        }
        if self.pinned {
            ser.append_pair("pinned", "1");
        }
        let query = ser.finish();
        if query.is_empty() {
            "/console/resources".to_owned()
        } else {
            format!("/console/resources?{query}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn key(name: &str) -> SortKey<'_> {
        SortKey {
            name,
            last_used: None,
            active: 0,
            total: 0,
            health: None,
            errors: 0,
        }
    }

    fn names<'a>(keys: &[SortKey<'a>]) -> Vec<&'a str> {
        keys.iter().map(|k| k.name).collect()
    }

    #[test]
    fn parse_falls_back_to_name_and_keeps_admin_sorts_from_others() {
        assert_eq!(ResourceSort::parse(None, true), ResourceSort::Name);
        assert_eq!(ResourceSort::parse(Some("nope"), true), ResourceSort::Name);
        assert_eq!(
            ResourceSort::parse(Some("recent"), false),
            ResourceSort::Recent
        );
        assert_eq!(
            ResourceSort::parse(Some("busiest"), true),
            ResourceSort::Busiest
        );
        // Counts and worker health are for admins: anyone else asking gets the default.
        assert_eq!(
            ResourceSort::parse(Some("busiest"), false),
            ResourceSort::Name
        );
        assert_eq!(
            ResourceSort::parse(Some("attention"), false),
            ResourceSort::Name
        );
    }

    #[test]
    fn the_menu_offers_only_what_the_viewer_may_use_and_marks_the_current_one() {
        let admin = ResourceSort::Busiest.options(true);
        assert_eq!(admin.len(), 4);
        assert_eq!(
            admin
                .iter()
                .filter(|o| o.selected)
                .map(|o| o.value)
                .collect::<Vec<_>>(),
            ["busiest"]
        );
        let user = ResourceSort::Name.options(false);
        assert_eq!(
            user.iter().map(|o| o.value).collect::<Vec<_>>(),
            ["name", "recent"]
        );
    }

    #[test]
    fn recent_puts_the_latest_first_and_never_used_last() {
        let mut keys = vec![key("c"), key("a"), key("b")];
        keys[0].last_used = Some(datetime!(2026-11-13 10:00 UTC));
        keys[2].last_used = Some(datetime!(2026-11-13 12:00 UTC));
        sort_keys(&mut keys, ResourceSort::Recent);
        assert_eq!(names(&keys), ["b", "c", "a"]);
    }

    #[test]
    fn busiest_orders_by_open_sessions_then_total_then_name() {
        let mut keys = vec![key("a"), key("b"), key("c"), key("d")];
        keys[0].total = 9;
        keys[1].active = 2;
        keys[2].active = 2;
        keys[2].total = 5;
        keys[3].total = 9;
        sort_keys(&mut keys, ResourceSort::Busiest);
        assert_eq!(names(&keys), ["c", "b", "a", "d"]);
    }

    #[test]
    fn attention_puts_offline_then_no_worker_then_erroring_ahead_of_the_rest() {
        let mut keys = vec![key("a"), key("b"), key("c"), key("d"), key("e")];
        keys[0].health = Some(Health::Up);
        keys[1].health = Some(Health::NoWorker);
        keys[2].health = Some(Health::Offline);
        keys[3].health = Some(Health::Up);
        keys[3].errors = 4;
        keys[4].health = Some(Health::Up);
        keys[4].errors = 9;
        sort_keys(&mut keys, ResourceSort::Attention);
        assert_eq!(names(&keys), ["c", "b", "e", "d", "a"]);
    }

    #[test]
    fn the_unfiltered_page_is_the_plain_address() {
        let f = Filters {
            kind: None,
            q: "",
            labels: &[],
            sort: ResourceSort::Name,
            attention: false,
            pinned: false,
        };
        assert_eq!(f.href(), "/console/resources");
    }

    #[test]
    fn every_filter_lands_in_the_link_and_is_escaped() {
        let labels = vec!["env=prod".to_owned()];
        let f = Filters {
            kind: Some("ssh"),
            q: "a&b c",
            labels: &labels,
            sort: ResourceSort::Recent,
            attention: true,
            pinned: true,
        };
        assert_eq!(
            f.href(),
            "/console/resources?kind=ssh&q=a%26b+c&label=env%3Dprod&sort=recent&attention=1&pinned=1"
        );
    }
}
