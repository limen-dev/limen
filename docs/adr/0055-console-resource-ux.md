# ADR-0055: Console resources and navigation

- Status: Proposed

## Context
The Overview page lets you act: it lists what you can reach with a command to copy next to each row, and shows live counts. The Resources pages, where people actually go to enter a resource, give less. The list has no command and no sense of state, and the detail page is a facts table with the connect command buried below it (and shown only when you already hold a principal). It doesn't say whether the resource is reachable, who is on it, or when it was last used, and it ends in a table of ten sessions with no way on.

Two things in the console already work and are kept: the in-place refresh (`<main data-refresh>`, ADR-0017) and the typeahead used by the simulator. This ADR builds on them rather than replacing them.

## Decisions
- **The list answers "can I get in, and is it up?"** Every row a viewer can open has a copy button for its connect command. Admins also get a **status** (`reachable`, `offline`, `no worker`), taken from the workers that match the resource's selector and the tunnels they hold. Everyone gets **last used** (an admin sees anyone's latest session; anyone else sees only their own). Sorting (name, recently used; for admins also busiest and needs-attention-first) and a **needs attention** filter are plain query parameters, so every view is bookmarkable and the filters still run after access control.
- **The detail page leads with how to connect.** A *Connect* card sits above the facts. Where the CLI lets a command name a principal, there is one command per principal: `limen ssh <login>@<resource>`, and `limen db connect <resource> --db-role <role>` when policy allows several roles. Every other kind has one command. No flag is invented, and a principal that isn't plain (`[A-Za-z0-9_.-]`, not starting with `-`) is left off the command line. A viewer with no principal sees how to ask instead.
- **State on the detail page.** A strip shows status (admins), last used, and who is on it now (readers of the record), with links to all sessions and the audit trail filtered to the resource. Open sessions list *Details* and, for SSH and only for people who may watch, *Watch*. Kill stays on the session page, where its confirmation and reason live.
- **Sections are server-rendered tabs**: Overview, Access (who can reach it; readers of the record only), Activity. They are plain links, so they bookmark and need no script.
- **Times read as "5 minutes ago"**, with the absolute UTC time as the tooltip. The server still renders the absolute text in a `<time datetime>`, so without script nothing changes.
- **Overview points at what needs doing.** Admins get an *Attention* card (disabled users, resources no worker can serve, access requests and reviews waiting). Everyone gets *Continue where you left off*: the resources they used last, from their own sessions.
- **A command palette** (`Ctrl/Cmd+K`) jumps to a page or a resource. Pages come from the menu the viewer already has, so it can't offer one they can't open. Resources come from one new read-only endpoint, `GET /console/suggest/resources?q=`, which applies the Resources page's own rule (admins: all; everyone else: only what their roles open) and returns at most eight `{name, kind, href}`. `g` then a letter moves between pages. The path is not under `/console/resources/` so a resource named `suggest` stays reachable.

## Constraints kept
- No inline script and no third-party origin (CSP, ADR-0017). New behaviour is in `console.js`.
- Internal addresses stay admin-only. Worker health, everyone's session counts and the needs-attention filter are admin-only; a non-admin asking for them gets the default.
- Filters apply after access control. A resource the viewer can't reach is a 404 whatever the query says.
- Every new view and the new endpoint are GETs with no side effect. Nothing here changes state; the threat model has a row for the endpoint.

## Left for later
Each of these needs its own decision, so none is built here:
- Pinned and favourite resources (they need per-user storage; a browser-only version would not follow the person between machines).
- Bulk actions on tables (multi-select kill, revoke): they need a confirmation design and their own audit.
- Markers on the recording timeline, a per-user "what can they reach" view, a worker health timeline, and push updates in place of polling.
- An error rate per resource: the sessions table has no uniform failure field across protocols.
- Breadcrumbs and the same "where next" links on the other detail pages (sessions, users, workers). The resource page has them first.

## Consequences
- One new query (`resource_activity`) replaces `session_counts_by_resource` and adds the latest session per resource; it scopes to one user for non-admins, so it can't leak another person's use.
- The saved pages in `crates/limen-control-plane/tests/console-pages/` and the browser matrix cover the new markup.
- `limen_core::resource::ResourceKind::access` stays the one place a connect command is defined; the console reads it.
