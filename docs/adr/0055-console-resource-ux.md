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
- Every new view and the palette endpoint are GETs with no side effect. What changes state is a POST with the console's origin and CSRF checks: pins and saved views (a preference, nothing granted), and the bulk end and revoke (each item its own audited operation). The threat model has a row for each.

## Also decided
- **Pins and saved views are server-side**, in a new table `console_pins` (migration 0032), so they follow the person between browsers. A pinned resource or a saved view (a console address) is the person's own preference: nothing audited, nothing granted. A view is only one of four listed pages (resources, sessions, audit trail, dashboards) with its query, and the page still enforces access when it is opened; the same address a member can't open can't be saved by them. 50 per person. The post carries the CSRF token and the console origin, and the way back must be a console address. Pinning a dashboard view is how "pin to Overview" works.
- **Bulk end-sessions and bulk revoke** loop over the existing single operations, so every item has its own audit event and the one reason; there is no batch shortcut. Admin only, at most 50.
- **Errors per resource** are the dashboards' own definitions over the last 24 hours: refused attempts (from the audit trail's resource field), statements that returned an error code, web responses of 500 and over, and Kubernetes answers of 400 and over. Admin only. A count and where to look, not a rate: the four sources have no common denominator.
- **Policy changes show a diff** per document against the active policy, so an approver reads what changes and not only who gains access.
- **Recordings carry markers** where the output paused for 30 seconds or more, and a link can point at a moment (`?t=`). The player is handed the one fetch of the recording.
- **A command builder** on the resource page covers every protocol the CLI opens: it lists the logins, roles or users the viewer may act as, what each may open (databases, vhosts, classes, indices, topics, groups) and builds the exact `limen` command with the flag that kind takes (`--db-role`, `--role`, `--user`, `--database`, `--vhost`, `--listen`). Only what the viewer's own roles and grants allow is offered, a wildcard becomes a text box, and every value is checked and plain before it reaches a command line. Flags come from one table that a test checks against `docs/cli-reference.md`. The quick commands on the Connect card use the same flags. It shows what policy grants, not what exists on the server (real database and topic names are not known to the console).
- **Other detail pages** (sessions, users, changes, requests, reviews, watch) get breadcrumbs; a session links to its resource, person, similar sessions and its own audit trail. Workers list the resources each can serve and flag *quiet* and *cert expired*. The Overview adds policy changes and reviews waiting, your own pending requests, and a console session about to end. Pages that refresh show when they last did, with *Pause* and *Refresh now*. `j` and `k` move through table rows. Failures say what to do next.

## Left for later
Each of these needs its own decision, so none is built here:
- Push updates in place of the 10-second poll (a stream per page needs a place in the proxy relay, as live watch has).
- An "Open" button for web apps: the browser address depends on the proxy's public port and app domain, which the console doesn't know. `limen web open` stays the way in.
- Remembering a dashboard's period by itself: a saved view of the dashboards page does it, explicitly.
- A rate (errors per session) per resource, and per-protocol failure fields in the sessions table.

## Consequences
- One new table, `console_pins`, and new queries: `resource_errors`, the pin reads and writes, and `resource_activity`, which replaces `session_counts_by_resource` and adds the latest session per resource; it scopes to one user for non-admins, so it can't leak another person's use.
- The saved pages in `crates/limen-control-plane/tests/console-pages/` need regenerating from a dev stack built from this change (runbook: console). Until then the browser job checks the new styles and scripts over the old markup.
- `limen_core::resource::ResourceKind::access` stays the one place a connect command is defined; the console reads it.
