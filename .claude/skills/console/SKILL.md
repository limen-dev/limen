---
name: console
description: Use when changing the Limen web console (crates/limen-control-plane/src/console, its Askama templates, CSS/JS assets, CSP) or any SQL in the control plane.
---
# Console

Rust is in `crates/limen-control-plane/src/console/`; Askama `templates/` and static `assets/` sit beside `src/` in the same crate.

- Askama templates are compiled in: rebuild after editing one.
- Reference static assets with `?v={{ chrome.assets }}` (they are fingerprinted).
- The CSP (`CSP` in `src/console/mod.rs`, tested in `crates/limen-e2e/tests/console.rs`) forbids inline script and third-party origins. Use external files and classes. Don't loosen it without an ADR note.
- The logo files in `assets/` are copies; change all copies together (`CONTRIBUTING.md`, Rules).
- SQL passed to sqlx must be literal. Build shared fragments with `macro_rules!` and `concat!` (see `component_columns!` in `src/db.rs`), never `format!`.
- Unit tests don't render pages; `.github/workflows/browser-tests.yml` does.
