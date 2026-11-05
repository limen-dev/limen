# Control plane and console

Console code is in `src/console/`; its Askama `templates/` and static `assets/` sit beside `src/`.

- Askama templates are compiled in: rebuild after editing one.
- Reference static assets with `?v={{ chrome.assets }}` (they are fingerprinted).
- The CSP (`CSP` in `src/console/mod.rs`, tested in `limen-e2e/tests/console.rs`) forbids inline script and third-party origins. Use external files and classes. Don't loosen it without an ADR note.
- The logo files in `assets/` are copies; change all copies together (see `CONTRIBUTING.md` Rules).
- SQL passed to sqlx must be literal. Build shared fragments with `macro_rules!` and `concat!` (see `component_columns!` in `src/db.rs`), never `format!`.
- Console changes are checked in a browser by `.github/workflows/browser-tests.yml`; unit tests don't render pages.
