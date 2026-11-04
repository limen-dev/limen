# CI runners and which jobs run

CI for `limen-dev/limen` runs on GitHub-hosted runners. Workflows (`.github/workflows/`): `rust.yml`, `audit.yml`, `secret-scan.yml`, `infra.yml`, `workflows.yml`, `website.yml`, `browser-tests.yml` and `release.yml`.

## What runs for a change

**Draft pull requests run nothing.** Open pull requests as drafts; CI starts when you mark one ready for review, and again on every push after. Pushes to `main`, releases and manual runs are unaffected.

Each workflow has a `paths:` filter. `rust.yml` lists what to leave out; the others list the files they check, so add a path when a check starts reading a new file. A workflow that doesn't start reports nothing (there's no combined `ci` check, and branch protection requires none).

| Workflow | Starts when these change | Jobs |
|---|---|---|
| `rust.yml` | Anything except docs, `website/`, `demos/`, `assets/`, Terraform, dashboards, `*.md` and the other workflows (new directories are tested by default; `examples/` counts because policy tests read it) | Lint (fmt, clippy, image versions), then tests (Linux x86_64 and arm64; macOS except on pull requests) and container images |
| `audit.yml` | `Cargo.toml`, `Cargo.lock`, `deny.toml`, `mise.toml`, the workflow itself; and weekdays 05:17 UTC, since advisories appear without a commit | cargo-deny, cargo-audit |
| `secret-scan.yml` | Every push to `main` and every pull request (no path filter: a secret can be in any file) | gitleaks over the whole git history. Reviewed false positives are in `.gitleaksignore` |
| `infra.yml` | `deploy/terraform/`, `deploy/helm/`, `deploy/grafana/`, dev-users files, `crates/` (dashboards are generated from metric names), the workflow itself | Terraform fmt and validate, Helm lint and schema check, dashboards, dev-users check |
| `workflows.yml` | `.github/workflows/` | actionlint |
| `website.yml` | `website/`, `docs/`, `deploy/compose/README.md`, `deploy/helm/limen/README.md` and the READMEs under `deploy/terraform/` (the build publishes them into the site), `mise.toml` | `npm ci` and `npm run build`: build, link and anchor check, site rules (ADR-0031). Not part of the release gate |
| `browser-tests.yml` | `crates/limen-control-plane/assets/`, `templates/` and `tests/console-pages/`, `deploy/compose/scripts/console-snapshot-matrix.mjs` (console job only, Chromium and WebKit, not on a draft); Mondays 04:30 UTC or `gh workflow run browser-tests.yml` run both jobs with Firefox | Console: the saved pages in `tests/console-pages/`. Website: the built site (`website/scripts/browser-matrix.mjs`, never on a pull request). Both in phone, tablet and desktop sizes, dark and light |

Issue templates and `dependabot.yml` start nothing. Manual runs (`workflow_dispatch`) ignore the filter and run every job of that workflow. `release.yml` calls the first four (not the website) before building anything.

In `rust.yml`, the slow test and image jobs start only after lint passes, so a formatting or clippy failure spends no runner minutes on tests. Pull requests read the Rust build cache from `main` but don't write one (`save-if`), saving over a minute at the end of each test job.

## Where jobs run

| Runner | Jobs |
|---|---|
| `ubuntu-24.04` | Lint, buf, Linux x86_64 tests, container images, audit, infra, actionlint, website build and browser matrix |
| `ubuntu-24.04-arm` | Linux arm64 tests |
| `macos-latest` | macOS unit tests |

The repository is public, so standard hosted runners cost no minutes. They have about 145 GB of disk, so jobs neither cap build parallelism nor free disk first.
