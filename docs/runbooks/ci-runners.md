# CI runners and which jobs run

CI for `limen-dev/limen` runs on GitHub-hosted runners. The workflows are `.github/workflows/ci-rust.yml`, `audit.yml`, `ci-infra.yml`, `ci-workflows.yml` and `ci-website.yml`.

## What runs for a change

**Draft pull requests run nothing.** Open pull requests as drafts; CI starts when you mark one ready for review (and again on every push after that). Pushes to `main`, releases and manual runs are unaffected.

Each workflow has a `paths:` filter. `ci-rust.yml` lists what to leave out; the others list the files they check, so add a path there when a check starts reading a new file. A workflow that does not start reports nothing (there is no combined `ci` check, and branch protection does not require any).

| Workflow | Starts when these change | Jobs |
|---|---|---|
| `ci-rust.yml` | Anything except docs, `website/`, `demos/`, `assets/`, Terraform, dashboards, `*.md` and the other workflows (a new directory is tested by default; `examples/` counts because the policy tests read it) | Lint (fmt, clippy, image versions), then tests (Linux x86_64 and arm64; macOS except on pull requests) and container images |
| `audit.yml` | `Cargo.toml`, `Cargo.lock`, `deny.toml`, `mise.toml`, the workflow itself; and weekdays 05:17 UTC, because advisories appear without a commit | cargo-deny and cargo-audit |
| `ci-infra.yml` | `deploy/terraform/`, `deploy/grafana/`, dev-users files, `crates/` (dashboards are generated from metric names), the workflow itself | Terraform fmt and validate, dashboards, dev-users check |
| `ci-workflows.yml` | `.github/workflows/` | actionlint |
| `website-browsers.yml` | Never on a push or pull request: Mondays 04:30 UTC, or `gh workflow run website-browsers.yml` | The built site in Chromium, WebKit and Firefox at phone, tablet and desktop sizes, dark and light (`website/scripts/browser-matrix.mjs`). |
| `ci-website.yml` | `website/`, `docs/` and `deploy/compose/README.md` (the build publishes them into the site), `mise.toml` | `npm ci` and `npm run build`: build, link and anchor check, site rules (ADR-0031). Not part of the release gate |

Issue templates and `dependabot.yml` start nothing. Manual runs (`workflow_dispatch`) ignore the filter and run every job of that workflow. A release (`release.yml`) calls the first four (not the website) before it builds anything.

In `ci-rust.yml` the slow test and image jobs start only after lint passes, so a formatting or clippy failure does not spend runner minutes on tests. Pull requests read the Rust build cache from `main` but do not write one (`save-if`), which saves over a minute at the end of each test job.

## Where the jobs run

| Runner | Jobs |
|---|---|
| `ubuntu-24.04` | Lint, buf, Linux x86_64 tests, container images, audit, infra, actionlint, website build and browser matrix |
| `ubuntu-24.04-arm` | Linux arm64 tests |
| `macos-latest` | macOS unit tests |

The repository is public, so standard hosted runners cost no minutes. They have about 145 GB of disk, so jobs neither cap the build's parallelism nor free disk first.
