# CI runners and which jobs run

CI for `limen-dev/limen` runs on GitHub-hosted runners. `.github/workflows/ci.yml` is the entry point; it calls `ci-rust.yml`, `audit.yml`, `ci-infra.yml`, `ci-workflows.yml`, `ci-website.yml` and `secret-scan.yml`.

## What runs for a change

**`ci.yml` decides what runs.** On every pull request and push to `main` it works out which areas the change touches (`scripts/ci-changes.sh`) and calls only those workflows, so a website change never builds the Rust code and a Rust change never builds the site. Its last job, `ci`, passes when everything that ran passed (an area that was skipped counts as passed). `ci` is the one check the ruleset on `main` requires. The per-area workflows have no triggers of their own, so a path filter can't leave a required check that never reports.

**Draft pull requests run nothing.** Open pull requests as drafts; CI starts when you mark one ready for review (and again on every push after that). Pushes to `main`, releases and manual runs are unaffected.

**Changing what starts an area:** edit the patterns in `scripts/ci-changes.sh` when a check starts reading a new file, and add a case to `scripts/test-ci-changes.sh` (it runs in `ci-workflows.yml`). A change to `ci.yml` or to the script itself runs every area.

| Workflow | Called when these change | Jobs |
|---|---|---|
| `ci-rust.yml` | Anything except docs, `website/`, `demos/`, `assets/`, Terraform, dashboards, `*.md` and the other workflows (a new directory is tested by default; `examples/` counts because the policy tests read it) | Lint (fmt, clippy, image versions), then tests (Linux x86_64 and arm64; macOS except on pull requests) and container images |
| `audit.yml` | `Cargo.toml`, `Cargo.lock`, `deny.toml`, `mise.toml`, the workflow itself; and weekdays 05:17 UTC, because advisories appear without a commit | cargo-deny and cargo-audit |
| `secret-scan.yml` | Every push to `main` and every pull request (no path filter: a secret can be in any file) | gitleaks over the whole git history. Reviewed false positives are in `.gitleaksignore` |
| `ci-infra.yml` | `deploy/terraform/`, `deploy/grafana/`, dev-users files, `crates/` (dashboards are generated from metric names), the workflow itself | Terraform fmt and validate, dashboards, dev-users check |
| `ci-workflows.yml` | `.github/workflows/` | actionlint |
| `website-browsers.yml` | Never on a push or pull request: Mondays 04:30 UTC, or `gh workflow run website-browsers.yml` | The built site in Chromium, WebKit and Firefox at phone, tablet and desktop sizes, dark and light (`website/scripts/browser-matrix.mjs`). |
| `ci-website.yml` | `website/`, `docs/` and `deploy/compose/README.md` (the build publishes them into the site), `mise.toml` | `npm ci` and `npm run build`: build, link and anchor check, site rules (ADR-0031). Not part of the release gate |

Issue templates, `dependabot.yml` and `CODEOWNERS` start nothing. A manual run of `ci.yml` (`gh workflow run ci.yml --ref <branch>`) runs every area; each per-area workflow can also be run by hand. A release (`release.yml`) calls `ci-rust`, `audit`, `ci-infra` and `ci-workflows` (not the website) before it builds anything.

**Pull requests made by bots.** release-please opens its pull request with the default token, which starts no workflows, so `ci` never reports and the pull request can't merge. Run `gh workflow run ci.yml --ref <branch>` on its branch (for release-please, `release-please--branches--main--components--limen`); the check it reports on the head commit satisfies the requirement.

In `ci-rust.yml` the slow test and image jobs start only after lint passes, so a formatting or clippy failure does not spend runner minutes on tests. Pull requests read the Rust build cache from `main` but do not write one (`save-if`), which saves over a minute at the end of each test job.

## Where the jobs run

| Runner | Jobs |
|---|---|
| `ubuntu-24.04` | Lint, buf, Linux x86_64 tests, container images, audit, infra, actionlint, website build and browser matrix |
| `ubuntu-24.04-arm` | Linux arm64 tests |
| `macos-latest` | macOS unit tests |

The repository is public, so standard hosted runners cost no minutes. They have about 145 GB of disk, so jobs neither cap the build's parallelism nor free disk first.
