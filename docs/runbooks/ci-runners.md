# CI on self-hosted runners

CI for `limen-dev/limen` runs on the owner's machines to save GitHub-hosted minutes. The workflows are `.github/workflows/ci-rust.yml`, `audit.yml`, `ci-infra.yml`, `ci-workflows.yml` and `ci-website.yml`. The machines and their runner setup are maintained outside this repository.

## What runs for a change

**Draft pull requests run nothing.** Open pull requests as drafts; CI starts when you mark one ready for review (and again on every push after that). Pushes to `main`, releases and manual runs are unaffected.

Each workflow has a `paths:` filter. `ci-rust.yml` lists what to leave out; the others list the files they check, so add a path there when a check starts reading a new file. A workflow that does not start reports nothing (there is no combined `ci` check, and branch protection does not require any).

| Workflow | Starts when these change | Jobs |
|---|---|---|
| `ci-rust.yml` | Anything except docs, `website/`, `demos/`, `assets/`, Terraform, dashboards, `*.md` and the other workflows (a new directory is tested by default; `examples/` counts because the policy tests read it) | Lint (fmt, clippy, image versions), then tests (Linux x86_64 and arm64, macOS) and container images |
| `audit.yml` | `Cargo.toml`, `Cargo.lock`, `deny.toml`, `mise.toml`, the workflow itself; and weekdays 05:17 UTC, because advisories appear without a commit | cargo-deny and cargo-audit |
| `ci-infra.yml` | `deploy/terraform/`, `deploy/grafana/`, dev-users files, `crates/` (dashboards are generated from metric names), the workflow itself | Terraform fmt and validate, dashboards, dev-users check |
| `ci-workflows.yml` | `.github/workflows/` | actionlint |
| `website-browsers.yml` | Never on a push or pull request: Mondays 04:30 UTC, or `gh workflow run website-browsers.yml` | The built site in Chromium, WebKit and Firefox at phone, tablet and desktop sizes, dark and light (`website/scripts/browser-matrix.mjs`). Self-hosted, so it costs no hosted minutes |
| `ci-website.yml` | `website/`, `docs/` and `deploy/compose/README.md` (the build publishes them into the site), `mise.toml` | `npm ci` and `npm run build`: build, link and anchor check, site rules (ADR-0031). Not part of the release gate |

Issue templates and `dependabot.yml` start nothing. Manual runs (`workflow_dispatch`) ignore the filter and run every job of that workflow. A release (`release.yml`) calls the first four (not the website) with `hosted: true` before it builds anything.

In `ci-rust.yml` the slow test and image jobs start only after lint passes, so a formatting or clippy failure does not spend 15 minutes of the single ARM64 runner on tests. Pull requests read the Rust build cache from `main` but do not write one (`save-if`), which saves over a minute at the end of each test job.

## Where the jobs run

The repository variable `CI_RUNNERS` picks the runners:

- unset (or any value other than `github-hosted`): the self-hosted machines
- `github-hosted`: GitHub-hosted runners, which use the account's hosted minutes

Releases always use hosted runners (`release.yml` passes `hosted: true`).

```sh
gh variable set CI_RUNNERS --body github-hosted --repo limen-dev/limen   # use hosted runners
gh variable delete CI_RUNNERS --repo limen-dev/limen                     # back to self-hosted
gh variable list --repo limen-dev/limen                                  # see what is set
```

Jobs wait for a runner. If the machines are off and `CI_RUNNERS` is unset, CI stays queued until they come back. Either start them or switch to hosted.

## Checking the runners

The machines are started and stopped outside this repository. To see what GitHub sees:

```sh
gh api repos/limen-dev/limen/actions/runners --jq '.runners[] | "\(.name) \(.status) busy=\(.busy)"'
```

Known limits: the three runners share a 16 GiB host, so running them all at once can run out of memory. The ARM64 VM runs with 8 GiB. The integration job compiles two crates at a time to fit.

## Reverting

Everything self-hosted is in the commits on `ci/self-hosted-runners` (PR 20). Each one is independent enough to revert on its own:

| Commit | What it does |
|---|---|
| `a9787bd` | Decides which jobs run from the diff |
| `aaab18d` | `CI_RUNNERS` variable chooses the runners |
| `2f7450a` | Fetched the commit with `git` instead of `actions/checkout` to avoid HTTP 429s when many runs started at once. Reverted once runs became rare (drafts, path filters). If the 429s come back, bring that step back from the git history of `.github/workflows/` |
| `36bedba` | Removes a concurrency group that cancelled queued jobs (don't add it back) |
| `6bcdcbc` | `CARGO_BUILD_JOBS=2` on the integration job (fixes the ARM64 out-of-memory kills) |
| the TB9 and runbook commit | Threat model entry and this runbook |

The single `ci.yml` of that time was later split into the four workflows above (PR 157). To go back to the older layout, `git revert` that pull request's squashed commit.

If PR 20 is squash-merged, the commit hashes above change. Use the squashed commit instead, or `git revert` the relevant part.
