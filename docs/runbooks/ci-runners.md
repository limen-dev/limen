# CI on self-hosted runners

CI for `jfcmartins/limen` runs on the owner's machines to save GitHub-hosted minutes. The workflow is `.github/workflows/ci.yml`. The machines are set up with [gha-local-ci](https://github.com/jfcmartins/gha-local-ci) (`~/projects/gha-local-ci`).

## What runs for a change

The `what changed` job reads the diff against the merge base and decides which jobs run. Skipped jobs count as passing in the `ci` summary.

| Change touches | Jobs |
|---|---|
| Only docs (`docs/`, `*.md`) | None. `ci` passes |
| Rust code, `Cargo.*`, `proto/`, `deploy/docker/`, `.github/`, `mise.toml`, toolchain or lint config | fmt + clippy, tests (Linux x86_64 and arm64, macOS), cargo-deny and cargo-audit, images |
| `deploy/terraform/`, `deploy/grafana/`, dev-users files, `crates/` | terraform validate, dashboards and dev-users check |
| `.github/` | actionlint (and everything under "Rust code" above) |
| Manual runs (`workflow_dispatch`) and releases | Everything |

## Where the jobs run

The repository variable `CI_RUNNERS` picks the runners:

- unset (or any value other than `github-hosted`): the self-hosted machines
- `github-hosted`: GitHub-hosted runners, which use the account's hosted minutes

Releases always use hosted runners (`release.yml` passes `hosted: true`).

```sh
gh variable set CI_RUNNERS --body github-hosted --repo jfcmartins/limen   # use hosted runners
gh variable delete CI_RUNNERS --repo jfcmartins/limen                     # back to self-hosted
gh variable list --repo jfcmartins/limen                                  # see what is set
```

Jobs wait for a runner. If the machines are off and `CI_RUNNERS` is unset, CI stays queued until they come back. Either start them or switch to hosted.

## Turning the machines on and off

From `~/projects/gha-local-ci`:

```sh
./gha-power.sh status          # what GitHub sees
./gha-power.sh on              # start the macOS runner and both VMs
./gha-power.sh off             # stop them; refuses while a job is running
./gha-power.sh off --force     # stop them anyway; the running job is lost
```

Known limits: the three runners share a 16 GiB host, so running them all at once can run out of memory. The ARM64 VM runs with 8 GiB. The integration job compiles two crates at a time to fit.

## Reverting

Everything self-hosted is in the commits on `ci/self-hosted-runners` (PR 20). Each one is independent enough to revert on its own:

| Commit | What it does |
|---|---|
| `a9787bd` | Decides which jobs run from the diff |
| `aaab18d` | `CI_RUNNERS` variable chooses the runners |
| `2f7450a` | Fetches the commit with `git`, not `actions/checkout` (fixes the HTTP 429s) |
| `36bedba` | Removes a concurrency group that cancelled queued jobs (don't add it back) |
| `6bcdcbc` | `CARGO_BUILD_JOBS=2` on the integration job (fixes the ARM64 out-of-memory kills) |
| the TB9 and runbook commit | Threat model entry and this runbook |

To go back to the workflow `main` had before this work, restore both workflow files and commit:

```sh
git checkout main -- .github/workflows/ci.yml .github/workflows/release.yml
git commit -m "revert: back to the workflows on main"
```

If PR 20 is squash-merged, the commit hashes above change. Use the squashed commit instead, or `git revert` the relevant part.
