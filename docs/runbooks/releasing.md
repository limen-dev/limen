# Releasing

Releases are made by merging a pull request. Read [ADR-0024](../adr/0024-release-strategy.md) for the why.

## Normal flow
1. Work lands on `main` with conventional commit messages (`feat:`, `fix:`, `docs:` ...). Breaking changes use `feat!:` or a `BREAKING CHANGE:` footer.
2. release-please keeps a pull request titled *chore(main): release X.Y.Z* up to date. It holds the version bump and the changelog. A job refreshes `Cargo.lock` on it and runs CI on its branch.
3. When a roadmap milestone closes and the PR's checks are green, **merge it**. That is the release.
4. The `release` workflow then tests the release commit, builds the binaries and the three multi-arch images, makes the SBOM and the deploy bundle, smoke-tests them, and attaches everything to a **draft** GitHub release.
5. Open the draft, skim the notes, and publish it. (Set the repository variable `RELEASE_AUTO_PUBLISH` to `true` to skip this step once the pipeline has proven itself.)

## What you get
`limen-vX-<target>.tar.gz` (four targets), `SHA256SUMS`, `limen-vX.sbom.cdx.json`, `limen-vX-deploy.zip`, `image-refs.txt` (the pinned image digests), and `ghcr.io/<owner>/limen-{control-plane,proxy,worker}:vX.Y.Z`. There is no `latest` tag.

## Checking a release by hand
`deploy/compose/smoke-release.sh vX.Y.Z` (or `--dir DIR` with the assets of a draft) verifies `SHA256SUMS`, runs the CLI from the tarball for your OS, pulls the three images by digest, and runs the Phase 3.5 demo against them. It needs `gh`, and `docker` signed in to `ghcr.io` while the repository is private. It is the check ADR-0024 asks for before a pre-release becomes a release.

## Upgrading a deployment
Control plane first, then proxies, then workers. Database migrations run when the control plane starts and only move forward, so a rollback means restoring a backup.

## If something fails
- **No release PR appears:** the repository setting *Actions > General > Allow GitHub Actions to create and approve pull requests* must be on.
- **The workflow failed after the merge:** the tag and draft release already exist. Fix the cause, then re-run the failed jobs from the Actions page. Uploads use `--clobber`, so re-running is safe.
- **Wrong version proposed:** the PR's title can't be edited by hand; add a commit with the right type, or set `release-as` in `release-please-config.json` for one release.
