# ADR-0024: Releases and distribution

- Status: Proposed (owner asked for a strategy 2026-10-14)
- Date: 2026-10-14

## Context
Limen ships several kinds of artifact: the `limen` CLI, three server programs (control plane, proxy, worker), container images for them, Terraform modules, Grafana dashboards, a compose stack, and (planned) a Helm chart and a docs site. Today only one release path exists: pushing a tag `vX.Y.Z` builds the four binaries for Linux and macOS (x86_64 and arm64) and attaches them, with checksums, to a **draft** GitHub release. No tag has ever been cut, and nothing publishes container images, SBOMs, or signatures.

## Decision
- **One product, one version.** The whole repository is released together as `vMAJOR.MINOR.PATCH`. The components share the tunnel and API protocols, the certificate formats, the policy snapshot, and the audit schema, so version skew is a bug source, not a feature. Separate versions for the CLI or the modules would only make sense once we make a compatibility promise (after 1.0).
- **Cadence before 1.0:** a minor release when a roadmap milestone closes (`v0.1.0` = phases 0 to 3.5, then `v0.2.0` for the next phase, and so on), patch releases for fixes. Releases are marked *pre-release* on GitHub until 1.0. Breaking changes are allowed at 0.x but must be listed under "Upgrade notes" in the release notes. Notes are generated from labels (`.github/release.yml`).
- **What a release contains:**
  1. **Binaries:** `limen` and the server programs for Linux (x86_64, arm64) and macOS (arm64, x86_64), with one `SHA256SUMS` file, a CycloneDX SBOM, and a build attestation (GitHub artifact attestation or cosign keyless), so people can verify what they run.
  2. **Container images** for `limen-control-plane`, `limen-proxy`, and `limen-worker`: multi-arch, distroless, published to GHCR as `ghcr.io/<owner>/limen-<component>:vX.Y.Z` and a floating `:0.N`. No `latest` tag, and each image is signed.
  3. **Terraform modules:** consumed straight from Git by tag, for example `source = "github.com/<owner>/limen//deploy/terraform/modules/audit?ref=v0.2.0"`. A module's image-tag default is its own release, so modules and images can't drift. The public Terraform Registry wants one repository per module (`terraform-<provider>-<name>`), so that is deferred until the repository is public and we know people want it.
  4. **Dashboards and the compose stack** as a release asset (a zip) and in the repository at the tag.
  5. **Helm chart** (when it exists, Phases 5 and 13) as an OCI chart in GHCR, same version.
  6. **Docs:** continuous from `main` at first. Versioned docs (`/docs/v0.5/`, plus *latest*) start at 1.0.
- **CLI distribution:** release tarballs and an install script first; a Homebrew tap once the repository is public. `cargo install --git … --tag vX.Y.Z` works from day one. Windows is not supported yet.
- **Compatibility and upgrades** (stated now, enforced once Phase 5 lands): upgrade the control plane first, then proxies, then workers. A control plane at N serves proxies and workers at N and N-1 so rolling upgrades work. Protobuf changes are additive (field numbers are never reused); the audit schema and policy snapshot already carry versions. A newer or older CLI within one minor works. Database migrations are forward-only and run when the control plane starts, so a rollback is a restore, which the upgrade guide says.
- **1.0 means** verified against real AWS, Okta, and Datadog; the chaos and scale-out suites passing; an upgrade path tested from the previous minor; the docs site; and a security review.

## Automation
Releases are automated; a person decides *when*, never *how*.
- **release-please** (conventional commits are already required) keeps a standing **release pull request** on `main`: it proposes the next version from the commits since the last tag (pre-1.0, features bump the minor), updates the workspace version and `CHANGELOG.md`, and lists what changed. **Merging that PR is the act of releasing**, and we merge it when a milestone closes.
- Merging it tags `vX.Y.Z` and creates the GitHub release (marked *pre-release* before 1.0). **The same workflow** then builds the binaries, builds and pushes the signed images, generates the SBOM and attestation, uploads everything to that release, and runs the smoke test. (One workflow, not a tag-triggered second one: a tag pushed with the default `GITHUB_TOKEN` doesn't start other workflows.)
- The release PR also runs the full CI, so a release can't be cut from a red `main`.
- No manual tagging, no hand-written notes, no copying files around. The release stays a *draft* until the pipeline has run cleanly a few times; after that it publishes itself.

## Stages
1. **Prove the pipeline (now):** adopt release-please, add image publishing, the SBOM, and the attestation, then merge the first release PR as `v0.1.0-rc.1` (a *pre-release*) from the Phase 3.5 state. It shows whether the pipeline works end to end.
2. **`v0.1.0`** once the rc passes a smoke test (install the CLI from the release, start the published images with the compose file, run `demo-phase35.sh`).
3. **Each milestone** closes with a tag and release notes.
4. **When the repository goes public:** Homebrew tap, public image visibility, and the Terraform Registry decision.

## Consequences
- The repository is private today, so releases and GHCR images are visible to collaborators only until it is public.
- `Cargo.toml`'s workspace version is the single source of the number; the release workflow must check that the tag matches it.
- The existing `release.yml` (tag triggers a draft with binaries) is replaced by the release-please workflow above; its build matrix and packaging steps carry over.
