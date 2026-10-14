# ADR-0021: Documentation site and project homepage

- Status: Proposed. Hosting is an owner decision (the domain isn't chosen yet).
- Date: 2026-10-14

## Context
Tools of this kind have a public homepage and a documentation site: what it is, how to install it, how to deploy it, how to use each protocol, and the reference for policy and the CLI. The owner plans `docs.<domain>` for documentation and `<domain>` for the homepage, and asked whether GitHub Pages is a good start. Limen's docs today are design notes written for contributors (design, ADRs, threat model, runbooks), not for someone evaluating or deploying it.

## Decision
- **Two audiences, one source tree.** Contributor documents stay in `docs/` (design, ADRs, threat model). A new `website/` holds the public site: a landing page and the user documentation, built with **Astro and Starlight** (static output, dark and light themes, search without a server, MDX for examples). ADRs and the threat model are published inside the docs site under "Architecture" so they are not written twice.
- **Docs structure:** Introduction and concepts; Quickstart (Docker Compose, five minutes); Install and deploy (Compose, Terraform for ECS, Terraform for EC2, Kubernetes); Identity (Okta, any OIDC, bots); one guide per protocol; Policy reference; CLI reference (generated from the `clap` definitions so it can't drift); Web console; Audit and dashboards; Operations (runbooks, scaling, backup, upgrades); Security.
- **Docs are tested like code:** every command in the quickstart runs in CI against the compose stack, and links are checked.
- **Hosting:** see "Opinion". The site builds to plain static files, so the host can change without touching content.

## Opinion on GitHub Pages (for the owner to decide)
GitHub Pages is a reasonable place to **start**: free, deploys from the Actions we already run, custom domain and HTTPS included. Three things to know:
1. **One Pages site per repository.** `docs.<domain>` and `<domain>` as separate sites need two repositories, or one site that serves the homepage at `/` and the docs at `/docs/` (with `docs.<domain>` redirecting there).
2. **The repository is private today.** Pages from a private repository needs a paid GitHub plan, and the published site is public either way.
3. No preview deployments for pull requests, and no server-side redirects or custom headers.

**Cloudflare Pages is the better fit** if you want the two-subdomain layout: free, works with private repositories, one repository can feed several projects (`docs` and `www`) from different build directories, pull requests get preview URLs, and redirects and headers are configurable. The cost is one more account and DNS on Cloudflare.

**Recommendation:** build `website/` now and deploy it with Cloudflare Pages to the two subdomains when the domain is chosen. If you prefer to stay entirely on GitHub, use one Pages site with `/docs/`. Either way nothing in the content depends on the host. Don't buy hosting or a custom CMS: a static site is all this needs.

## Consequences
- A new milestone ("Docs site and homepage") and a `website/` workspace outside the Rust build; CI builds it and checks links.
- The README stays short and points to the docs site once it exists.
