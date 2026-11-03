# Publishing the website

The site in `website/` is published to GitHub Pages at <https://limen-dev.github.io/limen> by the `deploy` job of `.github/workflows/website.yml`. That workflow builds and checks the site (links, third-party requests, ADR-0031 claims) on every pull request and every push to `main` that touches `website/`, `docs/`, `deploy/compose/README.md`, `deploy/helm/limen/README.md`, a README under `deploy/terraform/` or `mise.toml`. On `main` the deploy job runs after the checks pass. A manual run (`gh workflow run website.yml`) ignores the path filter.

## Switches

The repository is public and the site is live. Two settings control it, and both are already set:

1. Settings, Pages, Source: **GitHub Actions** (or `gh api -X POST repos/limen-dev/limen/pages -f build_type=workflow`).
2. The repository variable `PUBLISH_SITE` is `true` (`gh variable set PUBLISH_SITE --body true --repo limen-dev/limen`). The deploy job is skipped without it.

To publish a fork, set both there and run `gh workflow run website.yml`, then open the URL the deploy job prints.

To stop publishing, delete the variable (`gh variable delete PUBLISH_SITE --repo limen-dev/limen`). The last deployed site stays up; to take it down, disable Pages in Settings.

## Custom domain

Set `SITE_URL` to the domain and `SITE_BASE` to `/` as repository variables (`gh variable set SITE_URL --body https://docs.example.com`), set the domain in Settings, Pages, and run the workflow again. Nothing in the content depends on the host (ADR-0021). Redirects from other addresses are #136.

## If a deploy fails

- **The build job fails:** the same checks as `website.yml`. Run `npm ci && npm run build` in `website/` with `SITE_URL=https://limen-dev.github.io SITE_BASE=/limen` and fix what it reports.
- **The deploy job fails on permissions or "Pages not enabled":** Pages is not set to GitHub Actions (on a fork, also check `PUBLISH_SITE`).
- **Links and assets 404 on the live site only:** `SITE_BASE` does not match the address the site is served from.
