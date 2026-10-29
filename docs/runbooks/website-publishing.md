# Publishing the website

The site in `website/` is published to GitHub Pages at <https://limen-dev.github.io/limen> by `.github/workflows/deploy-website.yml`. It builds on every push to `main` that touches `website/`, `docs/`, `deploy/compose/README.md` or `mise.toml`, with the same checks as `ci-website.yml` (links, third-party requests, ADR-0031 claims), and deploys only if they pass. A manual run (`gh workflow run deploy-website.yml`) ignores the path filter.

## Turning it on

Pages from a private repository needs a paid GitHub plan, and the published site is public either way. Until the repository is public the workflow does nothing: both jobs are skipped unless the repository variable `PUBLISH_SITE` is `true`.

When `limen-dev/limen` goes public:

1. Settings, Pages, Source: **GitHub Actions** (or `gh api -X POST repos/limen-dev/limen/pages -f build_type=workflow`).
2. `gh variable set PUBLISH_SITE --body true --repo limen-dev/limen`
3. `gh workflow run deploy-website.yml --repo limen-dev/limen`, then open the URL the deploy job prints.

To stop publishing, delete the variable (`gh variable delete PUBLISH_SITE --repo limen-dev/limen`). The last deployed site stays up; to take it down, disable Pages in Settings.

## Custom domain

Set `SITE_URL` to the domain and `SITE_BASE` to `/` as repository variables (`gh variable set SITE_URL --body https://docs.example.com`), set the domain in Settings, Pages, and run the workflow again. Nothing in the content depends on the host (ADR-0021). Redirects from other addresses are #136.

## If a deploy fails

- **The build job fails:** the same checks as `ci-website.yml`. Run `npm ci && npm run build` in `website/` with `SITE_URL=https://limen-dev.github.io SITE_BASE=/limen` and fix what it reports.
- **The deploy job fails on permissions or "Pages not enabled":** Pages is not set to GitHub Actions, or the repository is private on a plan without Pages.
- **Links and assets 404 on the live site only:** `SITE_BASE` does not match the address the site is served from.
