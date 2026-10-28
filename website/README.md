# Limen website

The homepage and documentation site ([ADR-0021](../docs/adr/0021-docs-site-and-homepage.md)). Astro with Starlight for the docs, and a hand-built homepage. Output is plain static files.

```sh
mise install                 # Node comes from mise.toml
cd website
npm ci
npm run dev                  # http://localhost:4321, syncs docs/ first
npm run build                # sync, build, check links, check site rules
npm run preview              # serve dist/ (SITE_BASE=/limen/ npm run build to try the Pages path)
```

## Where things live

| Path | What |
|---|---|
| `src/layouts/Site.astro`, `src/scripts/site.ts` | What every non-docs page shares: head, header, footer, the ⌘K palette, theme |
| `src/pages/index.astro` | The homepage. Markup and copy |
| `src/pages/404.astro`, `src/scripts/notfound.ts` | The 404 page: goes to the page with the trailing slash when it exists, otherwise suggests the closest pages. Starlight's own 404 is turned off |
| `src/data/site.ts` | Links and the page list shared by the homepage, the palette and the 404 page |
| `src/styles/landing.css`, `src/scripts/landing.ts` | Styles for these pages, and the homepage-only interactions (hero, terminal replay, hash-chain demo, ⌘K palette) |
| `src/styles/tokens.css` | The palette shared by the homepage and the docs |
| `src/styles/docs.css` | Starlight restyled with those tokens |
| `src/content/docs/docs/*.md(x)` | Pages written by hand: introduction, quickstart, concepts, status |
| `scripts/sync-docs.mjs` | Publishes `docs/` and `deploy/compose/README.md` into the site at build time. The generated pages are git-ignored. Edit the source documents, not the copies |
| `scripts/check-links.mjs`, `scripts/check-site.mjs` | Fail the build on a broken link or anchor, a missing guide, a third-party request, or a claim ADR-0031 forbids |
| `astro.config.mjs` | Sidebar and site settings. A new guide must be added to the sidebar |

## Rules for the copy

- Say what is unverified. Anything tested only against a local stand-in carries the `unverified` label, on the homepage as in the docs (ADR-0031).
- Do not claim what is planned: no "access receipts", no AI agents, no comparisons with other products.
- No third-party requests. Fonts are packaged with the site. `check-site.mjs` enforces it.

## Publishing

Nothing is published until the repository is public, so there is **no workflow yet** (#138). Run `npm run build` before you push a change to the site or to a document in `docs/`: it is the whole check. When publishing arrives, `SITE_URL` and `SITE_BASE` set the address (for GitHub Pages `/limen/`; for a custom domain `/`).
