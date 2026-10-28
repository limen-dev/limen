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

## Checking it in other browsers and on phones

`npm run build` does not render anything. `scripts/browser-matrix.mjs` loads the built site in real engines (Chromium, WebKit, Firefox) at desktop, tablet and phone sizes, and reports sideways scrolling, JS errors, third-party requests, axe WCAG 2.1 A/AA violations and touch targets under 24px. It also drives the theme toggle, the ⌘K palette, docs search and the mobile menu. It exits non-zero on any problem and is not a dependency of the site: Playwright and axe-core are resolved from the directory you run it in.

```sh
mkdir -p /tmp/limen-browsers && cd /tmp/limen-browsers && npm i playwright-core axe-core && npx playwright-core install chromium webkit firefox
(cd <repo>/website && npm run build && npx astro preview --port 4341 &)
SITE_URL=http://localhost:4341 node <repo>/website/scripts/browser-matrix.mjs             # dark
THEME=light SITE_URL=http://localhost:4341 node <repo>/website/scripts/browser-matrix.mjs
```

`BROWSERS=chromium,webkit` limits the engines. An engine that cannot start is reported as `NOT RUN` with its full launch error, and the script exits 2, never 0. This is not real devices, a screen reader, or an older browser than the engines above.

**Supported browsers:** the current and previous major release of Chrome, Edge, Safari (macOS, iOS, iPadOS), Firefox and Firefox ESR, and Chrome on Android. The docs' mobile menu is Starlight's popover button, so the oldest versions that have everything the site uses (`popover`, `color-mix()`, `:has()`; from browser compatibility data) are Chrome and Edge 114, Safari 17 and Firefox 125. What the menu does below that was not tried. What was run: Chromium and WebKit. **Firefox has not been run (unverified):** a static check (`doiuse`) found nothing in the built CSS that current Firefox lacks except print-only rules, but that is not a test. Run the matrix with `BROWSERS=firefox` on a normal machine before relying on it.

## Publishing

Nothing is published until the repository is public, so there is **no workflow yet** (#138). Run `npm run build` before you push a change to the site or to a document in `docs/`: it is the whole check. When publishing arrives, `SITE_URL` and `SITE_BASE` set the address (for GitHub Pages `/limen/`; for a custom domain `/`).
