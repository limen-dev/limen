---
name: website
description: Use when editing the documentation site or homepage (website/), or docs that are published into it.
---
# Website

Layout and build are in `website/README.md`. Rules that matter when editing:

- Much of `website/src/content/docs/` is generated from `docs/` by `scripts/sync-docs.mjs` and git-ignored. Edit the source documents, not the copies.
- A new guide must be added to the sidebar in `astro.config.mjs`.
- Copy follows ADR-0031: label anything tested only against a stand-in `unverified`; don't claim what is planned; no third-party requests.
- Check with `npm run build` (links and site rules) or `demos/demo-website.sh`. Neither renders pages; `scripts/browser-matrix.mjs` does.
