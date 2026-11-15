// Checks the built site for things a link checker cannot see. ADR-0031 applies to marketing:
// nothing planned is stated as shipped, and the site makes no request the visitor didn't ask for.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const site = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(site, 'dist');
const repo = resolve(site, '..');
const errors = [];
const fail = (m) => errors.push(m);

const walk = (dir) =>
  readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
const pages = walk(dist).filter((f) => f.endsWith('.html'));

// 1. Every guide and runbook in docs/ is published.
for (const [src, out] of [['docs/guides', 'docs/guides'], ['docs/runbooks', 'docs/runbooks']]) {
  for (const f of readdirSync(join(repo, src)).filter((f) => f.endsWith('.md') && f !== 'README.md')) {
    if (!existsSync(join(dist, out, f.slice(0, -3), 'index.html'))) fail(`${src}/${f} is not on the site`);
  }
}

// 1b. Every guide is in the sidebar. Publishing a page nobody can navigate to is how the SCIM guide went unlisted.
// (Runbooks and decision records are generated into the sidebar, so only the guides are listed by hand.)
const sidebar = readFileSync(join(site, 'astro.config.mjs'), 'utf8');
for (const f of readdirSync(join(repo, 'docs/guides')).filter((f) => f.endsWith('.md') && f !== 'README.md')) {
  if (!sidebar.includes(`'docs/guides/${f.slice(0, -3)}'`)) fail(`docs/guides/${f} is not in the sidebar (website/astro.config.mjs)`);
}

// 2. No page loads anything from another origin (fonts, scripts, styles, images, frames).
for (const file of pages) {
  const html = readFileSync(file, 'utf8');
  for (const m of html.matchAll(/<(?:script|img|iframe|source|link)\b[^>]*\s(?:src|href)="(https?:)?\/\/([^"/]+)[^"]*"/g)) {
    if (/<link\b[^>]*rel="(?:canonical|alternate|sitemap)"/.test(m[0])) continue;
    fail(`${file.slice(dist.length)} loads from ${m[2]}`);
  }
  if (/<link\b[^>]*rel="stylesheet"[^>]*href="https?:/.test(html)) fail(`${file.slice(dist.length)} loads a third-party stylesheet`);
}

// 3. The homepage keeps its promises: it says what is unverified, and claims nothing that is not built.
const home = readFileSync(join(dist, 'index.html'), 'utf8');
if (!/unverified/i.test(home)) fail('the homepage no longer says anything is unverified');
if (!/not yet been verified against real AWS/i.test(home)) fail('the homepage lost its statement about real-service verification');
for (const banned of [/access receipts?/i, /more secure than/i, /\bSOC ?2 compliant\b/i, /\bAI agents?\b/i]) {
  if (banned.test(home)) fail(`the homepage makes a claim ADR-0031 forbids: ${banned}`);
}

// 3b. Every console screenshot the homepage points at is published, in both themes.
const shots = [...home.matchAll(/data-(?:dark|light)="([^"]*?(console\/[^/"]+\.jpg))"/g)];
if (!shots.length) fail('the homepage shows no console screenshots');
for (const [, , file] of shots) if (!existsSync(join(dist, file))) fail(`the homepage points at ${file}, which is not published`);
for (const [, , file] of shots) {
  const other = file.endsWith('-dark.jpg') ? file.replace('-dark.jpg', '-light.jpg') : file.replace('-light.jpg', '-dark.jpg');
  if (!shots.some(([, , f]) => f === other)) fail(`${file} has no ${file.endsWith('-dark.jpg') ? 'light' : 'dark'} counterpart on the homepage`);
}

// 4. The status page and search index exist.
for (const p of ['docs/status/index.html', 'pagefind/pagefind.js', 'sitemap-index.xml', 'favicon.svg', 'og.png', '404.html']) {
  if (!existsSync(join(dist, p))) fail(`missing ${p}`);
}

if (errors.length) {
  console.error(`site checks failed:\n${errors.map((e) => `  - ${e}`).join('\n')}`);
  process.exit(1);
}
console.log(`site checks ok: ${pages.length} pages`);
