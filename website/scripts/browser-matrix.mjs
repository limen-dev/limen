// Runs the built site through real browser engines at phone, tablet and desktop sizes.
//
// Not a dependency of the site: Playwright and axe-core are resolved from the directory you run
// it in, so install them anywhere (a scratch dir is fine) and run from there:
//
//   npm i playwright-core axe-core && npx playwright-core install chromium webkit firefox
//   (cd website && npm run build && npx astro preview --port 4341 &)
//   SITE_URL=http://localhost:4341 node /path/to/website/scripts/browser-matrix.mjs
//
// Per page and profile it reports sideways scrolling, JS errors, failed requests, any request to
// another origin, axe WCAG 2.1 A/AA violations and touch targets under 24px. On the homepage and
// docs it also drives the theme toggle, the ⌘K palette, docs search and the mobile menu.
//
//   BROWSERS=chromium,webkit,firefox   (default: all installed)   THEME=dark|light (default dark)
//   CHROMIUM_EXECUTABLE=<path>         use a headless shell instead of the full Chromium
//
// Exits non-zero when anything is reported.
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

const require = createRequire(`${process.cwd()}/`);
const { chromium, webkit, firefox, devices } = require('playwright-core');
const axeSource = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');

const base = (process.env.SITE_URL ?? 'http://localhost:4321').replace(/\/$/, '');
const theme = process.env.THEME ?? 'dark';
const wanted = (process.env.BROWSERS ?? 'chromium,webkit,firefox').split(',');
const engines = { chromium, webkit, firefox };

const pages = [
  '/',
  '/docs/',
  '/docs/quickstart/',
  '/docs/status/',
  '/docs/concepts/',
  '/docs/architecture/threat-model/',
  '/docs/guides/databases/',
  '/docs/runbooks/',
  '/docs/runbooks/database-onboarding/',
  '/docs/reference/compose-stack/',
  '/this-page-does-not-exist',
];

const desktop = (w, h) => ({ viewport: { width: w, height: h } });
const profiles = [
  { engine: 'chromium', name: 'chromium-desktop-1440', ctx: desktop(1440, 900) },
  { engine: 'chromium', name: 'chromium-1024', ctx: desktop(1024, 768) },
  { engine: 'chromium', name: 'chromium-pixel7', ctx: devices['Pixel 7'], mobile: true },
  { engine: 'chromium', name: 'chromium-360', ctx: { ...devices['Pixel 7'], viewport: { width: 360, height: 740 } }, mobile: true },
  { engine: 'webkit', name: 'webkit-desktop-1440', ctx: desktop(1440, 900) },
  { engine: 'webkit', name: 'webkit-iphone13', ctx: devices['iPhone 13'], mobile: true },
  { engine: 'webkit', name: 'webkit-ipad', ctx: devices['iPad (gen 7)'], mobile: true },
  { engine: 'firefox', name: 'firefox-desktop-1440', ctx: desktop(1440, 900) },
  { engine: 'firefox', name: 'firefox-360', ctx: { viewport: { width: 360, height: 740 }, hasTouch: false }, mobile: true },
].filter((p) => wanted.includes(p.engine));

const launched = {};
for (const e of wanted) {
  try {
    launched[e] = await engines[e].launch(
      e === 'chromium' && process.env.CHROMIUM_EXECUTABLE ? { executablePath: process.env.CHROMIUM_EXECUTABLE } : {},
    );
  } catch (err) {
    console.log(`SKIPPED ${e}: ${String(err.message).split('\n')[0]}`);
  }
}

let problems = 0;
const report = (profile, path, msg) => {
  problems += 1;
  console.log(`  ✗ ${profile} ${path}: ${msg}`);
};

async function interact(page, profile, path) {
  const fail = (m) => report(profile.name, path, m);
  if (path === '/') {
    const before = await page.evaluate(() => document.documentElement.dataset.theme);
    await page.click('#theme');
    const after = await page.evaluate(() => document.documentElement.dataset.theme);
    if (before === after) fail('theme toggle did not change the theme');
    await page.click('#theme');

    await page.click('#open-palette');
    await page.fill('#palette-input', 'quick');
    const opts = await page.locator('#palette-list a').count();
    if (!opts) fail('palette found nothing for "quick"');
    const box = await page.locator('#palette > *').first().boundingBox();
    const vw = page.viewportSize().width;
    if (box && (box.x < -1 || box.x + box.width > vw + 1)) fail(`palette overflows the viewport (${Math.round(box.x)}..${Math.round(box.x + box.width)} of ${vw})`);
    await page.keyboard.press('Escape');
    if (await page.locator('#palette').isVisible()) fail('Escape did not close the palette');
  } else if (path.startsWith('/docs/')) {
    const search = page.locator('button[data-open-modal]').first();
    if (await search.isVisible()) {
      await search.click();
      const input = page.locator('dialog[open] input, .pagefind-ui__search-input').first();
      await input.waitFor({ timeout: 5000 }).catch(() => fail('docs search did not open'));
      await input.fill('postgres');
      const hit = page.locator('dialog[open] a[href*="/docs/"]').first();
      await hit.waitFor({ timeout: 8000 }).catch(() => fail('docs search returned no results for "postgres"'));
      await page.keyboard.press('Escape');
    }
    if (profile.mobile) {
      // Starlight's menu is a popover button; the sidebar is `:popover-open` once it is shown.
      const menu = page.locator('button.sl-menu-button').first();
      if (await menu.isVisible()) {
        await menu.click();
        const links = await page.locator('#starlight__sidebar a:visible').count();
        if (!links) fail('mobile menu opened with no visible sidebar links');
        await page.keyboard.press('Escape');
      } else if (page.viewportSize().width < 800) fail('no mobile menu button at phone width');
    }
  }
}

for (const profile of profiles) {
  const browser = launched[profile.engine];
  if (!browser) continue;
  console.log(`\n${profile.name} [${theme}]`);
  const ctx = await browser.newContext({ ...profile.ctx, colorScheme: theme });
  await ctx.addInitScript((t) => {
    try {
      localStorage.setItem('starlight-theme', t);
    } catch {}
  }, theme);
  for (const path of pages) {
    const page = await ctx.newPage();
    const errors = [];
    page.on('pageerror', (e) => errors.push(`js: ${e.message}`));
    page.on('console', (m) => m.type() === 'error' && !/404/.test(m.text()) && errors.push(`console: ${m.text()}`));
    // The 404 page probes the slash-less URL on purpose, so a failed request there is expected.
    page.on('requestfailed', (r) => path !== '/this-page-does-not-exist' && errors.push(`failed: ${r.url()}`));
    page.on('request', (r) => {
      const u = new URL(r.url());
      if (/^https?:$/.test(u.protocol) && u.origin !== base) errors.push(`third-party request: ${r.url()}`);
    });
    const res = await page.goto(base + path, { waitUntil: 'networkidle' });
    const want = path === '/this-page-does-not-exist' ? 404 : 200;
    if (res.status() !== want) report(profile.name, path, `HTTP ${res.status()}, expected ${want}`);
    if (path === '/') {
      await page.evaluate(() => document.querySelectorAll('.reveal').forEach((e) => e.classList.add('in')));
      await page.waitForTimeout(700);
    }

    const wide = await page.evaluate(() => {
      const w = document.documentElement.clientWidth;
      const offenders = [...document.querySelectorAll('body *')]
        .filter((e) => e.getBoundingClientRect().right > w + 1 && !e.closest('pre, .table-scroll, [data-scroll], .tabs, svg'))
        .slice(0, 3)
        .map((e) => `${e.tagName.toLowerCase()}${e.className ? '.' + String(e.className).split(' ')[0] : ''}`);
      return { scroll: document.documentElement.scrollWidth - w, offenders };
    });
    if (wide.scroll > 1) report(profile.name, path, `sideways scroll of ${wide.scroll}px (${wide.offenders.join(', ') || 'no single culprit'})`);

    await page.evaluate(axeSource);
    const axe = await page.evaluate(() => axe.run(document, { runOnly: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] }));
    for (const v of axe.violations) report(profile.name, path, `axe ${v.id} (${v.impact}) x${v.nodes.length}, e.g. ${v.nodes[0].target.join(' ')}`);

    if (profile.mobile) {
      // Skipped on purpose: a link card's <a> is stretched over the whole card, and heading anchors
      // have nothing within 24px of them (the WCAG 2.5.8 spacing exception).
      const small = await page.evaluate(() =>
        [...document.querySelectorAll('a[href], button, input, select, summary')]
          .filter((e) => {
            const r = e.getBoundingClientRect();
            const s = getComputedStyle(e);
            return r.width && r.height && s.visibility !== 'hidden' && (r.width < 23.5 || r.height < 23.5) && !(e.tagName === 'A' && getComputedStyle(e).display === 'inline') && !e.closest('.sl-link-card') && !e.matches('.sl-anchor-link');
          })
          .slice(0, 3)
          .map((e) => `${e.tagName.toLowerCase()} "${(e.textContent || e.getAttribute('aria-label') || '').trim().slice(0, 20)}" ${Math.round(e.getBoundingClientRect().width)}x${Math.round(e.getBoundingClientRect().height)}`),
      );
      if (small.length) report(profile.name, path, `touch targets under 24px: ${small.join('; ')}`);
    }

    try {
      await interact(page, profile, path);
    } catch (err) {
      report(profile.name, path, `interaction threw: ${String(err.message).split('\n')[0]}`);
    }
    for (const e of errors) report(profile.name, path, e);
    await page.close();
  }
  await ctx.close();
}

for (const b of Object.values(launched)) await b.close();
console.log(problems ? `\n${problems} problem(s)` : '\nclean');
process.exit(problems ? 1 : 0);
