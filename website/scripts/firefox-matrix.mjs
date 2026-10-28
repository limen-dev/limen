// The same checks as browser-matrix.mjs, in a regular Firefox.
//
// Playwright can only drive its own patched Firefox build, which does not start on every macOS
// version (#151). Puppeteer drives an installed Firefox over WebDriver BiDi, so this covers the gap.
// Keep the page list and the checks in step with browser-matrix.mjs.
//
//   npm i puppeteer-core axe-core        (anywhere; resolved from the directory you run it in)
//   SITE_URL=http://localhost:4341 node /path/to/website/scripts/firefox-matrix.mjs
//
//   THEME=dark|light (default dark)
//   FIREFOX_EXECUTABLE=<path>  (default /Applications/Firefox.app/Contents/MacOS/firefox)
//
// Exits 1 when anything is reported, and 2 when Firefox could not start (nothing was tested).
// Differences from the Playwright script: viewport sizes only, and no touch-target check, because
// touch cannot be emulated here and the 32px sizes apply only to `pointer: coarse`.
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

const require = createRequire(`${process.cwd()}/`);
const puppeteer = require('puppeteer-core');
const axeSource = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');

const base = (process.env.SITE_URL ?? 'http://localhost:4321').replace(/\/$/, '');
const theme = process.env.THEME ?? 'dark';
const executablePath = process.env.FIREFOX_EXECUTABLE ?? '/Applications/Firefox.app/Contents/MacOS/firefox';

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
const profiles = [
  { name: 'firefox-desktop-1440', width: 1440, height: 900 },
  { name: 'firefox-1024', width: 1024, height: 768 },
  { name: 'firefox-412', width: 412, height: 915, mobile: true },
  { name: 'firefox-360', width: 360, height: 740, mobile: true },
];

let browser;
try {
  browser = await puppeteer.launch({ browser: 'firefox', executablePath, headless: true, protocol: 'webDriverBiDi' });
} catch (err) {
  console.log(`NOT RUN firefox:\n${String(err.message).split('\n').slice(0, 14).map((l) => `    ${l}`).join('\n')}`);
  console.log('NOT RUN, so not verified: firefox');
  process.exit(2);
}
console.log(`Firefox ${(await browser.version()).replace(/^.*\//, '')}`);

let problems = 0;
let loads = 0;
const report = (profile, path, msg) => {
  problems += 1;
  console.log(`  ✗ ${profile} ${path}: ${msg}`);
};
const visible = (page, sel) => page.$eval(sel, (e) => !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length)).catch(() => false);

async function interact(page, profile, path) {
  const fail = (m) => report(profile.name, path, m);
  if (path === '/') {
    const theme0 = await page.evaluate(() => document.documentElement.dataset.theme);
    await page.click('#theme');
    const theme1 = await page.evaluate(() => document.documentElement.dataset.theme);
    if (theme0 === theme1) fail('theme toggle did not change the theme');
    await page.click('#theme');

    await page.click('#open-palette');
    await page.type('#palette-input', 'quick');
    if (!(await page.$$('#palette-list a')).length) fail('palette found nothing for "quick"');
    const box = await page.$eval('#palette > *', (e) => {
      const r = e.getBoundingClientRect();
      return { x: r.x, right: r.x + r.width };
    });
    if (box.x < -1 || box.right > profile.width + 1) fail(`palette overflows the viewport (${Math.round(box.x)}..${Math.round(box.right)} of ${profile.width})`);
    await page.keyboard.press('Escape');
    if (await visible(page, '#palette')) fail('Escape did not close the palette');
  } else if (path.startsWith('/docs/')) {
    if (await visible(page, 'button[data-open-modal]')) {
      await page.click('button[data-open-modal]');
      const opened = await page.waitForSelector('dialog[open] input', { timeout: 5000 }).catch(() => null);
      if (!opened) fail('docs search did not open');
      else {
        await page.type('dialog[open] input', 'postgres');
        const hit = await page.waitForSelector('dialog[open] a[href*="/docs/"]', { timeout: 8000 }).catch(() => null);
        if (!hit) fail('docs search returned no results for "postgres"');
      }
      await page.keyboard.press('Escape');
    }
    if (profile.mobile) {
      if (await visible(page, 'button.sl-menu-button')) {
        await page.click('button.sl-menu-button');
        const links = await page.$$eval('#starlight__sidebar a', (as) => as.filter((a) => a.offsetWidth && a.offsetHeight).length);
        if (!links) fail('mobile menu opened with no visible sidebar links');
        await page.keyboard.press('Escape');
      } else fail('no mobile menu button at phone width');
    }
  }
}

for (const profile of profiles) {
  console.log(`\n${profile.name} [${theme}]`);
  for (const path of pages) {
    const page = await browser.newPage();
    await page.setViewport({ width: profile.width, height: profile.height });
    await page.setCacheEnabled(false); // a cached file answers 304, which is not the page's fault
    const errors = [];
    page.on('pageerror', (e) => errors.push(`js: ${e.message}`));
    page.on('console', (m) => m.type() === 'error' && !/404/.test(m.text()) && errors.push(`console: ${m.text()}`));
    page.on('request', (r) => {
      const u = new URL(r.url());
      if (/^https?:$/.test(u.protocol) && u.origin !== base) errors.push(`third-party request: ${r.url()}`);
    });
    // Theme: both the docs and the homepage read this key. Set it on a page with no scripts, so
    // that leaving it aborts nothing (leaving a real page mid-load reports a failed lazy import).
    await page.goto(`${base}/sitemap-index.xml`, { waitUntil: 'domcontentloaded' });
    await page.evaluate((t) => localStorage.setItem('starlight-theme', t), theme);
    const res = await page.goto(base + path, { waitUntil: 'networkidle0' });
    loads += 1;
    const want = path === '/this-page-does-not-exist' ? 404 : 200;
    if (res.status() !== want) report(profile.name, path, `HTTP ${res.status()}, expected ${want}`);
    if (path === '/') {
      await page.evaluate(() => document.querySelectorAll('.reveal').forEach((e) => e.classList.add('in')));
      await new Promise((r) => setTimeout(r, 700));
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

    try {
      await interact(page, profile, path);
    } catch (err) {
      report(profile.name, path, `interaction threw: ${String(err.message).split('\n')[0]}`);
    }
    for (const e of errors) report(profile.name, path, e);
    await page.close();
  }
}

await browser.close();
console.log(problems ? `\n${problems} problem(s) in ${loads} page loads` : `\nno problems in ${loads} page loads`);
process.exit(problems ? 1 : 0);
