// Opens every console page in several browser engines and screen sizes, signed in through
// the identity provider like a person, and reports: sideways scrolling, JavaScript errors,
// accessibility violations (axe-core, WCAG 2.1 AA) and touch targets under 32px.
//
// Dev only: it signs in as a Dex static user and skips the certificate check for the
// browser it starts, because the dev stack's proxy uses the dev CA.
//
//   mkdir /tmp/matrix && cd /tmp/matrix && npm init -y && npm i playwright-core axe-core
//   npx playwright-core install chromium webkit firefox     # once
//   deploy/compose/setup.sh --yes --stacks tcp,web          # something for the pages to show
//   CONSOLE_URL=https://localhost:3443 node <repo>/deploy/compose/scripts/console-matrix.mjs
//   THEME=light node <repo>/deploy/compose/scripts/console-matrix.mjs webkit-iPhone13 shots
//
// Arguments: a filter on "engine-profile" (for example chromium, webkit-iPad, Pixel7), then
// "shots" to save a screenshot of every page into the current directory.
// Run it from the directory where you installed the packages.
// Environment: CONSOLE_URL, CONSOLE_USER (default admin@example.com), CONSOLE_PASSWORD
// (default password), THEME (dark or light), CHROMIUM_EXECUTABLE (to use a browser you have).
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

const req = createRequire(`${process.cwd()}/`);
const { chromium, firefox, webkit, devices } = req('playwright-core');
const axeSrc = readFileSync(req.resolve('axe-core/axe.min.js'), 'utf8');

const BASE = process.env.CONSOLE_URL ?? 'https://localhost:3443';
const USER = process.env.CONSOLE_USER ?? 'admin@example.com';
const PASSWORD = process.env.CONSOLE_PASSWORD ?? 'password';
const THEME = process.env.THEME ?? 'dark';
const [, , only, shots] = process.argv;

const profiles = [
  ['chromium', chromium, { viewport: { width: 1440, height: 900 } }, 'desktop'],
  ['chromium', chromium, { viewport: { width: 1024, height: 768 } }, 'laptop1024'],
  ['chromium', chromium, devices['Pixel 7'], 'Pixel7'],
  ['chromium', chromium, { viewport: { width: 360, height: 740 }, isMobile: true, hasTouch: true, deviceScaleFactor: 2 }, 'small360'],
  ['webkit', webkit, { viewport: { width: 1440, height: 900 } }, 'desktop'],
  ['webkit', webkit, devices['iPhone 13'], 'iPhone13'],
  ['webkit', webkit, devices['iPad (gen 7)'], 'iPad'],
  ['firefox', firefox, { viewport: { width: 1440, height: 900 } }, 'desktop'],
  ['firefox', firefox, { viewport: { width: 390, height: 844 } }, 'phone390'],
];
const slug = (s) => s.replace(/\W+/g, '');
const results = [];
const skipped = [];

for (const [engine, type, opts, name] of profiles) {
  if (only && !`${engine}-${name}`.includes(only)) continue;
  let browser;
  try {
    browser = await type.launch(engine === 'chromium' && process.env.CHROMIUM_EXECUTABLE ? { executablePath: process.env.CHROMIUM_EXECUTABLE } : {});
  } catch (e) {
    skipped.push(`${engine}-${name}:\n${String(e.message).split('\n').slice(0, 14).map((l) => `    ${l}`).join('\n')}`);
    continue;
  }
  const ctx = await browser.newContext({ ...opts, ignoreHTTPSErrors: true, colorScheme: THEME });
  await ctx.addInitScript((t) => { try { localStorage.setItem('limen-theme', t); } catch { /* private mode */ } }, THEME);
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));

  await page.goto(`${BASE}/console/login`, { waitUntil: 'networkidle' });
  await page.fill('input[name="login"]', USER);
  await page.fill('input[name="password"]', PASSWORD);
  await Promise.all([page.waitForURL(/\/console\//, { timeout: 30000 }), page.click('button[type="submit"]')]);
  await page.waitForLoadState('networkidle');

  // The list pages, plus the first detail page each one links to.
  const pages = ['/console/', '/console/resources', '/console/sessions', '/console/bots', '/console/users', '/console/workers', '/console/audit', '/console/audit/kubernetes', '/console/dashboards', '/console/policy', '/console/access', '/console/reviews', '/console/discovered'];
  for (const [list, prefix] of [['/console/resources', '/console/resources/'], ['/console/sessions', '/console/sessions/'], ['/console/users', '/console/users/'], ['/console/access', '/console/access/']]) {
    await page.goto(BASE + list, { waitUntil: 'networkidle' });
    const href = await page.$$eval(`a[href^="${prefix}"]`, (as, p) => as.map((a) => a.getAttribute('href')).find((h) => h !== p && !h.endsWith('/recording') && !h.endsWith('/kill')) ?? null, prefix);
    if (href) pages.push(href);
  }

  for (const path of pages) {
    const before = errors.length;
    const resp = await page.goto(BASE + path, { waitUntil: 'networkidle' });
    await page.waitForTimeout(250);
    const m = await page.evaluate(() => {
      const w = document.documentElement.clientWidth;
      const offenders = [...document.querySelectorAll('body *')].filter((e) => {
        const r = e.getBoundingClientRect();
        if (r.width === 0 || r.right <= w + 1) return false;
        for (let n = e.parentElement; n && n !== document.body; n = n.parentElement) {
          if (['auto', 'scroll', 'hidden', 'clip'].includes(getComputedStyle(n).overflowX)) return false;
        }
        return true;
      }).slice(0, 3).map((e) => `${e.tagName.toLowerCase()}.${String(e.className).slice(0, 28)}`);
      const small = [...document.querySelectorAll('a, button, input, select, summary, [role=button]')].filter((e) => {
        const r = e.getBoundingClientRect();
        const inline = e.tagName === 'A' && e.closest('p, li, td, .chips') && r.height >= 18; // a link in running text
        return r.width > 0 && r.height > 0 && e.type !== 'hidden' && (r.height < 32 || r.width < 32) && !inline;
      }).length;
      return { scroll: document.documentElement.scrollWidth, client: w, offenders, small };
    });
    const problems = [];
    if (resp.status() >= 400) problems.push(`HTTP ${resp.status()}`);
    if (m.scroll > m.client + 1) problems.push(`scrolls sideways ${m.scroll}>${m.client} [${m.offenders.join(' ')}]`);
    if (errors.length > before) problems.push(`JavaScript error ${JSON.stringify(errors.slice(before)).slice(0, 140)}`);
    await page.evaluate(axeSrc);
    const axe = await page.evaluate(() => axe.run(document, { runOnly: ['wcag2a', 'wcag2aa', 'wcag21aa'] }));
    results.push({ profile: `${engine}/${name}`, path, problems, small: m.small, axe: axe.violations.map((v) => `${v.id}(${v.nodes.length})`) });
    if (shots) await page.screenshot({ path: `console-${engine}-${slug(name)}-${THEME}-${slug(path) || 'home'}.png` });
  }
  await browser.close();
}

const bad = results.filter((r) => r.problems.length || r.axe.length);
console.log(`${results.length} page loads in ${THEME}; ${bad.length} with a problem`);
for (const r of bad) console.log(` ${r.profile.padEnd(20)} ${r.path.padEnd(30)} ${[...r.problems, ...r.axe.map((a) => `axe: ${a}`)].join(' | ')}`);
const smalls = results.filter((r) => r.small > 0 && /Pixel|small|iPhone|phone/.test(r.profile));
if (smalls.length) console.log(`touch targets under 32px on phones (informational): ${smalls.slice(0, 8).map((r) => `${r.path}:${r.small}`).join(' ')}`);
for (const s of skipped) console.log(`NOT RUN (engine did not start), so not verified: ${s}`);
// An engine that did not start tested nothing, so that is never a pass.
process.exitCode = bad.length ? 1 : skipped.length ? 2 : 0;
