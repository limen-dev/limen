// The console check of console-matrix.mjs, in a regular Firefox.
//
// Playwright can only drive its own patched Firefox build, which does not start on every macOS
// version (#151). Puppeteer drives an installed Firefox over WebDriver BiDi, so this covers the gap.
// Same pages and checks as console-matrix.mjs; keep them in step. Differences: viewport sizes only
// (no touch or device emulation), so no touch-target count, and no screenshots.
//
// Dev only: it signs in as a Dex static user and accepts the dev stack's certificate in the browser
// it starts (the proxy uses the dev CA). It does not touch any trust store.
//
//   mkdir /tmp/matrix && cd /tmp/matrix && npm init -y && npm i puppeteer-core axe-core
//   deploy/compose/setup.sh --yes --stacks tcp,web
//   CONSOLE_URL=https://localhost:3443 node <repo>/deploy/compose/scripts/console-matrix-firefox.mjs
//   THEME=light node <repo>/deploy/compose/scripts/console-matrix-firefox.mjs
//
// Run it from the directory where you installed the packages.
// Environment: CONSOLE_URL, CONSOLE_USER (default admin@example.com), CONSOLE_PASSWORD (default
// password), THEME (dark or light), FIREFOX_EXECUTABLE (default /Applications/Firefox.app/...).
// Exits 1 when anything is reported, and 2 when Firefox could not start (nothing was tested).
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

const req = createRequire(`${process.cwd()}/`);
const puppeteer = req('puppeteer-core');
const axeSrc = readFileSync(req.resolve('axe-core/axe.min.js'), 'utf8');

const BASE = process.env.CONSOLE_URL ?? 'https://localhost:3443';
const USER = process.env.CONSOLE_USER ?? 'admin@example.com';
const PASSWORD = process.env.CONSOLE_PASSWORD ?? 'password';
const THEME = process.env.THEME ?? 'dark';
const executablePath = process.env.FIREFOX_EXECUTABLE ?? '/Applications/Firefox.app/Contents/MacOS/firefox';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const profiles = [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'laptop1024', width: 1024, height: 768 },
  { name: 'phone390', width: 390, height: 844 },
  { name: 'small360', width: 360, height: 740 },
];

let browser;
try {
  browser = await puppeteer.launch({ browser: 'firefox', executablePath, headless: true, protocol: 'webDriverBiDi', acceptInsecureCerts: true });
} catch (e) {
  console.log(`NOT RUN firefox:\n${String(e.message).split('\n').slice(0, 14).map((l) => `    ${l}`).join('\n')}`);
  console.log('NOT RUN, so not verified: firefox');
  process.exit(2);
}
console.log(`Firefox ${(await browser.version()).replace(/^.*\//, '')}`);

const results = [];
for (const profile of profiles) {
  const page = await browser.newPage();
  await page.setViewport({ width: profile.width, height: profile.height });
  await page.setCacheEnabled(false); // a cached file answers 304, which is not the page's fault
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));

  await page.goto(`${BASE}/console/login`, { waitUntil: 'networkidle0' });
  await page.type('input[name="login"]', USER);
  await page.type('input[name="password"]', PASSWORD);
  await Promise.all([page.waitForFunction(() => location.pathname.startsWith('/console/') && !location.pathname.startsWith('/console/login'), { timeout: 30000 }), page.click('button[type="submit"]')]);
  await sleep(800);
  // Theme: the console reads this key. It has to be set on the console's own origin, so after
  // sign-in (the login page belongs to the identity provider), and every page after it applies it.
  await page.evaluate((t) => localStorage.setItem('limen-theme', t), THEME);

  // The list pages, plus the first detail page each one links to.
  const pages = ['/console/', '/console/resources', '/console/sessions', '/console/bots', '/console/users', '/console/workers', '/console/audit', '/console/audit/kubernetes', '/console/dashboards', '/console/policy', '/console/access', '/console/reviews', '/console/discovered'];
  for (const [list, prefix] of [['/console/resources', '/console/resources/'], ['/console/sessions', '/console/sessions/'], ['/console/users', '/console/users/'], ['/console/access', '/console/access/']]) {
    await page.goto(BASE + list, { waitUntil: 'networkidle0' });
    const href = await page.$$eval(`a[href^="${prefix}"]`, (as, p) => as.map((a) => a.getAttribute('href')).find((h) => h !== p && !h.endsWith('/recording') && !h.endsWith('/kill')) ?? null, prefix);
    if (href) pages.push(href);
  }

  for (const path of pages) {
    const before = errors.length;
    const resp = await page.goto(BASE + path, { waitUntil: 'networkidle0' });
    await sleep(250);
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
      return { scroll: document.documentElement.scrollWidth, client: w, offenders, theme: document.documentElement.dataset.theme ?? null };
    });
    const problems = [];
    if (resp.status() >= 400) problems.push(`HTTP ${resp.status()}`);
    if (m.theme !== THEME) problems.push(`theme is ${m.theme}, not ${THEME}, so this was not a ${THEME} run`);
    if (m.scroll > m.client + 1) problems.push(`scrolls sideways ${m.scroll}>${m.client} [${m.offenders.join(' ')}]`);
    if (errors.length > before) problems.push(`JavaScript error ${JSON.stringify(errors.slice(before)).slice(0, 140)}`);
    await page.evaluate(axeSrc);
    const axe = await page.evaluate(() => axe.run(document, { runOnly: ['wcag2a', 'wcag2aa', 'wcag21aa'] }));
    results.push({ profile: `firefox/${profile.name}`, path, problems, axe: axe.violations.map((v) => `${v.id}(${v.nodes.length})`), theme: m.theme });
  }
  await page.close();
}
await browser.close();

const bad = results.filter((r) => r.problems.length || r.axe.length);
const themes = [...new Set(results.map((r) => r.theme))].join(',');
console.log(`${results.length} page loads in ${THEME} (page theme seen: ${themes}); ${bad.length} with a problem`);
for (const r of bad) console.log(` ${r.profile.padEnd(20)} ${r.path.padEnd(30)} ${[...r.problems, ...r.axe.map((a) => `axe: ${a}`)].join(' | ')}`);
process.exitCode = bad.length ? 1 : 0;
