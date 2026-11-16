// Retakes the console screenshots on the homepage (website/public/console/<id>-dark.jpg and -light.jpg)
// from a running dev stack that has been given something to show. Dev only. It is a maintainer tool, not a
// dependency of the site: Playwright is resolved from the directory you run it in.
//
//   mkdir /tmp/shots && cd /tmp/shots && npm i playwright-core && npx playwright-core install chromium
//   CONSOLE_CA=<repo>/deploy/compose/.state/internal-ca.pem node <repo>/website/scripts/console-shots.mjs
//
// What the pages show comes from the stack, so seed it first (see "Retaking the console screenshots" in
// website/README.md). Environment:
//   CONSOLE_CA        the dev CA (required). The browser it starts trusts only chains through this key, and
//                     no certificate error is ignored for any other: the dev stack's proxy uses this CA, and
//                     nothing is added to a trust store.
//   CONSOLE_URL       default https://localhost:3443
//   CONSOLE_USER      default admin@example.com (password: CONSOLE_PASSWORD, default "password")
//   OUT               where the pictures go, default ./console-shots
//   PREP=1            first do the console steps some pictures need: star three resources, disable the user
//                     `contractor@example.com` with a reason. It changes the stack.
//   REPLAY_SESSION, COMMANDS_SESSION   session ids for the Replay and Commands pictures, when the newest
//                     SSH session and the newest database session are not the ones you want.
//   CHROMIUM_EXECUTABLE   a browser to use instead of Playwright's own.
// Arguments: ids to retake (for example `overview replay`); none means all.
//
// Sign in once per person in the CLI while seeding: Dex refuses an earlier login's refresh token when the same
// person signs in again, and the IdP check then locks them (docs/guides/offboarding.md, "Dex").
import { createHash, X509Certificate } from 'node:crypto';
import { mkdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const { chromium } = createRequire(`${process.cwd()}/`)('playwright-core');

const BASE = process.env.CONSOLE_URL ?? 'https://localhost:3443';
const USER = process.env.CONSOLE_USER ?? 'admin@example.com';
const PASSWORD = process.env.CONSOLE_PASSWORD ?? 'password';
const OUT = process.env.OUT ?? 'console-shots';
const [W, H, SCALE] = [1440, 880, 1.4]; // 2016x1232, the size index.astro declares
const only = process.argv.slice(2);

if (!process.env.CONSOLE_CA) {
  console.error('CONSOLE_CA is required: the dev CA, deploy/compose/.state/internal-ca.pem');
  process.exit(1);
}
const spki = createHash('sha256').update(new X509Certificate(readFileSync(process.env.CONSOLE_CA)).publicKey.export({ type: 'spki', format: 'der' })).digest('base64');

mkdirSync(OUT, { recursive: true });
const browser = await chromium.launch({
  ...(process.env.CHROMIUM_EXECUTABLE ? { executablePath: process.env.CHROMIUM_EXECUTABLE } : {}),
  args: [`--ignore-certificate-errors-spki-list=${spki}`],
});
const ctx = await browser.newContext({ viewport: { width: W, height: H }, deviceScaleFactor: SCALE });
const page = await ctx.newPage();

await page.goto(`${BASE}/console/login`, { waitUntil: 'networkidle' });
await page.fill('input[name="login"]', USER);
await page.fill('input[name="password"]', PASSWORD);
await Promise.all([page.waitForURL(/\/console\//, { timeout: 30000 }), page.click('button[type="submit"]')]);
await page.waitForLoadState('networkidle');

const settle = async (ms = 700) => { await page.waitForLoadState('networkidle'); await page.waitForTimeout(ms); };
const go = async (path) => { await page.goto(BASE + path, { waitUntil: 'networkidle' }); await settle(); };

/** The newest session whose row has this link text ("Replay" for a recording, "Details" for the rest). */
async function newestSession(linkText) {
  await go('/console/sessions');
  return page.$$eval('main tr', (rows, text) => {
    for (const r of rows) {
      const a = [...r.querySelectorAll('a[href^="/console/sessions/"]')].find((x) => x.textContent.trim().endsWith(text));
      if (a) return a.getAttribute('href');
    }
    return null;
  }, linkText);
}
const firstLink = async (list, prefix) => { await go(list); return page.$$eval(`main a[href^="${prefix}"]`, (as) => as[0]?.getAttribute('href') ?? null); };

if (process.env.PREP === '1') {
  for (const r of ['orders-staging', 'web-staging-1', 'cache-staging']) {
    await go(`/console/resources/${r}`);
    const star = page.locator('main form[action="/console/favourites"] button').first();
    if (/^Favourite$/i.test((await star.innerText()).trim())) await Promise.all([page.waitForNavigation({ waitUntil: 'networkidle' }), star.click()]);
  }
  await go('/console/users/contractor%40example.com');
  const disable = page.locator('main form[action$="/lock"]'); // absent when the user is already disabled
  if (await disable.count()) {
    await disable.locator('input[name="reason"]').fill('Contract ended on 2026-11-14');
    await Promise.all([page.waitForNavigation({ waitUntil: 'networkidle' }), disable.locator('button').click()]);
  }
}

// id -> where to go, and what to do there. The ids are the homepage tabs (consolePages in src/pages/index.astro).
const pages = {
  overview: { path: '/console/' },
  resources: { path: '/console/resources' },
  connect: { path: '/console/resources/orders-staging?who=limen_read' },
  sessions: { path: '/console/sessions' },
  replay: {
    find: async () => process.env.REPLAY_SESSION ? `/console/sessions/${process.env.REPLAY_SESSION}` : newestSession('Replay'),
    prep: async () => {
      await page.click('button[aria-label="Play"]');
      await page.waitForTimeout(6500);
      await page.click('button[aria-label="Pause"]').catch(() => {});
      await page.waitForTimeout(300);
    },
  },
  commands: { find: async () => process.env.COMMANDS_SESSION ? `/console/sessions/${process.env.COMMANDS_SESSION}` : newestSession('Details') },
  access: {
    path: '/console/access',
    prep: async () => {
      await page.click('main a:has-text("Waiting for me")');
      await settle(900);
      await Promise.all([page.waitForLoadState('networkidle'), page.click('main a:has-text("Decide")')]);
      await settle(900);
    },
  },
  reviews: { find: () => firstLink('/console/reviews', '/console/reviews/') },
  controls: { path: '/console/controls' },
  users: { path: '/console/users' },
  audit: {
    path: '/console/audit',
    prep: async () => {
      await page.fill('input[placeholder^="Find a statement"]', 'from orders');
      await Promise.all([page.waitForLoadState('networkidle'), page.keyboard.press('Enter')]);
      await settle(1000);
    },
  },
  dashboards: { path: '/console/dashboards' },
  policy: { path: '/console/policy' },
  simulator: { path: '/console/simulator?person=developer%40example.com' },
  palette: {
    path: '/console/',
    prep: async () => {
      await page.keyboard.press('Control+K');
      await page.waitForTimeout(300);
      await page.keyboard.type('orders', { delay: 60 });
      await page.waitForTimeout(800);
    },
  },
};

const log = [];
for (const theme of ['dark', 'light']) {
  await page.goto(`${BASE}/console/`, { waitUntil: 'networkidle' });
  await page.evaluate((t) => localStorage.setItem('limen-theme', t), theme);
  for (const [id, spec] of Object.entries(pages)) {
    if (only.length && !only.includes(id)) continue;
    const path = spec.find ? await spec.find() : spec.path;
    if (!path) { log.push(`${id}: nothing to show on this stack (seed it first)`); continue; }
    await go(path);
    if (spec.prep) await spec.prep();
    await page.mouse.move(W - 4, H - 4); // park the pointer where it hovers nothing
    await page.waitForTimeout(400);
    await page.screenshot({ path: `${OUT}/${id}-${theme}.jpg`, type: 'jpeg', quality: 80 });
    log.push(`${id}-${theme}  ${path}`);
  }
}
console.log(log.join('\n'));
await browser.close();
process.exitCode = log.some((l) => l.includes('nothing to show')) ? 1 : 0;
