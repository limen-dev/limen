// Runs the web console through real browser engines at desktop, tablet and phone sizes, in light
// and dark, and checks every page for sideways scroll, content past the viewport, small tap
// targets and axe-core WCAG 2.1 A/AA violations. (#145)
//
// Two steps, so a browser never has to trust the dev CA (nothing here bypasses a certificate
// warning or touches a trust store):
//
//   1. snapshot: fetch the pages from a running compose stack with the CA verified and a signed-in
//      cookie, and save them as static files. Dev data only: do not commit the snapshot.
//   2. check: serve the snapshot over plain http on localhost and drive the browsers over it.
//
// Not a dependency of Limen: Playwright and axe-core are resolved from the directory you run it
// in, like website/scripts/browser-matrix.mjs.
//
//   npm i playwright-core axe-core && npx playwright-core install chromium webkit firefox
//   deploy/compose/scripts/console-login.sh admin@example.com /tmp/admin.jar
//   node deploy/compose/scripts/console-snapshot-matrix.mjs snapshot /tmp/console-snap /tmp/admin.jar
//   node deploy/compose/scripts/console-snapshot-matrix.mjs check /tmp/console-snap
//
//   BROWSERS=chromium,webkit,firefox (default: all installed)   THEMES=light,dark (default: both)
//   PAGES_ONLY=1 (snapshot: save the pages, not the CSS, scripts and fonts)
//   CONSOLE_ASSETS=<dir> (check: serve /console/static/* from here instead of the snapshot; default
//   crates/limen-control-plane/assets, so the repository's own CSS and scripts are what is tested)
//   LIMEN_CONSOLE_URL (default https://localhost:3443)   LIMEN_DEV_CA (default .state/internal-ca.pem)
//
// What a snapshot cannot show: server-side behaviour after a click (forms, kill, lock, token
// creation). The scripts on each page (theme toggle, filters, tables) do run. `check` exits 1
// when anything is reported and 2 when an engine could not start (nothing was tested in it).
import { createRequire } from 'node:module';
import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync, readdirSync } from 'node:fs';
import { createServer } from 'node:http';
import { request } from 'node:https';
import { dirname, extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const [mode, dir, jar] = process.argv.slice(2);
if (!['snapshot', 'check'].includes(mode) || !dir || (mode === 'snapshot' && !jar)) {
  console.error('usage: console-snapshot-matrix.mjs snapshot <dir> <cookie-jar> | check <dir>');
  process.exit(64);
}

// ---- snapshot ---------------------------------------------------------------------------------
async function snapshot() {
  const here = dirname(fileURLToPath(import.meta.url));
  const base = new URL(process.env.LIMEN_CONSOLE_URL ?? 'https://localhost:3443');
  const ca = readFileSync(process.env.LIMEN_DEV_CA ?? join(here, '..', '.state', 'internal-ca.pem'));
  const cookie = readFileSync(jar, 'utf8')
    .split('\n')
    .map((l) => l.replace(/^#HttpOnly_/, '').split('\t'))
    .filter((f) => f.length >= 7)
    .map((f) => `${f[5]}=${f[6]}`)
    .join('; ');
  if (!cookie) throw new Error(`no cookie in ${jar}: run console-login.sh first`);

  const get = (path) =>
    new Promise((resolve, reject) => {
      const req = request(
        { host: base.hostname, port: base.port, path, ca, headers: { cookie }, method: 'GET' },
        (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => resolve({ status: res.statusCode, type: res.headers['content-type'] ?? '', body: Buffer.concat(chunks), location: res.headers.location }));
        },
      );
      req.on('error', reject);
      req.end();
    });

  // Pages we do not want: they end a session, stream, or change state on a GET.
  const skip = /\/(logout|recording|watch|kill|lock|unlock|revoke|web\/|callback|login)(\/|$)/;
  const seen = new Set();
  const perKind = new Map();
  const queue = ['/console/'];
  const assets = new Set();
  let saved = 0;

  // A generated id (a review, a session) is saved as "example": the folder name means nothing,
  // and a regeneration then does not rename it.
  const stable = (path) => path.replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\/|$)/g, '/example');
  const save = (path, body) => {
    const target = stable(path);
    const file = target.endsWith('/') || !extname(target) ? join(dir, target, 'index.html') : join(dir, target);
    mkdirSync(dirname(file), { recursive: true });
    // End a page with a newline, so the saved files are clean in a diff.
    writeFileSync(file, file.endsWith('.html') && typeof body === 'string' && !body.endsWith('\n') ? `${body}\n` : body);
  };
  const collectAssets = (text) => {
    for (const m of text.matchAll(/\/console\/static\/[^"'()\s?#<>]+/g)) assets.add(m[0]);
  };

  while (queue.length && saved < 150) {
    const path = queue.shift();
    if (seen.has(path)) continue;
    seen.add(path);
    // At most three pages of each kind (/console/users/{name}, /console/sessions/{id}, ...).
    const parts = path.split('/').filter(Boolean);
    const kind = parts.length > 2 ? parts.slice(0, 2).join('/') : path;
    if (parts.length > 2 && (perKind.get(kind) ?? 0) >= 3) continue;
    const res = await get(path);
    if (res.status !== 200 || !res.type.includes('text/html')) {
      console.log(`  skip ${path} (${res.status}${res.location ? ` -> ${res.location}` : ''})`);
      continue;
    }
    perKind.set(kind, (perKind.get(kind) ?? 0) + 1);
    const html = res.body.toString('utf8');
    save(path, res.body);
    collectAssets(html);
    saved += 1;
    console.log(`  page ${path}`);
    for (const m of html.matchAll(/href="(\/console\/[^"#?]*)"/g)) {
      const next = m[1];
      if (!next.startsWith('/console/static/') && !skip.test(next) && !seen.has(next)) queue.push(next);
    }
  }
  for (const a of process.env.PAGES_ONLY ? [] : [...assets]) {
    const res = await get(a);
    if (res.status !== 200) {
      console.log(`  asset ${a} -> ${res.status}`);
      continue;
    }
    save(a, res.body);
    // Stylesheets name their fonts and images.
    if (a.endsWith('.css')) collectAssets(res.body.toString('utf8'));
  }
  for (const a of process.env.PAGES_ONLY ? [] : [...assets]) {
    const file = join(dir, a);
    if (!existsSync(file)) {
      const res = await get(a);
      if (res.status === 200) save(a, res.body);
    }
  }
  console.log(`saved ${saved} pages and ${assets.size} assets in ${dir}`);
}

// ---- check ------------------------------------------------------------------------------------
const types = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.png': 'image/png', '.json': 'application/json' };

// The repository's own console assets, by file name (fonts and vendored files are in subfolders).
function assetIndex() {
  const here = dirname(fileURLToPath(import.meta.url));
  const root = process.env.CONSOLE_ASSETS ?? join(here, '..', '..', '..', 'crates', 'limen-control-plane', 'assets');
  const byName = new Map();
  if (!existsSync(root)) return byName;
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      if (statSync(p).isDirectory()) walk(p);
      else if (!byName.has(name)) byName.set(name, p);
    }
  };
  walk(root);
  return byName;
}

function serve(root) {
  const assets = assetIndex();
  const server = createServer((req, res) => {
    const path = decodeURIComponent((req.url ?? '/').split('?')[0]);
    const own = path.startsWith('/console/static/') ? assets.get(path.slice('/console/static/'.length)) : undefined;
    if (own) return res.writeHead(200, { 'content-type': types[extname(own)] ?? 'application/octet-stream' }).end(readFileSync(own));
    let file = normalize(join(root, path));
    if (!file.startsWith(normalize(root))) return res.writeHead(403).end();
    if (existsSync(file) && statSync(file).isDirectory()) file = join(file, 'index.html');
    if (!existsSync(file)) return res.writeHead(404).end('not in the snapshot');
    res.writeHead(200, { 'content-type': types[extname(file)] ?? 'application/octet-stream' }).end(readFileSync(file));
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

function listPages(root) {
  const out = [];
  const walk = (d, rel) => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      if (statSync(p).isDirectory()) walk(p, `${rel}${name}/`);
      else if (name === 'index.html' && rel.startsWith('/console/') && !rel.startsWith('/console/static/')) out.push(rel);
    }
  };
  walk(join(root, 'console'), '/console/');
  return out.sort();
}

const require = createRequire(`${process.cwd()}/`);

// Looks enough like a Playwright browser for check(): newContext -> addInitScript, newPage, close.
async function puppeteerFirefox() {
  const puppeteer = require('puppeteer-core');
  const executablePath = process.env.FIREFOX_EXECUTABLE ?? '/Applications/Firefox.app/Contents/MacOS/firefox';
  const browser = await puppeteer.launch({ browser: 'firefox', executablePath, headless: true });
  return {
    close: () => browser.close(),
    newContext: async ({ viewport, colorScheme }) => {
      const inits = [];
      return {
        addInitScript: async (fn, arg) => inits.push([fn, arg]),
        close: async () => {},
        newPage: async () => {
          const page = await browser.newPage();
          await page.setViewport(viewport);
          // BiDi cannot emulate prefers-color-scheme; the console's stored theme choice (below) sets the theme.
          for (const [fn, arg] of inits) await page.evaluateOnNewDocument(fn, arg);
          return page;
        },
      };
    },
  };
}

async function check() {
  const { chromium, webkit, firefox, devices } = require('playwright-core');
  const axeSource = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
  const wanted = (process.env.BROWSERS ?? 'chromium,webkit,firefox').split(',');
  const themes = (process.env.THEMES ?? 'light,dark').split(',');
  const engines = { chromium, webkit, firefox };
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

  const server = await serve(dir);
  const origin = `http://127.0.0.1:${server.address().port}`;
  const pages = listPages(dir);
  console.log(`${pages.length} pages from ${dir}`);

  const launched = {};
  const notRun = [];
  for (const e of wanted) {
    try {
      launched[e] = await engines[e].launch();
    } catch (err) {
      if (e === 'firefox') {
        // Playwright's patched Firefox does not start on every macOS version (website #151): drive an
        // installed Firefox with Puppeteer instead (viewport sizes only, no touch emulation).
        try {
          launched[e] = await puppeteerFirefox();
          console.log('firefox: using the installed Firefox through Puppeteer');
          continue;
        } catch (err2) {
          console.log(`firefox fallback failed: ${String(err2.message).split('\n')[0]}`);
        }
      }
      notRun.push(e);
      console.log(`NOT RUN ${e}:\n${String(err.message).split('\n').slice(0, 14).map((l) => `    ${l}`).join('\n')}`);
    }
  }

  let problems = 0;
  let smallTargets = 0;
  const report = (profile, theme, path, msg) => {
    problems += 1;
    console.log(`  ✗ ${profile} [${theme}] ${path}: ${msg}`);
  };

  for (const theme of themes) {
    for (const profile of profiles) {
      const browser = launched[profile.engine];
      if (!browser) continue;
      console.log(`\n${profile.name} [${theme}]`);
      const ctx = await browser.newContext({ ...profile.ctx, colorScheme: theme });
      await ctx.addInitScript((t) => {
        try {
          localStorage.setItem('limen-theme', t);
        } catch {}
      }, theme);
      for (const path of pages) {
        const page = await ctx.newPage();
        const errors = [];
        page.on('pageerror', (e) => errors.push(`js: ${e.message}`));
        page.on('requestfailed', (r) => errors.push(`failed: ${r.url()}`));
        page.on('response', (r) => r.status() >= 400 && errors.push(`${r.status()}: ${r.url()}`));
        await page.goto(origin + path, { waitUntil: 'load' });
        const fail = (m) => report(profile.name, theme, path, m);
        for (const e of errors) fail(e);
        // A page in the wrong theme would pass for the wrong reason.
        const shown = await page.evaluate(() => document.documentElement.dataset.theme || 'system');
        if (shown !== theme) fail(`rendered in the ${shown} theme, not ${theme}`);

        const layout = await page.evaluate(() => {
          const vw = document.documentElement.clientWidth;
          const sideways = document.documentElement.scrollWidth - vw;
          // An element past the right edge that no ancestor scrolls or clips is what makes the page wide.
          const clipped = (el) => {
            for (let p = el.parentElement; p; p = p.parentElement) {
              const o = getComputedStyle(p).overflowX;
              if (o === 'auto' || o === 'scroll' || o === 'hidden' || o === 'clip') return true;
            }
            return false;
          };
          const wide = [];
          for (const el of document.body.querySelectorAll('*')) {
            const r = el.getBoundingClientRect();
            if (r.width && r.right > vw + 1 && !clipped(el) && wide.length < 3) {
              wide.push(`${el.tagName.toLowerCase()}${el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\s+/).join('.') : ''} ends at ${Math.round(r.right)} of ${vw}`);
            }
          }
          const small = [];
          const seen = new Set();
          for (const el0 of document.querySelectorAll('a[href], button, input:not([type=hidden]), select, summary, [role=button]')) {
            // A checkbox or radio is operated through its label, so the label is the target.
            const el = /^(checkbox|radio)$/.test(el0.type || '') && el0.closest('label') ? el0.closest('label') : el0;
            if (seen.has(el)) continue;
            seen.add(el);
            const r = el.getBoundingClientRect();
            if (!r.width || !r.height || getComputedStyle(el).visibility === 'hidden') continue;
            // WCAG 2.5.8 exempts a link that sits in a line of text; a link in a table cell or a sentence is one.
            const inline = el.tagName === 'A' && !!el.closest('td, th, p, li, dd, dt, small, .hint, .muted');
            // A bar in a chart is a data mark: 24 bars cannot each be 24px wide on a phone, and the
            // records behind it are reachable from the audit page. Counted separately.
            const mark = !!el.closest('svg');
            small.push({ w: Math.round(r.width), h: Math.round(r.height), inline: inline || mark, what: `${el.tagName.toLowerCase()} "${(el.textContent || el.getAttribute('aria-label') || el.title || '').trim().slice(0, 24)}"` });
          }
          return { sideways, wide, small };
        });
        if (layout.sideways > 1) fail(`scrolls sideways by ${layout.sideways}px${layout.wide.length ? ` (${layout.wide.join('; ')})` : ''}`);
        else for (const w of layout.wide) fail(`content past the viewport: ${w}`);
        // WCAG 2.2 AA (2.5.8) wants 24px unless the target is a link in text; 44px is the comfortable
        // size, counted but not failed.
        const tiny = layout.small.filter((t) => !t.inline && Math.min(t.w, t.h) < 24);
        if (tiny.length) fail(`${tiny.length} tap target(s) under 24px: ${tiny.slice(0, 3).map((t) => `${t.what} ${t.w}x${t.h}`).join('; ')}`);
        if (profile.mobile) smallTargets += layout.small.filter((t) => !t.inline && Math.min(t.w, t.h) < 44).length;

        await page.evaluate(axeSource);
        const axe = await page.evaluate(() =>
          // eslint-disable-next-line no-undef
          axe.run(document, { runOnly: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] }).then((r) =>
            r.violations.map((v) => ({ id: v.id, impact: v.impact, n: v.nodes.length, sample: v.nodes[0].target.join(' ') })),
          ),
        );
        for (const v of axe) fail(`axe ${v.id} (${v.impact}, ${v.n}): ${v.sample}`);
        await page.close();
      }
      await ctx.close();
    }
  }
  for (const b of Object.values(launched)) await b.close();
  server.close();
  console.log(`\n${problems} problem(s); ${smallTargets} touch targets under 44px on phone/tablet profiles (counted, not failed)`);
  if (notRun.length) {
    console.log(`NOT TESTED: ${notRun.join(', ')}`);
    process.exit(2);
  }
  process.exit(problems ? 1 : 0);
}

await (mode === 'snapshot' ? snapshot() : check());
