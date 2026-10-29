// Fails the build when a built page links to a page, file or anchor that does not exist.
// External links are not fetched (CI must not depend on other people's servers).
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const dist = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'dist');
const base = (process.env.SITE_BASE ?? '/').replace(/\/?$/, '/');

const walk = (dir) =>
  readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });

const htmlFiles = walk(dist).filter((f) => f.endsWith('.html'));
const idCache = new Map();
const idsOf = (file) => {
  if (!idCache.has(file)) {
    const html = readFileSync(file, 'utf8');
    idCache.set(file, new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1])));
  }
  return idCache.get(file);
};

const errors = [];
for (const file of htmlFiles) {
  const html = readFileSync(file, 'utf8');
  const pageUrl = '/' + file.slice(dist.length + 1).replace(/index\.html$/, '');
  for (const m of html.matchAll(/\s(?:href|src)="([^"]*)"/g)) {
    let url = m[1].replace(/&amp;/g, '&');
    if (!url || /^([a-z][a-z0-9+.-]*:|\/\/)/i.test(url)) continue;
    let [path, hash] = url.split('#');
    let target;
    if (!path) target = file;
    else {
      path = path.split('?')[0];
      const abs = path.startsWith('/')
        ? (path.startsWith(base) ? '/' + path.slice(base.length) : path)
        : new URL(path, `http://x${pageUrl}`).pathname;
      const fsPath = join(dist, decodeURIComponent(abs));
      target = [fsPath, join(fsPath, 'index.html'), `${fsPath}.html`].find((p) => existsSync(p) && statSync(p).isFile());
      if (!target) {
        errors.push(`${pageUrl}: ${url} -> no such page or file`);
        continue;
      }
    }
    if (hash && target.endsWith('.html') && !idsOf(target).has(decodeURIComponent(hash))) {
      errors.push(`${pageUrl}: ${url} -> no anchor #${hash}`);
    }
  }
}

if (errors.length) {
  console.error(`${errors.length} broken link(s):\n${[...new Set(errors)].join('\n')}`);
  process.exit(1);
}
console.log(`links ok: ${htmlFiles.length} pages checked`);
