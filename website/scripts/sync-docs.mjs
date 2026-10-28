// Publishes the repository's documents inside the docs site, so each is written once.
//
// Sources stay where contributors expect them (docs/, deploy/compose/README.md).
// This copies them into src/content/docs/docs/ (git-ignored) with the frontmatter
// Starlight needs, and rewrites relative links to site-relative ones, so the site
// works under any base path. Links to files that are not published become GitHub links.
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, posix, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const out = resolve(root, 'website', 'src', 'content', 'docs', 'docs');
const GITHUB = 'https://github.com/jfcmartins/limen';

// Generated sections. Hand-written pages live beside them and are never touched.
const generated = ['guides', 'runbooks', 'architecture', 'reference'];

/** @type {Map<string, {slug: string, label?: string}>} repo-relative source -> page */
const pages = new Map();

function add(src, slug, label) {
  pages.set(src, { slug, label });
}

const listMd = (dir) => readdirSync(join(root, dir)).filter((f) => f.endsWith('.md')).sort();

for (const f of listMd('docs/guides')) add(`docs/guides/${f}`, `guides/${f.slice(0, -3)}`);
for (const f of listMd('docs/runbooks')) {
  add(`docs/runbooks/${f}`, f === 'README.md' ? 'runbooks/index' : `runbooks/${f.slice(0, -3)}`);
}
for (const f of listMd('docs/adr')) {
  add(`docs/adr/${f}`, f === 'README.md' ? 'architecture/adr/index' : `architecture/adr/${f.slice(0, -3)}`);
}
add('docs/design.md', 'architecture/design');
add('docs/components.md', 'architecture/components');
add('docs/threat-model.md', 'architecture/threat-model');
add('docs/pentest-plan.md', 'architecture/pentest-plan');
add('docs/policy.md', 'reference/policy');
add('docs/cli-reference.md', 'reference/cli', 'CLI reference');
add('docs/diagrams/README.md', 'architecture/diagrams', 'Diagrams');
add('deploy/compose/README.md', 'reference/compose-stack', 'Local stack (Compose)');

// Pages written by hand (none are link targets yet).
const handwritten = {};

const routeOf = (slug) => `docs/${slug}`.replace(/\/index$/, '');

function relativeRoute(fromRoute, toRoute) {
  // Both are directory-style URLs (".../x/"), so ".." climbs one segment per level.
  const from = fromRoute.split('/');
  const to = toRoute.split('/');
  let i = 0;
  while (i < from.length && i < to.length && from[i] === to[i]) i++;
  const up = '../'.repeat(from.length - i);
  const down = to.slice(i).join('/');
  return `${up}${down}${down ? '/' : ''}` || './';
}

function rewriteTarget(target, srcPath, fromRoute) {
  if (/^([a-z][a-z0-9+.-]*:|#|\/\/)/i.test(target)) return target;
  const [pathPart, ...hashParts] = target.split('#');
  const hash = hashParts.length ? `#${hashParts.join('#')}` : '';
  if (!pathPart) return target;
  const abs = posix.normalize(posix.join(posix.dirname(srcPath), pathPart));
  const page = pages.get(abs);
  if (page) return relativeRoute(fromRoute, routeOf(page.slug)) + hash;
  const hand = handwritten[abs];
  if (hand) return relativeRoute(fromRoute, routeOf(hand)) + hash;
  if (abs.startsWith('docs/diagrams/') && abs.endsWith('.svg')) {
    return `./${posix.basename(abs)}`; // copied beside the page that shows it, below
  }
  if (abs.startsWith('..')) return target;
  const isDir = pathPart.endsWith('/') || !posix.basename(abs).includes('.');
  return `${GITHUB}/${isDir ? 'tree' : 'blob'}/main/${abs.replace(/\/$/, '')}${hash}`;
}

function describe(body) {
  const para = body
    .split(/\n\s*\n/)
    .map((p) => p.trim())
    .find((p) => p && !/^(#|[|>`<\-*]|\d+\.)/.test(p));
  if (!para) return '';
  const plain = para
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[`*_]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  return plain.length > 180 ? `${plain.slice(0, 177).replace(/\s+\S*$/, '')}…` : plain;
}

function transform(srcPath, page) {
  const raw = readFileSync(join(root, srcPath), 'utf8');
  const fromRoute = routeOf(page.slug);
  const lines = raw.split('\n');
  let title = '';
  let fence = false;
  const kept = [];
  for (const line of lines) {
    if (/^\s*(```|~~~)/.test(line)) fence = !fence;
    if (!fence && !title && /^# /.test(line)) {
      title = line.slice(2).trim();
      continue;
    }
    // The compose README opens with a centred logo that the site header already shows.
    if (!fence && /^<p align="center"><picture>/.test(line)) continue;
    if (fence) {
      kept.push(line);
      continue;
    }
    kept.push(
      line
        // A diagram wrapped in a link to itself: the image is bundled beside the page, the
        // link opens the full-size copy in public/diagrams (it is unreadable at column width).
        .replace(/\[(!\[[^\]]*\]\([^)]*\.svg\))\]\(([^)]*\.svg)\)/g, (_, img, t) => `[${img}](${'../'.repeat(fromRoute.split('/').length)}diagrams/${posix.basename(t)})`)
        .replace(/(\]\()([^)\s]+)(\s+"[^"]*")?(\))/g, (_, a, t, ttl = '', z) => `${a}${rewriteTarget(t, srcPath, fromRoute)}${ttl}${z}`)
        .replace(/(href=")([^"]+)(")/g, (_, a, t, z) => `${a}${rewriteTarget(t, srcPath, fromRoute)}${z}`),
    );
  }
  const body = kept.join('\n').replace(/^\s+/, '');
  const adr = /^ADR-(\d+): (.*)$/.exec(title);
  const label = page.label ?? (adr ? `${adr[1]} ${adr[2]}` : title);
  const fm = [
    '---',
    `title: ${JSON.stringify(title || page.slug)}`,
    `description: ${JSON.stringify(describe(body))}`,
    `editUrl: ${JSON.stringify(`${GITHUB}/edit/main/${srcPath}`)}`,
    'sidebar:',
    `  label: ${JSON.stringify(label)}`,
    '---',
    '',
  ].join('\n');
  const dest = join(out, `${page.slug}.md`);
  mkdirSync(dirname(dest), { recursive: true });
  writeFileSync(dest, `${fm}${body}\n`);
}

for (const dir of generated) rmSync(join(out, dir), { recursive: true, force: true });
for (const [src, page] of pages) transform(src, page);

// The diagrams page shows the SVGs, so they sit beside it and Astro bundles them. A second
// copy in public/ is the full-size one the images link to.
const full = resolve(root, 'website', 'public', 'diagrams');
rmSync(full, { recursive: true, force: true });
mkdirSync(full, { recursive: true });
for (const f of readdirSync(join(root, 'docs/diagrams')).filter((f) => f.endsWith('.svg'))) {
  cpSync(join(root, 'docs/diagrams', f), join(out, 'architecture', f));
  cpSync(join(root, 'docs/diagrams', f), join(full, f));
}

console.log(`synced ${pages.size} documents into ${relative(root, out)}`);
if (!existsSync(join(out, 'index.mdx'))) console.warn('warning: website/src/content/docs/docs/index.mdx is missing');
