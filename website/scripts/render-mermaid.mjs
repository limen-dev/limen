// Draws the Mermaid diagrams in docs/ as SVG, once in a light theme and once in a dark one.
//
// The site shows these pictures instead of running Mermaid in the reader's browser (no script, no
// third-party origin). Run it after changing a ```mermaid block, and commit docs/diagrams/mermaid/.
// sync-docs.mjs fails the build when a block has no picture, so a stale one cannot be published.
//
//   node website/scripts/render-mermaid.mjs
//
// Needs Node and a Chrome or Chromium. Set CHROME_PATH to use a particular one; otherwise
// Puppeteer's own is used. Set LIMEN_MERMAID_NO_SANDBOX=1 where Chromium cannot start sandboxed (a
// container running as root). The renderer is pinned here and fetched with npx; it is not a
// dependency of the site (ADR-0012).
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mermaidBlocks, mermaidFiles, mermaidId } from './mermaid.mjs';

const MERMAID_CLI = '@mermaid-js/mermaid-cli@12.0.0';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const outDir = join(root, 'docs', 'diagrams', 'mermaid');

const walk = (dir) =>
  readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });

const blocks = new Map(); // id -> source
for (const file of walk(join(root, 'docs')).filter((f) => f.endsWith('.md'))) {
  for (const source of mermaidBlocks(readFileSync(file, 'utf8'))) blocks.set(mermaidId(source), source);
}

mkdirSync(outDir, { recursive: true });
// Pictures drawn by another renderer version are drawn again: the file names say which diagram, not
// which renderer.
const stamp = join(outDir, 'RENDERER');
if (!existsSync(stamp) || readFileSync(stamp, 'utf8').trim() !== MERMAID_CLI) {
  for (const f of readdirSync(outDir)) if (f.endsWith('.svg')) rmSync(join(outDir, f));
  writeFileSync(stamp, `${MERMAID_CLI}\n`);
}
const tmp = mkdtempSync(join(tmpdir(), 'limen-mermaid-'));
const puppeteer = join(tmp, 'puppeteer.json');
writeFileSync(
  puppeteer,
  JSON.stringify({ ...(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {}), args: process.env.LIMEN_MERMAID_NO_SANDBOX === '1' ? ['--no-sandbox'] : [] }),
);

const wanted = new Set();
let drawn = 0;
try {
  for (const [id, source] of blocks) {
    const input = join(tmp, `${id}.mmd`);
    writeFileSync(input, source);
    for (const [file, theme] of mermaidFiles(source).map((f, i) => [f, ['default', 'dark'][i]])) {
      wanted.add(file);
      if (existsSync(join(outDir, file))) continue;
      const r = spawnSync('npx', ['--yes', MERMAID_CLI, '-p', puppeteer, '-i', input, '-o', join(outDir, file), '-t', theme, '-b', 'transparent', '-q'], { stdio: 'inherit' });
      if (r.status !== 0) {
        console.error(`could not draw ${file}`);
        process.exit(1);
      }
      drawn++;
    }
  }
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
// Pictures of diagrams that no longer exist.
for (const f of readdirSync(outDir)) if (f.endsWith('.svg') && !wanted.has(f)) rmSync(join(outDir, f));
console.log(`${blocks.size} diagram(s), ${drawn} picture(s) drawn`);
