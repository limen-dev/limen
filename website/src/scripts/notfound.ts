// The 404 page: says what was asked for and points at the likeliest page.
// It reads the palette's page list from the layout; nothing is sent anywhere.

type Entry = { t: string; h: string; k: string };

const el = <T extends HTMLElement>(id: string) => document.getElementById(id) as T | null;
const base = document.querySelector<HTMLAnchorElement>('.brand')?.getAttribute('href') ?? '/';
const entries: Entry[] = JSON.parse(el('palette-data')?.textContent ?? '[]');

const path = location.pathname;
const asked = path.startsWith(base) ? path.slice(base.length - 1) : path;
const pathEl = el('nf-path');
if (pathEl) pathEl.textContent = asked || '/';

// 1. The common slip: the right page, but no trailing slash. Go there rather than ask.
async function sameWithSlash() {
  if (path.endsWith('/') || /\.[a-z0-9]+$/i.test(path)) return;
  const target = `${path}/${location.search}${location.hash}`;
  try {
    const res = await fetch(`${path}/`, { method: 'HEAD' });
    // A static host answers a missing page with its 404 page, so only a real hit counts.
    if (!res.ok || res.url.endsWith('/404.html')) return;
    const guess = el('nf-guess');
    if (guess) {
      guess.append('Taking you to ');
      const a = document.createElement('a');
      a.href = target;
      a.textContent = `${asked}/`;
      guess.append(a, '…');
      guess.hidden = false;
    }
    // Hosts that do not add the slash themselves (a plain static server) end up here.
    location.replace(target);
  } catch {
    /* offline or blocked: the suggestions below still work */
  }
}

// 2. Otherwise rank the known pages by the words in the address, forgiving a typo or two.
function distance(a: string, b: string): number {
  const row = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    let prev = row[0];
    row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return row[b.length];
}

function closest(): Entry[] {
  const words = asked
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((w) => w.length > 1 && !['docs', 'html', 'index'].includes(w));
  return entries
    .map((e) => {
      const tokens = `${e.t} ${e.k} ${e.h}`.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
      const score = words.reduce((n, w) => {
        if (tokens.includes(w)) return n + 2;
        if (tokens.some((t) => t.includes(w) && w.length > 2)) return n + 1;
        // a near miss: "quikstart" for "quickstart"
        if (w.length >= 5 && tokens.some((t) => t.length >= 5 && distance(w, t) <= 2)) return n + 1;
        return n;
      }, 0);
      return { e, score };
    })
    .filter((x) => x.score > 0)
    .sort((a, b) => b.score - a.score)
    .filter((x, _, all) => x.score >= all[0].score / 2) // drop the weak matches next to a strong one
    .slice(0, 4)
    .map((x) => x.e);
}

const found = closest();
const popular = ['Quickstart', 'Concepts', 'What is built and verified', 'CLI guide']
  .map((t) => entries.find((e) => e.t === t))
  .filter((e): e is Entry => Boolean(e));
const list = found.length ? found : popular;
const title = el('nf-suggest-title');
if (title) title.textContent = found.length ? 'Closest pages' : 'Popular pages';
const ul = el('nf-suggest');
for (const e of list) {
  const li = document.createElement('li');
  const a = document.createElement('a');
  a.href = e.h;
  a.textContent = e.t;
  li.append(a);
  ul?.append(li);
}
if (list.length) el('nf-suggest-wrap')!.hidden = false;

el('nf-search')?.addEventListener('click', () => document.getElementById('open-palette')?.click());
if (!/Mac|iPhone|iPad/.test(navigator.platform)) {
  document.querySelectorAll('#nf-search kbd').forEach((k) => (k.textContent = 'Ctrl K'));
}

void sameWithSlash();
