// Behaviour every page shares: theme, header, reveal-on-scroll, the ⌘K palette.
// Plain DOM, no framework and no third-party requests.

const $ = <T extends HTMLElement>(sel: string) => document.querySelector(sel) as T | null;
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
const root = document.documentElement;
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, reduce ? 0 : ms));

/* ---------- theme (shares the docs' storage key) ---------- */
$('#theme')?.addEventListener('click', () => {
  const next = root.dataset.theme === 'light' ? 'dark' : 'light';
  root.dataset.theme = next;
  try {
    localStorage.setItem('starlight-theme', next);
  } catch {
    /* private mode: the choice just lasts for this page */
  }
});

/* ---------- nav shadow, reveal on scroll, card spotlight ---------- */
const nav = $('#nav');
const onScroll = () => nav?.classList.toggle('scrolled', scrollY > 8);
addEventListener('scroll', onScroll, { passive: true });
onScroll();

const reveals = document.querySelectorAll<HTMLElement>('.reveal');
if ('IntersectionObserver' in window && !reduce) {
  const io = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (e.isIntersecting) {
          e.target.classList.add('in');
          io.unobserve(e.target);
        }
      }
    },
    { threshold: 0.12, rootMargin: '0px 0px -6% 0px' },
  );
  reveals.forEach((el, i) => {
    el.style.setProperty('--d', `${(i % 4) * 70}ms`);
    io.observe(el);
  });
} else {
  reveals.forEach((el) => el.classList.add('in'));
}
document.querySelectorAll<HTMLElement>('.card').forEach((card) => {
  card.addEventListener('pointermove', (e) => {
    const r = card.getBoundingClientRect();
    card.style.setProperty('--mx', `${e.clientX - r.left}px`);
    card.style.setProperty('--my', `${e.clientY - r.top}px`);
  });
});

/* ---------- command palette ---------- */
type Entry = { t: string; h: string; k: string };
const entries: Entry[] = JSON.parse($('#palette-data')?.textContent ?? '[]');
const palette = $('#palette')!;
const input = $<HTMLInputElement>('#palette-input')!;
const list = $('#palette-list')!;
let sel = 0;
let shown: Entry[] = [];
let lastFocus: Element | null = null;

function render() {
  const q = input.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  shown = entries.filter((e) => q.every((w) => `${e.t} ${e.k}`.toLowerCase().includes(w)));
  sel = Math.min(sel, Math.max(shown.length - 1, 0));
  list.innerHTML = '';
  if (!shown.length) {
    const li = document.createElement('li');
    li.textContent = 'No match. Try “quickstart” or “postgres”.';
    li.style.cssText = 'padding:1rem;color:var(--lm-muted)';
    list.append(li);
    return;
  }
  shown.forEach((e, i) => {
    const li = document.createElement('li');
    const a = document.createElement('a');
    a.href = e.h;
    a.setAttribute('role', 'option');
    a.setAttribute('aria-selected', String(i === sel));
    a.innerHTML = '<span></span><small></small>';
    a.firstElementChild!.textContent = e.t;
    a.lastElementChild!.textContent = e.h.startsWith('http') ? 'github' : 'docs';
    a.addEventListener('mousemove', () => {
      sel = i;
      mark();
    });
    li.append(a);
    list.append(li);
  });
}
const mark = () =>
  list.querySelectorAll('a').forEach((a, i) => a.setAttribute('aria-selected', String(i === sel)));
function openPalette() {
  lastFocus = document.activeElement;
  palette.hidden = false;
  input.value = '';
  sel = 0;
  render();
  input.focus();
}
function closePalette() {
  palette.hidden = true;
  (lastFocus as HTMLElement | null)?.focus?.();
}
$('#open-palette')?.addEventListener('click', openPalette);
palette.addEventListener('mousedown', (e) => e.target === palette && closePalette());
input.addEventListener('input', () => {
  sel = 0;
  render();
});
input.addEventListener('keydown', (e) => {
  if (e.key === 'ArrowDown') (sel = (sel + 1) % Math.max(shown.length, 1)), mark(), e.preventDefault();
  else if (e.key === 'ArrowUp') (sel = (sel - 1 + shown.length) % Math.max(shown.length, 1)), mark(), e.preventDefault();
  else if (e.key === 'Enter' && shown[sel]) location.href = shown[sel].h;
  else if (e.key === 'Escape') closePalette();
});
addEventListener('keydown', (e) => {
  const typing = /input|textarea/i.test((e.target as HTMLElement)?.tagName ?? '');
  if ((e.key === 'k' && (e.metaKey || e.ctrlKey)) || (e.key === '/' && !typing)) {
    e.preventDefault();
    palette.hidden ? openPalette() : closePalette();
  }
});
if (!/Mac|iPhone|iPad/.test(navigator.platform)) {
  document.querySelectorAll('.kbd-btn kbd').forEach((k) => (k.textContent = 'Ctrl K'));
}

/* ---------- which section is on screen ---------- */
{
  const links = [...document.querySelectorAll<HTMLAnchorElement>('.nav-links a[href^="#"]')];
  const byId = new Map(links.map((a) => [a.getAttribute('href')!.slice(1), a]));
  if ('IntersectionObserver' in window) {
    const io = new IntersectionObserver(
      (es) => {
        for (const e of es) {
          if (!e.isIntersecting) continue;
          links.forEach((a) => a.removeAttribute('aria-current'));
          byId.get(e.target.id)?.setAttribute('aria-current', 'true');
        }
      },
      { rootMargin: '-45% 0px -50% 0px' },
    );
    // Every section, so the highlight clears in one that has no link of its own.
    document.querySelectorAll('main section[id]').forEach((el) => io.observe(el));
  }
}
