// Interactions for the homepage only. Plain DOM, no framework and no third-party requests.

const $ = <T extends HTMLElement>(sel: string) => document.querySelector(sel) as T | null;
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
const root = document.documentElement;
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, reduce ? 0 : ms));

/* ---------- copy button ---------- */
$('#copy')?.addEventListener('click', async (e) => {
  const btn = e.currentTarget as HTMLButtonElement;
  const text = ($('#install-code')?.textContent ?? '')
    .split('\n')
    .map((l) => l.replace(/^\$ /, ''))
    .join('\n');
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = 'Copied';
  } catch {
    btn.textContent = 'Select and copy';
  }
  setTimeout(() => (btn.textContent = 'Copy'), 1800);
});

/* ---------- hero: a certificate that runs out ---------- */
{
  const ttl = $('#ttl');
  const sub = $('#ttl-sub');
  const note = $('#ttl-note');
  const arc = document.querySelector<SVGCircleElement>('#ring-arc');
  const door = $('.threshold');
  const TOTAL = 3600;
  const SPEED = 144; // simulated seconds per real second, so the story fits a glance
  const C = 389.6;
  let remaining = TOTAL;
  let last = performance.now();
  let hold = 0;
  const fmt = (s: number) => `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(Math.floor(s % 60)).padStart(2, '0')}`;
  const paint = () => {
    if (!ttl || !arc) return;
    ttl.textContent = fmt(remaining);
    arc.style.strokeDashoffset = String(C * (1 - remaining / TOTAL));
  };
  paint();
  if (!reduce) {
    const tick = (now: number) => {
      const dt = (now - last) / 1000;
      last = now;
      if (hold > 0) {
        hold -= dt;
        if (hold <= 0) {
          remaining = TOTAL;
          door?.classList.remove('expired');
          if (sub) sub.textContent = 'expires in';
          if (note) note.textContent = 'Credentials that expire. By design.';
        }
      } else {
        remaining = Math.max(0, remaining - dt * SPEED);
        if (remaining === 0) {
          hold = 2.8;
          door?.classList.add('expired');
          if (sub) sub.textContent = 'expired';
          if (note) note.textContent = 'Expired on its own. limen login to continue.';
        }
      }
      paint();
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }
}

/* ---------- hero: traffic flowing to the doorway ---------- */
{
  const canvas = $<HTMLCanvasElement>('#flow');
  const ctx = canvas?.getContext('2d');
  if (canvas && ctx && !reduce) {
    type P = { sx: number; sy: number; cx: number; cy: number; t: number; v: number; w: number };
    let W = 0;
    let H = 0;
    let tx = 0;
    let ty = 0;
    let ps: P[] = [];
    let visible = true;
    const dpr = Math.min(devicePixelRatio || 1, 2);
    const aim = () => {
      const svg = document.querySelector('.threshold svg')?.getBoundingClientRect();
      const box = canvas.getBoundingClientRect();
      if (svg) {
        tx = svg.left - box.left + svg.width / 2;
        ty = svg.top - box.top + svg.height * (438 / 500);
      }
    };
    const spawn = (): P => {
      // From the right and below, so the streaks never cross the headline.
      const sx = W + 20;
      const sy = H * (0.2 + Math.random() * 0.8);
      return { sx, sy, cx: tx + 60 + Math.random() * 200, cy: ty + (Math.random() - 0.5) * 220, t: Math.random(), v: 0.0014 + Math.random() * 0.0022, w: 0.6 + Math.random() * 1.4 };
    };
    const resize = () => {
      W = canvas.clientWidth;
      H = canvas.clientHeight;
      canvas.width = W * dpr;
      canvas.height = H * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      aim();
      ps = Array.from({ length: Math.round(Math.min(70, W / 16)) }, spawn);
    };
    const at = (p: P, t: number) => {
      const u = 1 - t;
      return [u * u * p.sx + 2 * u * t * p.cx + t * t * tx, u * u * p.sy + 2 * u * t * p.cy + t * t * ty] as const;
    };
    // Read the theme colours once, and again only when the theme changes: a style lookup on every
    // frame forced a recalculation 60 times a second.
    let hot = '#5eead4';
    let cold = '#7f8ea9';
    const readColors = () => {
      const style = getComputedStyle(root);
      hot = style.getPropertyValue('--lm-accent-strong').trim() || hot;
      cold = style.getPropertyValue('--lm-muted').trim() || cold;
    };
    readColors();
    new MutationObserver(readColors).observe(root, { attributes: true, attributeFilter: ['data-theme'] });
    const frame = () => {
      if (visible) {
        ctx.clearRect(0, 0, W, H);
        for (const p of ps) {
          p.t += p.v;
          if (p.t >= 1) Object.assign(p, spawn(), { t: 0 });
          const [x, y] = at(p, p.t);
          const [x0, y0] = at(p, Math.max(p.t - 0.05, 0));
          ctx.globalAlpha = Math.min(1, p.t * 3) * (1 - Math.max(0, p.t - 0.85) / 0.15) * 0.6;
          ctx.strokeStyle = p.t > 0.7 ? hot : cold;
          ctx.lineWidth = p.w;
          ctx.lineCap = 'round';
          ctx.beginPath();
          ctx.moveTo(x0, y0);
          ctx.lineTo(x, y);
          ctx.stroke();
        }
        ctx.globalAlpha = 1;
      }
      requestAnimationFrame(frame);
    };
    new IntersectionObserver(([e]) => (visible = e.isIntersecting)).observe(canvas);
    addEventListener('resize', resize);
    resize();
    requestAnimationFrame(frame);
  }
}

/* ---------- the live session and its hash chain ---------- */
// The round constants depend on nothing, so derive them once.
const SHA = (() => {
  const primes: number[] = [];
  for (let n = 2; primes.length < 64; n++) if (primes.every((p) => n % p)) primes.push(n);
  const frac = (x: number) => Math.floor((x - Math.floor(x)) * 2 ** 32) >>> 0;
  return { K: primes.map((p) => frac(Math.cbrt(p))), H: primes.slice(0, 8).map((p) => frac(Math.sqrt(p))) };
})();

function sha256(text: string): string {
  const msg = new TextEncoder().encode(text);
  const { K } = SHA;
  const H = [...SHA.H];
  const len = msg.length;
  const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
  padded.set(msg);
  padded[len] = 0x80;
  new DataView(padded.buffer).setUint32(padded.length - 4, len * 8, false);
  new DataView(padded.buffer).setUint32(padded.length - 8, Math.floor((len * 8) / 2 ** 32), false);
  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));
  const w = new Uint32Array(64);
  for (let o = 0; o < padded.length; o += 64) {
    const dv = new DataView(padded.buffer, o, 64);
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) >>> 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      [h, g, f, e, d, c, b, a] = [g, f, e, (d + t1) >>> 0, c, b, a, (t1 + t2) >>> 0];
    }
    [a, b, c, d, e, f, g, h].forEach((v, i) => (H[i] = (H[i] + v) >>> 0));
  }
  return H.map((v) => v.toString(16).padStart(8, '0')).join('');
}

type Ev = { ty: string; who: string; detail: string };
type Step =
  | { c: string; prompt?: string }
  | { o: string; cls?: 'ok' | 'warn' | 'dim' }
  | { ev: Ev };

const ME = 'admin@example.com';
const scenarios: Record<string, Step[]> = {
  ssh: [
    { c: 'limen login' },
    { o: 'Opening your browser to sign in…', cls: 'dim' },
    { o: '✔ Signed in as admin@example.com · role sre · expires in 1h 0m', cls: 'ok' },
    { ev: { ty: 'auth.login', who: ME, detail: 'oidc, roles=sre' } },
    { c: 'limen ssh web-staging-1' },
    { o: '✔ Allowed as ubuntu · session recorded', cls: 'ok' },
    { ev: { ty: 'session.start', who: ME, detail: 'web-staging-1 as ubuntu' } },
    { c: 'sudo systemctl restart nginx', prompt: 'ubuntu@web-staging-1:~$' },
    { ev: { ty: 'session.recording', who: ME, detail: 'recording sealed with its hash' } },
    { c: 'exit', prompt: 'ubuntu@web-staging-1:~$' },
    { ev: { ty: 'session.end', who: ME, detail: 'web-staging-1 · 41s' } },
    { o: 'Connection closed. Replay it any time in the console.', cls: 'dim' },
  ],
  pg: [
    { c: 'limen db connect orders-staging' },
    { o: '✔ listening on 127.0.0.1:54321 · no password needed', cls: 'ok' },
    { ev: { ty: 'session.start', who: ME, detail: 'orders-staging as limen_read' } },
    { c: 'psql -h 127.0.0.1 -p 54321 orders' },
    { c: "select count(*) from invoices where status = 'open';", prompt: 'orders=>' },
    { o: ' count\n-------\n 18423\n(1 row)' },
    { ev: { ty: 'db.query', who: ME, detail: "select count(*) from invoices where status = …" } },
    { c: 'delete from invoices;', prompt: 'orders=>' },
    { o: 'ERROR:  permission denied for table invoices', cls: 'warn' },
    { ev: { ty: 'db.query', who: ME, detail: 'delete from invoices · refused by role limen_read' } },
    { c: '\\q', prompt: 'orders=>' },
    { ev: { ty: 'session.end', who: ME, detail: 'orders-staging · 2 statements' } },
  ],
  k8s: [
    { c: 'limen kube login eks-staging' },
    { o: '✔ kubeconfig written (it holds no secret, only a short-lived certificate)', cls: 'ok' },
    { c: 'kubectl get pods -n payments' },
    { o: 'NAME                          READY   STATUS    AGE\npayments-api-6d8f7c9b4-x2k9p   1/1     Running   2d' },
    { ev: { ty: 'kube.request', who: ME, detail: 'get pods in payments · allowed' } },
    { c: 'kubectl exec -it payments-api-6d8f7c9b4-x2k9p -n payments -- sh' },
    { ev: { ty: 'session.start', who: ME, detail: 'exec in payments-api · recorded' } },
    { c: 'exit', prompt: '/app #' },
    { ev: { ty: 'session.end', who: ME, detail: 'exec ended · 18s' } },
    { o: 'Impersonation means the cluster sees you, not a shared admin.', cls: 'dim' },
  ],
  req: [
    { c: 'limen request orders-prod --for 30m --reason "INC-123: orders table is locked" --wait' },
    { o: '⏳ Waiting for sre-leads to decide…', cls: 'dim' },
    { ev: { ty: 'access.request', who: 'alice@example.com', detail: 'orders-prod · 30m · INC-123' } },
    { o: '✔ Approved by priya@example.com: “ok for 30 minutes”', cls: 'ok' },
    { ev: { ty: 'access.approve', who: 'priya@example.com', detail: 'request for alice · 30m' } },
    { c: 'limen db connect orders-prod' },
    { o: '✔ listening on 127.0.0.1:54322 · grant ends in 29m 58s', cls: 'ok' },
    { ev: { ty: 'session.start', who: 'alice@example.com', detail: 'orders-prod as limen_read, under the grant' } },
    { o: '… 30 minutes later. The grant lapses by itself.', cls: 'dim' },
    { ev: { ty: 'session.end', who: 'alice@example.com', detail: 'grant expired · session ended' } },
  ],
};

{
  const term = $('#term')!;
  const blocksEl = $('#blocks')!;
  const status = $('#chain-status')!;
  const statusText = $('#chain-text')!;
  const msg = $('#ledger-msg')!;
  const tamperBtn = $<HTMLButtonElement>('#tamper')!;
  const restoreBtn = $<HTMLButtonElement>('#restore')!;
  const tabs = document.querySelectorAll<HTMLButtonElement>('[data-scn]');

  let events: Ev[] = [];
  let stored: string[] = []; // hashes written when each event happened
  let run = 0;
  let current = 'ssh';
  let editing = false;
  let tampered = -1;
  let finished = false;
  const GENESIS = '0'.repeat(64);

  const esc = (s: string) => s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]!);
  const chain = (evs: Ev[]) => {
    const out: string[] = [];
    evs.forEach((e, i) => out.push(sha256(`${out[i - 1] ?? GENESIS}|${e.ty}|${e.who}|${e.detail}`)));
    return out;
  };

  function paintLedger(added = false) {
    const live = events.map((e, i) => (i === tampered ? { ...e, who: 'svc-cleanup@example.com' } : e));
    const now = chain(live);
    let firstBad = -1;
    blocksEl.innerHTML = '';
    live.forEach((e, i) => {
      const bad = now[i] !== stored[i];
      if (bad && firstBad < 0) firstBad = i;
      const li = document.createElement('li');
      li.className = `blk${added && i === live.length - 1 ? ' fresh' : ''}${bad ? ' broken' : ''}${i === tampered ? ' tampered' : ''}${editing ? ' edit' : ''}`;
      li.dataset.i = String(i);
      if (editing) {
        li.tabIndex = 0;
        li.setAttribute('role', 'button');
        li.setAttribute('aria-label', `Rewrite event ${i + 1}, ${e.ty}`);
      }
      li.innerHTML =
        `<span class="n">#${String(i + 1).padStart(2, '0')}</span>` +
        `<span class="ty">${esc(e.ty)}</span>` +
        `<span class="h">${bad ? now[i].slice(0, 8) : stored[i].slice(0, 8)}<small>${bad ? '≠ ' + stored[i].slice(0, 8) : '← ' + (i ? stored[i - 1].slice(0, 6) : '000000')}</small></span>` +
        `<span class="who" title="${esc(e.detail)}">${esc(e.who)} · ${esc(e.detail)}</span>`;
      blocksEl.append(li);
    });
    if (tampered >= 0) blocksEl.children[tampered]?.scrollIntoView({ block: 'nearest' });
    else blocksEl.scrollTop = blocksEl.scrollHeight;
    const broken = firstBad >= 0;
    status.classList.toggle('bad', broken);
    status.classList.toggle('ok', !broken);
    statusText.textContent = broken ? `chain broken at #${String(firstBad + 1).padStart(2, '0')}` : events.length ? 'chain intact' : 'waiting';
    tamperBtn.disabled = !events.length || tampered >= 0;
    tamperBtn.classList.toggle('ready', finished && tampered < 0 && !editing);
    restoreBtn.disabled = tampered < 0 && !editing;
    const n = String(firstBad + 1).padStart(2, '0');
    if (editing) msg.innerHTML = 'Pick any event to rewrite it.';
    else if (broken) {
      msg.innerHTML = `<b>Event #${n} was rewritten.</b> It now blames <code>${esc(live[firstBad].who)}</code>. Its hash changed, so every hash after it stopped matching. A verifier finds exactly this.`;
    } else if (finished) msg.textContent = 'Every hash matches. Now try to rewrite history.';
    else msg.textContent = '';
  }

  function emit(e: Ev) {
    events.push(e);
    stored = chain(events);
    paintLedger(true);
  }

  const pre = (prompt: string) => `<span class="p">${esc(prompt)}</span> `;

  async function play(name: string) {
    const token = ++run;
    current = name;
    events = [];
    stored = [];
    tampered = -1;
    editing = false;
    finished = false;
    term.innerHTML = '';
    paintLedger();
    tabs.forEach((t) => t.setAttribute('aria-selected', String(t.dataset.scn === name)));
    const caret = document.createElement('span');
    caret.className = 'caret';
    term.append(caret);
    for (const step of scenarios[name]) {
      if (token !== run) return;
      if ('c' in step) {
        const line = document.createElement('span');
        line.innerHTML = pre(step.prompt ?? '$');
        const text = document.createElement('span');
        text.className = 'cmd';
        line.append(text, '\n');
        term.insertBefore(line, caret);
        for (const ch of step.c) {
          if (token !== run) return;
          text.textContent += ch;
          term.scrollTop = term.scrollHeight;
          await sleep(reduce ? 0 : 12 + Math.random() * 14);
        }
        await sleep(260);
      } else if ('o' in step) {
        const s = document.createElement('span');
        if (step.cls) s.className = step.cls;
        s.textContent = `${step.o}\n`;
        term.insertBefore(s, caret);
        await sleep(300);
      } else {
        emit(step.ev);
        await sleep(380);
      }
      term.scrollTop = term.scrollHeight;
    }
    caret.remove();
    finished = true;
    paintLedger();
  }

  tabs.forEach((t) => t.addEventListener('click', () => play(t.dataset.scn!)));
  $('#replay')?.addEventListener('click', () => play(current));

  tamperBtn.addEventListener('click', () => {
    editing = true;
    paintLedger();
    blocksEl.querySelector<HTMLElement>('.blk')?.focus();
  });
  const rewrite = (li: HTMLElement | null) => {
    if (!editing || !li) return;
    tampered = Number(li.dataset.i);
    editing = false;
    paintLedger();
    restoreBtn.focus();
  };
  blocksEl.addEventListener('click', (e) => rewrite((e.target as HTMLElement).closest<HTMLElement>('.blk')));
  blocksEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      rewrite((e.target as HTMLElement).closest<HTMLElement>('.blk'));
    }
  });
  restoreBtn.addEventListener('click', () => {
    tampered = -1;
    editing = false;
    paintLedger();
  });

  // Start when the demo scrolls into view, so the first thing a visitor sees is it typing.
  const theater = $('#theater');
  let started = false;
  const start = () => {
    if (!started) {
      started = true;
      play('ssh');
    }
  };
  if (theater && 'IntersectionObserver' in window) {
    new IntersectionObserver((es, o) => {
      if (es.some((e) => e.isIntersecting)) {
        start();
        o.disconnect();
      }
    }, { threshold: 0.3 }).observe(theater);
  } else start();
}


// PROTOCOL FILTER: show all tiles, only fully tested ones, or only those with an unverified cloud path.
{
  const bar = $('.pfilter');
  const tiles = [...document.querySelectorAll<HTMLElement>('.proto[data-status]')];
  const groups = [...document.querySelectorAll<HTMLElement>('.pgroup')];
  const count = $('#pcount');
  const apply = (f: string) => {
    let shown = 0;
    tiles.forEach((t) => {
      const on = f === 'all' || t.dataset.status === f;
      t.hidden = !on;
      if (on) shown++;
    });
    groups.forEach((g) => (g.hidden = !g.querySelector('.proto:not([hidden])')));
    if (count) count.textContent = f === 'all' ? '' : `${shown} of ${tiles.length}`;
    bar?.querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.f === f)));
  };
  bar?.addEventListener('click', (e) => {
    const b = (e.target as HTMLElement).closest<HTMLButtonElement>('button[data-f]');
    if (b) apply(b.dataset.f!);
  });
}
