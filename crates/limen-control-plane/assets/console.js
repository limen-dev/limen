// Theme and small conveniences for the console. Loaded as an external file
// so the page needs no inline script (CSP). Loaded in <head> without defer:
// the saved theme must be applied before first paint to avoid a flash.
(function () {
  var KEY = 'limen-theme';
  var root = document.documentElement;
  function saved() { try { return localStorage.getItem(KEY); } catch (e) { return null; } }
  function apply(mode) {
    if (mode === 'light' || mode === 'dark') root.setAttribute('data-theme', mode);
    else root.removeAttribute('data-theme');
  }
  apply(saved());

  // The sidebar: which groups are folded and whether it is icon-only. Read here, before the first
  // paint, and put on <html> so the CSS shows the right state with no flash. `js` lets the CSS show
  // the controls only when there is a script to run them. Browsers that block storage keep the
  // choice for the page only.
  var NAV_KEY = 'limen-nav';
  var SIDEBAR_KEY = 'limen-sidebar';
  function load(key) { try { return localStorage.getItem(key) || ''; } catch (e) { return ''; } }
  function store(key, value) {
    try { if (value) localStorage.setItem(key, value); else localStorage.removeItem(key); } catch (e) { /* private mode */ }
  }
  root.classList.add('js');
  root.setAttribute('data-nav', load(NAV_KEY));
  if (load(SIDEBAR_KEY) === 'collapsed') root.setAttribute('data-sidebar', 'collapsed');

  document.addEventListener('DOMContentLoaded', function () {
    // Fold and unfold a group. A group with the current page in it stays open, so the page you are
    // on is never hidden: its button does nothing and says nothing.
    document.querySelectorAll('.nav-group').forEach(function (group) {
      var button = group.querySelector('.nav-toggle');
      var name = group.getAttribute('data-group');
      if (!button || !name) return;
      if (group.querySelector('a[aria-current="page"]')) {
        button.disabled = true;
        button.setAttribute('aria-expanded', 'true');
        return;
      }
      function folded() { return (root.getAttribute('data-nav') || '').split(' ').indexOf(name) !== -1; }
      function paint() { button.setAttribute('aria-expanded', String(!folded())); }
      paint();
      button.addEventListener('click', function () {
        var names = (root.getAttribute('data-nav') || '').split(' ').filter(function (n) { return n && n !== name; });
        if (!folded()) names.push(name);
        root.setAttribute('data-nav', names.join(' '));
        store(NAV_KEY, names.join(' '));
        paint();
      });
    });

    // Keep the menu where it was scrolled. Each click loads a new page, so without this the menu
    // jumps back to the top and the end of a long list is out of sight again. Per tab, so another
    // window starts at the top.
    var nav = document.querySelector('.nav');
    if (nav) {
      var SCROLL_KEY = 'limen-nav-scroll';
      try {
        var at = (sessionStorage.getItem(SCROLL_KEY) || '').split(',');
        nav.scrollTop = Number(at[0]) || 0;
        nav.scrollLeft = Number(at[1]) || 0;
      } catch (e) { /* storage blocked: starts at the top */ }
      var remember = function () {
        try { sessionStorage.setItem(SCROLL_KEY, nav.scrollTop + ',' + nav.scrollLeft); } catch (e) { /* private mode */ }
      };
      nav.addEventListener('scroll', remember, { passive: true });
      // A click on a link navigates at once: record the position first.
      nav.addEventListener('click', remember);
      window.addEventListener('pagehide', remember);
    }

    // Collapse the sidebar to icons. Each link gets its name as a tooltip while the text is hidden.
    var side = document.querySelector('.sidebar-toggle');
    if (side) {
      var paintSide = function () {
        var collapsed = root.getAttribute('data-sidebar') === 'collapsed';
        var label = collapsed ? 'Expand the sidebar' : 'Collapse the sidebar';
        side.setAttribute('aria-expanded', String(!collapsed));
        side.setAttribute('aria-label', label);
        side.title = label;
        document.querySelectorAll('.nav a').forEach(function (a) {
          var text = a.querySelector('span');
          if (collapsed && text) a.title = text.textContent; else a.removeAttribute('title');
        });
      };
      paintSide();
      side.addEventListener('click', function () {
        var collapsed = root.getAttribute('data-sidebar') === 'collapsed';
        root.classList.add('nav-anim');
        if (collapsed) root.removeAttribute('data-sidebar'); else root.setAttribute('data-sidebar', 'collapsed');
        store(SIDEBAR_KEY, collapsed ? '' : 'collapsed');
        paintSide();
      });
    }

    var mode = saved() || 'system';
    var buttons = document.querySelectorAll('[data-theme-set]');
    function mark() {
      buttons.forEach(function (b) { b.setAttribute('aria-pressed', String(b.dataset.themeSet === mode)); });
    }
    mark();
    buttons.forEach(function (b) {
      b.addEventListener('click', function () {
        mode = b.dataset.themeSet;
        try { if (mode === 'system') localStorage.removeItem(KEY); else localStorage.setItem(KEY, mode); } catch (e) { /* private mode */ }
        apply(mode === 'system' ? null : mode);
        mark();
      });
    });

    // Copy buttons: <button data-copy="text">. Delegated, so buttons that
    // arrive with an auto-refresh keep working.
    document.addEventListener('click', function (e) {
      var b = e.target.closest && e.target.closest('[data-copy]');
      if (!b) return;
      var done = function () { b.classList.add('done'); setTimeout(function () { b.classList.remove('done'); }, 1200); };
      if (navigator.clipboard) navigator.clipboard.writeText(b.dataset.copy).then(done, function () {});
    });
  });
})();

// Auto-refresh: <main data-refresh="SECONDS"> is re-fetched and swapped in
// place. Polling, not SSE: it reuses the session cookie and needs no
// long-lived connections through the proxy. It pauses while the tab is hidden
// and never while something in the page has focus or a form has unsaved input.
(function () {
  document.addEventListener('DOMContentLoaded', function () {
    var main = document.querySelector('main[data-refresh]');
    var secs = main ? parseInt(main.dataset.refresh, 10) : 0;
    if (!main || !(secs > 0)) return;
    function busy() {
      var a = document.activeElement;
      if (a && a !== main && main.contains(a)) return true; // keep keyboard focus and open controls
      var sel = window.getSelection && window.getSelection();
      if (sel && !sel.isCollapsed && main.contains(sel.anchorNode)) return true;
      return Array.prototype.some.call(main.querySelectorAll('input,textarea,select'), function (el) {
        if (el.type === 'hidden' || el.type === 'submit' || el.type === 'button') return false;
        if (el.type === 'checkbox' || el.type === 'radio') return el.checked !== el.defaultChecked;
        return el.value !== el.defaultValue;
      });
    }
    function tick() {
      if (document.hidden || busy()) return;
      fetch(location.href, { credentials: 'same-origin', cache: 'no-store', headers: { 'X-Requested-With': 'refresh' } })
        .then(function (r) {
          // A redirect means the session ended: leave the page as it is.
          if (!r.ok || r.redirected) return null;
          return r.text();
        })
        .then(function (text) {
          if (!text || busy()) return;
          var next = new DOMParser().parseFromString(text, 'text/html').querySelector('main');
          if (next && next.innerHTML !== main.innerHTML) main.innerHTML = next.innerHTML;
        })
        .catch(function () { /* offline: try again next tick */ });
    }
    setInterval(tick, secs * 1000);
  });
})();

// Filter forms: <form data-autosubmit> submits when a dropdown or date changes;
// "/" focuses the search box; [data-check] buttons tick or clear a checkbox group.
(function () {
  document.addEventListener('change', function (e) {
    var el = e.target;
    var form = el.closest && el.closest('form[data-autosubmit]');
    if (!form || !(el.tagName === 'SELECT' || el.hasAttribute('data-datepicker'))) return;
    if (form.requestSubmit) form.requestSubmit(); else form.submit();
  });
  document.addEventListener('keydown', function (e) {
    if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
    var t = e.target;
    if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)) return;
    var box = document.querySelector('[data-focus-search]');
    if (box) { e.preventDefault(); box.focus(); box.select(); }
  });
  document.addEventListener('click', function (e) {
    var b = e.target.closest && e.target.closest('[data-check]');
    if (!b || !b.form) return;
    b.form.querySelectorAll('input[type=checkbox]').forEach(function (c) { c.checked = b.dataset.check === 'all'; });
  });
})();

// Date picker: <input data-datepicker> next to a .dp-btn gets a calendar styled like the
// rest of the console (the browser's own picker can't be themed). It writes YYYY-MM-DD;
// typing a date, or a date and time (YYYY-MM-DDTHH:MM), works too. All dates are UTC.
(function () {
  var MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
  var DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  var pop = null, owner = null, shown = null;
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function iso(y, m, d) { return y + '-' + pad(m + 1) + '-' + pad(d); }
  function parse(text) {
    var m = /^(\d{4})-(\d{2})-(\d{2})/.exec((text || '').trim());
    return m ? { y: +m[1], m: +m[2] - 1, d: +m[3] } : null;
  }
  function close() { if (pop) { pop.remove(); pop = null; owner = null; } }
  function pick(y, m, d) {
    owner.value = iso(y, m, d);
    var input = owner;
    close();
    input.focus();
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }
  function draw() {
    var today = new Date(), ty = today.getUTCFullYear(), tm = today.getUTCMonth(), td = today.getUTCDate();
    var sel = parse(owner.value);
    var first = new Date(Date.UTC(shown.y, shown.m, 1));
    var lead = (first.getUTCDay() + 6) % 7; // Monday first
    var count = new Date(Date.UTC(shown.y, shown.m + 1, 0)).getUTCDate();
    var html = '<div class="dp-head"><button type="button" class="dp-nav" data-dp="prev" aria-label="Previous month">‹</button>' +
      '<strong aria-live="polite">' + MONTHS[shown.m] + ' ' + shown.y + '</strong>' +
      '<button type="button" class="dp-nav" data-dp="next" aria-label="Next month">›</button></div><div class="dp-grid" role="grid">';
    DAYS.forEach(function (n) { html += '<span class="dp-dow">' + n + '</span>'; });
    for (var i = 0; i < lead; i++) html += '<span></span>';
    for (var d = 1; d <= count; d++) {
      var cls = 'dp-day' + (shown.y === ty && shown.m === tm && d === td ? ' today' : '') +
        (sel && sel.y === shown.y && sel.m === shown.m && sel.d === d ? ' sel' : '');
      html += '<button type="button" class="' + cls + '" data-d="' + d + '" aria-label="' + MONTHS[shown.m] + ' ' + d + ', ' + shown.y + '">' + d + '</button>';
    }
    html += '</div><div class="dp-foot"><button type="button" class="link" data-dp="today">Today</button><button type="button" class="link" data-dp="clear">Clear</button></div>';
    pop.innerHTML = html;
  }
  function open(input) {
    close();
    owner = input;
    var s = parse(input.value), now = new Date();
    shown = s ? { y: s.y, m: s.m } : { y: now.getUTCFullYear(), m: now.getUTCMonth() };
    pop = document.createElement('div');
    pop.className = 'dp-pop';
    pop.setAttribute('role', 'dialog');
    pop.setAttribute('aria-label', 'Choose a date');
    input.closest('.dp').appendChild(pop);
    draw();
  }
  document.addEventListener('click', function (e) {
    var t = e.target;
    var btn = t.closest && t.closest('.dp-btn');
    if (btn) { var input = btn.parentNode.querySelector('[data-datepicker]'); if (pop && owner === input) close(); else open(input); return; }
    if (t.closest && t.closest('[data-datepicker]')) { if (!pop || owner !== t) open(t); return; }
    if (!pop || !(t.closest && t.closest('.dp-pop'))) { close(); return; }
    var act = t.closest('[data-dp]'), day = t.closest('[data-d]');
    if (day) { pick(shown.y, shown.m, +day.dataset.d); return; }
    if (!act) return;
    if (act.dataset.dp === 'prev') { shown.m--; if (shown.m < 0) { shown.m = 11; shown.y--; } draw(); }
    else if (act.dataset.dp === 'next') { shown.m++; if (shown.m > 11) { shown.m = 0; shown.y++; } draw(); }
    else if (act.dataset.dp === 'today') { var n = new Date(); pick(n.getUTCFullYear(), n.getUTCMonth(), n.getUTCDate()); }
    else if (act.dataset.dp === 'clear') { var input2 = owner; input2.value = ''; close(); input2.dispatchEvent(new Event('change', { bubbles: true })); }
  });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && pop) { var i = owner; close(); i.focus(); } });
})();

// Keep addresses tidy: a filter form leaves its empty boxes out of the URL.
document.addEventListener('submit', function (e) {
  var f = e.target;
  if (!f.matches || !f.matches('form[data-autosubmit]')) return;
  var off = [];
  Array.prototype.forEach.call(f.elements, function (el) {
    if (el.name && el.value === '' && !el.disabled && el.type !== 'submit' && el.type !== 'button') { el.disabled = true; off.push(el); }
  });
  setTimeout(function () { off.forEach(function (el) { el.disabled = false; }); }, 0);
});

// Keyboard and small screens. A table that scrolls sideways is reachable from the keyboard, and
// the strip menu on a phone starts with the current page in view.
document.addEventListener('DOMContentLoaded', function () {
  function markScrollable() {
    Array.prototype.forEach.call(document.querySelectorAll('.table-wrap'), function (w) {
      if (w.scrollWidth > w.clientWidth + 1) {
        w.tabIndex = 0;
        if (!w.getAttribute('role')) { w.setAttribute('role', 'region'); w.setAttribute('aria-label', 'Table, scrolls sideways'); w.setAttribute('data-sc', ''); }
      } else if (w.hasAttribute('data-sc')) {
        w.removeAttribute('tabindex'); w.removeAttribute('role'); w.removeAttribute('aria-label'); w.removeAttribute('data-sc');
      }
    });
  }
  markScrollable();
  window.addEventListener('resize', markScrollable);
  var cur = document.querySelector('.nav a[aria-current="page"]');
  var nav = cur && cur.parentElement;
  if (nav && nav.scrollWidth > nav.clientWidth) nav.scrollLeft = Math.max(0, cur.offsetLeft - (nav.clientWidth - cur.offsetWidth) / 2);
});

// Typeahead: <div data-typeahead="/url"> around an <input> and an empty <ul class="ta-list">.
// As the box is typed in (or focused) the URL is asked, with ?q=, for [{name, kind, href}] and the
// answers are listed; arrows and Enter choose, a click follows the link. Without script the form
// submits and the server does the matching.
(function () {
  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('[data-typeahead]').forEach(function (root) {
      var src = root.getAttribute('data-typeahead');
      var input = root.querySelector('input');
      var list = root.querySelector('.ta-list');
      if (!src || !input || !list) return;
      var items = [], active = -1, timer = null, seq = 0;
      function render() {
        list.textContent = '';
        if (!items.length) { list.hidden = true; return; }
        items.forEach(function (it, i) {
          var li = document.createElement('li');
          li.setAttribute('role', 'option');
          if (i === active) li.className = 'on';
          var a = document.createElement('a');
          a.href = it.href;
          var n = document.createElement('span');
          n.textContent = it.name;
          var k = document.createElement('span');
          k.className = 'ta-kind';
          k.textContent = it.kind;
          a.appendChild(n);
          a.appendChild(k);
          li.appendChild(a);
          list.appendChild(li);
        });
        list.hidden = false;
      }
      function ask() {
        var mine = ++seq;
        fetch(src + '?q=' + encodeURIComponent(input.value), { credentials: 'same-origin', headers: { Accept: 'application/json' } })
          .then(function (r) { return r.ok ? r.json() : []; })
          .then(function (d) { if (mine !== seq) return; items = Array.isArray(d) ? d : []; active = -1; render(); })
          .catch(function () {});
      }
      input.addEventListener('input', function () { clearTimeout(timer); timer = setTimeout(ask, 100); });
      input.addEventListener('focus', ask);
      input.addEventListener('keydown', function (e) {
        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
          if (!items.length) return;
          e.preventDefault();
          active = (active + (e.key === 'ArrowDown' ? 1 : -1) + items.length + 1) % (items.length + 1);
          if (active === items.length) active = -1;
          render();
        } else if (e.key === 'Enter' && active >= 0) {
          e.preventDefault();
          window.location.href = items[active].href;
        } else if (e.key === 'Escape') {
          list.hidden = true;
        }
      });
      document.addEventListener('click', function (e) { if (!root.contains(e.target)) list.hidden = true; });
    });
  });
})();
