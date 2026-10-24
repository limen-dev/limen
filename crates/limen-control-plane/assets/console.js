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

  document.addEventListener('DOMContentLoaded', function () {
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

    // Copy buttons: <button data-copy="text">.
    document.querySelectorAll('[data-copy]').forEach(function (b) {
      b.addEventListener('click', function () {
        var done = function () { b.classList.add('done'); setTimeout(function () { b.classList.remove('done'); }, 1200); };
        if (navigator.clipboard) navigator.clipboard.writeText(b.dataset.copy).then(done, function () {});
      });
    });
  });
})();

// Auto-refresh: <main data-refresh="SECONDS"> is re-fetched and swapped in
// place. Polling, not SSE: it reuses the session cookie and needs no
// long-lived connections through the proxy. It pauses while the tab is hidden
// and never while a form has focus or unsaved input.
(function () {
  document.addEventListener('DOMContentLoaded', function () {
    var main = document.querySelector('main[data-refresh]');
    var secs = main ? parseInt(main.dataset.refresh, 10) : 0;
    if (!main || !(secs > 0)) return;
    function busy() {
      var a = document.activeElement;
      if (a && main.contains(a) && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName)) return true;
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
      fetch(location.href, { credentials: 'same-origin', headers: { 'X-Requested-With': 'refresh' } })
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
