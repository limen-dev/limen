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
