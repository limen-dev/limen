// Picks the direction of the animation when you move between pages (the CSS is in
// src/styles/transitions.css). It runs in the page you arrive on, before that page is first drawn.
// Browsers without cross-document view transitions never fire the event, so nothing changes.
(function () {
  var inDocs = function (path) { return /\/docs(\/|$)/.test(path); };
  addEventListener('pagereveal', function (e) {
    if (!e.viewTransition) return;
    // Back and forward: the browser restores the scroll position itself, and a slide would start
    // from the top of the page and then jump to that position. Leave these to the browser.
    var traversal = false;
    try { traversal = navigation.activation.navigationType === 'traverse'; } catch (_) {
      try { traversal = performance.getEntriesByType('navigation')[0].type === 'back_forward'; } catch (_) { /* unknown */ }
    }
    if (traversal) { e.viewTransition.skipTransition(); document.documentElement.dataset.vt = 'traverse'; return; }
    var from = '';
    try {
      var url = new URL(navigation.activation.from.url);
      if (url.origin === location.origin) from = url.pathname;
    } catch (_) {
      try {
        var ref = new URL(document.referrer);
        if (ref.origin === location.origin) from = ref.pathname;
      } catch (_) { /* a first visit: no animation */ }
    }
    var to = location.pathname;
    var type = 'none';
    if (from && from !== to) {
      var a = inDocs(from), b = inDocs(to);
      type = !a && b ? 'to-docs' : a && !b ? 'to-home' : a && b ? 'doc-to-doc' : 'page';
    }
    e.viewTransition.types.add(type);
    document.documentElement.dataset.vt = type;
  });
})();
