// Starts the asciinema player on the recording named in data-src.
// Kept in its own file so the page needs no inline script (CSP).
(function () {
  var el = document.getElementById('player');
  if (!el || !window.AsciinemaPlayer) return;
  window.AsciinemaPlayer.create(el.dataset.src, el, {
    fit: 'width',
    idleTimeLimit: 3,
    preload: true,
    theme: 'asciinema',
    // A search hit links to the moment it happened (?t=seconds).
    startAt: Number(el.dataset.start) || 0
  });
})();
