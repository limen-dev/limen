// Starts the asciinema player on the live stream named in data-src. Kept in
// its own file so the page needs no inline script (CSP): the stream is the
// same origin, which `connect-src 'self'` allows.
(function () {
  var el = document.getElementById('watch');
  var state = document.getElementById('watch-state');
  if (!el || !window.AsciinemaPlayer) return;
  window.AsciinemaPlayer.create({ driver: 'eventsource', url: el.dataset.src, bufferTime: 0.2 }, el, {
    fit: 'width',
    theme: 'asciinema',
    autoPlay: true,
    controls: false
  });
  if (state) state.textContent = 'Live. This view ends when the session does, or when you leave.';
})();
