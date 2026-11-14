// Starts the asciinema player on the recording named in data-src.
// Kept in its own file so the page needs no inline script (CSP).
//
// The recording is read once here so the timeline can carry markers: a long pause in the output
// ("Idle 1m 12s") is where somebody stopped to think, read or step away, and it is the first thing a
// reviewer wants to jump to or past. The player is handed the same text, so the file is fetched
// once. If the read fails the player is started on the address instead, with no markers.
(function () {
  var el = document.getElementById('player');
  if (!el || !window.AsciinemaPlayer) return;
  var url = el.dataset.src;
  var IDLE_SECONDS = 30;
  var MAX_MARKERS = 40;
  var player = null;

  function span(secs) {
    var s = Math.round(secs);
    var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
    s = s % 60;
    var parts = [];
    if (h) parts.push(h + 'h');
    if (m) parts.push(m + 'm');
    if (s || !parts.length) parts.push(s + 's');
    return parts.join(' ');
  }
  // asciicast v2: a header line, then [seconds, type, data] lines. A gap between two output events
  // of IDLE_SECONDS or more gets a marker where the output resumed.
  function idleMarkers(text) {
    var out = [], last = null;
    var lines = text.split('\n');
    for (var i = 1; i < lines.length && out.length < MAX_MARKERS; i++) {
      if (!lines[i]) continue;
      var ev;
      try { ev = JSON.parse(lines[i]); } catch (e) { continue; }
      if (!Array.isArray(ev) || typeof ev[0] !== 'number' || ev[1] !== 'o') continue;
      if (last !== null && ev[0] - last >= IDLE_SECONDS) out.push([ev[0], 'Idle ' + span(ev[0] - last)]);
      last = ev[0];
    }
    return out;
  }
  function start(src, markers) {
    player = window.AsciinemaPlayer.create(src, el, {
      fit: 'width',
      idleTimeLimit: 3,
      preload: true,
      theme: 'asciinema',
      markers: markers,
      // A search hit links to the moment it happened (?t=seconds).
      startAt: Number(el.dataset.start) || 0
    });
  }

  fetch(url, { credentials: 'same-origin' })
    .then(function (r) { if (!r.ok) throw new Error('recording'); return r.text(); })
    .then(function (text) { start({ data: text, parser: 'asciicast' }, idleMarkers(text)); })
    .catch(function () { start(url, []); });

  // "Copy link to this moment": the page's address with ?t= set to where the player is.
  document.addEventListener('click', function (e) {
    var b = e.target.closest && e.target.closest('[data-copy-moment]');
    if (!b || !player) return;
    Promise.resolve(player.getCurrentTime()).then(function (t) {
      var link = location.origin + location.pathname + '?t=' + Math.max(0, Math.floor(Number(t) || 0));
      if (navigator.clipboard) {
        navigator.clipboard.writeText(link).then(function () {
          b.classList.add('done');
          setTimeout(function () { b.classList.remove('done'); }, 1200);
        }, function () {});
      }
    });
  });
})();
