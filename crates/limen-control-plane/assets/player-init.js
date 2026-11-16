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
  var PLAYER_IDLE_LIMIT = 3;
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
  // An asciicast is a header line, then [time, type, data] lines. In v2 the time is seconds since the start;
  // in v3 (what the worker writes) it is seconds since the previous event. Either way a gap of IDLE_SECONDS
  // or more before output gets a marker where the output resumed. The player shortens every pause to
  // PLAYER_IDLE_LIMIT seconds (idleTimeLimit below), so a marker belongs where the output resumes on that
  // shortened timeline, not on the original one: it is the sum of the shortened gaps so far.
  function idleMarkers(text) {
    var lines = text.split('\n');
    var header;
    try { header = JSON.parse(lines[0]); } catch (e) { return []; }
    if (!header || typeof header !== 'object') return [];
    var relative = Number(header.version) >= 3;
    var out = [], shown = 0, previous = 0;
    for (var i = 1; i < lines.length && out.length < MAX_MARKERS; i++) {
      if (!lines[i]) continue;
      var ev;
      try { ev = JSON.parse(lines[i]); } catch (e) { continue; }
      if (!Array.isArray(ev) || typeof ev[0] !== 'number') continue;
      var gap = relative ? ev[0] : ev[0] - previous;
      previous = relative ? previous + ev[0] : ev[0];
      if (gap < 0) gap = 0;
      shown += Math.min(gap, PLAYER_IDLE_LIMIT);
      if (ev[1] === 'o' && gap >= IDLE_SECONDS) out.push([shown, 'Idle ' + span(gap)]);
    }
    return out;
  }
  function start(src, markers) {
    player = window.AsciinemaPlayer.create(src, el, {
      fit: 'width',
      idleTimeLimit: PLAYER_IDLE_LIMIT,
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
