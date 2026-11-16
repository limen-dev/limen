// Where the recording player puts its "Idle" markers (assets/player-init.js). Needs only Node:
//   node --test crates/limen-control-plane/tests/player-init.test.mjs
// The worker writes asciicast v3, whose times are relative to the previous event; v2 times are absolute.
// The player shortens every pause to 3 seconds, so markers sit on that shortened timeline.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const source = readFileSync(new URL('../assets/player-init.js', import.meta.url), 'utf8');

/** Runs the script against a fake page and recording, and returns the markers it gave the player. */
async function markersFor(cast) {
  let markers;
  const element = { dataset: { src: '/recording', start: '0' } };
  const document = { getElementById: () => element, addEventListener() {} };
  const window = { AsciinemaPlayer: { create: (_src, _el, options) => { markers = options.markers; return {}; } } };
  const fetch = () => Promise.resolve({ ok: true, text: () => Promise.resolve(cast) });
  new Function('document', 'window', 'fetch', source)(document, window, fetch);
  await new Promise((resolve) => setTimeout(resolve, 10));
  return markers;
}

const lines = (...l) => l.join('\n');

test('v3: every long pause is marked, where the output resumes on the shortened timeline', async () => {
  const cast = lines('{"version":3}', '[0.1,"o","a"]', '[40,"o","b"]', '[0.5,"o","c"]', '[40,"o","d"]', '[1,"o","e"]');
  assert.deepEqual(await markersFor(cast), [[3.1, 'Idle 40s'], [6.6, 'Idle 40s']]);
});

test('v2 (absolute times) gives the same markers for the same recording', async () => {
  const cast = lines('{"version":2}', '[0.1,"o","a"]', '[40.1,"o","b"]', '[40.6,"o","c"]', '[80.6,"o","d"]', '[81.6,"o","e"]');
  assert.deepEqual(await markersFor(cast), [[3.1, 'Idle 40s'], [6.6, 'Idle 40s']]);
});

test('a pause under 30 seconds is not marked, and the label is a readable duration', async () => {
  assert.deepEqual(await markersFor(lines('{"version":3}', '[29,"o","a"]', '[1,"o","b"]')), []);
  assert.deepEqual(await markersFor(lines('{"version":3}', '[0.1,"o","a"]', '[72,"o","b"]')), [[3.1, 'Idle 1m 12s']]);
});

test('a header that is not JSON gives no markers instead of an error', async () => {
  assert.deepEqual(await markersFor('nonsense\n[1,"o","a"]'), []);
});
