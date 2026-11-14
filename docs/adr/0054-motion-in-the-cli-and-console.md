# ADR-0054: Motion in the CLI and the console

- Status: Proposed (owner request, 2026-11-13; no issue yet). Built in the same PR at the owner's request, as listed under Built; the decisions under Open for review are not approved until the status changes.
- Date: 2026-11-13

## Context
Both surfaces already have a little motion: the CLI's braille spinner (`ui::spinner`, stderr, a plain line when stderr is not a terminal), the console's pulsing "live" dot, and the 0.22 s sidebar collapse that runs only on a click (documented in `docs/guides/console.md`). Four concrete gaps remain:
- **The console sidebar scrolls without saying so.** `.nav` scrolls inside the sidebar when the menu is taller than the window, and the thin scrollbar is easy to miss. Nothing tells you whether there is more above or below.
- **The CLI's slow steps leave no trace.** `Spinner::finish()` erases its line, so a step that took four seconds looks like nothing happened. `limen request --wait` and the browser wait in `limen login` can run for minutes with no sign that the command has not hung. `limen doctor` is silent until it prints its whole report.
- **The CLI spinner can corrupt the terminal.** A message longer than the terminal wraps, and `\r` only returns to the last row, so every frame leaves a row behind. `limen request --wait` has no Ctrl-C handler (its own text says "Ctrl-C to stop waiting"), so the default action ends the process, `Drop` never runs, and the shell prompt lands on a half-drawn line.
- **Page changes in the console are a hard blink**, because every page is a full navigation.

Constraints that decide most of the rest:
- The console is server-rendered under a CSP with no inline script and no third-party origin (ADR-0017). Motion is CSS, or a few lines in `console.js`.
- CLI output is read by people and parsed by scripts. Motion goes to stderr, on a terminal only.
- This is a security product. Motion must not delay an answer, hide a state, or be impossible to turn off.
- A new dependency needs an ADR-0012 row and `unsafe` is forbidden, so the CLI code is hand-written, like the spinner.

## Decision
### Rules for all motion
1. **It answers a question the user has**: is it working, did it finish, did it hang, is there more, what changed. Decoration is not added.
2. **Short and cheap.** Console transitions are 120 to 200 ms. Prefer `opacity` and `transform`. A layout property may animate only as the direct result of a click (as the sidebar collapse does today), never on page load. Nothing loops except a "live" or "waiting" signal.
3. **It never delays or hides information.** No animation holds back a result or a page's content, or shows data before it is true. A command that finishes quickly shows no spinner at all (see CLI 2).
4. **It can always be turned off, and off is the whole experience.** Console: `prefers-reduced-motion`. CLI: the gate below. With motion off every state still shows.
5. **State is never carried by motion alone.** A fade that says "more below" sits beside a scrollbar; a spinner is followed by a text result.

### Console
**1. A cue that the sidebar scrolls.** The cue is an edge fade, not a loading indicator: the menu is static and nothing is being fetched, so a loader would say "wait" about something complete. A soft shadow appears at the top once you have scrolled down, and at the bottom while there is more below, and each clears at its end. That is "have I reached the end of it or not".
- CSS only, using the `background-attachment: local` shadow pair on `.nav`. It works wherever CSS gradients do, so the scroll-driven (`animation-timeline`) variant was not needed and is dropped.
- Both themes. The dark sidebar is `#0c1018`, so a dark shadow on it is invisible: dark mode uses a lighter hairline or tint. The cover gradients use `var(--sidebar)` so the shadows are hidden at rest.
- A hovered or current link has its own opaque background, which paints over the shadow. Accepted: the cue is for the resting menu.
- The scrollbar (`scrollbar-width: thin`) stays. The cue is visual and links stay focusable, so nothing depends on it.
- The phone strip scrolls sideways and gets a right-edge fade by the same technique, which must not cover the last link or clip its focus ring.
- *Verification so far.* The real `console.css` with the sidebar's markup (a static harness, the menu forced shorter than the window) in one Chrome: in both themes the top shadow is absent at rest and present when scrolled, and the bottom shadow is present until the end. Not checked in Safari or Firefox, in the real console behind sign-in, with the collapsed sidebar, or on a phone width.

**2. Page changes that don't blink (built; the one taste call).** It answers "what changed?": the sidebar stays still while only the content swaps, so a click reads as a change of page, not a reload. `@view-transition { navigation: auto; }`, with the sidebar given `view-transition-name: sidebar` so a click cross-fades the main column while the sidebar stays put. The browser's default root cross-fade is believed to be 0.25 s (unverified), so the PR sets `::view-transition-old(root), ::view-transition-new(root) { animation-duration: .15s }`.
- It applies to every full navigation: link clicks, POST-redirects, auto-submitted filters and back/forward. The sign-in and error pages have no sidebar, so only the root fades. `/watch` pages start with a blank player, so the live-region fix (Console 3) ships first or with it.
- Open risk, to be tested: `console.js` restores the menu's scroll position in a `DOMContentLoaded` handler. If the browser captures the new page before that runs, the sidebar snapshot shows the menu at the top and then jumps. If so, the fix is to restore it earlier or drop the sidebar's own name.
- The theme script in `<head>` stays render-blocking, so there is no flash. Snapshots cover the viewport, so the cost does not grow with table size. `.sidebar` appears once per page, so the name is unique.
- Browser support varies and is checked when it is built (unverified here); where it is missing the rule is ignored and behaviour is as today. The base rule must come before the reduced-motion override in the cascade. One line to revert if it misbehaves.
- Under `prefers-reduced-motion` the PR also sets `@view-transition { navigation: none }`; setting `animation: none` on the pseudo-elements alone still runs the capture.

**3. Announce the connecting state.** `watch.html` already shows "Connecting…" (`#watch-state`) until the stream starts, but not as a live region, so a screen reader never hears it change. Give it `role="status"`. The recording player's loading state is checked in the same PR. No new motion.

**4. One reduced-motion block.** Today three separate `prefers-reduced-motion` blocks each switch off one animation. One block replaces them:
```css
@media (prefers-reduced-motion: reduce) {
  *:not(.ap-player, .ap-player *), *:not(.ap-player, .ap-player *)::before, *:not(.ap-player, .ap-player *)::after { animation-duration: .01ms !important; animation-iteration-count: 1 !important; transition-duration: .01ms !important; scroll-behavior: auto !important; }
}
```
The vendored asciinema player is excluded, because forcing its own loader and transitions to `.01ms` can freeze or hide them. Existing `animation: none` opt-outs stay where they are stricter. The live dot's pulse is also cut to one iteration, which is the intended reduced-motion result. The Rust test (`console/assets.rs`) reads `console.css` and checks the last reduced-motion block has these declarations and the player exclusion. The view-transitions PR adds `@view-transition { navigation: none }` to it. That protects the block from being removed or weakened; new rules are covered by the block itself, since it applies to everything.

**Not in the console:** chart draw-in (the server draws plain bars, and growing them delays the data), animated nav-group folds, button, flash and copy-icon polish, skeleton loaders, count-up numbers, and animating rows as they sort or filter. None answers a rule 1 question.

**5. Content moves between pages, and settles in (owner request).** The first cut only cross-faded the whole page. The content area now has its own view-transition name (`content`): the old page fades out in 0.1 s, the new one fades in and rises 8 px in 0.2 s, and the layer's own size change is switched off because pages differ in height. On a page load, stat cards, integration cards and the first ten table rows fade up one after another (at most 0.12 s of delay). Pages that refresh themselves (`console.js`) mark `main` as `refreshed` before swapping the content, so a changed row doesn't replay the entrance. Nav links also ease their background (0.12 s). All of it is CSS (plus one class in `console.js`), so the CSP is unchanged, and the one reduced-motion block turns it off. Not verified: playing in Safari and Firefox, and the rows' `transform` on very long or responsive (phone-card) tables.

### CLI
Everything goes through `crates/limen-cli/src/ui.rs`, on **stderr**, hand-written, with no new dependency.

**1. One gate, with explicit inputs.** `motion_enabled(stderr_is_tty, term, ci, opted_out)` is true only when stderr is a terminal, `TERM` is not `dumb`, `CI` is unset and `LIMEN_NO_ANIMATION` is unset. Only stderr is looked at (as the banner does), so `limen ls > file` still animates on the terminal and `2>/dev/null` shows nothing. `NO_COLOR` and `--color never` strip colour but do not stop motion. **This also regates the existing spinner**, which today animates on any terminal: a user in a CI-flagged terminal or `TERM=dumb` (an Emacs shell) now gets the plain `›` line. The spinner's `interactive` flag becomes the gate's result. Stdout is never written to by motion, so `--json` and tables are unchanged. The gate is a pure function and tested on its four inputs.

**2. Start late, so quick commands show nothing.** The spinner is drawn only after 300 ms. A step that finishes before that prints no spinner. This is what rule 3 requires; today the spinner appears at once.

**3. A spinner that ends in a result.** `Spinner::succeed(msg)` replaces the animated line with `✔ msg`, plus the elapsed time when the step took over a second (`✔ Approved.  1.4s`); the line stays in the scrollback. It is printed on stdout, as `ui::success` always did, whatever the motion state, so scripts see what they always saw; only the elapsed time is new, and only on a terminal. `finish()` keeps its meaning. The one site that prints a result right after `finish()` is `request --wait` ("Approved."), which now uses `succeed`. `selftest` and `login` keep their output (a verdict on stdout; a success line far from the spinner). **No `fail`:** an error already prints through the CLI's error renderer with `✖`, so a second line from the spinner would duplicate it.

**4. Waiting that shows it is waiting, and ends cleanly.** After 5 s the waiting spinners show a dimmed elapsed time (`⠋ Waiting for an approver · 2m14s`). It is a timer, not a bar, because the wait has no known length. The waits in `limen request --wait` (up to 1 h) and `limen login` (a 5 min timeout) have no Ctrl-C handler today (no `ctrl_c` in those files), so SIGINT ends the process and leaves a half-drawn line (`Drop` does not run on a signal). The PR selects on `tokio::signal::ctrl_c()` in those waits, finishes the spinner and exits 130. Because `ctrl_c()` disables the default SIGINT behaviour for the rest of the process, a task then makes any later Ctrl-C exit 130 too, so a token exchange stays interruptible. The exit code is a new convention (the CLI exits 1 on error, and `tcp` exits 0 on Ctrl-C), so it is documented in the CLI reference. No raw signal code and no `unsafe`.

**5. Other output never lands mid-spinner.** Tracing logs and `ui::warn` write to stderr, and `ui::success`/`info` to stdout, while the spinner thread rewrites its line every 80 ms. The rule: code that prints while a spinner is live finishes the spinner first. Every current spinner (`request --wait`, the `login` wait, `selftest`) prints nothing until it is finished, so no `Spinner::println` was built; add one when a caller needs it. A spinner is also finished before a command spawns a child process with inherited stdio.

**6. Fit the terminal (ships on its own).** Truncate the message to the terminal width minus the frame and a space, with `…`, **before** styling, never on a string that already has escape codes. The width is `COLUMNS` (re-read each frame), else the terminal's own answer from `stty size` (asked once, since shells rarely export `COLUMNS`), else 80; no dependency and no `unsafe`. A resize is picked up only when `COLUMNS` is set. Truncation counts `char`s; messages are static ASCII. Server-supplied text goes through `plain_line` first. A pure `fit(text, width)` function is unit tested. It should fix the wrapping described in Context (reasoned from the code, not yet reproduced), so it does not wait for the rest.

**7. `limen doctor` streaming.** On a terminal (motion on, not `--json`), each check is printed as it finishes, and before a slow one (network, tls, clock, session, access) a dim `… name` line shows what is running; it is erased when the result arrives. No spinner thread: everything is printed from the one task, so nothing interleaves. `Report::add` prints the checks it has not printed yet. The name column is a fixed width (the longest possible name, ten characters) because the widest name present is not known until the end, so a streamed report can be padded wider than today's; the lines are otherwise the same, a test compares them with `render`, and with motion off or `--json` the output is exactly today's.

**8. An animated logo (owner decision, reversing the first draft).** Where the banner already shows (`limen` with no arguments, `--help`, `login`) and motion is on, it is drawn as a left-to-right wipe with a bright teal leading edge, then stays as the static banner. The first version took 0.2 s and was too quick to see; it now takes about a second by default (0.5 s fast, 1.7 s slow, measured in a terminal). It adds that to those few commands and nothing to any other; with motion off, or `LIMEN_NO_BANNER`, it is as before.

**10. Settings under `limen config` (owner decision).** `limen config animations` shows and changes the preferences, saved in `$LIMEN_HOME/settings.json` (JSON, so no new dependency; nothing secret): animations on or off, speed (`slow`, `normal`, `fast`), the logo, the per-call spinner, and `--reset`. Each change plays the logo once. A saved `off` beats everything and is named as the reason by `limen config animations`; `LIMEN_NO_ANIMATION`, `LIMEN_NO_BANNER`, `CI`, `TERM=dumb` and a non-terminal stderr still turn motion off for a run. An unreadable file never stops a command: the defaults apply with a warning, while `config animations` itself refuses to overwrite a file it cannot parse. `limen config completions <shell>` is the visible home of the completion script, next to `config mcp`; the top-level `limen mcp` (what agents run) and `limen completions` (what shell setups call) are hidden from the menu but keep working, so existing configurations do not break.

**9. A spinner for every slow call.** The CLI's channel to the proxy is wrapped (`api::Channel`) so that a call taking over 300 ms shows a spinner named for it from its gRPC method (`List resources`, `List access requests`), gone when the last call returns, before the command prints. It is on for the commands that print after their calls return (`ls`, `show`, `request`, `requests`, `approve`, `deny`, `cancel`, `explain`, `policy`, `audit`, `review`, `admin`, `manage`), and off for `doctor` (its own streaming), `mcp` and `ssh-proxy` (they serve a protocol on stdout) and the long-lived commands. An explicit spinner (`request --wait`, `login`) replaces it while it runs. The frames take a teal gradient (the colour of the logo's dot).

**11. More of the CLI moves (owner request).** `limen doctor` shows a spinner named `Checking network` (and `tls`, `clock`, `session`, `access`) while a check is slow, and a short beat (20, 50 or 90 ms by speed) between checks so the list builds up. Tables and key/value blocks (`ls`, `requests`, `audit`, `status`, `show`, `review`, `admin`, `conns`, `policy`, `config animations`) are revealed a line at a time, 10, 22 or 40 ms apart and never longer than 0.4 s in all. This is timing only: no escape codes, the same bytes as before, and it needs motion on **and** stdout to be a terminal, so pipes and scripts see no delay. It is a deliberate exception to "no motion on stdout" below, which is about control codes.

**12. Every result and every lookup (owner request).** `✔` lines grow into place (`·`, `•`, `✔`, about 0.1 s; terminal and motion only). The per-call spinner now also covers the protocol commands (`connect`, `db`, `redis`, `mongo`, `search`, `mq`, `kafka`, `web`, `tcp`, `ssh`, `conns`) for their lookups, but never for a call that stays open for a session (`OpenSession`, `UploadRecording`, `Handoff`), which would draw over the user's own terminal. `kube` is left out: `limen kube login` runs as a credential plugin that answers on stdout. Menu: the daily commands come first (`login`, `ls`, `request`, `connect`, `status`, `doctor`), the per-protocol commands stay separate and visible, and `manage` is now `limen admin manage` (`limen manage` still works, hidden).
 Progress bars for work with no known length. Hiding the cursor: restoring it after a signal or panic without `unsafe` is the bug users remember. Motion on stdout, or in `ssh`, `connect`, `exec` and other commands that hand the terminal to another program. **Platforms:** macOS and Linux. Windows Terminal and ConPTY are unverified; `\r\x1b[2K` on older conhost is untested.

## Built
All of this was built in this PR, with the logo animation and the per-call spinner (CLI 8, 9) added at the owner's request after the first review: the console foundation (sidebar cue, one reduced-motion block and its test, the live-region fix) and view transitions; the CLI spinner (gate, delayed start, elapsed time, `succeed`, Ctrl-C handling, width fitting) and `doctor` streaming. Not built, and why: `fail` and `Spinner::println` (CLI 3, 5).

## Verification
Console: the real pages from the compose stack in more than one browser, both themes, with and without reduced motion, and the CSP report empty; browsers lacking a feature are checked, not assumed. CLI: unit tests on rendered lines with colour stripped, the gate's four inputs, `fit` at narrow widths; a run under a pseudo-terminal (`script`) and one with stderr redirected, both manual, since the repo has no pty harness. Anything seen in one browser or terminal only is labelled `unverified`.

## Consequences
- The existing spinner changes in CI-flagged and `TERM=dumb` terminals: they get the plain `›` line instead of the animation (CLI 1). Nothing else prints differently with motion off.
- Ctrl-C during a wait now exits 130 instead of being killed by the signal.
- The saved pages in `crates/limen-control-plane/tests/console-pages/` should need no change for the foundation PR (to be confirmed by running them).
- Risk: view transitions change how every page change feels. One rule to remove; the sidebar scroll-restore interaction is tested only for the position, not frame by frame.
- A streamed `doctor` report pads names to ten characters.
- The logo animation costs about a second by default on the commands that show it (settable). The per-call spinner adds a wrapper around every call to the proxy and a `tower` dependency to `limen-cli` (already adopted, ADR-0012).
- A result from `succeed` still goes to stdout; on a terminal it may end with the elapsed time.

## Open for review
1. **View transitions** are in, behind one CSS line to revert. Keep them? (Recommended: yes, if they feel right in the real console.)
2. **Windows:** not in scope; the CLI targets macOS and Linux and Windows terminals are unverified.

Proposed defaults, not asked: exit code 130 on Ctrl-C, a 300 ms spinner delay, the elapsed timer after 5 s, the CLI switch is `LIMEN_NO_ANIMATION`, and the terminal width comes from `COLUMNS` or `stty size`, with no new dependency.
