# ADR-0054: Motion in the CLI and the console

- Status: Proposed (owner request, 2026-11-13; no issue yet). Nothing here is built.
- Date: 2026-11-13

## Context
Both surfaces already have a little motion: the CLI's braille spinner (`ui::spinner`, stderr, silent when piped), the console's pulsing "live" dot, and the 0.22 s sidebar collapse that runs only on a click (documented in `docs/guides/console.md`). Four concrete gaps remain:
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
- CSS only. Where scroll-driven animations exist (`animation-timeline: scroll()`) they drive the fades; elsewhere the `background-attachment: local` shadow pair on `.nav` does.
- Both themes. The dark sidebar is `#0c1018`, so a dark shadow on it is invisible: dark mode uses a lighter hairline or tint. The cover gradients use `var(--sidebar)` so the shadows are hidden at rest.
- A hovered or current link has its own opaque background, which paints over the shadow. Accepted: the cue is for the resting menu.
- The scrollbar (`scrollbar-width: thin`) stays. The cue is visual and links stay focusable, so nothing depends on it.
- The phone strip scrolls sideways and gets a right-edge fade by the same technique, which must not cover the last link or clip its focus ring.
- *Partly verified.* The local-attachment technique was tried on a standalone page with 24 links in one Chrome: the shadows show at the top and bottom while mid-scroll and clear at the ends. `animation-timeline: scroll()` is supported in that Chrome (`CSS.supports`), but the scroll-driven path itself was not exercised. Not tried in Safari or Firefox, nor in the real sidebar (hover states, the collapsed mode, `margin: -2px`). The implementation PR must show the real sidebar in more than one browser, in both themes.

**2. Page changes that don't blink (its own PR).** `@view-transition { navigation: auto; }`, with the sidebar given `view-transition-name: sidebar` so a click cross-fades the main column while the sidebar stays put. The default root cross-fade is 0.25 s, so the PR sets `::view-transition-old(root), ::view-transition-new(root) { animation-duration: .15s }`.
- It applies to every full navigation: link clicks, POST-redirects, auto-submitted filters and back/forward. The sign-in and error pages have no sidebar, so only the root fades. `/watch` pages start with a blank player, so the live-region fix (item 3) ships first or with it.
- Open risk, to be tested: `console.js` restores the menu's scroll position in a `DOMContentLoaded` handler. If the browser captures the new page before that runs, the sidebar snapshot shows the menu at the top and then jumps. If so, the fix is to restore it earlier or drop the sidebar's own name.
- The theme script in `<head>` stays render-blocking, so there is no flash. Snapshots cover the viewport, so the cost does not grow with table size. `.sidebar` appears once per page, so the name is unique.
- Not supported in Firefox at the time of writing: the rule is ignored and behaviour is as today. One line to revert if it misbehaves.
- Under `prefers-reduced-motion` the PR also sets `@view-transition { navigation: none }`; setting `animation: none` on the pseudo-elements alone still runs the capture.

**3. Announce the connecting state.** `watch.html` already shows "Connecting…" (`#watch-state`) until the stream starts, but not as a live region, so a screen reader never hears it change. Give it `role="status"`. The recording player's loading state is checked in the same PR. No new motion.

**4. One reduced-motion block.** Today three separate `prefers-reduced-motion` blocks each switch off one animation. A single block replaces the need to remember:
```css
@media (prefers-reduced-motion: reduce) {
  *:not(.ap-player, .ap-player *), *::before, *::after { animation-duration: .01ms !important; animation-iteration-count: 1 !important; transition-duration: .01ms !important; scroll-behavior: auto !important; }
  @view-transition { navigation: none; }
}
```
The vendored asciinema player is excluded, because forcing its own loader and transitions to `.01ms` can freeze or hide them. Existing `animation: none` opt-outs stay where they are stricter. The Rust test reads `console.css` and checks the block is present with its view-transition line. That protects the block from being removed or weakened; new rules are covered by the block itself, since it applies to everything.

**Cut after review, and why.** Chart draw-in: the server draws plain bars (`<rect>`) with no lines to draw, a bar growing from zero delays the data that audit dashboards exist to show (rules 1 and 3), the 30 s auto-refresh would need a script to stop it replaying, and the corners of a scaled `rx` bar distort. Folding nav groups with a height animation: it needs a new wrapper in `base.html`, `visibility: hidden` on folded links (or they stay in the tab order) and click-only gating, to animate something that is a snap today. Button press states, eased flash messages and a fade on the copy icon: none answers a rule 1 question. Also not wanted: skeleton loaders (the server renders pages whole), count-up numbers (these are audit figures), parallax, and anything animating rows as they sort or filter.

**Possible later, not in scope:** a brief highlight on a live session that ends or is killed (this needs the live pages to push state; today they re-fetch every few seconds), and a confirmation state after lock or kill.

### CLI
Everything goes through `crates/limen-cli/src/ui.rs`, on **stderr**, hand-written, with no new dependency.

**1. One gate, with explicit inputs.** `motion_enabled(stderr_is_tty, term, ci, opted_out)` is true only when stderr is a terminal, `TERM` is not `dumb`, `CI` is unset and `LIMEN_NO_ANIMATION` is unset. Only stderr is looked at (as the banner does), so `limen ls > file` still animates on the terminal and `2>/dev/null` shows nothing. `NO_COLOR` and `--color never` strip colour but do not stop motion. **This also regates the existing spinner**, which today animates on any terminal: a user in a CI-flagged terminal or `TERM=dumb` (an Emacs shell) now gets the plain `›` line. The spinner's `interactive` flag becomes the gate's result, and it also decides whether the line is erased. Stdout is never written to by motion, so `--json` and tables are unchanged. The gate is a pure function and tested on its four inputs.

**2. Start late, so quick commands show nothing.** The spinner is drawn only after 300 ms. A step that finishes before that prints no spinner and, in `succeed`, no elapsed time. This is what rule 3 requires; today the spinner appears at once.

**3. A spinner that ends in a result.** `Spinner::succeed(msg)` and `Spinner::fail(msg)` replace the animated line with `✔ msg` or `✘ msg`, plus the elapsed time when it was over a second (`✔ Signed in as ana  1.4s`), and the line stays in the scrollback. They are for the call sites that today do `finish()` and then print a result: the result moves into `succeed`, so it is not printed twice, and, as motion is on stderr, such a result line moves from stdout to stderr. That is acceptable only where the line is a status for a person; a command whose result is data keeps printing it on stdout and calls `finish()`. Each call site is decided in the implementation PR. `finish()` keeps its meaning.

**4. Waiting that shows it is waiting, and ends cleanly.** After 5 s the waiting spinners show a dimmed elapsed time (`⠋ Waiting for an approver · 2m14s`). It is a timer, not a bar, because the wait has no known length. `limen request --wait`, the `limen login` browser wait and `limen selftest` run in loops that today have no Ctrl-C handler, so SIGINT ends the process and leaves a half-drawn line (`Drop` does not run on a signal). The PR selects on `tokio::signal::ctrl_c()` in those loops, finishes the spinner and exits 130. No raw signal code and no `unsafe`.

**5. Other output never lands mid-spinner.** Tracing logs and `ui::warn` write to stderr, and `ui::success`/`info` to stdout, while the spinner thread rewrites its line every 80 ms. While a spinner is live, output goes through `Spinner::println` (clear the line, print, redraw), or the spinner is finished first. A spinner is always finished, not left to drop later, before a command spawns a child process with inherited stdio.

**6. Fit the terminal (ships on its own).** Truncate the message to the terminal width minus the frame and a space, with `…`, **before** styling, never on a string that already has escape codes. The width is `COLUMNS` with an 80-column fallback, re-read each frame so a resize is picked up; no dependency. Truncation counts `char`s, so wide (CJK, emoji) text can overshoot by a column; messages today are static ASCII. Server-supplied text goes through `plain_line` first. A pure `fit(text, width)` function is unit tested. It fixes a bug today, so it does not wait for the rest.

**7. `limen doctor` streaming (its own PR, last).** On a terminal, print each check as it finishes with a spinner on the line below naming the running one, instead of one report after a silent wait. This is a real change in how `doctor` produces output, not a styling change: `diagnose` pushes checks into a `Report`, skips are added in bulk and after the fact, `render` pads names to the widest name, and a `fix` hint is a second line belonging to its check. The design is a sink on `Report::add`, a fixed name column taken from the list of check names, and multi-line entries printed whole (no in-place redraw). The text, `--json` and the output with motion off must equal today's, tested by comparing the streamed lines with `render`.

**Not in the CLI.** An animated banner (it would delay every interactive command; the banner stays static, opt-out `LIMEN_NO_BANNER`). Progress bars for work with no known length. Hiding the cursor: restoring it after a signal or panic without `unsafe` is the bug users remember. Motion on stdout, or in `ssh`, `connect`, `exec` and other commands that hand the terminal to another program. **Platforms:** macOS and Linux. Windows Terminal and ConPTY are unverified; `\r\x1b[2K` on older conhost is untested.

**Possible later:** a terminal bell when a long `--wait` resolves.

## Rollout
Independent PRs, each needing the owner's go-ahead:
1. **Console foundation:** sidebar scroll cue, the reduced-motion block and its test, the live-region fix.
2. **Console view transitions.**
3. **CLI spinner:** the gate, delayed start, `succeed`/`fail`, elapsed time, Ctrl-C handling, `Spinner::println`, width truncation. The truncation fix may go first on its own.
4. **`limen doctor` streaming.**

## Verification, per PR
Console: the real pages from the compose stack in more than one browser, both themes, with and without reduced motion, and the CSP report empty; browsers lacking a feature are checked, not assumed. CLI: unit tests on rendered lines with colour stripped, the gate's four inputs, `fit` at narrow widths; a run under a pseudo-terminal (`script`) and one with stderr redirected, both manual, since the repo has no pty harness. Anything seen in one browser or terminal only is labelled `unverified`.

## Consequences
- Roughly a few dozen lines of CSS and no script for the console, and on the order of 150 lines in `ui.rs` plus changes at the three spinner call sites (estimates).
- The existing spinner changes behaviour in CI-flagged and `TERM=dumb` terminals (CLI 1), and a status result may move from stdout to stderr where `succeed` is adopted (CLI 3).
- With motion off the console and the CLI look and print what they do today, so the saved pages in `crates/limen-control-plane/tests/console-pages/` should need no change for the foundation PR (to be confirmed by running them).
- Risk: view transitions change how every page change feels, hence their own PR.

## Open questions for the owner
1. **Order and scope.** All four PRs, or the console foundation and the CLI truncation and Ctrl-C fixes first, to judge the feel before adding more? (Recommended: that smaller start.)
2. **Windows.** Is the Windows terminal in scope for the CLI, or macOS and Linux only? (Recommended: macOS and Linux, Windows labelled unverified.)

Decided here, not asked: view transitions are included as their own revertible PR; the CLI switch is `LIMEN_NO_ANIMATION`; the terminal width comes from `COLUMNS` with no new dependency.
