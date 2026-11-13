# ADR-0054: Motion in the CLI and the console

- Status: Proposed (owner request, 2026-11-13; no issue yet). The first slice (Console 1, 3, 4 and CLI 4, 6) was started at the owner's request in the same PR; the rest is not built.
- Date: 2026-11-13
- Decision needed: approve the rollout order and answer the two open questions at the end.

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

**2. Page changes that don't blink (its own PR, and the one taste call).** It answers "what changed?": the sidebar stays still while only the content swaps, so a click reads as a change of page, not a reload. `@view-transition { navigation: auto; }`, with the sidebar given `view-transition-name: sidebar` so a click cross-fades the main column while the sidebar stays put. The browser's default root cross-fade is believed to be 0.25 s (unverified), so the PR sets `::view-transition-old(root), ::view-transition-new(root) { animation-duration: .15s }`.
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

### CLI
Everything goes through `crates/limen-cli/src/ui.rs`, on **stderr**, hand-written, with no new dependency.

**1. One gate, with explicit inputs.** `motion_enabled(stderr_is_tty, term, ci, opted_out)` is true only when stderr is a terminal, `TERM` is not `dumb`, `CI` is unset and `LIMEN_NO_ANIMATION` is unset. Only stderr is looked at (as the banner does), so `limen ls > file` still animates on the terminal and `2>/dev/null` shows nothing. `NO_COLOR` and `--color never` strip colour but do not stop motion. **This also regates the existing spinner**, which today animates on any terminal: a user in a CI-flagged terminal or `TERM=dumb` (an Emacs shell) now gets the plain `›` line. The spinner's `interactive` flag becomes the gate's result. Stdout is never written to by motion, so `--json` and tables are unchanged. The gate is a pure function and tested on its four inputs.

**2. Start late, so quick commands show nothing.** The spinner is drawn only after 300 ms. A step that finishes before that prints no spinner. This is what rule 3 requires; today the spinner appears at once.

**3. A spinner that ends in a result.** `Spinner::succeed(msg)` and `Spinner::fail(msg)` replace the animated line with `✔ msg` or `✘ msg`, plus the elapsed time when the step took over a second (`✔ Signed in to <proxy> as ana  1.4s`); the line stays in the scrollback. `finish()` keeps its meaning. Used only where the line is a status for a person: the one site that prints a result right after `finish()` is `request --wait` (`ui::success("Approved.")`, access.rs). `selftest` drops its spinner and prints a verdict to stdout, and the `login` spinner (in `oidc.rs`) is far from its success line (`login.rs`), so those keep their output and streams. With motion off, a result prints the same line to the same stream as today; a command whose result is data keeps printing it on stdout. Each call site is decided in the implementation PR.

**4. Waiting that shows it is waiting, and ends cleanly.** After 5 s the waiting spinners show a dimmed elapsed time (`⠋ Waiting for an approver · 2m14s`). It is a timer, not a bar, because the wait has no known length. The waits in `limen request --wait` (up to 1 h) and `limen login` (a 5 min timeout) have no Ctrl-C handler today (no `ctrl_c` in those files), so SIGINT ends the process and leaves a half-drawn line (`Drop` does not run on a signal). The PR selects on `tokio::signal::ctrl_c()` in those waits, finishes the spinner and exits 130. Because `ctrl_c()` disables the default SIGINT behaviour for the rest of the process, a task then makes any later Ctrl-C exit 130 too, so a token exchange stays interruptible. The exit code is a new convention (the CLI exits 1 on error, and `tcp` exits 0 on Ctrl-C), so it is documented in the CLI reference. No raw signal code and no `unsafe`.

**5. Other output never lands mid-spinner.** Tracing logs and `ui::warn` write to stderr, and `ui::success`/`info` to stdout, while the spinner thread rewrites its line every 80 ms. While a spinner is live, output goes through `Spinner::println` (clear the line, print, redraw), or the spinner is finished first. A spinner is always finished, not left to drop later, before a command spawns a child process with inherited stdio.

**6. Fit the terminal (ships on its own).** Truncate the message to the terminal width minus the frame and a space, with `…`, **before** styling, never on a string that already has escape codes. The width is `COLUMNS` (re-read each frame), else the terminal's own answer from `stty size` (asked once, since shells rarely export `COLUMNS`), else 80; no dependency and no `unsafe`. A resize is picked up only when `COLUMNS` is set. Truncation counts `char`s; messages are static ASCII. Server-supplied text goes through `plain_line` first. A pure `fit(text, width)` function is unit tested. It should fix the wrapping described in Context (reasoned from the code, not yet reproduced), so it does not wait for the rest.

**7. `limen doctor` streaming (its own PR, last).** On a terminal, print each check as it finishes with a spinner on the line below naming the running one, instead of one report after a silent wait. This is a real change in how `doctor` produces output, not a styling change: `diagnose` pushes checks into a `Report`, skips are added in bulk and after the fact, `render` pads names to the widest name, and a `fix` hint is a second line belonging to its check. The design is a sink on `Report::add`, a fixed name column taken from the list of check names, and multi-line entries printed whole (no in-place redraw). The text, `--json` and the output with motion off must equal today's, tested by comparing the streamed lines with `render`.

**Not in the CLI.** An animated banner (it would delay every interactive command; the banner stays static, opt-out `LIMEN_NO_BANNER`). Progress bars for work with no known length. Hiding the cursor: restoring it after a signal or panic without `unsafe` is the bug users remember. Motion on stdout, or in `ssh`, `connect`, `exec` and other commands that hand the terminal to another program. **Platforms:** macOS and Linux. Windows Terminal and ConPTY are unverified; `\r\x1b[2K` on older conhost is untested.

## Rollout
Three groups of PRs, each needing the owner's go-ahead, in this order:
1. **Console foundation:** sidebar scroll cue, the reduced-motion block and its test, the live-region fix.
2. **CLI:** truncation and the Ctrl-C handling first (both fix bugs today), then the gate, delayed start, `succeed`/`fail`, elapsed time and `Spinner::println`; `limen doctor` streaming last, on its own.
3. **Console view transitions**, last, because it changes how every page change feels and is a matter of taste.

## Verification, per PR
Console: the real pages from the compose stack in more than one browser, both themes, with and without reduced motion, and the CSP report empty; browsers lacking a feature are checked, not assumed. CLI: unit tests on rendered lines with colour stripped, the gate's four inputs, `fit` at narrow widths; a run under a pseudo-terminal (`script`) and one with stderr redirected, both manual, since the repo has no pty harness. Anything seen in one browser or terminal only is labelled `unverified`.

## Consequences
- The existing spinner changes in CI-flagged and `TERM=dumb` terminals: they get the plain `›` line instead of the animation (CLI 1). Nothing else prints differently with motion off.
- Ctrl-C during a wait now exits 130 instead of being killed by the signal.
- The saved pages in `crates/limen-control-plane/tests/console-pages/` should need no change for the foundation PR (to be confirmed by running them).
- Risk: view transitions change how every page change feels, hence last and separate.

## Open questions for the owner
1. **View transitions:** worth having, or is a hard page change fine? (Recommended: try them last, behind the other PRs.)
2. **Windows:** is the Windows terminal in scope for the CLI? (Recommended: no; macOS and Linux, Windows unverified.)

Proposed defaults, not asked: exit code 130 on Ctrl-C, a 300 ms spinner delay, the elapsed timer after 5 s, the CLI switch is `LIMEN_NO_ANIMATION`, and the terminal width comes from `COLUMNS` or `stty size`, with no new dependency.
