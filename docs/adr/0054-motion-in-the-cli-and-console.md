# ADR-0054: Motion in the CLI and the console

- Status: Proposed (a proposal for the owner; nothing here is built, and no code changes with this ADR)
- Date: 2026-11-13

## Context
Both surfaces already have a little motion, and it works: the CLI's braille spinner (`ui::spinner`, on stderr, silent when piped), the console's pulsing "live" dot, and the 0.22 s sidebar collapse that runs only when someone clicks the toggle (ADR-0017). What is missing is the small feedback that makes a tool feel finished rather than merely correct: a spinner that ends in a result, a page change that doesn't blink, a long menu that shows it has more below, a chart that doesn't just appear.

The constraints are real, and they decide most of what follows:
- The console is server-rendered, with a CSP that allows no inline script and no third-party origin (ADR-0017). Motion has to be CSS, or a few lines in the existing `console.js`.
- The CLI's output is read by people and parsed by scripts. Anything that moves must go to stderr, only on a terminal, and never change what a pipe sees.
- The product is for security people. Motion that delays an answer, hides a state, or can't be turned off is a cost, not a feature.
- A new dependency needs an ADR-0012 row, and `unsafe` is forbidden. Both push toward small, hand-written code, as the spinner already is.

## Decision
### Rules for all motion
1. **It answers a question the user has**: is it working, did it finish, what changed, is there more. Motion that only decorates is not added.
2. **Short and cheap.** Console transitions are 120 to 200 ms and animate `opacity` and `transform` only (no layout properties, so no layout shift). Nothing loops except a "this is live" or "this is waiting" signal.
3. **It never delays work.** No animation holds back a command's result or a page's content. A command that finishes in 50 ms shows no spinner at all.
4. **It can always be turned off, and off is the full experience.** Console: `prefers-reduced-motion: reduce`. CLI: described below. With motion off, every state still shows, only without the movement.
5. **State is never carried by motion alone.** A fade that says "more below" is backed by something that works without it (a scrollbar, a count, a text result).

### Console
**1. A cue that the sidebar scrolls (the idea that started this).** The menu already scrolls inside the sidebar when it is taller than the window (`.nav { overflow-y: auto }`, ADR-0017 amendment). Nothing tells you, and the thin scrollbar is hidden on macOS until you scroll. The right cue is not a loading indicator: the menu is static, nothing is being fetched, and a loader would say "wait" about something that is already complete. The cue is an **edge fade**: a soft shadow at the top once you have scrolled down, and at the bottom while there is more below, which disappears when you reach the end. That is exactly "have I reached the end of it or not".
- Built in CSS only, no JavaScript. Where scroll-driven animations exist (`animation-timeline: scroll()`), the fades are driven by the scroll position. Elsewhere the classic `background-attachment: local` shadow pair on `.nav` gives the same result. The fades sit on the container's own background, so links keep their hover and current-page backgrounds.
- Applies where the sidebar scrolls (width over 900 px). The phone strip scrolls sideways and is a different cue (a fade at the right edge, same technique).
- Collapsed mode keeps the same fades.
- *Partly verified.* The `background-attachment: local` fallback was tried on a standalone page with 24 links in one Chrome: the shadow shows at the top once scrolled and at the bottom until the end, and neither shows at the other extreme's rest position. `animation-timeline: scroll()` is supported in that Chrome (`CSS.supports` returned true) but the scroll-driven path itself was not exercised. Not tried in Safari or Firefox, and not in the real sidebar (its hover and current-page backgrounds and the collapsed mode). A browser dark-mode extension recoloured the page until it was given `darkreader-lock`, which the console pages already carry. The first implementation PR must show the real sidebar in more than one browser.

**2. Page changes that don't blink.** Every console page is a full navigation. Add `@view-transition { navigation: auto; }` and give the sidebar a `view-transition-name`, so a click cross-fades only the main column over about 150 ms while the sidebar stays where it is (it also stops the sidebar's scroll position flickering). Browsers without the feature ignore the rule and behave as today. It is same-origin, needs no script, and doesn't touch the CSP. The theme script in `<head>` still runs before first paint, so the no-flash guarantee holds. Under `prefers-reduced-motion` the transition is turned off.

**3. Charts draw in.** The dashboards are server-drawn SVG. Bars grow from the baseline and lines draw along their path once, over about 400 ms, with a small stagger, using CSS `transform`/`stroke-dashoffset`. Numbers and labels are in place from the first frame, so the page is readable and printable at once. Only on a full page load. Pages that auto-refresh (`data-refresh`, swapped in place by `console.js`) must not replay it every few seconds, so the draw-in is skipped for a swap.

**4. Small acknowledgements.** The copy button already gets a `.done` class for 1.2 s in `console.js`; the icon swap to a check becomes a short fade instead of a jump. Flash messages after a POST ease in rather than appear. Folding a nav group animates its height (`grid-template-rows: 0fr → 1fr`) instead of snapping, on click only, like the sidebar collapse. Buttons get a pressed state. A live watch or a recording player shows a "connecting" state until the first frame, so a blank box is never mistaken for a dead stream.

**5. One switch.** A single block in `console.css`:
```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .01ms !important; animation-iteration-count: 1 !important; transition-duration: .01ms !important; scroll-behavior: auto !important; }
  ::view-transition-group(*), ::view-transition-old(*), ::view-transition-new(*) { animation: none !important; }
}
```
replaces the per-rule opt-outs added one at a time (today there are three, in different places), so new motion is safe by default. A Rust test reads `console.css` and fails if it contains `@keyframes` or `transition` while that block is missing.

**Not in the console.** Skeleton loaders (pages are rendered whole by the server, so nothing loads in pieces), spinners on links, count-up numbers (they make a figure unreadable for the first second, and these are audit numbers), parallax or scroll-jacking, and anything that animates a table of sessions or audit rows as they sort or filter. Live rows that change state may get a brief highlight later, if the live pages grow polling; that is out of scope here.

### CLI
All of it goes through `crates/limen-cli/src/ui.rs`, on **stderr**, hand-written like the spinner. No new dependency in the first version.

**1. One gate for motion.** `ui::motion_enabled()` is true only when stderr is a terminal, `TERM` is not `dumb`, `CI` is unset, and `LIMEN_NO_ANIMATION` is unset. When false, every animated element prints the plain line it prints today (`› message`, then the result). `NO_COLOR` does not turn motion off, because it is about colour and the spinner already respects that; `--color never` likewise. Stdout is never touched, so `--json`, tables and anything piped are byte-for-byte unchanged.

**2. A spinner that ends in a result.** Today `finish()` erases the line, so a slow step leaves no trace. Add `Spinner::succeed(msg)` and `Spinner::fail(msg)`, which replace the spinner with `✔ msg` or `✘ msg` plus the elapsed time when it was over a second (`✔ Signed in as ana  1.4s`). The line stays in the scrollback. `finish()` keeps its current meaning, so existing callers don't change until they choose to. `Drop` still clears the line, so an early return or `?` never leaves a half-drawn spinner.

**3. Waiting that shows it is waiting.** `limen request --wait` (for an approver) and the browser wait in `limen login` can run for minutes. Show elapsed time, dimmed, after the first 5 seconds (`⠋ Waiting for an approver · 2m14s`). That one number answers "has it hung?". It is a timer, not a progress bar, because the wait has no known length and a fake bar would be a lie.

**4. Steps for the multi-part commands.** `limen doctor` runs its checks and then prints the whole report at once, after a silent wait; `limen selftest` shows one spinner for the whole run. On a terminal, show each check as its own line while it runs (a spinner, then `✔`, `!`, `✖` or `–` in place), so the report builds up top to bottom and ends as the same report it prints today. The final text, `--json`, and the output when motion is off are unchanged. This is the one CLI item that changes how `doctor` produces its output (it must print as checks finish instead of once at the end), so it is built last and tested against the existing `render` tests.

**5. Fit the terminal.** `\r` returns to the start of the current line only, so a spinner message longer than the terminal wraps and leaves the first rows behind on every frame. Truncate the message to the terminal width (with `…`). Reading the width without `unsafe` needs either the `COLUMNS` variable or a small crate (`terminal_size`, which would need an ADR-0012 row). See Open questions.

**Not in the CLI.** An animated banner (it would delay every interactive command to show a logo; the banner stays a static three lines, opt-out `LIMEN_NO_BANNER`). Progress bars for work with no known length. Hiding the cursor (restoring it after Ctrl-C or a panic without `unsafe` or a signal handler is exactly the bug users remember). Colour cycling or rainbow effects. Any motion on stdout, and any motion in `limen ssh`, `connect`, `exec` or other commands that hand the terminal to another program.

## Rollout
Three small PRs, each needing the owner's go-ahead, in this order because each stands alone:
1. **Console foundation:** the reduced-motion block and its test, the sidebar scroll cue, the copy and flash transitions.
2. **Console navigation and charts:** view transitions, nav group fold, chart draw-in.
3. **CLI:** `motion_enabled`, `succeed`/`fail`, elapsed time, step lines, width truncation; `login`, `request --wait`, `doctor`, `selftest` adopt them.

## How each will be verified
- *Console:* load the pages from the compose stack in Chrome, Safari and Firefox, with and without `prefers-reduced-motion`, and attach recordings or screenshots. Check the CSP report stays empty. Check the page is readable on the first frame and that no animation shifts layout. Browsers lacking a feature are checked, not assumed.
- *CLI:* unit tests on the rendered lines with colour stripped (as `ui.rs` does today); the gate tested for each of its four inputs; a run under a real pseudo-terminal (`script`) and with stderr piped to prove the piped output is identical to today's; width truncation tested at narrow widths.
- Anything seen in only one browser or terminal is labelled `unverified` in the PR.

## Consequences
- The console gains a few dozen lines of CSS and no script. The CLI gains perhaps 100 lines in `ui.rs`.
- Pages from before the change and after it look the same with motion off; the screenshot tests in `crates/limen-control-plane/tests/console-pages/` need no change for the foundation PR.
- Every future addition is held to the five rules above, and the CSS test makes the reduced-motion default hard to forget.
- Risk: view transitions are the one item that changes how every page change feels. If it misbehaves (a flash during the theme switch, a stuck frame on the login redirect), it is one line to remove.

## Open questions for the owner
1. **Scope.** All three PRs, or only the console foundation to try the feel first? (Recommended: foundation first.)
2. **Terminal width.** A `terminal_size` dependency (an ADR-0012 row, one small crate), or `COLUMNS` with an 80-column fallback and no dependency? (Recommended: the dependency, because `COLUMNS` is usually not exported.)
3. **View transitions.** Include them, knowing Firefox ignores them today? (Recommended: yes; a no-op where unsupported.)
4. **Names.** `LIMEN_NO_ANIMATION` for the CLI switch, or reuse `LIMEN_NO_BANNER` for both?
