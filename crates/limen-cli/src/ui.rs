//! Terminal output: colour, glyphs, aligned tables, a spinner, tidy errors.
//!
//! Everything is built as a `String` first and printed through `anstream`,
//! which removes the colour when output isn't a terminal or `NO_COLOR` is set
//! (and downgrades truecolor to what the terminal supports). Tests strip the
//! escape codes and check the text.

use std::fmt::Write as FmtWrite;
use std::io::{IsTerminal, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anstyle::{AnsiColor, Color, Effects, RgbColor, Style};

pub const TEAL: Style = Style::new()
    .fg_color(Some(Color::Rgb(RgbColor(20, 184, 166))))
    .effects(Effects::BOLD);
const GREEN: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green)));
const RED: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Red)));
const YELLOW: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow)));
const DIM: Style = Style::new().effects(Effects::DIMMED);
const BOLD: Style = Style::new().effects(Effects::BOLD);

fn paint(style: Style, text: &str) -> String {
    format!("{style}{text}{style:#}")
}

pub fn bold(text: &str) -> String {
    paint(BOLD, text)
}

pub fn dim(text: &str) -> String {
    paint(DIM, text)
}

pub fn green(text: &str) -> String {
    paint(GREEN, text)
}

pub fn red(text: &str) -> String {
    paint(RED, text)
}

pub fn yellow(text: &str) -> String {
    paint(YELLOW, text)
}

pub fn accent(text: &str) -> String {
    paint(TEAL, text)
}

/// The text as a person sees it, without escape codes.
pub fn plain(text: &str) -> String {
    anstream::adapter::strip_str(text).to_string()
}

fn visible_width(text: &str) -> usize {
    plain(text).chars().count()
}

// ---- banner ---------------------------------------------------------------------

/// Set to anything to turn the banner off.
const BANNER_OPT_OUT: &str = "LIMEN_NO_BANNER";

/// One run of banner text and its style (`None` is plain).
type Piece = (String, Option<Style>);

/// The doorway mark (an arch, a dot, a threshold) and the product name, as
/// three lines of styled pieces. As in the logo, the arch takes the text colour
/// and the dot and threshold are teal. One source for the static banner and
/// the animated one.
fn banner_lines() -> [Vec<Piece>; 3] {
    let piece = |text: &str, style: Option<Style>| (text.to_owned(), style);
    [
        vec![piece("  ╭───╮", Some(BOLD))],
        vec![
            piece("  │ ", Some(BOLD)),
            piece("●", Some(TEAL)),
            piece(" │", Some(BOLD)),
            piece("   ", None),
            piece("limen", Some(BOLD)),
            piece(" ", None),
            piece(limen_core::VERSION, Some(DIM)),
        ],
        vec![
            piece(" ━━━━━━━", Some(TEAL)),
            piece("  ", None),
            piece("identity-aware access", Some(DIM)),
        ],
    ]
}

/// The banner followed by a blank line, so it stands apart from what follows.
fn banner_text() -> String {
    let mut out = String::new();
    for line in banner_lines() {
        for (text, style) in line {
            match style {
                Some(style) => out.push_str(&paint(style, &text)),
                None => out.push_str(&text),
            }
        }
        out.push('\n');
    }
    out.push('\n');
    out
}

/// The banner with only the first `reveal` columns drawn and a bright teal
/// edge at the leading column: a wipe from the left. Always four lines, so
/// each frame can be drawn over the last.
fn banner_frame(reveal: usize) -> String {
    let mut out = String::new();
    for line in banner_lines() {
        let mut col = 0;
        for (text, style) in line {
            for ch in text.chars() {
                if col < reveal {
                    match style {
                        Some(style) => out.push_str(&paint(style, &ch.to_string())),
                        None => out.push(ch),
                    }
                } else if col == reveal && ch != ' ' {
                    out.push_str(&paint(TEAL, &ch.to_string()));
                } else {
                    out.push(' ');
                }
                col += 1;
            }
        }
        out.push('\n');
    }
    out.push('\n');
    out
}

fn banner_enabled(stderr_is_terminal: bool, opted_out: bool) -> bool {
    stderr_is_terminal && !opted_out
}

/// Print the logo to stderr, so it never mixes into output that is parsed or
/// piped. Skipped when stderr isn't a terminal, `LIMEN_NO_BANNER` is set, or the
/// logo is off in the settings. Where motion is on, the logo is drawn as a wipe
/// at the chosen speed (about a second by default); otherwise it is printed at once.
pub fn banner() {
    let opted_out = std::env::var_os(BANNER_OPT_OUT).is_some() || !crate::settings::get().logo;
    if !banner_enabled(std::io::stderr().is_terminal(), opted_out) {
        return;
    }
    draw_logo(crate::settings::get().speed);
}

/// Play the logo once at `speed`, whatever the logo setting says: for trying a setting out.
pub fn preview_logo(speed: crate::settings::Speed) {
    if std::io::stderr().is_terminal() {
        draw_logo(speed);
    }
}

fn draw_logo(speed: crate::settings::Speed) {
    let width = banner_lines()
        .iter()
        .map(|l| l.iter().map(|(t, _)| t.chars().count()).sum::<usize>())
        .max()
        .unwrap_or(0);
    // The wipe moves the cursor up four lines, which only holds while no line wraps.
    if !motion() || columns() <= width {
        anstream::eprint!("{}", banner_text());
        return;
    }
    let mut reveal = 0;
    loop {
        anstream::eprint!("{}", banner_frame(reveal));
        let _ = std::io::stderr().flush();
        if reveal > width {
            break;
        }
        reveal += 1;
        std::thread::sleep(Duration::from_millis(speed.banner_step_ms()));
        // Back to the first line of the banner (raw: `anstream` drops cursor codes under NO_COLOR).
        let _ = std::io::stderr().write_all(b"\x1b[4F");
    }
}

// ---- messages -------------------------------------------------------------------

pub fn success(message: &str) {
    anstream::println!("{} {message}", green("✔"));
}

pub fn info(message: &str) {
    anstream::println!("{} {message}", accent("›"));
}

pub fn warn(message: &str) {
    anstream::eprintln!("{} {message}", yellow("!"));
}

/// A suggestion for what to do next.
pub fn hint(message: &str) {
    anstream::println!("{}", dim(&format!("  {message}")));
}

/// Untrusted text for one line of terminal output: control characters
/// (including escape sequences) become spaces and the length is bounded.
#[must_use]
pub fn plain_line(s: &str, max_chars: usize) -> String {
    let mut out: String = s
        .chars()
        .take(max_chars)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if s.chars().nth(max_chars).is_some() {
        out.push('…');
    }
    out
}

/// The error and its causes, with the usual fixes as hints.
pub fn error(err: &anyhow::Error) {
    anstream::eprintln!("{}", render_error(err));
}

#[must_use]
pub fn render_error(err: &anyhow::Error) -> String {
    let mut out = format!("{} {}", paint(RED.effects(Effects::BOLD), "✖"), err);
    for cause in err.chain().skip(1) {
        let _ = write!(out, "\n  {} {cause}", dim("caused by:"));
    }
    let text = format!("{err:#}");
    let hint = if text.contains("not logged in")
        || text.contains("EXPIRED")
        || text.contains("expired")
    {
        Some("Run `limen login` to sign in again.")
    } else if text.contains("untrusted") || text.contains("certificate") && text.contains("CA") {
        Some(
            "Pin the server's CA with `limen login --ca-file <ca.pem>`, or if it now has a public certificate and you pinned an old CA, run `limen login --system-roots`.",
        )
    } else if text.contains("control plane unreachable") || text.contains("unavailable") {
        Some("The service may be restarting. Try again in a few seconds.")
    } else {
        None
    };
    if let Some(h) = hint {
        let _ = write!(out, "\n  {}", dim(&format!("→ {h}")));
    }
    out
}

// ---- layout -----------------------------------------------------------------------

/// `label  value` lines with the labels aligned.
#[must_use]
pub fn key_values(rows: &[(&str, String)]) -> String {
    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    rows.iter()
        .map(|(k, v)| format!("  {}  {v}", dim(&format!("{k:<width$}"))))
        .collect::<Vec<_>>()
        .join("\n")
}

/// An aligned table with a dim, upper-case header. Cells may contain colour.
#[must_use]
pub fn table<const N: usize>(header: [&str; N], rows: &[[String; N]]) -> String {
    let mut widths = header.map(str::len);
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(visible_width(cell));
        }
    }
    let pad = |cell: &str, w: usize| {
        let missing = w.saturating_sub(visible_width(cell));
        format!("{cell}{}", " ".repeat(missing))
    };
    let mut out = String::new();
    // The last column isn't padded: trailing spaces are noise.
    let last = N.saturating_sub(1);
    let head: Vec<String> = header
        .iter()
        .zip(widths)
        .enumerate()
        .map(|(i, (h, w))| {
            let h = h.to_uppercase();
            dim(&if i == last { h } else { pad(&h, w) })
        })
        .collect();
    out.push_str(head.join("  ").trim_end());
    for row in rows {
        out.push('\n');
        let cells: Vec<String> = row
            .iter()
            .zip(widths)
            .enumerate()
            .map(|(i, (c, w))| if i == last { c.clone() } else { pad(c, w) })
            .collect();
        out.push_str(cells.join("  ").trim_end());
    }
    out
}

pub fn print_table<const N: usize>(header: [&str; N], rows: &[[String; N]]) {
    reveal(&table(header, rows));
}

/// The most time a reveal may take, however long the list.
const REVEAL_BUDGET: Duration = Duration::from_millis(400);

/// Print `text` and a newline. On a terminal with motion on, the lines appear one after another
/// (the whole thing never takes longer than [`REVEAL_BUDGET`]); anywhere else, all at once, so
/// pipes, logs and scripts see exactly the same bytes either way.
pub fn reveal(text: &str) {
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < 2 || !motion() || !std::io::stdout().is_terminal() {
        anstream::println!("{text}");
        return;
    }
    let each = Duration::from_millis(crate::settings::get().speed.reveal_ms());
    let step = each.min(REVEAL_BUDGET / u32::try_from(lines.len()).unwrap_or(u32::MAX));
    for line in lines {
        anstream::println!("{line}");
        let _ = std::io::stdout().flush();
        std::thread::sleep(step);
    }
}

/// A beat between two steps that are shown one by one (the `doctor` checks), when motion is on
/// and the output is a terminal. Nothing otherwise.
pub fn pace() {
    if motion() && std::io::stdout().is_terminal() {
        std::thread::sleep(Duration::from_millis(
            crate::settings::get().speed.pace_ms(),
        ));
    }
}

// ---- resource kinds and roles ---------------------------------------------------------

/// A coloured glyph and the kind name, e.g. `● postgres`.
#[must_use]
pub fn kind_label(kind: &str) -> String {
    let rgb = match kind {
        "ssh" => (16, 185, 129),
        "postgres" | "postgresql" => (65, 105, 225),
        "mysql" => (68, 121, 161),
        "redshift" => (140, 79, 255),
        "redis" => (255, 68, 56),
        "kubernetes" => (50, 108, 229),
        "mongodb" => (71, 162, 72),
        "opensearch" => (0, 94, 184),
        "elasticsearch" => (0, 167, 157),
        "rabbitmq" => (255, 102, 0),
        "kafka" => (156, 163, 175),
        "web" => (139, 92, 246),
        _ => (100, 116, 139),
    };
    let style = Style::new().fg_color(Some(Color::Rgb(RgbColor(rgb.0, rgb.1, rgb.2))));
    format!("{} {kind}", paint(style, "●"))
}

/// A role name in a colour that is stable for that name.
#[must_use]
pub fn role(name: &str) -> String {
    const COLORS: [(u8, u8, u8); 6] = [
        (20, 184, 166),
        (59, 130, 246),
        (139, 92, 246),
        (245, 158, 11),
        (236, 72, 153),
        (16, 185, 129),
    ];
    let idx = name
        .bytes()
        .fold(0u8, |h, b| h.wrapping_mul(31).wrapping_add(b))
        % 6;
    let (r, g, b) = COLORS[usize::from(idx)];
    paint(
        Style::new().fg_color(Some(Color::Rgb(RgbColor(r, g, b)))),
        name,
    )
}

/// "in 7m 12s" / "expired", coloured by how much time is left.
#[must_use]
pub fn expiry(remaining: time::Duration) -> String {
    if !remaining.is_positive() {
        return red("expired");
    }
    let text = if remaining.whole_hours() > 0 {
        format!(
            "in {}h {}m",
            remaining.whole_hours(),
            remaining.whole_minutes() % 60
        )
    } else {
        format!(
            "in {}m {}s",
            remaining.whole_minutes(),
            remaining.whole_seconds() % 60
        )
    };
    if remaining.whole_minutes() < 2 {
        yellow(&text)
    } else {
        green(&text)
    }
}

// ---- spinner ---------------------------------------------------------------------------

/// How long a step runs before its spinner is drawn: a quick one shows nothing.
const SPINNER_DELAY: Duration = Duration::from_millis(300);
/// How long before the elapsed time is appended, so a long wait shows it has not hung.
const TIMER_AFTER: Duration = Duration::from_secs(5);

/// Why nothing may move on stderr, or `None` when it may: it takes a terminal that can show it,
/// outside CI, and neither the environment (`LIMEN_NO_ANIMATION`) nor the saved settings
/// (`limen config animations --off`) opting out. Only stderr is looked at (as for the banner), so a
/// redirected stdout changes nothing. `NO_COLOR` strips colour but is not about motion.
pub fn motion_off_reason_for(
    stderr_is_tty: bool,
    term: Option<&str>,
    ci: bool,
    env_opted_out: bool,
) -> Option<&'static str> {
    if env_opted_out {
        Some("LIMEN_NO_ANIMATION is set")
    } else if ci {
        Some("CI is set")
    } else if term == Some("dumb") {
        Some("TERM is dumb")
    } else if !stderr_is_tty {
        Some("stderr is not a terminal")
    } else {
        None
    }
}

/// [`motion_off_reason_for`] for this process: the real terminal, environment and settings.
pub fn motion_off_reason() -> Option<&'static str> {
    // The saved setting wins over everything else, and says so.
    if !crate::settings::get().animations {
        return Some("animations are off in the settings");
    }
    let ci = std::env::var("CI").is_ok_and(|v| !matches!(v.as_str(), "" | "0" | "false"));
    motion_off_reason_for(
        std::io::stderr().is_terminal(),
        std::env::var("TERM").ok().as_deref(),
        ci,
        std::env::var_os("LIMEN_NO_ANIMATION").is_some(),
    )
}

pub fn motion() -> bool {
    motion_off_reason().is_none()
}

/// `4.2s`, or `2m14s` from a minute on.
fn elapsed_text(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{:.1}s", d.as_secs_f64())
    }
}

/// A spinner on stderr while something slow happens. It appears only after
/// 300 ms, adds the elapsed time after 5 s, and is a plain `›` line when
/// motion is off (see [`motion_off_reason_for`]), so scripts and logs stay clean.
/// Output from other code while one is live would land in the middle of it:
/// finish it first (every current caller does).
#[derive(Debug)]
pub struct Spinner {
    /// An explicit spinner (not the per-call one), which the per-call one steps aside for.
    counted: bool,
    stop: std::sync::Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    interactive: bool,
    started: std::time::Instant,
    /// Set by the thread once it has drawn a frame; only then is there a line to erase.
    drawn: std::sync::Arc<AtomicBool>,
}

#[must_use]
pub fn spinner(message: &str) -> Spinner {
    // Count first, so a call starting now stays out of the way; then replace a running per-call one.
    EXPLICIT.fetch_add(1, Ordering::Relaxed);
    drop(take_busy());
    start(message, true, true)
}

/// Teal, brightening and fading: the frames take the colour of the logo's dot.
const TEAL_RAMP: [(u8, u8, u8); 8] = [
    (13, 148, 136),
    (20, 184, 166),
    (45, 212, 191),
    (94, 234, 212),
    (153, 246, 228),
    (94, 234, 212),
    (45, 212, 191),
    (20, 184, 166),
];

fn ramp(step: usize) -> Style {
    let (r, g, b) = TEAL_RAMP[step % TEAL_RAMP.len()];
    Style::new()
        .fg_color(Some(Color::Rgb(RgbColor(r, g, b))))
        .effects(Effects::BOLD)
}

/// `announce`: print a plain `›` line when motion is off (the per-call spinner stays silent).
fn start(message: &str, announce: bool, counted: bool) -> Spinner {
    let interactive = motion();
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let started = std::time::Instant::now();
    let drawn = std::sync::Arc::new(AtomicBool::new(false));
    let handle = interactive.then(|| {
        let stop = std::sync::Arc::clone(&stop);
        let drawn = std::sync::Arc::clone(&drawn);
        let message = message.to_owned();
        let frame_tens = crate::settings::get().speed.frame_tens();
        std::thread::spawn(move || {
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            // Draw nothing until the step has taken a moment.
            while started.elapsed() < SPINNER_DELAY {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let mut i = 0;
            while !stop.load(Ordering::Relaxed) {
                let elapsed = started.elapsed();
                let timer = if elapsed >= TIMER_AFTER {
                    format!(" · {}", elapsed_text(elapsed))
                } else {
                    String::new()
                };
                // Read each frame, so a resize is picked up. The frame, a space, and one
                // spare column keep the line from wrapping, which `\r` can't undo.
                let room = columns().saturating_sub(3 + timer.chars().count());
                let text = fit(&message, room);
                clear_line();
                drawn.store(true, Ordering::Relaxed);
                anstream::eprint!(
                    "{} {text}{}",
                    paint(ramp(i / 2), frames[i % frames.len()]),
                    if timer.is_empty() { timer } else { dim(&timer) }
                );
                let _ = std::io::stderr().flush();
                i += 1;
                // In short slices, so stopping the spinner never waits out a whole frame.
                for _ in 0..frame_tens {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        })
    });
    if !interactive && announce {
        anstream::eprintln!("{} {message}", accent("›"));
    }
    Spinner {
        counted,
        stop,
        handle,
        interactive,
        started,
        drawn,
    }
}

// ---- per-call spinner ------------------------------------------------------------------

/// Explicit spinners alive now; the per-call one stays out of their way.
static EXPLICIT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// Set by commands that want a spinner while a call to the proxy is slow.
static BUSY_ON: AtomicBool = AtomicBool::new(false);
static BUSY: std::sync::Mutex<Busy> = std::sync::Mutex::new(Busy {
    calls: 0,
    spinner: None,
});

struct Busy {
    calls: usize,
    spinner: Option<Spinner>,
}

fn busy_state() -> std::sync::MutexGuard<'static, Busy> {
    BUSY.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn take_busy() -> Option<Spinner> {
    busy_state().spinner.take()
}

/// Turn on the per-call spinner for this run. Only for commands that print after their calls
/// return; never for ones that serve a protocol on stdout or hand the terminal over.
pub fn enable_busy() {
    BUSY_ON.store(true, Ordering::Relaxed);
}

/// Held while one call to the proxy is in flight. The first call to take longer than 300 ms
/// shows a spinner named for it; it is gone when the last call returns. Silent when motion is
/// off, when not enabled, and while an explicit spinner is running.
pub struct BusyGuard;

#[must_use]
pub fn busy(label: &str) -> Option<BusyGuard> {
    if !BUSY_ON.load(Ordering::Relaxed)
        || EXPLICIT.load(Ordering::Relaxed) > 0
        || !crate::settings::get().call_spinner
        || !motion()
    {
        return None;
    }
    let mut state = busy_state();
    state.calls += 1;
    if state.spinner.is_none() {
        state.spinner = Some(start(label, false, false));
    }
    Some(BusyGuard)
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        let finished = {
            let mut state = busy_state();
            state.calls = state.calls.saturating_sub(1);
            if state.calls == 0 {
                state.spinner.take()
            } else {
                None
            }
        };
        drop(finished); // stops the thread outside the lock
    }
}

/// `/limen.v1.Access/ListAccessRequests` as `List access requests`.
pub fn method_label(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or_default();
    let mut words: Vec<String> = Vec::new();
    let mut prev_lower = false;
    for ch in name.chars() {
        if ch.is_uppercase() && (prev_lower || words.is_empty()) {
            words.push(String::new());
        }
        if let Some(word) = words.last_mut() {
            word.push(ch);
        }
        prev_lower = ch.is_lowercase();
    }
    if words.is_empty() {
        return "Working".to_owned();
    }
    words
        .iter()
        .enumerate()
        .map(|(i, w)| {
            // Keep a lone capital (the `I` in `WhoAmI`) and acronyms; lower-case the rest.
            if i == 0 || w.chars().count() == 1 || w.chars().all(char::is_uppercase) {
                w.clone()
            } else {
                w.to_lowercase()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Width assumed when neither `COLUMNS` nor the terminal gives a usable one.
const FALLBACK_COLUMNS: usize = 80;

/// Return to the start of the line and erase it. Written to stderr directly,
/// because `anstream` drops escape sequences when colour is off (`NO_COLOR`),
/// and the line must be erased all the same.
fn clear_line() {
    let mut err = std::io::stderr();
    let _ = err.write_all(b"\r\x1b[2K");
    let _ = err.flush();
}

/// The terminal width. `COLUMNS` wins and is read each call; shells rarely
/// export it, so otherwise the terminal is asked once (`stty size`), then 80.
fn columns() -> usize {
    static PROBED: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    columns_from(
        std::env::var("COLUMNS").ok().as_deref(),
        *PROBED.get_or_init(probe_columns),
    )
}

fn columns_from(variable: Option<&str>, probed: Option<usize>) -> usize {
    variable
        .and_then(|v| v.trim().parse::<usize>().ok())
        .or(probed)
        .filter(|&n| n >= 10)
        .unwrap_or(FALLBACK_COLUMNS)
}

/// Ask the terminal behind stderr for its width with `stty size` (POSIX), which
/// needs no dependency and no `unsafe`. `None` if that fails for any reason.
#[cfg(unix)]
fn probe_columns() -> Option<usize> {
    use std::os::fd::AsFd;
    let tty = std::io::stderr().as_fd().try_clone_to_owned().ok()?;
    let out = std::process::Command::new("stty")
        .arg("size")
        .stdin(std::process::Stdio::from(tty))
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    parse_stty_size(&String::from_utf8_lossy(&out.stdout))
}

#[cfg(not(unix))]
fn probe_columns() -> Option<usize> {
    None
}

/// `stty size` prints "ROWS COLUMNS".
fn parse_stty_size(output: &str) -> Option<usize> {
    output.split_whitespace().nth(1)?.parse().ok()
}

/// Shorten `text` to at most `width` characters, ending in `…` when it was cut.
/// Counts characters, not display columns, and must be given text without
/// escape codes (style after fitting).
fn fit(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    let keep = width.saturating_sub(1);
    let mut out: String = text.chars().take(keep).collect();
    if width > 0 {
        out.push('…');
    }
    out
}

/// Ctrl-C during a wait: erase the spinner, say what happened, and exit 130
/// (the shell's code for an interrupt). A signal skips `Drop`, so without this
/// the prompt lands on a half-drawn spinner line.
///
/// `tokio::signal::ctrl_c()` replaces the default SIGINT behaviour for the rest
/// of the process, so once a wait is over, call [`exit_on_ctrl_c`] or a later
/// Ctrl-C (during a token exchange, say) would be swallowed.
pub fn interrupted(spinner: Spinner, message: &str) -> ! {
    spinner.finish();
    anstream::eprintln!("{message}");
    std::process::exit(130)
}

/// After a wait that used `ctrl_c()`: make Ctrl-C end the process again (130).
/// For commands that run once and finish. A command that installs its own
/// graceful handler must not call it.
pub fn exit_on_ctrl_c() {
    tokio::spawn(async {
        if tokio::signal::ctrl_c().await.is_ok() {
            std::process::exit(130);
        }
    });
}

impl Spinner {
    /// Stop and erase the spinner line.
    pub fn finish(mut self) {
        self.halt();
    }

    /// Stop the spinner and print a result in its place: `✔ message` on stdout,
    /// as [`success`] does, with the time it took added when the step ran over
    /// a second on a terminal. Where the result goes never depends on motion.
    pub fn succeed(mut self, message: &str) {
        let elapsed = self.started.elapsed();
        let interactive = self.interactive;
        self.halt();
        if interactive && elapsed >= Duration::from_secs(1) {
            success(&format!(
                "{message}{}",
                dim(&format!("  {}", elapsed_text(elapsed)))
            ));
        } else {
            success(message);
        }
    }

    fn halt(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        if self.drawn.load(Ordering::Relaxed) {
            clear_line();
        }
        if std::mem::take(&mut self.counted) {
            EXPLICIT.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.halt();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_aligns_by_visible_width_not_escape_codes() {
        let rows = [
            [role("admin"), "a".into()],
            [role("developer-readonly"), "bb".into()],
        ];
        let out = plain(&table(["role", "n"], &rows));
        let lines: Vec<_> = out.lines().collect();
        let col = |a: &str, b: &str| format!("{a:<18}  {b}");
        assert_eq!(lines[0], col("ROLE", "N"));
        assert_eq!(lines[1], col("admin", "a"));
        assert_eq!(lines[2], col("developer-readonly", "bb"));
    }

    #[test]
    fn banner_is_three_short_lines_with_the_text_aligned() {
        let out = plain(&banner_text());
        let lines: Vec<_> = out.lines().collect();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[3], "");
        assert!(lines.iter().all(|l| l.chars().count() <= 40));
        let column = |line: &str, text: &str| {
            let at = line.find(text).expect("banner text is present");
            line[..at].chars().count()
        };
        assert_eq!(column(lines[1], "limen"), column(lines[2], "identity"));
    }

    #[test]
    fn banner_only_on_a_terminal_and_unless_opted_out() {
        assert!(banner_enabled(true, false));
        assert!(!banner_enabled(false, false));
        assert!(!banner_enabled(true, true));
    }

    #[test]
    fn method_names_read_as_sentences() {
        assert_eq!(
            method_label("/limen.v1.Access/ListAccessRequests"),
            "List access requests"
        );
        assert_eq!(method_label("/limen.v1.Auth/WhoAmI"), "Who am I");
        assert_eq!(method_label("/x.Y/Ping"), "Ping");
        assert_eq!(method_label(""), "Working");
    }

    #[test]
    fn the_logo_wipes_in_and_ends_as_the_banner() {
        // Last frame: every column drawn, the same text as the static banner (the colour codes
        // differ only in being per character).
        assert_eq!(plain(&banner_frame(1000)), plain(&banner_text()));
        assert!(
            banner_frame(1000).contains("\x1b[38;2;20;184;166m●"),
            "the dot is teal"
        );
        // First frame: nothing but the leading edge; always four lines.
        let first = plain(&banner_frame(0));
        assert_eq!(first.lines().count(), 4);
        assert!(first.lines().take(3).all(|l| l.trim().chars().count() <= 1));
        // Mid-way: part of the text is there, part is not.
        let mid = plain(&banner_frame(14));
        assert!(mid.contains("limen") && !mid.contains("identity-aware access"));
    }

    #[test]
    fn motion_needs_a_terminal_and_no_opt_out() {
        let why = |tty, term, ci, env| motion_off_reason_for(tty, term, ci, env);
        assert_eq!(why(true, Some("xterm-256color"), false, false), None);
        assert_eq!(why(true, None, false, false), None);
        assert!(why(false, Some("xterm"), false, false).is_some());
        assert!(why(true, Some("dumb"), false, false).is_some());
        assert!(why(true, Some("xterm"), true, false).is_some());
        assert_eq!(
            why(true, Some("xterm"), false, true),
            Some("LIMEN_NO_ANIMATION is set")
        );
    }

    #[test]
    fn elapsed_reads_in_seconds_then_minutes() {
        assert_eq!(elapsed_text(Duration::from_millis(1400)), "1.4s");
        assert_eq!(elapsed_text(Duration::from_secs(59)), "59.0s");
        assert_eq!(elapsed_text(Duration::from_secs(134)), "2m14s");
        assert_eq!(elapsed_text(Duration::from_secs(60)), "1m00s");
    }

    #[test]
    fn fit_cuts_long_text_and_marks_it() {
        assert_eq!(fit("short", 10), "short");
        assert_eq!(fit("exactly ten", 11), "exactly ten");
        assert_eq!(fit("a message that is too long", 10), "a message…");
        assert_eq!(fit("anything", 1), "…");
        assert_eq!(fit("anything", 0), "");
        // Characters, not bytes: a multi-byte one is never split.
        assert_eq!(fit("ééééé", 3), "éé…");
    }

    #[test]
    fn columns_reads_the_variable_with_a_fallback() {
        assert_eq!(columns_from(Some("120"), Some(60)), 120);
        assert_eq!(columns_from(Some(" 100 "), None), 100);
        // Not exported: the terminal's own answer, then the fallback.
        assert_eq!(columns_from(None, Some(132)), 132);
        assert_eq!(columns_from(Some("wide"), Some(132)), 132);
        assert_eq!(columns_from(None, None), FALLBACK_COLUMNS);
        assert_eq!(columns_from(Some("0"), None), FALLBACK_COLUMNS);
    }

    #[test]
    fn stty_output_is_rows_then_columns() {
        assert_eq!(parse_stty_size("24 132\n"), Some(132));
        assert_eq!(parse_stty_size(""), None);
        assert_eq!(parse_stty_size("stty: not a tty\n"), None);
    }

    #[test]
    fn key_values_align_labels() {
        let out = plain(&key_values(&[
            ("User", "admin".into()),
            ("Expires", "soon".into()),
        ]));
        assert_eq!(out, "  User     admin\n  Expires  soon");
    }

    #[test]
    fn errors_show_causes_and_a_hint() {
        let err =
            anyhow::anyhow!("not logged in to p; run `limen login`").context("listing resources");
        let out = plain(&render_error(&err));
        assert!(out.starts_with("✖ listing resources"));
        assert!(out.contains("caused by: not logged in"));
        assert!(out.contains("→ Run `limen login`"));
    }

    #[test]
    fn expiry_reads_naturally() {
        assert_eq!(plain(&expiry(time::Duration::seconds(-5))), "expired");
        assert_eq!(plain(&expiry(time::Duration::seconds(432))), "in 7m 12s");
        assert_eq!(plain(&expiry(time::Duration::minutes(130))), "in 2h 10m");
    }

    #[test]
    fn role_colours_are_stable() {
        assert_eq!(role("ops"), role("ops"));
        assert_eq!(plain(&role("ops")), "ops");
    }

    #[test]
    fn kind_labels_name_the_kind() {
        assert_eq!(plain(&kind_label("postgres")), "● postgres");
        assert_eq!(plain(&kind_label("something-new")), "● something-new");
    }
}
