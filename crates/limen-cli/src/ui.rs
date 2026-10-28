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

/// The doorway mark (an arch, a dot, a threshold) and the product name, then a
/// blank line so it stands apart from what follows.
fn banner_text() -> String {
    format!(
        "{}\n{}   {} {}\n{}  {}\n\n",
        accent("  ╭───╮"),
        accent("  │ ● │"),
        bold("limen"),
        dim(limen_core::VERSION),
        accent(" ━━━━━━━"),
        dim("identity-aware access"),
    )
}

fn banner_enabled(stderr_is_terminal: bool, opted_out: bool) -> bool {
    stderr_is_terminal && !opted_out
}

/// Print the logo to stderr, so it never mixes into output that is parsed or
/// piped. Skipped when stderr isn't a terminal or `LIMEN_NO_BANNER` is set.
pub fn banner() {
    let opted_out = std::env::var_os(BANNER_OPT_OUT).is_some();
    if banner_enabled(std::io::stderr().is_terminal(), opted_out) {
        anstream::eprint!("{}", banner_text());
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
    let hint =
        if text.contains("not logged in") || text.contains("EXPIRED") || text.contains("expired") {
            Some("Run `limen login` to sign in again.")
        } else if text.contains("untrusted") || text.contains("certificate") && text.contains("CA")
        {
            Some("Pin the proxy's CA with `limen login --ca-file <ca.pem>`.")
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
    anstream::println!("{}", table(header, rows));
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

/// A spinner on stderr while something slow happens. Silent when stderr isn't
/// a terminal, so scripts and logs stay clean.
pub struct Spinner {
    stop: std::sync::Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    interactive: bool,
}

#[must_use]
pub fn spinner(message: &str) -> Spinner {
    let interactive = std::io::stderr().is_terminal();
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let handle = interactive.then(|| {
        let stop = std::sync::Arc::clone(&stop);
        let message = message.to_owned();
        std::thread::spawn(move || {
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let mut i = 0;
            while !stop.load(Ordering::Relaxed) {
                anstream::eprint!("\r{} {message}", accent(frames[i % frames.len()]));
                let _ = std::io::stderr().flush();
                i += 1;
                std::thread::sleep(Duration::from_millis(80));
            }
        })
    });
    if !interactive {
        anstream::eprintln!("{} {message}", accent("›"));
    }
    Spinner {
        stop,
        handle,
        interactive,
    }
}

impl Spinner {
    /// Stop and erase the spinner line.
    pub fn finish(mut self) {
        self.halt();
    }

    fn halt(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        if self.interactive {
            anstream::eprint!("\r\x1b[2K");
            let _ = std::io::stderr().flush();
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
