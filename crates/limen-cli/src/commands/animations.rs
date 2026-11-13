//! `limen config animations`: show or change how the CLI looks and moves.

use crate::settings::{self, Settings, Speed, Switch};
use crate::ui;

#[derive(Debug, Default)]
pub struct Args {
    pub on: bool,
    pub off: bool,
    pub speed: Option<Speed>,
    pub logo: Option<Switch>,
    pub call_spinner: Option<Switch>,
    pub reset: bool,
}

impl Args {
    fn changes(&self) -> bool {
        self.on
            || self.off
            || self.speed.is_some()
            || self.logo.is_some()
            || self.call_spinner.is_some()
            || self.reset
    }
}

/// Apply `args` to `settings`.
fn apply(settings: &mut Settings, args: &Args) {
    if args.reset {
        *settings = Settings::default();
    }
    if args.on {
        settings.animations = true;
    }
    if args.off {
        settings.animations = false;
    }
    if let Some(speed) = args.speed {
        settings.speed = speed;
    }
    if let Some(logo) = args.logo {
        settings.logo = logo.is_on();
    }
    if let Some(spinner) = args.call_spinner {
        settings.call_spinner = spinner.is_on();
    }
}

fn word(on: bool) -> &'static str {
    if on { "on" } else { "off" }
}

fn render(settings: &Settings, file: &str) -> String {
    ui::key_values(&[
        ("Animations", word(settings.animations).to_owned()),
        ("Speed", settings.speed.name().to_owned()),
        ("Logo", word(settings.logo).to_owned()),
        ("Call spinner", word(settings.call_spinner).to_owned()),
        ("File", file.to_owned()),
    ])
}

pub fn run(args: &Args) -> anyhow::Result<()> {
    let path = settings::path()?;
    let mut current = settings::load_from(&path)?;
    if args.changes() {
        apply(&mut current, args);
        settings::save_to(&path, &current)?;
    }
    anstream::println!("{}", render(&current, &path.display().to_string()));
    if args.changes() {
        // What was just set, so it can be judged: the logo plays at the chosen speed.
        if current.animations && ui::motion_off_reason().is_none() {
            ui::preview_logo(current.speed);
        }
    }
    match ui::motion_off_reason() {
        Some(why) => ui::hint(&format!("Plain output in this shell: {why}.")),
        None => ui::hint(
            "Change it with `limen config animations --off`, `--speed slow|normal|fast`, \
             `--logo on|off`, `--call-spinner on|off`, or `--reset`.",
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_change_only_what_they_name() {
        let mut s = Settings::default();
        apply(
            &mut s,
            &Args {
                off: true,
                speed: Some(Speed::Slow),
                ..Args::default()
            },
        );
        assert!(!s.animations);
        assert_eq!(s.speed, Speed::Slow);
        assert!(s.logo && s.call_spinner);
        apply(
            &mut s,
            &Args {
                logo: Some(Switch::Off),
                call_spinner: Some(Switch::Off),
                ..Args::default()
            },
        );
        assert!(!s.logo && !s.call_spinner);
        apply(
            &mut s,
            &Args {
                reset: true,
                ..Args::default()
            },
        );
        assert_eq!(s, Settings::default());
    }

    #[test]
    fn the_summary_lists_every_setting() {
        let text = ui::plain(&render(&Settings::default(), "/h/settings.json"));
        for needle in [
            "Animations",
            "Speed",
            "Logo",
            "Call spinner",
            "normal",
            "/h/settings.json",
        ] {
            assert!(text.contains(needle), "missing {needle}: {text}");
        }
        assert!(!Args::default().changes());
    }
}
