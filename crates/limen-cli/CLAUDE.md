# CLI

- All terminal output goes through `src/ui.rs`, not bare `println!`. Cover layout with a test that strips colour (`CONTRIBUTING.md`, "The CLI's look").
- `docs/cli-reference.md` is generated. After adding or changing a command or option, run `scripts/gen-cli-reference.sh`; CI fails when it is stale.
- User-facing behavior changes also update `docs/guides/cli.md`.
