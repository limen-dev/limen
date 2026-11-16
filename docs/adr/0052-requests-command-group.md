# ADR-0052: One `limen requests` group for deciding access requests

- Status: Accepted (the owner asked for it on 2026-11-11)
- Date: 2026-11-11

## Context
Access requests had five top-level verbs (`request`, `requests`, `approve`, `deny`, `cancel`), plus hidden duplicates under `limen admin`. The first three screens of `limen --help` were mostly one object. `limen manage changes` used `reject` for what `requests` calls `deny`.

## Decision
- `limen request <resource>` stays: it is the action nearly everyone takes, and it is short.
- Everything else about requests lives under `limen requests`: `ls` (the default, so bare `limen requests` and `limen requests --approvals` still work), `approve`, `deny`, `cancel`. A group of its own, not subcommands of `request`, because `request` takes a resource name and a resource called `ls` or `approve` would be ambiguous.
- Top-level `approve`, `deny` and `cancel` are removed (amended before the first stable release). Typing one answers like any unknown command and names the new one (`did you mean limen requests approve`); so do the old `limen manage` and `limen completions`, and a few names people reach for by habit. Only `limen mcp` still runs from a script, because agents start it. `limen admin approve|deny` (hidden duplicates) are removed.
- `limen manage changes reject` is renamed `deny`, to match; `reject` stays as an alias. Server-side states and API names (`rejected`, `RejectChange`) do not change.
- Help text carries no ADR numbers; they stay in code comments and docs for developers.

This supersedes the command names in ADR-0025's "Console and CLI" paragraph. Behavior is unchanged.
