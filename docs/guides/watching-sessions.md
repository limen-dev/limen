# Watching a live session

Recordings answer questions afterwards; session kill stops one. Sometimes you want to *see* an incident-time SSH session as it happens, read-only, and decide ([ADR-0030](../adr/0030-live-session-watch.md)).

In the console, a live SSH session's page has **Watch it**. You see the terminal as it is recorded, with a *live* indicator, and the same *End this session* button the session page has. You see output only, never what the person types.

## Rules

- **It is audited, always.** `session.watch.start` and `session.watch.stop`, with who watched whom. A watch that cannot be audited does not start. The session's own page lists who watched it, for the user as well as admins.
- **Roles can say people are told.** `notify_observed: true` on a role prints *"[limen] This session may be observed by an administrator."* in the user's terminal when the shell starts.
- **A separate power.** Admins can watch. Auditors can only if the operator sets `--auditors-may-watch`, because reading the record is not the same as looking over someone's shoulder. You cannot watch your own session.
- **The session always wins.** A slow watcher, a slow control plane, or none costs the user nothing: output is buffered in small bounded rings and dropped when nobody keeps up. Nothing is sent unless someone is watching.
- **Bounded:** five watchers per session, five sessions per watcher; the stream re-checks every few seconds that you are still signed in, not locked, and that the session is still running, and ends if not.
- **Only what the recording holds.** The stream is the same bytes the worker records; masking rules that apply to recordings apply to it.

## How it works (and what changed from the ADR)

The ADR expected the proxy to copy the stream. It cannot: an SSH session is encrypted between the user's client and the worker, so a proxy only carries ciphertext. The **worker**, which holds the plaintext it records, publishes. It asks the control plane every two seconds which of its sessions are being watched, and while one is, sends the output in small chunks. Chunks go through the shared database, so the control plane replica serving your browser need not be the one the worker talked to, and the browser reads them as a server-sent stream from the same origin (the console's CSP is unchanged). A late watcher starts with the last few kilobytes so the screen has context.

Only SSH sessions can be watched. Other protocols have no terminal to render.

Metrics: `limen_session_watchers`.
