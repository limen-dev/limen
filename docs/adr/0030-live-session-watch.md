# ADR-0030: Watching a live session

- Status: Proposed (owner requested 2026-10-14; priority: **nice to have**)
- Date: 2026-10-14

## Context
Recordings answer questions after the fact, and session kill stops one. Sometimes you want to *see* an incident-time session as it happens, read-only, and decide.

## Decision
- **Read-only watching, first.** An admin or auditor opens a live session in the console and sees the terminal as it is being recorded, with a clear "live" indicator. Taking over, typing into someone else's session, and two-person joins are out of scope.
- **Path.** The proxy that holds the session tees the recorded output stream to authorised observers over a server-sent stream (no WebSocket: the existing CSP `connect-src 'self'` covers it and every browser supports it). When the observer's request reaches a different proxy, it is forwarded to the proxy that owns the session, as peering already does for sessions (ADR-0004). *How the console, which lives in the control plane, finds the owning proxy is the one thing to prove in a short spike before the phase commits.*
- **The session always wins.** Observers read from a bounded buffer; a slow observer is dropped and never slows or blocks the user's session. Observers see output only, never input.
- **Transparency.** A role can set `notify_observed: true`, which tells the user they may be observed (a banner at session start). Watching is **always audited**: `session.watch.start` and `session.watch.stop` with the observer and the session; the console shows who is watching.
- **Permission:** a separate `session:watch` capability, held by admins and, optionally, `limen:auditor` (ADR-0026). Not implied by being able to play recordings.
- **Stop with one click:** the watch view has the same "end session" action as the session page.

## Threats this design has to survive
- **Silent surveillance:** every watch is audited; `notify_observed` is available; the user's own console shows watch events on their sessions.
- **Leaking more than the recording would:** the stream is the same bytes the recording stores, with the same masking rules if any; no extra capture.
- **Resource exhaustion:** a cap on observers per session, bounded buffers, and drop-on-lag.
- **Observer reaching the wrong session:** authorisation is re-checked per stream open and every few seconds, so a lock or a lost role ends the watch.

## Consequences
- The proxy gains a fan-out buffer per session (small and bounded).
- Database and other protocol sessions (later phases) can reuse it once they have a text-renderable stream; they are not in scope here.
