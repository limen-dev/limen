# Locking a user and ending a session

Use this when a laptop is lost, an account is compromised, or a session looks wrong.

```sh
limen admin lock alice@example.com --reason "laptop stolen"   # refuse logins and sessions, end open ones
limen admin locks                                              # who is locked, by whom, why
limen admin unlock alice@example.com

limen admin kill-session 01a13b06-6a37-7590-a594-66b3d60772d9 --reason "unexpected command"
```

Find a session ID in the audit trail (`session.start`, filter by user) or in the Grafana "Who accessed what" panel.

## What happens, and how fast
| | Effect |
|---|---|
| Login | Refused immediately (`auth.denied`, reason `user locked`). |
| New SSH session | Refused at the proxy within about 10 s (the policy snapshot refresh), and by the control plane **immediately** when it issues the per-session certificates, so SSH sessions are blocked at once. |
| Open session | The proxy ends it within about 11 s (10 s snapshot refresh, 1 s check). `session.end` records reason `user locked` or `session killed`, and the recording is kept. |

The user's login certificate stays valid until it expires but Limen no longer honours it. Locks outlive restarts: they are rows in the control plane database, and every snapshot carries them.

If the control plane is down you can't lock or unlock. Proxies and workers keep enforcing the last snapshot they have, including existing locks.

## Audit
`user.lock`, `user.unlock`, and `session.kill` events record who did it, whom it applied to, and why. If audit is unavailable the command reports it: the lock is applied but wasn't recorded, so retry the audit path (see [spool full](audit-spool-full.md)).

## Limits
- Only SSH sessions exist today. Database, Redis, and Kubernetes sessions (Phase 4 onward) will use the same mechanism.
- Locking doesn't revoke credentials the user already holds on a target, such as a long-running process they started. Per-session certificates last about a minute.
- Locking is by username. If the identity provider renames a user, lock the new name too.
