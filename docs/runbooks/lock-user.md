# Locking a user and ending a session

Use this when a laptop is lost, an account is compromised, or a session looks wrong.

```sh
limen admin lock admin@example.com --reason "laptop stolen"   # refuse logins and sessions, end open ones
limen admin locks                                              # who is locked, by whom, why
limen admin unlock admin@example.com

limen admin kill-session 01a13b06-6a37-7590-a594-66b3d60772d9 --reason "unexpected command"
```

Find a session ID in the audit trail (`session.start`, filter by user) or in the Grafana "Who accessed what" panel.

## What happens, and how fast
| | Effect |
|---|---|
| Login | Refused immediately (`auth.denied`, reason `user locked`). |
| New SSH session | Refused at the proxy within about 10 s (the policy snapshot refresh), and by the control plane **immediately** when it issues the per-session certificates, so SSH sessions are blocked at once. |
| Control plane API | Refused **immediately** for every call the user makes (admin, management, access requests, reviews, audit search, `limen ls`), with `auth.denied`, `action: api`. A locked admin can't change policy or unlock themselves. |
| Open session | The proxy ends it within about 11 s (10 s snapshot refresh, 1 s check). `session.end` records reason `user locked` or `session killed`, and the recording is kept. |

The user's login certificate stays valid until it expires but Limen no longer honours it. Locks outlive restarts: they are rows in the control plane database, and every snapshot carries them.

Keep a second admin: a locked admin can't unlock themselves, so keep at least two people with `limen:admin` (or the `--bootstrap-admin-group`). If the only admin is locked, release the lock in the database (`UPDATE user_locks SET released_at = now(), released_by = 'db' WHERE username = '...' AND released_at IS NULL`); it is not audited, so record it.

If the control plane is down you can't lock or unlock. Proxies and workers keep enforcing the last snapshot they have, including existing locks.

## Audit
When the IdP deactivates a person, Limen ends their logins by itself within a few minutes ([offboarding](../guides/offboarding.md)); a lock is the immediate version. `user.lock`, `user.unlock`, `session.kill`, and `idp.offboard` events record who did it, whom it applied to, and why. If audit is unavailable the command reports it: the lock is applied but wasn't recorded, so retry the audit path (see [spool full](audit-spool-full.md)).

## Limits
- Sessions of every protocol end within about ten seconds of a lock: the proxy checks the lock every second against the policy snapshot it refreshes every 10 s, then tells the worker to close. A statement the database is already running may finish there.
- Locking doesn't revoke credentials the user already holds on a target, such as a long-running process they started. Per-session certificates last about a minute.
- Locking is by username. If the identity provider renames a user, lock the new name too.
- A locked (disabled) user can be **deleted** from their page in the console. That removes the user record only: sessions, recordings and audit events stay. An admin's lock outlives the deletion. The IdP check deletes the people it disabled after `--idp-purge-after` (90 days by default); it never deletes someone an admin disabled.
