The web console is for looking around and for the occasional admin action. For daily work, see [the CLI guide](cli.md). Setting it up for your own deployment: [the console runbook](../runbooks/console.md).

# Using the console

Open **`https://<your proxy>/console/`** (locally `https://localhost:3443/console/`) and choose *Continue with single sign-on*. You sign in with the same identity provider as the CLI. What you see depends on your roles.

| Page | What you can do | Who |
|---|---|---|
| **Overview** | See your identity and roles, what you can reach (with a copy-paste `limen ssh` command), and recent sessions. Admins also get live counts: active sessions, users, locks, workers, policy version | everyone |
| **Resources** | Search and filter by kind. Open a resource to see its labels and, for admins, its target, **which roles grant access**, **which live workers can serve it** (a red *none* means sessions will fail), and its sessions | everyone sees their own; admins see all |
| **Sessions** | Browse live and past sessions. Open one to **replay the recording** (the control plane verifies its hash first) and, as an admin, **end it** with a reason | everyone sees their own; admins see all |
| **Users** | See who has signed in and their roles. **Lock** a user (they are signed out, can't log in, and their open sessions end within seconds) or **unlock** them, always with an audited reason | admins |
| **Workers** | See enrolled proxies and workers and their tunnels. **Create single-use join tokens** (shown once) and **revoke** a component | admins |
| **Policy** | Browse roles, mappings, and resources as the YAML behind them, and **check a change**: paste YAML, see the diff, nothing is applied | admins |

A few things worth knowing:
- **Policy stays in Git.** The console shows and checks policy but doesn't edit it. Apply with `limen admin apply`.
- **Everything you change is audited** as you, marked as coming from the console.
- **Switch theme** with the sun/moon buttons at the bottom of the sidebar (it follows your system by default).
- **Sessions last as long as your login certificate** (10 minutes by default). Sign in again when it ends.
- Setup for your own deployment (OIDC client, public URL): [`docs/runbooks/console.md`](../runbooks/console.md).
