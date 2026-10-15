The `limen` command is for signing in and connecting. For browsing and admin actions in a browser, see [the console guide](console.md).

# Using the CLI

```sh
limen login                  # sign in (opens a browser). On a machine without one: limen login --device
limen status                 # who am I, which roles, when does it expire?
limen ls                     # what can I reach?   add --json for scripts
limen ssh web-staging-1      # connect; the login is picked from policy when there's only one
limen ssh ubuntu@web-staging-1 -- uptime   # explicit login, run a command
limen logout                 # delete local credentials
```

What `limen ls` looks like:

```text
NAME             KIND        ACCESS AS                 LABELS
bastion-staging  ● ssh       ec2-user, ubuntu          env=staging tier=bastion
orders-staging   ● postgres  limen_readonly, limen_rw  env=staging team=payments
web-staging-1    ● ssh       ec2-user, ubuntu          env=staging
  3 resources · connect with `limen ssh <name>`
```

<details>
<summary><b>All commands</b></summary>

| Command | What it does |
|---|---|
| `limen login [--device] [--no-browser] [--ca-file PEM]` | Sign in through the identity provider and get short-lived credentials. `--ca-file` pins the proxy's CA for later commands |
| `limen login --bot <github_actions\|gitlab\|oidc> [--bot-name N] [--token-env VAR] [--token-file FILE] [--audience A]` | Log in as a **bot** with a CI platform's identity token (for CI jobs; see [the bots guide](bots.md)) |
| `limen logout` | Delete the local credentials |
| `limen status` | Show your identity, roles, and the time left on your credentials |
| `limen ls [--json]` | List the resources you can access |
| `limen ssh [login@]resource [command…]` | Open an SSH session through Limen (recorded and audited) |
| `limen config ssh` | Print an `~/.ssh/config` block so plain `ssh <login>@web-staging-1.limen` works |
| `limen admin apply <files or dirs> [--dry-run] [--source-ref SHA]` | Validate and apply policy YAML; shows a coloured diff |
| `limen admin policy` | Show the active policy version, digest, and author |
| `limen admin components` | List enrolled proxies and workers and their tunnels |
| `limen admin token create [--kind worker\|proxy] [--label k=v] [--ttl 15m]` | Create a single-use join token |
| `limen admin lock <user> --reason …` / `unlock <user>` / `locks` | Lock or unlock a user; list locks |
| `limen admin kill-session <id> --reason …` | End one live session |
| `limen admin revoke <component> --reason …` | Stop honouring a proxy's or worker's certificate |
| `limen db connect`, `redis connect`, `kube login`, `mongo connect`, `search connect`, `mq connect`, `kafka connect`, `web open`, `tcp` | **Planned**, one per integration ([roadmap](https://github.com/jfcmartins/limen/milestones)). The commands and their options exist so scripts and docs can be written now; each one says which phase delivers it and does nothing else. The resources they will open are already listed by `limen ls` and in the console |

Global options: `--proxy HOST:PORT` (or `LIMEN_PROXY`; remembered after the first login), `--color auto|always|never`, `--help`, `--version`.
</details>

**Good to know**
- **Credentials are short-lived on purpose.** They live in `~/.limen/` (override with `LIMEN_HOME`) and expire in minutes. When they do, the CLI tells you to run `limen login`.
- **Plain `ssh` works too.** Run `limen config ssh >> ~/.ssh/config`, then `ssh <login>@<resource>.limen`.
- **Scripting.** Output is plain text when piped; `limen ls --json` is stable for tools; `NO_COLOR=1` or `--color never` turns colour off everywhere.
- **Admin commands need the `limen:admin` role** and are audited like everything else.
