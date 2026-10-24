The `limen` command is for signing in and connecting. For browsing and admin actions in a browser, see [the console guide](console.md).

# Using the CLI

```sh
limen login                  # sign in (opens a browser). On a machine without one: limen login --device
limen status                 # who am I, which roles, when does it expire?
limen ls                     # what can I reach?   add --json for scripts
limen ls --type postgres --label env=staging   # filter by type and label (repeat --label to require several)
limen db ls --label env=staging            # per-protocol view: db, redis, kube, mongo, search, mq, kafka, web
limen ssh web-staging-1      # connect; the login is picked from policy when there's only one
limen ssh ubuntu@web-staging-1 -- uptime   # explicit login, run a command
limen redis connect cache-staging          # a local listener for redis-cli, no password
limen mongo connect catalog-staging        # a local listener for mongosh, no password
limen search connect search-staging        # a local listener for curl and Elasticsearch/OpenSearch clients, no credential
limen show orders-staging    # type, labels, who you may act as, and the command to connect
limen connect orders-staging # open any resource by name; picks db/redis/ssh/... from its type
limen redis connect cache-staging --detach   # run in the background; limen conns ls / stop
limen status --json          # identity and expiry for scripts (local only, no admin needed)
limen completions zsh        # shell completions (bash, zsh, fish, elvish, powershell)
limen logout                 # end this login and delete local credentials
```

What `limen ls` looks like:

```text
NAME             KIND        ACCESS AS                 LABELS
bastion-staging  ● ssh       ec2-user, ubuntu          env=staging tier=bastion
orders-staging   ● postgres  limen_read, limen_write  env=staging team=payments
web-staging-1    ● ssh       ec2-user, ubuntu          env=staging
  3 resources · connect with `limen ssh <name>`
```

<details>
<summary><b>All commands</b></summary>

| Command | What it does |
|---|---|
| `limen login [--device] [--no-browser] [--ca-file PEM]` | Sign in through the identity provider and get short-lived credentials. `--ca-file` pins the proxy's CA for later commands |
| `limen login --bot <github_actions\|gitlab\|oidc> [--bot-name N] [--token-env VAR] [--token-file FILE] [--audience A]` | Log in as a **bot** with a CI platform's identity token (for CI jobs; see [the bots guide](bots.md)) |
| `limen logout` | End this login at the proxy (it and its open sessions stop within about 10 seconds, wherever a copy of the certificate is) and delete the local credentials. Your other logins are not affected. If the proxy can't be reached the credentials are still deleted, and the certificate stays valid until it expires |
| `limen status [--json]` | Show your identity, roles, and the time left on your credentials. `--json` is for scripts; it reads local credentials only, so it needs no admin role |
| `limen ls [--json] [--type KIND] [--label KEY=VALUE]…` | List the resources you can access, optionally only one type and only those carrying every given label |
| `limen <group> ls [--json] [--label KEY=VALUE]…` | The same list limited to one family: `db` (postgres, mysql, redshift), `redis`, `kube`, `mongo`, `search` (opensearch, elasticsearch), `mq` (rabbitmq), `kafka`, `web`. For SSH use `limen ls --type ssh`; for TCP, `--type tcp` |
| `limen ls [QUERY] [-q] [--watch[=SECS]]` | `QUERY` matches names and labels (case-insensitive); `-q` prints names only; `--watch` redraws every SECS seconds (default 2) |
| `limen show <resource> [--json]` | One resource: type, labels, principals, default database or address, and the command that connects |
| `limen connect <resource> [options…]` | Opens a resource by name using the right command for its type; options after the name go to that command |
| `limen <connect command> … --detach` (`-d`) | Run the listener in the background and return once it prints its address. It ends when your login expires, on `limen logout`, on `limen conns stop`, or after the idle timeout ([ADR-0039](../adr/0039-detached-connections.md)). macOS and Linux |
| `limen conns ls [--json]`, `limen conns stop <id>…\|--all` | List and end detached connections |
| `limen completions <shell>` | Print a shell completion script |
| `limen ssh [login@]resource [command…]` | Open an SSH session through Limen (recorded and audited) |
| `limen redis connect <resource> [--user U] [--listen ADDR \| --socket PATH] [--idle-timeout 1h]` | Open a loopback listener for `redis-cli` or any Redis or Valkey client; each connection is an audited session (see [the Redis guide](redis.md)) |
| `limen mongo connect <resource> [--role R] [--database D] [--listen ADDR \| --socket PATH] [--idle-timeout 1h]` | Open a loopback listener for `mongosh` or any MongoDB driver; each connection is an audited session (see [the MongoDB guide](mongodb.md)) |
| `limen search connect <resource> [--role R] [--listen ADDR \| --socket PATH] [--idle-timeout 1h]` | Open a loopback listener for `curl` or any Elasticsearch or OpenSearch client; each connection is an audited session (see [the search guide](search.md)) |
| `limen config ssh` | Print an `~/.ssh/config` block so plain `ssh <login>@web-staging-1.limen` works |
| `limen admin apply <files or dirs> [--dry-run] [--source-ref SHA]` | Validate and apply policy YAML; shows a coloured diff |
| `limen admin policy` | Show the active policy version, digest, and author |
| `limen admin components` | List enrolled proxies and workers and their tunnels |
| `limen admin token create [--kind worker\|proxy] [--label k=v] [--ttl 15m]` | Create a single-use join token |
| `limen admin lock <user> --reason …` / `unlock <user>` / `locks` | Lock or unlock a user; list locks |
| `limen admin kill-session <id> --reason …` | End one live session |
| `limen admin revoke <component> --reason …` | Stop honouring a proxy's or worker's certificate |
| `limen kube login <cluster> [--kubeconfig FILE \| --print]` | Write a kubeconfig for a cluster you may reach. `kubectl` then runs `limen kube credentials`, the exec plugin that prints your short-lived certificate. See [the Kubernetes guide](kubernetes.md) |
| `limen db connect <resource> [--db-role R] [--database D] [--listen ADDR \| --socket PATH]` | Open a local address for `psql`, `mysql`, or a driver, with no password: PostgreSQL, MySQL, Aurora, Redshift. Every connection is a session and every statement is audited. See [the databases guide](databases.md) |
| `limen mq connect <resource> [--user U] [--vhost V] [--listen ADDR] [--idle-timeout 1h]` | Open a loopback listener for an AMQP 0-9-1 client; prints an `amqp://` URL with no real password (see [the messaging guide](messaging.md)) |
| `limen kafka connect <resource> [--user U] [--listen ADDR] [--brokers 8] [--idle-timeout 1h]` | Open a bootstrap listener and one per broker slot for a Kafka client; prints the bootstrap address |
| `limen web open [--no-browser] <resource>` | Open an internal web app behind Limen SSO in the browser, or print its URL (see [the web apps guide](web-apps.md)) |
| `limen tcp <resource> [--listen ADDR]` | Open a loopback listener that forwards to one fixed TCP target; each connection is an audited session (see [the TCP guide](tcp.md)) |

Global options: `--proxy HOST:PORT` (or `LIMEN_PROXY`; remembered after the first login), `--color auto|always|never`, `--help`, `--version`.
</details>

### Local listeners

`limen db`, `redis`, `mongo`, `search`, `mq`, `kafka` (each with `connect`) and `limen tcp` open a listener on your machine for your usual client, which needs no password:
- It binds loopback only (`--listen 127.0.0.1:PORT` fixes the port), or a private unix socket with `--socket PATH` where offered (mode 0600, in a directory only you can enter). Anyone who can reach it acts as you, so don't forward the port.
- Each connection is its own audited session, so a client that pools connections opens several. Leave the command running while you work; Ctrl-C stops it, and where `--idle-timeout` is offered it stops by itself after an hour with no connection (`--idle-timeout 30m`, `0` for never).
- A refusal reaches your client as that protocol's own error.

### Good to know
- **Credentials are short-lived on purpose.** They live in `~/.limen/` (override with `LIMEN_HOME`) and expire in minutes. When they do, the CLI tells you to run `limen login`.
- **Plain `ssh` works too.** Run `limen config ssh >> ~/.ssh/config`, then `ssh <login>@<resource>.limen`.
- **Scripting.** Output is plain text when piped; `limen ls --json` is stable for tools; `NO_COLOR=1` or `--color never` turns colour off everywhere.
- **Admin commands need the `limen:admin` role** and are audited like everything else.
