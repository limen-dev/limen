# Using the CLI

`limen` signs you in and connects you to things. For browsing and admin in a browser, see the [console guide](console.md). Every command and option is in the [CLI reference](../cli-reference.md).

```sh
limen login                  # sign in (opens a browser); on a machine without one: --device
limen status                 # who am I, which roles, when does it expire?
limen ls                     # what can I reach?  --json for scripts
limen ls --type postgres --label env=staging   # filter by type and label (repeat --label to require several)
limen show orders-staging    # type, labels, who you may act as, and how to connect
limen connect orders-staging # open any resource by name; picks db/redis/ssh/... from its type
limen ssh ubuntu@web-staging-1 -- uptime   # explicit login, run a command
limen request orders-prod --for 30m --reason "INC-123" --wait   # ask for expiring access
limen explain orders-prod    # why you can or can't reach it
limen doctor [resource]      # checks proxy, CA, network, clock, login, in order
limen config ssh --install   # plain `ssh web-staging-1`, scp, rsync and git
limen kube config            # one kubeconfig with a context per reachable cluster
limen logout                 # end this login and delete local credentials
```

```text
NAME             KIND        ACCESS AS                 LABELS
bastion-staging  ● ssh       ec2-user, ubuntu          env=staging tier=bastion
orders-staging   ● postgres  limen_read, limen_write  env=staging team=payments
web-staging-1    ● ssh       ec2-user, ubuntu          env=staging
  3 resources · connect with `limen ssh <name>`
```

## Commands by task

| To… | Use | Guide |
|---|---|---|
| Sign in as a person or a CI job | `login [--device]`, `login --bot …` | [Bots](bots.md) |
| Open SSH, with recording | `ssh`, `config ssh` | [below](#plain-ssh-scp-rsync-git) |
| Connect a SQL database | `db connect` | [Databases](databases.md) |
| Connect Redis, MongoDB, search | `redis connect`, `mongo connect`, `search connect` | [Redis](redis.md), [MongoDB](mongodb.md), [Search](search.md) |
| Connect brokers | `mq connect`, `kafka connect` | [Messaging](messaging.md) |
| Use Kubernetes | `kube config`, `kube login` | [Kubernetes](kubernetes.md) |
| Open a web app or a raw TCP target | `web open`, `tcp` | [Web apps](web-apps.md), [TCP](tcp.md) |
| Ask for, approve or revoke access | `request`, `requests`, `approve`, `deny`, `cancel`, `admin grants` | [Access requests](access-requests.md) |
| Test and question policy | `policy test`, `who-can`, `what-can`, `diff`, `explain` | [Policy tooling](policy-tooling.md) |
| Search the audit trail | `audit search` | [Audit search](audit-search.md) |
| Review access, export evidence | `review …`, `admin evidence` | [Access reviews](access-reviews.md) |
| Review discovered resources | `admin discovery` | [Discovery](discovery.md) |
| Administer | `admin apply`, `policy`, `components`, `token create`, `lock`, `kill-session`, `revoke`, `manage` (schema, get, changes) | [Management API](management-api.md), [Runbooks](../runbooks/README.md) |
| Run connections in the background | `--detach`, `conns ls`, `conns stop` | [ADR-0039](../adr/0039-detached-connections.md) |

Admin commands need the `limen:admin` role and are audited like everything else.

`limen logout` ends the login at the proxy (it and its open sessions stop within about 10 seconds, wherever a copy of the certificate is) and deletes local credentials. If the proxy is unreachable the credentials are still deleted, and the certificate stays valid until it expires. Your other logins are unaffected.

Global options: `--proxy HOST:PORT` (or `LIMEN_PROXY`; remembered after the first login), `--color auto|always|never`, `--help`, `--version`.

## Local listeners

`limen db`, `redis`, `mongo`, `search`, `mq`, `kafka` (each with `connect`) and `limen tcp` open a passwordless listener on your machine for your usual client.

- It binds loopback only (`--listen 127.0.0.1:PORT` fixes the port), or a private unix socket with `--socket PATH` where offered (mode 0600, in a directory only you can enter). Anyone who can reach it acts as you, so don't forward the port.
- Each connection is its own audited session, so a client that pools connections opens several.
- Leave the command running while you work. Ctrl-C stops it; where `--idle-timeout` is offered it stops by itself after an hour without a connection (`--idle-timeout 30m`, `0` for never).
- `--detach` (`-d`, macOS and Linux) runs it in the background and returns once it prints its address. It ends when your login expires, on `limen logout`, on `limen conns stop`, or at the idle timeout.
- A refusal reaches your client as that protocol's own error.

## Good to know

- Credentials live in `~/.limen/` (override with `LIMEN_HOME`) and expire in minutes. When they do, the CLI tells you to run `limen login`.
- Output is plain text when piped. `limen ls --json` is stable for tools. `NO_COLOR=1` or `--color never` turns colour off. The banner goes to stderr, only on a terminal; `LIMEN_NO_BANNER=1` hides it.
- Database GUIs (DBeaver, DataGrip) want a fixed port: `limen db connect orders-staging --listen 127.0.0.1:5433 --detach`, then point the GUI at it.

## Plain ssh, scp, rsync, git

```sh
limen config ssh --install
ssh web-staging-1                       # login filled in when policy allows only one
ssh ec2-user@bastion-staging            # name it when there are several
scp build.tar.gz web-staging-1:/tmp/
rsync -a ./site/ web-staging-1:/srv/site/
git clone web-staging-1:/srv/repo.git
```

`--install` adds this to the top of `~/.ssh/config` (following a symlink, keeping permissions):

```text
# >>> limen >>> added by `limen config ssh --install`; `--uninstall` removes it
Include /Users/you/.limen/ssh_config
# <<< limen <<<
```

The included file has one `Host` entry per SSH resource (`web-staging-1` and `web-staging-1.limen`) and is rewritten on every `limen login`, so it follows your roles. It holds no key or certificate: each entry runs `limen ssh-proxy`, which needs a current login. With several proxies, each one's resources are listed, the current one first.

- A Limen resource named like one of your own `Host` entries takes its place, because the `Include` comes first. `limen config ssh --uninstall` removes everything.
- IDE remotes that tunnel over SSH port forwarding (VS Code Remote-SSH, JetBrains Gateway) don't work: Limen refuses SSH port forwarding.
- `scp` uses SFTP unless you pass `-O`, so the target needs an SFTP subsystem. Without one, `scp` fails with `subsystem request failed`; use `scp -O`. `rsync` and `git` must be installed on the target.
- Names OpenSSH can't take as host aliases (spaces, wildcards, quotes) are skipped with a warning; `limen ssh <name>` still works.
- To leave `~/.ssh/config` alone, `limen config ssh` prints a `Host *.limen` block to paste, for `ssh <login>@<resource>.limen`.

## Troubleshooting

`limen doctor` checks what access depends on, in the order it usually breaks, and says how to fix each failure. It exits 1 if any check failed.

```text
✔ proxy    localhost:3443 (from the last login)
✔ ca       1 CA certificate pinned
✔ network  [::1]:3443 accepts connections
✔ tls      the proxy's certificate is signed by the pinned CA
✔ clock    in step with the proxy
✖ login    the login for developer@example.com expired 12m ago
           → `limen login`
– session  skipped: no valid login
```

With a resource name (`limen doctor orders-staging`) it also checks that policy gives it to you, that a connected worker can reach it, that your grant isn't about to end, and that the client (`ssh`, `kubectl`) is installed. If policy says no, the answer is [`limen explain`](access-requests.md)'s: your roles, the role you can ask for, who approves it, and the command. `--json` is for support tickets and never includes your key, certificate or a token.

A refused connection says the same, plain `ssh` included:

```text
$ ssh ubuntu@orders-prod.limen
✖ access denied to ubuntu@orders-prod
  You can't reach `orders-prod` yet, but you can ask for it.
  Request one of: prod-ssh.
    - `prod-ssh`: approved by members of sre-leads
  Run: limen request orders-prod --for 30m --reason "..."
```
