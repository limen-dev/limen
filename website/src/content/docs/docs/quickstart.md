---
title: Quickstart
description: Run Limen locally with Docker Compose, sign in, and open a recorded SSH session.
---
This runs a complete Limen deployment on your machine, with an identity provider ([Dex](https://dexidp.io)), PostgreSQL, a local S3 and KMS, and an SSH target. It is for trying Limen out. **Nothing in it is fit for real use**: Dex has static users whose password is `password`, join tokens are static, and the CA keys sit on a Docker volume.

## You need

| Needed | Why |
|---|---|
| Docker with Compose v2.24 or newer (macOS: [OrbStack](https://orbstack.dev) or Docker Desktop) | runs every service |
| The Rust toolchain and `protoc` from `mise.toml` (`mise install`), or an existing `limen` binary in `LIMEN_BIN` | builds the CLI |
| `curl` and an OpenSSH client | health checks and `limen ssh` |

The scripts are plain bash, tested on macOS and untested on Linux. On Windows use WSL 2 (untested). The first build takes several minutes.

## 1. Start it

```sh
git clone https://github.com/limen-dev/limen && cd limen
deploy/compose/setup.sh
```

The script checks your tools, asks which stacks to enable (an SSH host, databases, Redis, Kubernetes, observability, and more), starts everything, applies the example policy, and prints the ports, a command for each resource, and how to sign in.

## 2. Install the CLI and sign in

```sh
scripts/install-cli.sh
limen --server localhost:3443 login --ca-file deploy/compose/.state/internal-ca.pem
```

`--ca-file` is only for this local stack, whose certificate comes from its own CA. Against a deployment with a public certificate you run `limen login --server limen.example.com` and nothing else.

A browser opens on Dex. Sign in as `admin@example.com` with password `password`. On a machine without a browser, use `limen login --device`.

:::caution[If a command says "user locked" a few seconds later]
Dex stops honouring a person's earlier login when they sign in again. `setup.sh` has already signed in as `admin@example.com`, so your sign-in makes Dex refuse the script's, and the dev stack's 15-second check reads that as a deactivation and locks the account. Run `limen logout`, then `limen login` again, or sign in to the console, which lifts the lock. Seen with Dex v2.46.0; Okta is not verified ([#64](https://github.com/limen-dev/limen/issues/64)).
:::

Your credentials are now a certificate in `~/.limen/` that lasts an hour. Check them:

```sh
limen status      # who you are, your roles, and the time left
limen ls          # what you can reach
```

```text
NAME                   KIND        ACCESS AS                                          LABELS
bastion-staging        ● ssh       ec2-user, ubuntu                                   env=staging tier=bastion
billing-mysql-staging  ● mysql     limen_read, limen_readonly, limen_rw, limen_write  env=staging team=payments
orders-mysql-staging   ● mysql     limen_read, limen_readonly, limen_rw, limen_write  env=staging team=payments
orders-prod            ● postgres  limen_read, limen_write                            env=prod team=payments
orders-staging         ● postgres  limen_read, limen_write                            env=staging team=payments
warehouse-prod         ● redshift  limen_read, limen_readonly, limen_rw, limen_write  env=prod team=data
web-staging-1          ● ssh       ec2-user, ubuntu                                   env=staging
  7 resources · `limen show <name>` tells you how to connect to one
```

That is what you see with the SSH and database stacks enabled; each other stack you enable adds its own resources. These are stand-ins: nothing here is a real bastion or database.

## 3. Use it

```sh
limen ssh ubuntu@web-staging-1      # a recorded SSH session
limen db connect orders-staging --db-role limen_read   # a local address for psql, with no password
limen explain orders-prod           # why you can or can't reach something
```

`ubuntu` is the login and `limen_read` the database role: the **ACCESS AS** column of `limen ls` lists the ones you may use, and Limen asks you to pick when there is more than one.

Then open the console at `https://localhost:3443/console/` and sign in as the same user. The first page lists what needs you, your favourites and where you left off. Open **Sessions**, find the one you just had, and replay its recording. **Resources** shows what each resource is doing, and each resource page starts with the command to connect to it. Press `Ctrl+K` (`⌘K` on a Mac) to jump to anything. [The console guide](../guides/console/) covers every page.

:::note
The proxy's certificate comes from the Limen dev CA, so the browser warns about it. That is expected here. Do not add the CA to your system trust store: click through the warning on localhost, or use `curl --cacert deploy/compose/.state/internal-ca.pem`.
:::

## 4. Try the other users

| User | Groups | What they see |
|---|---|---|
| `developer@example.com` | `developers` | read-only access to the staging resources |
| `auditor@example.com` | `auditors` | every database, read only, and no shell; the audit trail in the console |
| `viewer@example.com` | `viewers` | the staging databases, read only |
| `oncall@example.com` | `sre-oncall` | the databases, production included, and SSH, for a short window |
| `contractor@example.com` | `contractors` | one staging host, short-lived and narrow |
| `guest@example.com` | `marketing` | nothing: login is denied, and the denial is audited |

Apart from `guest`, they can sign in to the console too, and see only what their roles allow.

The full list is in the [local stack reference](../reference/compose-stack/#dev-users).

## Next

- [Concepts](../concepts/): what just happened.
- [The CLI](../guides/cli/) and the guide for each protocol.
- Replace the example policy: [policy reference](../reference/policy/).
