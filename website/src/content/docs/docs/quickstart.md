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
limen --proxy localhost:3443 login --ca-file deploy/compose/.state/internal-ca.pem
```

A browser opens on Dex. Sign in as `admin@example.com` with password `password`. On a machine without a browser, use `limen login --device`.

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

Then open the console at `https://localhost:3443/console/`, sign in as the same user, find the session, and replay its recording.

:::note
The proxy's certificate comes from the Limen dev CA, so the browser warns about it. That is expected here. Do not add the CA to your system trust store: click through the warning on localhost, or use `curl --cacert deploy/compose/.state/internal-ca.pem`.
:::

## 4. Try the other users

| User | Groups | What they see |
|---|---|---|
| `developer@example.com` | `developers` | read-only access to dev resources |
| `auditor@example.com` | `auditors` | the audit trail, not the resources |
| `guest@example.com` | `marketing` | nothing: login is denied, and the denial is audited |

The full list is in the [local stack reference](../reference/compose-stack/#dev-users).

## Next

- [Concepts](../concepts/): what just happened.
- [The CLI](../guides/cli/) and the guide for each protocol.
- Replace the example policy: [policy reference](../reference/policy/).
