# ADR-0041: Tools you already use, and `limen doctor`

- Status: Proposed; built for review (issues #118 and #119, epic #121).
- Date: 2026-10-25

## Context
Epic #121 asks that Limen be unremarkable to use: plain `ssh`, `scp`, `rsync`, `git` and `kubectl` should work as they are, and so should IDE remotes, and a failure should explain itself. Before this ADR, `limen config ssh` printed a `Host *.limen` block to paste by hand, `limen kube login <cluster>` wrote one kubeconfig per cluster, and the only way to find out why something failed was to read the error of whichever command failed first.

Issue #119 left open: ProxyCommand versus a native certificate in the agent, Windows paths, and how detached connections (ADR-0039) fit database GUI clients. Issue #118 lists checks; some need server support that doesn't exist yet.

## Decisions

### 1. OpenSSH: `ProxyCommand`, not a certificate in the agent
SSH runs end to end between OpenSSH and the **worker**, which authenticates the user with the `none` method over a stream the proxy already authorised (design §5.1). There is no user SSH certificate on the laptop to put in an agent: per-session certificates are issued to the worker, for the target. So `ProxyCommand limen ssh-proxy %r %h` is the only shape that keeps the existing guarantees (host-CA pinning, no user keys offered, per-session certificates, recording at the worker). It is what `limen ssh` already does.

### 2. One `Include` in `~/.ssh/config`, everything else generated
`limen config ssh --install`:
- writes each proxy's SSH resources (from `limen ls`) to `profiles/<proxy>/ssh_config`, one `Host <name> <name>.limen` block per resource, with `User` when policy allows a single login;
- joins every proxy's fragment, the current one first, into `$LIMEN_HOME/ssh_config`, ending with `Host *.limen` for the current proxy so a resource added since the last refresh still works as `<name>.limen`;
- puts one `Include` line, between `# >>> limen >>>` and `# <<< limen <<<`, at the **top** of `~/.ssh/config` (or `--file`). `Include` must come before any `Host` to apply everywhere. Being first, Limen's entries win for the names they define: if you have your own `Host web-1`, Limen's replaces it. That is the point of installing it; the generated file lists the names.

`~/.ssh/config` is edited in place: a symlink is followed (dotfile managers link it), permissions are kept, a new file is 0600 in a 0700 directory, and installing twice replaces the block. A block with a begin marker and no end marker is refused, not guessed at. `--uninstall` removes the block and the generated files.

The generated files hold no credential. Every connection still runs `limen ssh-proxy`, which needs a current login.

### 3. Names are checked before they are written
Resource names and logins come from policy and end up as `ssh_config` syntax. A name with a space, newline, quote, wildcard or leading `-` could add directives (`ProxyCommand …`) to the user's SSH configuration. Only `[A-Za-z0-9._-]` names are written; others are skipped with a warning and still work with `limen ssh`. The proxy address in `ProxyCommand` is shell-quoted.

### 4. Refreshed on login, only if installed
`limen login` (people and bots) regenerates whichever of the two integrations exists, so the lists follow policy and roles. A failure there is a warning: the login stands.

### 5. kubectl: a separate kubeconfig, added to `KUBECONFIG`
`limen kube config` writes `$LIMEN_HOME/kubeconfig` (mode 0600) with a context `limen-<cluster>` for every cluster you can reach through every proxy you use (current proxy first; a clashing name keeps the current proxy's), and a user `limen@<proxy>` whose only credential is the `limen kube credentials` exec plugin. It sets no `current-context`.

It does not merge into `~/.kube/config`. Merging would mean a YAML parser (a new dependency), editing a file that cloud CLIs and other tools also rewrite, and either taking over or racing on `current-context`. kubectl already merges a `KUBECONFIG` list, so the user adds one line to their shell profile; the command prints it. `limen kube login <cluster>` is unchanged.

### 6. IDE remotes and GUI database clients
VS Code Remote-SSH and JetBrains Gateway read `~/.ssh/config`, so they find the hosts, but they run their server over SSH port forwarding, which the worker refuses (design §5.1) and the generated entries turn off (`ClearAllForwardings`). They need SSH forwarding support first; that is a separate decision with its own audit questions.

DBeaver, DataGrip and the like want a fixed host and port. They work with a detached connection on a fixed port, `limen db connect orders --listen 127.0.0.1:5433 --detach` (ADR-0039). No new mechanism.

### 7. Windows
Not built or tested. OpenSSH for Windows reads `%USERPROFILE%\.ssh\config` and supports `Include` and `ProxyCommand`, so the design should hold; `--file` covers a home directory that `HOME` doesn't name. Marked unverified.

### 8. `limen doctor [resource] [--json]`
Runs, in order, and stops depending checks when one fails (they show as skipped):

| Check | Fails when |
|---|---|
| proxy | none selected, or not `host:port` |
| ca | none pinned, unreadable, or expired |
| network | the name doesn't resolve, or nothing accepts a TCP connection |
| tls | the proxy's certificate isn't from the pinned CA, has another name, or is outside its validity period |
| clock | more than 2 minutes from the proxy's clock (warns at 30 s); read from the `Date` header of the unauthenticated `GetAuthConfig` call. Also warns when client and server versions differ in major or minor |
| login | no local login, the certificate doesn't match the key, or it expired (warns under 5 minutes); warns if the key is readable by others |
| session | the proxy refuses the certificate (`WhoAmI`): login ended, revoked, or user locked |
| access | (with a resource) policy doesn't list it for you. The fix is `explain`'s answer (ADR-0028): your roles, or the role you can request, who approves it, and the `limen request` command; a grant of yours that just ended is named |
| grant | (when access comes from an approved request) it ends within 10 minutes (warning) |
| worker | no worker that may serve the resource holds a live tunnel (from `explain`; skipped on older control planes) |
| client | for SSH, no host CA or no `ssh`; for Kubernetes, no `kubectl` (warning) |
| ssh-config, kubeconfig | installed, but not included by `~/.ssh/config` or not in `KUBECONFIG` (warnings) |

Each failure says how to fix it. The exit code is 1 if anything failed. `--json` is for support tickets and holds no key, certificate or token: names, statuses, user name, roles and times only.

### 9. Denial hints (#120)
A refusal says why and how to get access, where the user meets it, not only in `limen explain`. The proxy marks a policy refusal in `SessionResponse.denied` (capacity and outages are not marked); the CLI then calls `Explain` for the resource (5-second limit; without an answer the refusal stands alone) and prints its lines under the error. Every session command goes through this, plain `ssh` included: `limen ssh-proxy` writes to stderr, which OpenSSH shows. An unknown resource name gets the same lines.

`Explain` grew three things for this, all within ADR-0028's visibility rule (a hidden resource reads like a missing one):
- For a role the caller may request: who approves it (groups and named users, and how many approvals), or that it is break-glass, and the exact command.
- The caller's own grant on the resource that expired or was revoked in the last day. It is their own, so nothing new is revealed.
- For a resource the caller can reach, whether a worker that may serve it holds a live tunnel (also as the field `worker_connected`). The control plane already knows this from the proxies' tunnel reports. It is not said for resources the caller can't reach.

## Consequences
- `~/.ssh/config` is now a file Limen edits, inside a marked block, only on `--install` and `--uninstall`.
- New files under `$LIMEN_HOME`: `ssh_config`, `kubeconfig`, and per-proxy fragments. They list resource names, which `limen ls` shows anyway, and no credential (threat model, TB1).
- `limen login` makes one more `ListResources` call when an integration is installed.
- A refused session costs one more `Explain` call.
