# ADR-0019: Machine identities (bots) for CI and automation

- Status: Accepted (owner approved Phase 4 on 2026-10-15; amended below as built)
- Date: 2026-10-14

## Context
Today every actor is a human who logs in through OIDC. CI pipelines, deploy bots, and scheduled jobs also reach infrastructure, and they are usually the hardest actors to audit: a shared SSH key or a database password in a CI secret tells you nothing about *which run* did something. Limen's rule is "no long-lived credentials"; bots must follow it too. The owner wants bots audited as first-class actors, next to human users from Okta or created directly.

## Decision
- **A bot is a distinct principal**, `kind: bot` in policy, named `bot:<name>`. It is not a user with a flag: it can't be created by an IdP group, it has no interactive login, and it appears separately in the console and in audit (`actor_type: bot`).
- **It logs in by presenting a workload identity token, never a secret Limen issued.** Supported join methods, in order: GitHub Actions OIDC, GitLab CI ID tokens, generic OIDC (CircleCI, Buildkite, Bitbucket, Argo, Tekton), AWS IAM (a signed `sts:GetCallerIdentity`, as ADR-0016 plans for components), and Kubernetes projected service account tokens. The control plane verifies the token against the provider's JWKS and matches claims against the bot's rules.
- **Policy document:**
  ```yaml
  kind: bot
  version: v1
  metadata: { name: deploy-staging }
  spec:
    join:
      method: github_actions
      match:                       # all must match exactly; no bare wildcards on `sub`
        repository: acme/infra
        ref: refs/heads/main
        environment: staging
    roles: [deployer]
    max_ttl: 15m
  ```
  Roles then work exactly as for people, so a bot gets the same least-privilege grants.
- **Credentials are the same short-lived certificates** (X.509 and per-session SSH), with a bot marker in the certificate and a TTL of at most 1 hour (default 15 minutes) and **no refresh**: the next job logs in again.
- **Audit records the run, not just the name.** Every event from a bot session carries `actor_type: bot` and a `ci` object (provider, repository, workflow, run ID and attempt, commit SHA, ref, and the human who triggered the run when the provider says so). Dashboards get a human/bot filter and a "bot sessions by repository" panel.
- **CLI:** `limen login --bot <method>` reads the provider's token from its standard environment (for GitHub, the request URL and token the runner provides), so there is nothing to configure in a secret store. A small GitHub Action wrapping it comes later.
- **Controls shared with humans:** lock and session kill apply to bots by name; the console lists bots, their last run, and their sessions.

## Threats this design has to survive
- **Overly broad claim matches** (a rule on `repository` only lets any branch, or a fork's pull request, in): matches must name `ref` or `environment`, and the policy validator rejects a bot with only a repository match. Docs show the pull-request-from-fork pitfall.
- **Token replay:** each token is accepted once (the login-nonce table already does this for the device flow) and must have an audience of `limen`.
- **Issuer confusion:** the issuer URL and JWKS are pinned per join method; a generic OIDC bot must name its issuer in policy.
- **A compromised repository** can still run its own jobs. The mitigation is the policy match plus short TTL, short sessions, recording, and the lock button; it can't be eliminated.

## Consequences
- Authentication gains a second login path in the control plane and a second identity kind in certificates (`ADR-0006` is extended, not replaced).
- Every later protocol must take the actor from the certificate rather than assume a person.
- *Unverified against real GitHub or GitLab tokens until tested with them*; tests use a mock OIDC provider.

## Amendment: as built (Phase 4)
- **Join methods built:** `github_actions`, `gitlab`, and generic `oidc`. A Kubernetes cluster's projected service account tokens work through `oidc` when the cluster publishes OIDC discovery. **Deferred to Phase 14, with the IAM join for components (ADR-0016): the AWS IAM method** (a presigned `sts:GetCallerIdentity`), because verifying one means the control plane calls an STS endpoint the caller names, which needs its own SSRF design, and Phase 14 is where STS verification is built for components.
- **Login:** a new unauthenticated `BotLogin` RPC: `{method, token, csr_der, bot?}`. The control plane only contacts issuers that a `bot` document names (chosen from the token's unverified `iss` against that allow-list), verifies signature, `aud` (default `limen`, `--bot-audience`), `exp`, and a required `iat` no older than `--bot-max-token-age` (15 minutes), records the token's `jti` (or its hash) so it works once, then matches claims. `http` issuers need `--bot-allow-insecure-issuers` (development only).
- **Matching:** exact values, no wildcards. The validator additionally refuses pull request refs and events (GitHub), an unprotected GitLab `ref`, `oidc` rules without an issuer and an exact `sub`, built-in roles, and a lifetime over one hour. A token matching more than one bot is refused (`--bot-name` resolves it).
- **A token is spent late.** Matching, the lock check, and the CSR check come first; the token's record is taken just before credentials are issued, and released if issuing, recording the bot, or auditing fails, because nothing was handed out. The record lives until the later of the token's `exp` and the end of its `iat` window (`max age + 60 s`). Pull request runs never match a `github_actions` rule, whatever the rule names (the validator's checks alone couldn't stop a rule that names neither `ref` nor `event_name`). A bot's `users` row is never taken over from a person's, and a login that can't record its bot fails.
- **Replay record and key origin:** a token's record is its `jti` (with the issuer) or, without one, the hash of its signed part `header.payload`, never its signature (which can be altered without invalidating the token). The signing keys must be on the issuer's own origin: a discovery document that points them elsewhere is refused, so a compromised issuer can't aim the control plane at another address.
- **Facts are bounded and trusted:** the certificate's CI facts come from a fixed allow-list per provider (for `oidc`, only the claims the matched rule named), are cut by bytes on a character boundary to what the CA accepts, drop empty values, and can't replace `provider`, `iss`, or `sub`. Verification rejects repeated or too many facts.
- **Identity:** the certificate has `limen://actor/bot` and one `limen://ci/<key>/<value>` per CI fact, next to the usual user, login, and role entries. The `bot:` username prefix is reserved: people with such an IdP name are refused, issuance refuses a mismatch, and verification checks the marker and the prefix agree.
- **Audit:** `actor_type` (`user` or `bot`) is on `auth.login`, `session.start`, `session.end`, and `ssh.exec`. The **`ci` object is on `auth.login`, `auth.denied` (the refused run), and `session.start`**, not on every event: `session.end` and `ssh.exec` link to it through the session id. This narrows "every event carries `ci`" above. The Glue and Trino tables, and the Grafana dashboards, gained `actor_type`, `method`, `bot`, and the `ci` fields.
- **State:** `users` rows for bots (`actor_type = 'bot'`, `last_ci`) and `sessions.actor_type` and `sessions.ci` (migration 0005). The console lists bots on their own page and keeps them out of the people list; locks work by the name `bot:<name>`.
- **CLI:** `limen login --bot <method>`, with `--bot-name`, `--token-env`, `--token-file`, and `--audience`. In GitHub Actions the token is requested for you.
- **Development stand-in:** `fake-ci-issuer` (a compose service, development only) serves discovery and keys like GitHub's token service and mints GitHub-shaped tokens on request. `deploy/compose/demo-phase4.sh` uses it. Everything is **unverified against real GitHub or GitLab tokens**.
- **Not built:** the AWS IAM join (above), a GitHub Action wrapping the CLI, per-bot IP restrictions, and the agent flavour ([ADR-0032](0032-ai-agents-as-principals.md)).
