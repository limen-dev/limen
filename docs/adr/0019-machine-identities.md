# ADR-0019: Machine identities (bots) for CI and automation

- Status: Proposed (owner requested 2026-10-14)
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
