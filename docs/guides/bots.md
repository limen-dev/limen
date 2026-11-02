This guide is for **CI jobs and automation**: how they log in, what they get, and what you can see afterwards. People: see [the CLI guide](cli.md). Design: [ADR-0019](../adr/0019-machine-identities.md). **Unverified:** everything here ran against a stand-in issuer minting GitHub-shaped tokens, not real GitHub or GitLab tokens.

# Bots: CI jobs as audited principals

A bot is its own kind of principal, `bot:<name>`, not a person with a flag. It logs in with the **workload identity token its CI platform mints for the job** (a short OIDC token, valid for minutes). Limen verifies the token, matches its claims against a `bot` document in your policy, and issues the same short-lived certificate people get, marked as a bot's. **No secret is stored anywhere**: not in your CI secrets, not in Limen.

## 1. Write the bot in policy

```yaml
kind: bot
version: v1
metadata: { name: deploy-staging }
spec:
  join:
    method: github_actions          # github_actions | gitlab | oidc
    match:                          # exact matches only: no wildcards
      repository: acme/infra
      ref: refs/heads/main
      environment: staging
  roles: [deployer]                 # the same roles people use
  max_ttl: 15m                      # at most 1h; there is no refresh
```

Apply it like any policy (`limen admin apply`). The validator refuses rules too broad to mean anything: a repository alone, a wildcard, a pull-request ref or event, a GitLab `ref` without `ref_protected: "true"`, an `oidc` rule without an issuer and exact `sub`, and built-in roles such as `limen:admin`. See [the policy reference](../policy.md#bot).

## 2. Log in from the job

**GitHub Actions.** Permit the job to request a token, then log in. The CLI asks GitHub for a token with the audience your control plane expects, so nothing is configured:

```yaml
permissions:
  id-token: write
  contents: read
steps:
  - run: |
      limen login --bot github_actions
      limen ssh web-staging-1 -- ./deploy.sh
```

**GitLab CI.** Declare an ID token with the right audience:

```yaml
deploy:
  id_tokens:
    LIMEN_ID_TOKEN:
      aud: limen
  script:
    - limen login --bot gitlab
    - limen ssh web-staging-1 -- ./deploy.sh
```

**Any other OIDC provider** (CircleCI, Buildkite, Bitbucket, Argo, Tekton, a Kubernetes cluster's projected service account tokens when it publishes OIDC discovery): `limen login --bot oidc --token-env VAR` or `--token-file FILE` (`-` reads standard input). Policy names the issuer and the exact `sub`.

If several bots could match a token, name one: `--bot-name deploy-staging`. The audience defaults to `limen` (the control plane's `LIMEN_BOT_AUDIENCE`).

## What the bot gets

- **A certificate lasting at most an hour** (15 minutes by default), with **no refresh**: the next job logs in again.
- **One login per token.** A used token is refused, so a leaked token is useless once the job has run, and the control plane requires it minted within `LIMEN_BOT_MAX_TOKEN_AGE` (15 minutes). A token is *spent* only when credentials are issued: a bad key, wrong `--bot-name` or a token matching no bot leaves it usable, and a login that fails after the control plane took the token gives it back.
- **The same roles as anyone**, hence the same least-privilege grants and recordings.

## What you can see

- **Audit.** `auth.login`, `session.start`, `session.end` and `ssh.exec` carry `actor_type: bot`. Logins and session starts also carry the **CI run**: provider, repository, workflow, run id, commit, ref, environment and who triggered it. Refused logins are audited with the run that was refused. Tokens never appear in the trail or logs.
- **Console.** The **Bots** page lists each bot, what it matches, its last login and run (linked on GitHub and GitLab) and its sessions, which show a bot badge and a "The CI run" card. Bots aren't listed among people. Dashboards split people and bots and rank bot sessions by repository.
- **Lock.** `limen admin lock bot:deploy-staging --reason …` (or the console) stops logins and ends open sessions, as for a person.

## When a login is refused

The CLI shows the control plane's reason; the audit trail has the run's details.

| Reason | Meaning |
|---|---|
| `invalid token` | Signature, audience, issuer, expiry or age failed. Check the audience (`LIMEN_BOT_AUDIENCE`), that the token was minted just now, and that policy names this issuer |
| `token already used` | Each token logs in once. Mint a new one |
| `no bot matches this token` | Every `match` entry must equal a claim exactly. The audit event shows the refused repository and ref |
| `more than one bot matches this token` | Two bot rules accept it. Narrow them, or pass `--bot-name` |
| `no bot accepts this kind of token` | No bot uses that `--bot` method |
| `bot locked` | An admin locked it |
| `reserved username` | A person's IdP user name starts with the reserved `bot:` |

## Pitfalls

- **Pull requests from forks** run code the author chose. On GitHub, a token from a pull request run (`pull_request`, `pull_request_target`, or a `refs/pull/…` ref) **never matches a bot, whatever the rule says**, and the validator refuses rules naming them. Match a protected branch or an **environment** with required reviewers instead.
- **A compromised repository can still run its own jobs.** The exact match, short lifetime, recordings and lock button narrow the damage; they don't remove it.
- **Multi-tenant issuers.** If one issuer serves many customers, `sub` alone is unique only within a tenant. Add a tenant claim to `match` (such as `tid`), or another tenant's job could present the same `sub`.
- **Removing a bot from policy** stops new logins but not a credential it holds (an hour at most). Lock it to end its sessions at once.
- **Signing keys** are fetched only from the issuer's own address; if its discovery document points them at another host, the login is refused.
- **Issuers must be https.** The control plane refuses plain `http` unless `LIMEN_BOT_ALLOW_INSECURE_ISSUERS` is set (development only).
- **Not built:** the AWS IAM join (a signed `sts:GetCallerIdentity`) is planned with the IAM join for proxies and workers in Phase 15 (ADR-0016), and a GitHub Action wrapping `limen login --bot` comes later.
