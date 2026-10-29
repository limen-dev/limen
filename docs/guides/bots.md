The CLI guide covers people. This one is for **CI jobs and automation**: how they log in, what they get, and what you can see afterwards. Design: [ADR-0019](../adr/0019-machine-identities.md). Everything here has run against a stand-in issuer that mints GitHub-shaped tokens, **not** against real GitHub or GitLab tokens yet.

# Bots: CI jobs as audited principals

A bot is not a person with a flag. It is its own kind of principal, `bot:<name>`, that logs in with the **workload identity token its CI platform mints for the job** (a short OIDC token, valid for minutes). Limen verifies the token, matches its claims against a `bot` document in your policy, and issues the same short-lived certificate people get, marked as a bot's. **No secret is stored anywhere**: nothing in your CI secrets, nothing in Limen.

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
Apply it like any policy (`limen admin apply`). The validator refuses rules that are too broad to mean anything: a repository alone, a wildcard, a pull-request ref or event, a GitLab `ref` without `ref_protected: "true"`, an `oidc` rule without an issuer and an exact `sub`, and built-in roles such as `limen:admin`. See [the policy reference](../policy.md#bot).

## 2. Log in from the job
**GitHub Actions.** Give the job permission to request a token, then log in. The CLI asks GitHub for a token with the audience your control plane expects, so nothing is configured:
```yaml
permissions:
  id-token: write
  contents: read
steps:
  - run: |
      limen login --bot github_actions
      limen ssh web-staging-1 -- ./deploy.sh
```
**GitLab CI.** Declare an ID token with the right audience and point the CLI at it:
```yaml
deploy:
  id_tokens:
    LIMEN_ID_TOKEN:
      aud: limen
  script:
    - limen login --bot gitlab
    - limen ssh web-staging-1 -- ./deploy.sh
```
**Any other OIDC provider** (CircleCI, Buildkite, Bitbucket, Argo, Tekton, a Kubernetes cluster's projected service account tokens when it publishes OIDC discovery): `limen login --bot oidc --token-env VAR` or `--token-file FILE` (`-` reads standard input). The policy names the issuer and the exact `sub`.

If more than one bot could match a token, name it: `--bot-name deploy-staging`. The audience defaults to `limen` and is the control plane's `LIMEN_BOT_AUDIENCE`.

## What the bot gets
- **A certificate that lasts at most an hour** (15 minutes by default), with **no refresh**: the next job logs in again.
- **One login per token.** A token that was already used is refused, so a leaked token is useless once the job has run, and the control plane insists the token was minted within `LIMEN_BOT_MAX_TOKEN_AGE` (15 minutes). A token is only *spent* when credentials are issued: a bad key, a wrong `--bot-name`, or a token that matches no bot leaves it usable, and a login that fails after the control plane took the token gives it back.
- **The same roles as anyone**, so it gets the same least-privilege grants and the same recordings.

## What you can see
- **Audit.** `auth.login`, `session.start`, `session.end`, and `ssh.exec` carry `actor_type: bot`. Logins and session starts also carry the **CI run**: provider, repository, workflow, run id, commit, ref, environment, and who triggered it. Refused logins are audited with the run that was refused. Tokens never appear in the trail or the logs.
- **Console.** The **Bots** page lists each bot, what it matches, its last login and run (with a link to the run on GitHub and GitLab), and its sessions. Sessions show a bot badge and a "The CI run" card. Bots are not listed among people. The Dashboards page splits people and bots and ranks bot sessions by repository.
- **Lock.** `limen admin lock bot:deploy-staging --reason …` (or the console) stops it from logging in and ends its open sessions, exactly as for a person.

## When a login is refused
The CLI shows the control plane's reason. The audit trail has the details of the run.
| Reason | Meaning |
|---|---|
| `invalid token` | The signature, audience, issuer, expiry, or age didn't check out. Check the audience (`LIMEN_BOT_AUDIENCE`), that the job's token was minted just now, and that policy names this issuer |
| `token already used` | Each token logs in once. Mint a new one |
| `no bot matches this token` | Every `match` entry must equal a claim exactly. The audit event shows the refused repository and ref |
| `more than one bot matches this token` | Two bot rules accept it. Narrow them, or pass `--bot-name` |
| `no bot accepts this kind of token` | No bot uses that `--bot` method |
| `bot locked` | An admin locked it |
| `reserved username` | A person's IdP user name starts with `bot:`, which is reserved |

## Pitfalls worth knowing
- **Pull requests from forks.** A job triggered by a pull request runs code the author chose. For GitHub, a token from a pull request run (`pull_request` or `pull_request_target` events, or a `refs/pull/…` ref) **never matches a bot, whatever the rule says**, and the validator also refuses rules that name them. Match a protected branch or an **environment** with required reviewers instead.
- **A compromised repository can still run its own jobs.** The defences are the exact match, the short lifetime, recordings, and the lock button. They narrow the damage; they don't remove it.
- **Multi-tenant issuers.** If one issuer serves many customers (some cloud identity providers do), a `sub` alone is only unique within a tenant. Add a tenant claim to `match` (for example `tid`), or another tenant's job could present the same `sub`.
- **Removing a bot from policy** stops new logins but not a credential it already holds (at most an hour). Lock it to end its sessions at once.
- **Signing keys** are fetched from the issuer's own address only: if its discovery document points the keys at another host, the login is refused.
- **Real issuers are https.** The control plane refuses plain `http` issuers unless `LIMEN_BOT_ALLOW_INSECURE_ISSUERS` is set, which is for the development stack only.
- **Not built yet:** the AWS IAM join (a signed `sts:GetCallerIdentity`) is planned with the IAM join for proxies and workers in Phase 15 (ADR-0016), and a GitHub Action that wraps `limen login --bot` comes later.
