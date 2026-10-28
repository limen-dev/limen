# Security policy

Limen controls access to infrastructure, so a flaw in it can matter more than a flaw in most software. Thank you for taking the time to report one privately.

## Reporting a vulnerability

**Please don't open a public issue, pull request or discussion for a security problem.**

Report it through GitHub's private vulnerability reporting instead:

1. Go to the repository's [**Security** tab](https://github.com/jfcmartins/limen/security).
2. Choose **Report a vulnerability** ([direct link](https://github.com/jfcmartins/limen/security/advisories/new)).
3. Fill in the form. Only you and the maintainers can see it.

A useful report says:

- what an attacker can do, and what they need first (network access, a valid login, a particular role, a compromised worker...)
- the component and version: `limen-control-plane`, `limen-proxy`, `limen-worker` or the `limen` CLI, and the commit you tested
- steps to reproduce it, ideally against the local stack (`deploy/compose/setup.sh`)
- anything you know about a fix

You don't need a complete exploit. A clear description of the problem is enough to start.

## What happens next

The report becomes a private draft advisory, and we discuss it there with you. We confirm whether it is a vulnerability, agree a fix, and publish the advisory once a fix is available, crediting you unless you'd rather not be named. If we disagree about severity or scope, we'll say why.

## Supported versions

There is no tagged release yet. Fixes go to the `main` branch only. Once releases start, this section will list which ones receive security fixes.

## Scope

**In scope:** the code in this repository. That means the control plane, proxy, worker and CLI, the console, the audit pipeline and `limen-audit-verify`, the Terraform modules in `deploy/terraform`, and the Kubernetes examples in `deploy/kubernetes`.

Examples of what we especially want to hear about:

- getting access that policy doesn't grant, or keeping access after a lock, a logout, or a grant's expiry
- obtaining a certificate, a join token or a target credential you shouldn't have
- a session that isn't audited or recorded when it should be, or audit that can be altered or dropped without `limen-audit-verify` noticing
- secrets, tokens or session content appearing in logs, traces, metrics or the audit trail where the docs say they don't

**Out of scope:**

- **The local dev stack** in `deploy/compose`. It deliberately uses static test users, the password `password`, static join tokens and CA keys on a Docker volume. It is not meant for real use.
- **The demos** in `demos/`, and anything that depends on the dev stack's insecure defaults.
- **Accepted residual risks** already listed in [§6 of the threat model](docs/threat-model.md#6-accepted-residual-risks-v1). If you find a way to make one of them worse than the threat model describes, that is in scope.
- **Problems in a dependency** that don't affect Limen. Please report those to the dependency's maintainers. If one does affect Limen, tell us too.
- **Results from automated scanners** without a way to exploit them.

## Background

- [Threat model](docs/threat-model.md): the assets, the trust boundaries, and how each threat is handled
- [Penetration test plan](docs/pentest-plan.md): what will be tested before Limen is called production-ready
- [What is built and what is verified](website/src/content/docs/docs/status.mdx): Limen has not yet been verified against real AWS, Okta or Datadog
