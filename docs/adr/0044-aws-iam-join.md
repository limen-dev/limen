# ADR-0044: Joining with an AWS IAM identity (components and bots)

- Status: **Proposed**, for the owner's decision. Nothing here is built. Completes ADR-0016's second join method ("planned, Phase 15") and the bot variant parked in ADR-0019. Tracks two items of #16.
- Date: 2026-11-04

## Context
A proxy or worker enrolls with a join token (ADR-0016): single-use for hosts a person sets up, or a static multi-use token for autoscaled tasks, which must then live in a secret store and be rotated. ADR-0016 names an AWS IAM join as the intended default for ECS and Auto Scaling groups: no secret to distribute, because the task proves who it is with the IAM role it already runs as. ADR-0019 wants the same for bots that run in AWS (a CodeBuild or Lambda job that has no CI OIDC token). Both were deferred because of one problem:

> The proof is a signed `sts:GetCallerIdentity` request, and the **control plane has to send it to STS for the caller**. The caller chooses what is in that request. Done naively, the control plane becomes a server-side request forger that calls any URL a stranger names, with a stranger's headers.

The enrollment and bot-login RPCs are reachable without authentication (they are how you get an identity), so the verifier is exposed to anyone who can reach the proxy.

## Decision (proposed)
**The caller sends a signed request; the control plane never uses the caller's URL, host or any header it did not expect.**

1. **What the caller sends.** For enrollment, a new `iam` field beside `join_token` in `EnrollRequest` (additive, so `buf breaking` stays quiet): `{region, headers, challenge}`. For bots, `method: aws_iam` in `BotLoginRequest`, with the same field. The caller signs a `POST` of `Action=GetCallerIdentity&Version=2011-06-15` with SigV4, using the credentials of its role. The body is fixed and is not sent; the control plane supplies it.
2. **A challenge, so a captured request can't be replayed.** The control plane first returns a random challenge (one RPC, short-lived, single use, stored hashed like a join token). The caller includes it as a signed header `x-limen-challenge`. STS does not check this header, but because it is part of the signature, the signed request is useless for any other challenge, and any other service or deployment that would accept the same request. (This is the idea behind Vault's `X-Vault-AWS-IAM-Server-ID`; here it is per attempt, not per server.) `x-amz-date` older than 5 minutes is refused before STS is asked.
3. **The control plane builds the request itself.**
   - The URL is `https://sts.<region>.amazonaws.com/` with `region` checked against a fixed list of AWS regions the operator allows (default: the control plane's own region), or the global `sts.amazonaws.com`. It is never taken from the caller. `sts.<region>.amazonaws.com.cn` is a separate, explicit opt-in.
   - Method `POST`, body fixed, headers limited to an allow list: `host` (must equal the host the control plane chose), `x-amz-date`, `x-amz-security-token`, `authorization`, `content-type`, `x-limen-challenge`. Anything else is dropped, and a header that appears twice is refused.
   - No redirects, a 5 second timeout, the response capped at 64 KiB, a fixed DNS name resolved by the control plane's own resolver, and the connection refused if it resolves to a private, loopback or link-local address. These are the same guards a worker's SSRF check uses (ADR-0042 delegated resources), reused.
4. **What the answer is checked against.** The response is XML; the control plane takes `Arn` and `Account` from it and nothing else. The ARN is normalized (`arn:aws:sts::<acct>:assumed-role/<role>/<session>` becomes `arn:aws:iam::<acct>:role/<role>`; the session name is kept only as an audit label) and matched against **operator-defined rules** that bind an IAM role pattern to what the component or bot is allowed: for components, kind, labels and DNS names, as a join token does today; for bots, the `bot` document names the role ARN pattern (`aws_iam: { role: "arn:aws:iam::123456789012:role/deploy-*" }`). An unmatched role is refused and audited like a bad token.
5. **Audit and revocation** are the same as for tokens: `worker.enroll` with `token_type: aws_iam` and the role ARN; `auth.login` with the role for bots. Revoking a component (`components.revoked_at`) still blocks renewal.
6. **Not in the first cut:** cross-account roles through an STS endpoint the operator supplies (private endpoints, VPC), GovCloud and China partitions, and identity from IAM Roles Anywhere.

## Alternatives considered
- **Let the caller send the full request and forward it (the naive design).** Rejected: the SSRF above.
- **EC2 instance identity documents.** They do not work on ECS tasks or Lambda, and the signature chain has its own caveats. Not general enough.
- **AWS OIDC identity federation (outbound identity tokens for workloads).** Possibly cleaner, and a candidate for the generic `oidc` bot method already built. Its availability and its coverage of ECS tasks, EC2 and Lambda have not been checked for this ADR; check before choosing between the two.
- **Keep static tokens.** What ships now, with its recorded threat-model risk. This ADR is the way off them.

## Consequences
- \+ No long-lived secret for ECS or Auto Scaling groups, and an audit trail naming the role.
- \+ The same verifier serves components and bots.
- − A new unauthenticated, outbound-calling code path in the control plane. It is the most exposed code this ADR adds, so it gets the most tests (every header and URL variation above, a hostile caller) and its own entry in the threat model.
- − The control plane needs outbound HTTPS to STS (an egress rule, or a VPC endpoint).
- − Verified only against a stand-in unless a real AWS account is available: the SigV4 canonicalization, the STS response format and the regional endpoints are what real STS defines, and a fake can agree with a wrong reading. Labelled `unverified` until #84 or a similar account run.

## What it needs to be accepted
- Owner decisions: the challenge step (per-attempt challenge versus a fixed deployment id), the default allowed regions, and whether bots on AWS should wait for the OIDC route.
- Threat-model rows for the new entry point (unauthenticated enrollment with `iam`) and the outbound STS call.
- A fake STS in the testkit (`limen-testkit` has a fake AWS today for other services) that checks the signature and the challenge, for the integration tests.
