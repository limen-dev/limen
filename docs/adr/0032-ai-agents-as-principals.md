# ADR-0032: AI agents as principals

- Status: Proposed (a direction from ADR-0031; to be designed properly before anything is built)
- Date: 2026-10-15

## Context
Automation is no longer only CI jobs. Software agents, driven by language models, now run commands, query databases, and call tools on people's behalf, often with far more freedom than a pipeline step and with credentials handed to them in a prompt or an environment variable. The risks are different from a CI job's: the agent's actions aren't fixed in a script, its input can be attacked (prompt injection), and "who authorised this?" is often a person who isn't watching.

Machine identities (ADR-0019) already give automation its own audited principal with short-lived credentials and no stored secret. An agent should be a kind of that, not a loophole around it.

## Decision (direction, not a contract)
- **An agent is a bot with a `kind: agent` flavour**, named `agent:<name>`, with everything a bot has (no long-lived secret, a short lifetime, exact join rules, lock, kill, recordings, the CI-run style context) and some things a bot doesn't need.
- **It joins on behalf of a person or a team.** The join names who is accountable (a user, or an IdP group), and the audit trail records it on every event, next to the agent's own identity and, where the platform provides one, the run or conversation id.
- **Narrow by default.** Agent roles can only be granted what is listed, never through group mappings; lifetimes are shorter than a bot's (minutes); sessions are recorded with the full transcript.
- **Approval per action.** Through ADR-0025 an agent's role can require a person's approval for specific actions (an elevated database role, a destructive statement, access to production), with the agent's stated reason shown to the approver. Routine reads stay automatic.
- **Tool access, not just shells.** Whatever Limen brokers (SSH, databases, later Kubernetes, web apps) can be offered to an agent as a tool, for example through the Model Context Protocol, so access goes through policy, audit, and recording instead of around them.
- **Detection.** Dashboards separate people, bots, and agents; an agent acting outside its usual pattern is an alert in the same way a person's would be.

## What is deliberately not decided
How an agent proves who it is (a platform-issued token, a signed attestation from the agent runtime, or an approval from the accountable person at start-up), what the first integration is, whether tool access is exposed as an MCP server in the CLI, the proxy, or a separate component, and what "transcript" means for each protocol. Each needs a short spike against a real agent runtime before this ADR is accepted.

## Consequences
- ADR-0019's `bot` document and the certificate marker (`limen://actor/…`) are the base; an `agent` actor type extends them without a new login path.
- Approvals (ADR-0025) and recordings stay the controls that matter most, which is why they come before this.
- Nothing in Phase 4 implements this; it is listed so the bot design isn't narrowed in a way that blocks it.

## Amendment: spike 0 and desk analysis of the open questions (2026-11-06)
The status stays Proposed. This records what was built and what reading Limen at `0bc7da6` (ADR-0019, ADR-0025, ADR-0042 as built) suggests for the questions above. **Nothing below was run against a real agent runtime**; each answer is a recommendation for the owner, and spikes 1 to 3 are still to do.

- **Spike 0 is built:** `limen mcp` (#268), a read-only stdio server in the CLI with five tools (`status`, `ls`, `show`, `explain`, `requests`). It runs the CLI with `--json` as the logged-in person, so it grants nothing new and has no agent identity. It has not been tested against a live login. Threat model: TB15. `policy who-can` and `what-can` are left out because they read local policy files or need `limen:admin`.
- **Where the server lives:** in the CLI first (`limen mcp`). A separate component is justified only by a remote, multi-tenant server that many agents connect to, which has a larger attack surface and no demand yet. The separate `mcp-server-limen` repository was archived for this reason.
- **How an agent proves who it is:** a platform-issued OIDC token through the existing bot join (ADR-0019), with no new login path. A signed attestation needs a trust root nobody has defined. Approval by the accountable person at start-up is an additional control, not the proof. A local desktop agent has no workload identity; today it can only use the person's own login, which is not an agent identity. The accountable person must come from something the issuer vouches for or from the `bot` document, never from a claim the agent makes about itself.
- **Transcripts:** SSH is the best understood (the session recording plus the tool call and stated reason, linked by session id, redacted before storage). For databases, statements and row counts, not result rows (ADR-0033 already audits one `db.query` per statement without parameter values). Kubernetes and web apps are undecided.
- **Blocker found:** bots cannot request access (ADR-0025, as built), so approval per action for an agent is impossible until Limen lets agents request. Bots also never hold built-in roles, which should stay true for agents.
- **First action tool, when allowed:** a wrapper over `limen request --wait`, because approval is the control that matters most; then SSH.
- **Stop condition (unchanged):** if `limen mcp` proves little used, drop the idea.
