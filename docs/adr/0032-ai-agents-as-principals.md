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
