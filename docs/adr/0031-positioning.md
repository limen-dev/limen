# ADR-0031: Positioning: access you can prove

- Status: Proposed (owner asked for a differentiator 2026-10-14; the direction below is the recommendation made then and is **not yet confirmed** by the owner)
- Date: 2026-10-15

## Context
Identity-aware access platforms are a crowded space, and the usual way to compete (how many protocols, how many integrations) is a race Limen joins anyway: SSH, databases, Kubernetes, MongoDB, search, brokers, web apps. Protocol breadth is necessary and will not make anyone choose Limen. Limen needs a reason that is true of the design, hard to copy by adding a feature, and visible in the first five minutes.

*Everything about other products in this document is a general impression, not a researched comparison. Before any of it appears in public material, check it against what those products ship at that moment.*

## Decision
**Position Limen as access you can prove.** Not "access you can log": access where every grant, every decision, and every session can be shown to be what it claims to be, by someone who does not have to trust Limen.

The one-sentence version: *Limen makes access short-lived, justified, and provable.*

### Pillars
1. **Provable.** The audit trail is signed and hash-chained (ADR-0009). The step beyond that is the **access receipt**: for any session, one bundle holding the recording, its events, the chain proof, the policy version and digest in force, the identity and roles, and the approval that allowed it (ADR-0025). `limen-audit-verify` checks a receipt **offline**, so an auditor, a customer, or a court needs no access to Limen.
2. **Explainable.** Every decision, allow or deny, can say why: which role, which rule, which label did not match, which lock or expired grant applied (`explain`, ADR-0028). Users get the reason for their own denials; admins get the full trace. Policy changes show their effect on *effective access* before they land (`policy diff`), and tests run in CI (`policy test`).
3. **Justified and short-lived.** No standing credentials anywhere: certificates in minutes, access requests with a reason, approvals, break-glass that is loud (ADR-0025). The approver sees context, and later can be given more (an open incident, the on-call rota, a ticket's state) so that routine approvals are automatic and unusual ones are not. Risky statements (for example `DELETE` without `WHERE`) can require a second person, because the wire-level audit already sees them.
4. **Machines and agents are principals too.** CI jobs (ADR-0019) and, next, **AI agents** get scoped, short-lived, approved, recorded access under the same rules as people, with their full transcript kept and individual risky actions approvable by a human. This is the part of the product that looks furthest ahead.
5. **Open and plain to run.** Everything ships in the Apache-2.0 build: no paid tier for approvals, auditing, discovery, or reviews. Static binaries, PostgreSQL as the only required store, a Terraform module, no long-lived secrets. (Whether competitors gate comparable features is unverified; the claim Limen makes is only about itself.)

### What each pillar rests on (built, decided, or still to do)
| Pillar | Built today | Decided (ADR) | To add |
|---|---|---|---|
| Provable | Signed hash-chained audit, `limen-audit-verify`, recording hashes checked before playback | ADR-0029 evidence packs | **Access receipts** per session; offline verification of a receipt; policy digest recorded on every session event |
| Explainable | Dry run with a diff; denials audited with a reason | ADR-0028 | Decision traces, `explain`, effective-access diff, `policy test` |
| Justified | 10-minute certificates, locks, kills, revokes | ADR-0025 | Requests, approvals, break-glass; context sources for approvers; statement-level second approval (needs the Phase 6 protocol work) |
| Machines and agents | None yet | ADR-0019 (bots) | **Agent principals**: a bot kind for AI agents, per-action approval, transcript recording; an ADR when Phase 4 starts |
| Open and plain | Apache-2.0, Terraform audit module, compose stack | ADR-0024 | Honest "what is not built yet" page |

### What we will not claim
- "More secure than" anything. We claim properties that can be demonstrated and tested.
- Anything verified only against a local stand-in. The `unverified` label (ADR-0023) applies to marketing too.
- Compliance outcomes. Evidence packs help an audit; they are not a certification (ADR-0029).
- Features that are planned. The roadmap table says which are which, and so does every page that mentions one.

### How it shows up
- **Homepage and docs (ADR-0021):** lead with a receipt, not a feature grid: "Here is a session. Here is the proof. Verify it yourself with one command." A downloadable sample receipt and its verification command are on the landing page.
- **The console:** a session page gets a "Receipt" button next to "Replay"; a denied user sees *why* and how to ask.
- **README:** the tagline stays, the first paragraph gains the one-sentence version once receipts exist.
- **Demos:** a new demo (with Phase 6.5) ends by verifying a receipt offline, on a machine with no connection to the stack.

## Work this adds to the roadmap
- **Phase 6.5 (epic #19):** access receipts and offline verification (builds on ADR-0026 and ADR-0029); the policy digest on session events; context sources for approvers as an extension point in ADR-0025.
- **Phase 4:** the bot design gains an `agent` flavour; a short ADR before building.
- **Docs site phase:** the receipt page and sample.
Nothing here starts without the owner's approval of the phase it belongs to.

## Risks
- **A promise we can't keep:** "provable" must stay literally true. A receipt that verifies but omits something is worse than none, so the receipt format is specified and tested like a wire protocol (including a test that tampering with any part fails verification).
- **Agents are moving fast:** the agent pillar may need to change shape. It is a direction, not a contract, until Phase 4 designs it.
- **Positioning drift:** if the product starts to look like a feature checklist again, this ADR is the thing to reread.

## Consequences
- Receipts, explanations, and approvals move up in priority within Phase 6.5; protocol breadth stays on its own phases.
- Marketing copy is reviewed against this list of claims and the "will not claim" list.
- The owner can replace the direction (for example, to lead with agents) by amending this ADR; the pillars are independent enough to reorder.
