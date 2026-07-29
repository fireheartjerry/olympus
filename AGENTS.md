# Olympus Repository Instructions

Read the approved design specification before changing architecture or security behavior:

`docs/superpowers/specs/2026-07-28-agentic-vps-god-agent-design.md`

## Non-negotiable rules

- Preserve every design invariant in Section 22.
- Temporal owns durable workflow state; LangGraph reasoning runs inside Temporal activities.
- The orchestrator stays non-root. Root actions go through the signed, typed host broker.
- Never weaken literal signed approvals, transitive taint tracking, immutable policy releases, spending limits, bounded cycles, or external-effect reconciliation.
- Never place credentials, private keys, tokens, production payloads, or live infrastructure state in Git.
- Do not reboot, resize, deploy to, or mutate the live VPS unless the current task explicitly authorizes that exact operation.
- Keep `outputs/`, `work/`, generated artifacts, caches, and local secrets untracked.

## Engineering workflow

- Implement one approved plan slice at a time.
- Prefer a side-effect-free vertical slice before enabling a real external mutation.
- Use tests first for policy, workflow, taint, budget, idempotency, and admission behavior.
- Pin dependencies and deployment artifacts through lock files or immutable digests.
- Run the repository verification suite before committing.
- Keep commits narrow and name the invariant or capability they establish.
