# Olympus

Olympus is Jerry's private, always-on agent orchestration platform: one governed command surface coordinating durable Claude, Codex, browser, Workspace, GitHub, and infrastructure workflows.

The implementation source of truth is the approved [design specification](docs/superpowers/specs/2026-07-28-agentic-vps-god-agent-design.md). Work begins with a side-effect-free vertical slice before privileged adapters or production mutations are enabled.

## Status

- Architecture: approved and resource-sized for the OVH VPS-4 production-v1 node.
- Implementation: planning.
- Repository visibility: private.

## Delivery sequence

1. Foundation and durable no-op command path.
2. Discord identity, authority leases, and inspect/freeze controls.
3. Signed policy, budget, approval, audit, and taint enforcement.
4. Isolated local Claude, Codex, browser, and verifier workers.
5. Workspace, GitHub, browser, and infrastructure adapters with reconciliation.
6. Production rollout gates, high autonomy, and optional elastic workers.

Security invariants in the approved design are release blockers, not backlog suggestions.
