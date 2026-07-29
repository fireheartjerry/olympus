# Olympus Implementation Roadmap Design

**Status:** Approved

**Date:** 2026-07-29

**Owner:** Jerry

**Parent specification:** `2026-07-28-agentic-vps-god-agent-design.md`

## 1. Objective

Decompose the approved Olympus architecture into independently testable
capability slices. Each slice must leave the system safe, operable, and more
capable without weakening any invariant in Section 22 of the parent
specification.

## 2. Sequencing Principle

Implementation follows invariant-first vertical slices rather than parent
specification numbering or infrastructure layers. A slice crosses contracts,
workflow behavior, policy enforcement, tests, and operational evidence where
needed to unlock one bounded capability.

No slice unlocks merely because its code is merged. Each slice has an explicit
acceptance gate, and capability activation occurs through versioned policy
after the required evidence exists.

## 3. Slice Roadmap

### Slice 0 — Foundation Acceptance Closure

Record successful post-merge CI evidence and formally accept the existing
side-effect-free walking skeleton.

**Coverage:** Parent Sections 5, 8, 12, 15, 18, and 22.

**Gate:** The implementation SHA and successful Python and Helm jobs are
recorded in the foundation acceptance document.

### Slice 1 — Trusted Ingress and Emergency Control

Implement Discord ingress, literal commander verification, 24-hour authority
leases, anomaly revocation, and durable `/freeze`, pause, inspect, cancel, and
resume controls. This slice performs no privileged or third-party mutations.

**Coverage:** Parent Sections 6, 7, 10, and 22.

**Gate:** Only Jerry's configured Discord identity can submit commands;
expired, revoked, malformed, replayed, or anomalous leases cannot authorize
mutation; emergency controls remain effective across process restarts.

### Slice 2 — Immutable Governance Kernel

Define the policy bundle schemas and isolated release path for authorization,
budget, trust, approval, and root-broker policy. Verify signatures before
loading releases and prevent agent service credentials from modifying or
activating them.

**Coverage:** Parent Sections 10, 16.1, and 22.

**Gate:** Modified, unsigned, expired, rolled-back, or unauthorized bundles are
rejected; activation requires the approved release mechanism; agent
credentials cannot write the policy source or release path.

### Slice 3 — Authorization, Taint, Approval, Budget, and Audit

Implement typed action classification, transitive trust-label propagation,
literal payload-bound approvals, bounded schedule capabilities, the monthly
spending governor, and tamper-evident authorization audit events.

**Coverage:** Parent Sections 10, 14.1, 15, 16, 19.1, and 22.

**Gate:** Adversarial tests reject approval replay or alteration, tainted
privileged inputs, scope escape, missing audit records, and any attempt to
exceed the hard variable-spend ceiling.

### Slice 4 — Bounded Graph-of-Graphs Execution

Expand the no-op compiler into typed, inspectable execution DAGs. Temporal
remains the sole owner of durable execution state; LangGraph reasoning runs
only inside bounded Temporal activities.

**Coverage:** Parent Sections 5.2, 7, 8, and 15.

**Gate:** Replay, timeout, cancellation, bounded retry, fan-out, revision,
dead-letter, and worker-recovery tests pass without moving durable state into
LangGraph.

### Slice 5 — Isolated Workers and Admission

Add isolated Claude, Codex, Chromium, and verifier worker classes, worktree and
artifact boundaries, priority scheduling, and resource-aware admission and
degradation.

**Coverage:** Parent Sections 9 and 12.3 through 12.6.

**Gate:** Cross-worker isolation, saturation, constrained-mode,
degraded-mode, survival-mode, and control-plane priority tests pass.

### Slice 6 — Canonical Persistence and Artifact Plane

Introduce PostgreSQL/pgvector, Redis, MinIO, Temporal persistence, and
observability storage with one canonical owner per datum and rebuildable
derived projections.

**Coverage:** Parent Sections 13 and 17.

**Gate:** Ownership, migration, retention, rebuild, backup, restore, and
corruption tests pass without treating caches or indexes as canonical state.

### Slice 7 — Read-only Integrations and Shadow Mode

Add fake-backed and read-only Discord, Google Workspace, GitHub, browser, and
infrastructure contracts. Compile real requests into projected actions,
costs, approvals, and audit records without external mutation.

**Coverage:** Parent Sections 14, 18, 19, and Rollout Phase 1.

**Gate:** The one-hundred-job representative corpus completes with zero
critical policy misses.

### Slice 8 — Safe Local Autonomy

Enable research, code generation, isolated worktrees, tests, drafts, local
containers, and verifier-controlled revision without connected external
effects.

**Coverage:** Parent Rollout Phase 2 and representative Jobs 1, 4, and 9.

**Gate:** Seven stable days and at least 95 percent useful completion on
accepted pilot jobs.

### Slice 9 — External-effect Ledger and Connected Adapters

Implement the common intent, receipt, reconciliation, dedupe, and compensation
framework, then add Gmail, Calendar, Drive, GitHub, and browser adapters using
effect-specific strategies.

**Coverage:** Parent Section 15.1 and Rollout Phase 3.

**Gate:** Uncertain-completion, retry, compensation, provider-failure, and
post-effect verification tests cause no duplicate external effects.

### Slice 10 — Typed Root Broker

Implement the host-only signed broker with a fixed typed operation registry.
Keep the orchestrator non-root and require Face ID bound to the exact literal
command digest for arbitrary root commands.

**Coverage:** Parent Sections 11 and 16 and representative Job 8.

**Gate:** Signature, nonce, expiry, replay, operation-schema, literal-command,
socket-isolation, and privilege-boundary tests pass.

### Slice 11 — Production Control Plane and Recovery

Deploy the resource-bounded K3s control plane, private networking,
observability, secrets, encrypted backups, and disaster recovery procedures.

**Coverage:** Parent Sections 12, 17, and Rollout Phases 0A and 0B.

**Gate:** Restore, RPO/RTO, normal mixed-load, overload, survival-mode, audit,
and control-plane SLO tests pass. Live VPS mutation still requires explicit
task authorization for each operation.

### Slice 12 — High-autonomy Operations

Enable proactive chief-of-staff workflows, inbox and calendar automation,
signed schedules, routine reversible repairs, and self-scheduled follow-ups.

**Coverage:** Parent Rollout Phase 4 and representative Jobs 2, 3, 8, and 10.

**Gate:** Schedule-scope, expiry, anomaly, taint, protected-action, and
long-running reliability tests pass, followed by Jerry's explicit Face ID
activation.

### Slice 13 — Elastic Burst Workers

Add cost forecasting, temporary provider provisioning, private K3s joining,
draining, deletion, and orphan reconciliation.

**Coverage:** Parent Section 12.4, Rollout Phase 5, and representative Job 5.

**Gate:** The activation threshold is evidenced and twenty burst drills finish
with zero orphaned resources or spending-limit violations.

## 4. Per-slice Delivery Protocol

Each slice follows the same controlled cycle:

1. Derive and approve a focused design specification from the parent spec.
2. Map every affected Section 22 invariant and define the threat model.
3. Define typed interfaces, canonical data ownership, and failure states.
4. Produce a task-level, test-first implementation plan.
5. Implement against fakes or side-effect-free boundaries before enabling a
   real mutation.
6. Run unit, property, integration, adversarial, recovery, and replay tests
   appropriate to the slice.
7. Record immutable verification evidence in a slice acceptance document.
8. Merge narrowly, then activate capability only through the approved policy
   mechanism.

## 5. Immediate Next Step

With Slice 0 accepted, the next design unit is Slice 1: trusted Discord
ingress, authority leases, anomaly revocation, and emergency controls. Its
design must preserve the existing no-op execution boundary and must not
authorize Discord connectivity, WebAuthn deployment, production credentials,
or any external mutation until its separate implementation plan and execution
are approved.
