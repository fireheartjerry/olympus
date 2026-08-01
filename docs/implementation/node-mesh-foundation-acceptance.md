# Execution Node Mesh Foundation Acceptance

## Decision status: locally verified, not deployed

The execution-node foundation slice is implemented and verified against the
local gate. It is **not** deployed. No live VPS service, Tailscale Serve
mapping, Temporal server, Kubernetes object, Windows machine, or external
integration was created or mutated to produce this evidence.

| Required evidence | Record |
| --- | --- |
| Design specification | `docs/superpowers/specs/2026-08-01-distributed-execution-node-mesh-design.md` |
| Parent amendment | Section 23.1 of `2026-07-28-agentic-vps-god-agent-design.md` |
| Roadmap slice | Slice 1N in `2026-07-29-olympus-implementation-roadmap-design.md` |
| Operator runbook | `docs/operations/node-mesh.md` |
| Local suite | `uv run pytest -W error` — **239 passed**, of which 142 are new. |
| Post-merge CI | Pending. |
| Acceptance decision | Pending CI evidence. |

## Local evidence

The gate was run on 2026-08-01 against the working tree.

- `uv lock --check`, `uv sync --locked --all-groups`, `ruff format --check`,
  `ruff check`, and strict `mypy` completed successfully across 48 source
  files.
- `uv run pytest -W error` completed with **239 passed**. That includes:
  - registry tests covering enrollment issuance, expiry, replay, revocation,
    scope mismatch, declaration narrowing, heartbeat expiry, session
    replacement, the dispatch admission matrix, freeze idempotence, monotonic
    freeze epochs, and epoch-bound unfreeze;
  - protocol tests covering Ed25519 proof verification, altered payloads,
    wrong keys, enrollment-secret hashing, dedupe determinism, frame size and
    schema bounds, client/server frame separation, credential redaction, and
    hash-chain tamper detection;
  - session and dispatch tests covering mutual authentication, a forged
    control plane, an unexpected control-plane key identifier, an unsigned
    node, an unsupported protocol version, a revoked node, progress streaming,
    cancellation, deduplicated replay, reconnect replay, session loss,
    oversized output, secret redaction, artifacts, concurrency bounds, session
    replacement, and freeze behaviour;
  - workflow tests proving the bounded activity options, retry within the
    two-attempt worker-recovery bound, a non-retryable permanent refusal, and
    cancellation producing a declared `cancelled` outcome rather than a lost
    execution;
  - gateway tests covering credential and authority-header rejection, refusal
    status mapping, admission before any durable state exists, node lifecycle
    endpoints, console isolation, and audit exposure;
  - three end-to-end tests over real HTTP, a real WebSocket, and a real
    Temporal server that enroll a node, dispatch a job, stream progress,
    return a result, verify the audit chain, reconnect the node, and exercise
    the dispatch kill switch.
- The Helm gate was re-run unchanged: strict lint, render, and kubeconform
  strict validation of the same eight resources against Kubernetes 1.36.1
  schemas pinned at `05eeed51991935dd1f47cd3b3682de4e8af233f3`, plus the
  capacity and override guardrails. This slice adds no Kubernetes object.
- `uv run python -m olympus.demo.node_mesh` completed the full operator
  demonstration end to end on loopback.
- `git diff --check` completed successfully.

The gate made read-only package and pinned-tool downloads and started an
ephemeral local Temporal dev server on loopback. It contacted no target
integration, no live infrastructure, and no external-effect API.

## Required acceptance checklist

- [x] Only an authorized operator can issue capability grants, dispatch node
  work, or change mesh control state; an absent, wrong, or malformed
  credential is refused before anything else happens.
- [x] An enrollment token is single-use, short-lived, scope-bound, stored only
  as a domain-separated hash, revocable before redemption, and refused while
  the mesh is frozen.
- [x] Replaying a consumed token with a different key is refused and audited;
  retrying with the same key returns the original record so a network retry
  during enrollment is safe.
- [x] Both directions of the handshake are authenticated with Ed25519 proofs
  bound to the other party's fresh nonce and to the session identifier; a
  forged control plane, an unexpected key identifier, and an unsigned node are
  each refused.
- [x] A node's declared capability set can only narrow its operator grant,
  never widen it; unknown declared names are dropped rather than trusted.
- [x] A node whose heartbeats stop is derived offline and is not dispatchable;
  the sweeper detaches it and records the expiry.
- [x] Re-dispatching the same job identity and parameters replays the recorded
  result instead of repeating the work, across activity retries and across a
  reconnect.
- [x] Cancellation reaches the node, and the workflow returns a declared
  `cancelled` outcome rather than a failed or lost execution.
- [x] Job output, artifacts, progress events, frames, and per-node concurrency
  are bounded; oversized output is redacted first and then truncated with an
  explicit flag.
- [x] Credential-shaped strings are redacted on the node before transmission,
  again on receipt, and again before entering the audit chain.
- [x] Freezing refuses new admission at the gateway, refuses again inside the
  dispatch activity, cancels work in flight, and is idempotent; unfreezing
  requires naming the exact current freeze epoch.
- [x] The audit chain verifies, detects modification and reordering, and
  contains no credential material.
- [x] All node output carries the `external-untrusted` trust label; a node
  outcome cannot be constructed with the `control` label.
- [x] Only `system.inspect@1` is dispatchable. `shell.powershell@1`,
  `fs.read@1`, `fs.write@1`, `agent.claude@1`, `agent.codex@1`,
  `browser.session@1`, `desktop.stream@1`, and `desktop.takeover@1` are
  reserved and are refused at dispatch and at grant time.
- [x] Temporal owns every node job. The dispatch service holds connections
  only; no second orchestrator exists.
- [x] The Windows installer opens no inbound port, creates no listener, pins
  its dependencies by hash, passes the enrollment token on standard input
  rather than in the process argument list, and is re-runnable.
- [x] No secret, key, or token is committed to the repository.

## Known limitations recorded rather than hidden

- The registry, job records, and audit chain are in-process and are lost when
  the gateway restarts. PostgreSQL becomes their canonical owner in the
  persistence slice.
- There is no off-host audit export yet, so this slice claims tamper evidence
  but not off-host immutability.
- Unfreeze is bound to the freeze epoch but not yet to a Face ID assertion.
- The operator boundary is still the development shared token from the
  foundation slice; the trusted-ingress slice replaces it with a lease.
- Transport identity relies on Tailscale plus the application-layer
  control-plane key, not on a pinned TLS certificate.
- `system.inspect@1` has not been executed on a real Windows host, because no
  Windows machine was enrolled during this gate. Its Windows-specific memory
  and uptime probes are exercised only through the injected fake probe.

## Scope and authorization boundary

This slice authorizes designing the next node capability. It does not
authorize deployment, a Tailscale Serve change, a Kubernetes apply, Discord
connectivity, production credentials, a root broker operation, WebAuthn,
policy-bundle activation, shell or file access on any node, browser or desktop
control, or any external side effect.
