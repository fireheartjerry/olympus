# Phase 0 Foundation Walking Skeleton Acceptance

## Decision status: accepted

The foundation walking skeleton is accepted. GitHub Actions completed
successfully for post-merge `main` at the recorded commit, and both required
jobs passed.

| Required evidence | Record |
| --- | --- |
| Implementation commit SHA | `27a055cea59fe8a39cec8ef305d60da06ef71a28` |
| GitHub Actions run URL | https://github.com/fireheartjerry/olympus/actions/runs/30434521789 |
| `python` job conclusion | Success. |
| `helm` job conclusion | Success. |
| Acceptance decision | Accepted on 2026-07-29. |

## Current local evidence

The local gate was run against the implementation worktree on 2026-07-28.

- `uv lock --check`, locked dependency sync, Ruff format check, Ruff lint, and
  strict mypy completed successfully.
- `uv run pytest -W error` completed with **97 passed**. This includes the
  Temporal test-server integration tests, which start local test workers and
  prove both the workflow/activity boundary and the bounded unavailable-activity
  deadline without a Temporal CLI server.
- Helm 3.17.3 and kubeconform 0.8.0 completed the hardened verifier using
  Kubernetes **1.36.1** strict schemas pinned at
  `05eeed51991935dd1f47cd3b3682de4e8af233f3`: **8/8 rendered resources**
  validated.
- The verifier also checks the fixed capacity plan and rejects altered quota,
  namespace, unknown, string, and fractional overrides—including attempts that
  use `--skip-schema-validation`.
- `git diff --check` completed successfully before the documentation commit.

The manual Temporal/worker/gateway walkthrough in the README is an operator
procedure, not local evidence. The Temporal CLI was unavailable locally, so it
was not run. The gate contacted no target integration, live infrastructure, or
external-effect API. It did use read-only package, portable-tool, and
pinned-schema downloads; those did not exercise a target integration, live
infrastructure, or an external effect API.

## Required acceptance checklist

- [x] Reject blank, oversized, structurally invalid commands, bad development
  tokens, malformed/duplicate authority headers, and public gateway binds.
- [x] Capture commander and authority-lease IDs literally at the development
  gateway boundary.
- [x] Start the command workflow through the Temporal worker boundary in the
  local integration test.
- [x] Compile exactly one `record-command-without-side-effects` graph node;
  preserve its user-authorized taint, bounded node/fan-out values, and stable
  digest.
- [x] Prove the VPS-4 capacity plan preserves required headroom and stays
  within its 22-GiB pod-limit envelope.
- [x] Strictly render and validate eight chart resources: four namespaces,
  three priority classes, and the fixed local-worker `ResourceQuota`.
- [x] Render declared worker-priority and lifecycle metadata: the chart defines
  `olympus-worker` at `-10000` with `preemptionPolicy: Never`, assigns it to no
  workload in this slice, and gives singleton cluster-scoped resources
  `helm.sh/resource-policy: keep`.
- [x] Record the network-policy boundary: no `NetworkPolicy` is rendered; the
  namespace annotations record `not-installed` and the required pending
  blocked-admission status, but are inert metadata. Actual admission and
  network enforcement remain pending the dedicated security slice.
- [x] Link a successful pull-request run from this implementation branch or a
  post-merge `main` run, with both `python` and `helm` jobs green. A standalone
  implementation-branch push is not evidence because the workflow does not
  trigger for it.
- [x] Record the SHA and run URL in the status table, then mark this gate
  accepted in a follow-up evidence-only update.

## Scope and authorization boundary

This accepted gate authorizes planning—but not implementation—of the next
identity and authority-lease slice. It does not authorize a live VPS
deployment, a Kubernetes apply, Discord connectivity, production credentials,
a root broker, WebAuthn, policy-bundle activation, or any external side effect.
Temporal owns the walking skeleton's workflow state; LangGraph and privileged
adapters are outside this slice.
