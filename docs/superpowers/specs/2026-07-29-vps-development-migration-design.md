# Olympus VPS Development Migration Design

**Status:** Approved

**Date:** 2026-07-29

**Owner:** Jerry

## 1. Objective

Make the OVH VPS the primary development workspace for Olympus while
preserving GitHub as the canonical Git remote and retaining the existing local
repository as a rollback copy.

The migrated workspace must contain the complete tracked repository and Git
history at `/home/ubuntu/olympus`, reproduce the locked development
environment, and pass the repository verification suite on the VPS.

## 2. Scope

The migration will:

1. Push the verified local `main` branch to `origin`.
2. Clone `origin/main` into `/home/ubuntu/olympus` as the non-root `ubuntu`
   user.
3. Install the repository's pinned user-scoped development tools:
   - uv 0.11.19
   - CPython 3.13.13 through uv
   - Helm 3.17.3
   - kubeconform 0.8.0
4. Recreate the Python environment from `uv.lock`.
5. Run build, formatting, lint, strict typing, test, distribution, and Helm
   guardrail verification on the VPS.
6. Confirm the VPS checkout and GitHub `main` resolve to the same commit.
7. Preserve the local repository without deleting or rewriting it.

## 3. Explicit Exclusions

This migration does not:

- Copy `.env`, credentials, tokens, SSH keys, local caches, `.venv`,
  `outputs/`, `work/`, or other ignored/generated state.
- Install or activate K3s, Temporal Server, production services, systemd
  units, ingress, databases, or observability components.
- Reboot, resize, repartition, deploy to, or otherwise mutate the production
  runtime.
- Install a permanently root-running Olympus process.
- Change policy, approval, taint, budget, audit, or security behavior.

Service deployment remains a separate approved plan slice.

## 4. Transfer Design

GitHub is the transfer and canonical synchronization path:

```text
verified local main -> origin/main -> /home/ubuntu/olympus
```

Only committed and tracked Git content crosses the boundary. This avoids
transporting machine-specific state or secrets and provides a commit digest
that can be compared at every stage.

The VPS checkout uses the existing public HTTPS remote. Development commands
run as `ubuntu`; no root access is required for the repository or toolchain.

## 5. Toolchain Installation

Tools are installed under the `ubuntu` user's home directory. Downloads use
immutable versions and upstream checksums where release archives are
available. The migration must fail closed on a checksum mismatch.

uv installs CPython 3.13.13 and creates the project `.venv` from the committed
lockfile. Helm and kubeconform use the exact versions and checksums already
declared by the repository CI workflow.

Agent CLI authentication is not copied from the local machine. Codex or Claude
CLI installation and interactive authentication may be added after the
verified repository migration, but credentials must be entered or delegated
through their supported authentication flows on the VPS.

## 6. Verification

The migration succeeds only when the VPS proves all of the following:

1. `git status --short` is clean.
2. `HEAD`, `origin/main`, and the approved migration commit are identical.
3. `uv lock --check` succeeds.
4. `uv sync --locked --all-groups` succeeds.
5. Source and wheel distributions build and pass distribution-content
   verification.
6. Ruff formatting and lint checks pass.
7. Strict mypy checking passes.
8. The complete pytest suite passes with warnings treated as errors.
9. The Helm verifier passes strict lint, pinned-schema validation, capacity
   comparison, and invalid-override rejection.
10. `git diff --check` succeeds.

Verification artifacts remain under ignored paths and are not committed.

## 7. Failure and Rollback

The local repository remains untouched as the rollback source. If setup or
verification fails, the VPS workspace stays non-authoritative and the failure
is reported with the exact failing command.

Because `/home/ubuntu/olympus` is currently absent, initial clone failure can
be recovered by removing only that newly created incomplete directory and
retrying. No existing VPS data is replaced.

No deployment capability is unlocked by this migration. Production behavior
remains unchanged regardless of migration outcome.

## 8. Invariants

The migration preserves all invariants in the approved Olympus design:

- The orchestrator remains non-root.
- Temporal remains the sole owner of durable workflow state.
- No external effect path, signed approval rule, transitive taint rule,
  immutable policy release, spending limit, or execution bound is weakened.
- No secret or live infrastructure state enters Git.
- No live Olympus service or VPS infrastructure is mutated by this
  development-workspace migration.
