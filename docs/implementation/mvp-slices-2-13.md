# Olympus MVP Slices 2–13

**Status:** Implemented as a shallow, side-effect-free MVP

**Branch:** `feat/trusted-authority-control`

**Verification date:** 2026-07-29

## Capability map

| Slice | MVP capability | Primary implementation |
|---|---|---|
| 2 | Signed, canonical, expiring, rollback-resistant policy releases with an isolated activation principal | `olympus.governance.policy` |
| 3 | Typed actions, transitive taint, literal one-use approvals, bounded schedules, hard monthly budget, chained audit | `olympus.governance.authorization` |
| 4 | Deterministic typed DAG compilation with node, fan-out, timeout, retry, and cycle bounds | `olympus.graphs` |
| 5 | Claude, Codex, Chromium, and verifier admission with resource, concurrency, mode, worktree, and artifact isolation | `olympus.workers.admission` |
| 6 | Explicit canonical ownership, rebuildable projections, content-addressed artifacts, and verified backup/restore | `olympus.persistence.ownership` |
| 7 | Discord, Google, GitHub, browser, and infrastructure read-only shadow projections; 100-case corpus | `olympus.integrations.shadow` |
| 8 | Contained local research/code/test/draft/container capabilities with verifier-bounded revision | `olympus.workers.local_autonomy` |
| 9 | Idempotent effect intents, receipts, uncertain-completion reconciliation, and compensation | `olympus.effects.ledger` |
| 10 | Non-root peer boundary, signed typed host requests, nonce/expiry replay protection, literal command approval binding | `olympus.broker.root` |
| 11 | Control-plane degradation modes and authenticated encrypted recovery snapshots | `olympus.operations.control_plane` |
| 12 | Face-ID-verifier-gated high autonomy, scoped schedules, anomaly shutdown, and bounded follow-ups | `olympus.operations.autonomy` |
| 13 | Evidence-gated cost forecasts, private join, drain/delete, spending ceilings, and orphan reconciliation | `olympus.capacity.burst` |

The cross-slice integration test
`tests/integration/test_mvp_graph.py` proves a governed path from signed policy
activation through authorization, DAG compilation, worker admission, verified
local work, artifact persistence, shadow projection, a deduplicated fake
external effect, and a signed typed fake host operation.

## Verification evidence

The following commands passed from the repository worktree:

```text
uv lock --check
uv sync --locked --all-groups
uv run ruff format --check src tests migrations
uv run ruff check src tests migrations
uv run mypy
uv run pytest -W error -ra
git diff --check
pwsh -NoLogo -NoProfile -File deploy/helm/olympus-foundation/tests/verify.ps1 ...
```

Python result: **234 passed, 2 skipped**. The two skipped tests require the
explicit disposable PostgreSQL DSN. CI now provisions a digest-pinned
PostgreSQL 17.6 service, runs migrations down/up, and supplies that DSN, so
those tests are mandatory remotely rather than silently skipped.

Helm result: strict lint passed, all eight resources passed kubeconform, exact
VPS-4 capacity matched, and every malicious override case was rejected.

## Deliberate production gaps

This is a working governed MVP, not an activated production control plane:

- provider, root-host, burst-cloud, and local worker executors are contract
  fakes; they perform no live external or privileged mutation;
- PostgreSQL/Temporal durability is covered by existing adapters and tests,
  but the complete relational recovery test awaits the CI service run;
- Redis, MinIO, pgvector, observability, private K3s, secrets, and off-host
  backup services are modeled but not deployed;
- high-autonomy and arbitrary-root activation still require a real canonical
  Face ID proof verifier;
- the seven-day pilot, 60-minute mixed-load run, disaster-recovery drill, and
  live twenty-burst drill remain production activation gates.

No Discord credential, passkey, provider credential, live infrastructure,
external effect, root command, reboot, resize, or deployment was used.
