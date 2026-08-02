# Olympus Node-Mesh Persistence Design

**Status:** Approved

**Date:** 2026-08-01

**Owner:** Jerry

**Roadmap slice:** Slice 6 (node-mesh scope)

**Parent specifications:**

- `2026-07-28-agentic-vps-god-agent-design.md`
- `2026-07-29-olympus-implementation-roadmap-design.md`
- `2026-07-29-trusted-ingress-authority-control-design.md`
- `2026-08-01-distributed-execution-node-mesh-design.md`

## 1. Objective

Make PostgreSQL the canonical owner of node-mesh registry, enrollment, job
metadata, and audit state, so that the mesh survives a control-plane restart
without losing identity, grants, revocations, the dispatch kill switch, or the
audit chain.

Until this slice, the registry and audit chain lived in process memory. A
restart silently returned the mesh to an empty, unfrozen, unaudited state.
That is the defect this slice closes.

This slice is a prerequisite for the Slice 1 Control Store: leases, credentials,
and authority epochs need the same durable substrate and the same
transaction discipline established here.

## 2. Scope

### 2.1 Included

- A versioned, forward-only migration runner holding an advisory lock.
- PostgreSQL ownership of enrollment tokens, node records, the dispatch
  control state, node job metadata, and the audit chain.
- Audit appends that commit in the same transaction as the state change they
  describe.
- Restart recovery: sessions do not survive a restart and must not appear to.
- Reconciliation of job metadata whose owning workflow is no longer running.

### 2.2 Excluded

- Off-host audit export and tamper-resistant archival (next slice).
- Discord identity, WebAuthn credentials, authority leases, and signed policy
  (Slice 1 and Slice 2; this slice only prepares their substrate).
- Any new dispatchable capability. `system.inspect@1` remains the only one.
- pgvector, MinIO, Redis, and Temporal's own persistence backend.

### 2.3 Non-goals

- Multi-writer control planes. Exactly one control plane writes at a time,
  enforced by an advisory lock, not by optimistic concurrency.
- Retaining job payloads. Metadata is durable; parameters and outputs are not
  persisted by this slice.

## 3. Invariants Preserved

| Invariant | How this slice preserves it |
| --- | --- |
| Temporal owns workflow state | PostgreSQL stores job *metadata* for observation and reconciliation. It never becomes the authority for whether a job runs; a job exists here because a Temporal activity awaits it. |
| Audit is append-only | The audit table has no `UPDATE` or `DELETE` path in application code, a monotonic sequence with a unique constraint, and a hash chain verified on read. |
| A revoked node stays revoked | Revocation is durable and irreversible in storage; restart cannot resurrect a revoked node. |
| Freeze survives restart | The kill switch is a single durable row, and freeze epochs are monotonic. A restart while frozen comes back frozen. |
| Secrets never enter Git | Only the enrollment secret *hash* is stored, as before. The database URL lives in the untracked environment, never in the repository. |
| Reducing authority never needs authority | Freeze remains writable without a lease; unfreeze still requires the exact freeze epoch and, from Slice 1, fresh user verification. |

## 4. Schema

One migration, `0001_node_mesh`, creates:

- `schema_migrations(version, name, applied_at)` — the migration ledger.
- `enrollment_tokens` — keyed by `token_id`; stores `secret_hash`, scope
  (`node_name`, `kind`, `platform`), the capability grant, issuance and expiry,
  and the single-use consumption and revocation stamps.
- `nodes` — keyed by `node_id`; stores identity, public key, grants,
  declarations, labels, session binding, last heartbeat and health, and the
  quarantine and revocation stamps.
- `dispatch_control` — a single row pinned by a `CHECK (id = 1)` constraint,
  holding `frozen`, `freeze_epoch`, `changed_at`, and `reason`.
- `node_jobs` — keyed by `job_id`; stores node, capability, dedupe key,
  status, attempt, authority, timestamps, progress count, and reason.
- `node_audit_events` — the hash chain: `sequence` (unique, monotonic),
  `event_id`, `actor`, `action`, `decision`, `reason`, `node_id`, `job_id`,
  redacted `payload`, `payload_digest`, `previous_hash`, and `event_hash`.

Capability lists and labels are stored as ordered `text[]` so a grant round
trips to the exact tuple the registry compares against.

### 4.1 Audit sequencing

`sequence` is allocated inside the writing transaction as
`max(sequence) + 1` under the same row lock that guards the chain head, not
from a sequence generator. A generator would leave gaps on rollback, and a gap
is indistinguishable from a deletion in a chain whose whole purpose is to make
deletion visible.

## 5. Transaction Discipline

Every registry mutation that emits an audit event does both in one
transaction. The previous in-memory implementation appended to the audit log
*after* releasing its lock, so a crash between the two left a state change with
no audit record. Under PostgreSQL that ordering becomes a durable
inconsistency, so the audit append moves inside the transaction and the
`append` call becomes awaitable.

Denials audit too. A refused enrollment or a mismatched freeze epoch commits
its `deny` event even though it changes no other state.

## 6. Restart Recovery

A control-plane restart invalidates every live WebSocket, because sessions are
process-local connections. Recovery therefore runs before the mesh accepts
traffic and:

1. clears `session_id` and `session_started_at` on every node, so no node
   claims a session that no socket backs;
2. leaves `last_heartbeat_at` untouched, so state derivation ages nodes to
   `offline` naturally rather than erasing their history;
3. appends one `session-closed` audit event per cleared session, with the
   reason `control-plane-restart`; and
4. re-reads the dispatch control row, so a mesh frozen before the restart is
   still frozen after it.

Recovery is idempotent: running it twice clears nothing the second time and
appends no second event.

## 7. Reconciliation

Job metadata can outlive the workflow that owned it — a crash mid-dispatch
leaves a row in `dispatched` or `running` that nothing will ever complete.
Reconciliation marks any non-terminal job whose control plane no longer holds
a live session as `timed-out` with the reason `control-plane-restart`, and
audits each transition.

This never resurrects or re-dispatches a job. Temporal decides retries; this
only stops durable metadata from claiming a job is running when it is not.

## 8. Deployment

PostgreSQL 16 runs on the control-plane host bound to `127.0.0.1` with a
persistent volume. It exposes no public port and no management port. The
connection URL is supplied through the untracked environment.

The in-memory store remains for tests and the offline demonstration. It is
selected only when no database URL is configured, and the gateway logs which
store is canonical at startup so a production process cannot silently run on
memory.

## 9. Testing Strategy

- Migration tests: applying twice is a no-op; the ledger records one row.
- Round-trip tests per record type, including that an empty grant, unicode
  labels, and null health survive storage unchanged.
- Single-use enforcement: two concurrent redemptions of one token produce
  exactly one node.
- Audit tests: the chain verifies across a reconnect; a tampered payload,
  a deleted row, and a reordered sequence each fail verification.
- Atomicity: a forced failure after the state write and before commit leaves
  neither the state change nor its audit event.
- Restart tests: freeze, revoke, and quarantine all survive a store rebuild;
  sessions do not.
- Reconciliation tests: a non-terminal job is timed out exactly once.

Tests requiring PostgreSQL skip cleanly when no test database is configured,
and CI provides one as a service container.

## 10. Acceptance Gate

1. The migration applies to an empty database and is idempotent.
2. Registry, enrollment, job, and audit state survive a full process restart.
3. A frozen mesh restarts frozen; a revoked node restarts revoked.
4. The audit chain verifies end to end after a restart, and detects tampering.
5. No state change commits without its audit event, and no audit event commits
   without its state change.
6. The full suite, formatter, linter, and strict type check pass.
7. No credential, connection string, or payload is committed.

Passing this gate authorizes the off-host audit export slice. It does not
authorize any reserved capability, any new external effect, or Slice 1
authority activation.
