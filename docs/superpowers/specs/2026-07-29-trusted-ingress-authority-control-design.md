# Olympus Trusted Ingress and Authority Control Design

**Status:** Approved

**Date:** 2026-07-29

**Owner:** Jerry

**Roadmap slice:** Slice 1

**Parent specifications:**

- `2026-07-28-agentic-vps-god-agent-design.md`
- `2026-07-29-olympus-implementation-roadmap-design.md`

## 1. Objective

Replace the development command boundary with a production-shaped,
single-commander control plane that:

- accepts Discord commands only from Jerry's immutable Discord user ID;
- restricts authority to an explicit allowlist of `AGENT OPS` guild and
  channel IDs;
- issues one server-side 24-hour authority lease after a production WebAuthn
  ceremony requiring user verification through phone Face ID;
- revokes authority and freezes new mutations when an anomaly is detected;
- provides durable freeze, inspect, pause, cancel, resume, and recovery
  controls; and
- preserves the existing side-effect-free execution boundary.

The authorized commander ID is the literal Discord snowflake
`628053765181800448`.

## 2. Scope

### 2.1 Included

- Discord interaction signature and timestamp verification.
- Literal commander, guild, and channel ID allowlists.
- Private WebAuthn credential registration and authentication.
- Stable private HTTPS origin and relying-party configuration compatible with
  Tailscale Serve.
- Single-use WebAuthn challenges.
- Server-side authority leases and monotonic authority epochs.
- One active mutation lease at a time.
- Atomic lease replacement, expiry, revocation, and anomaly freeze.
- Durable freeze, inspect, pause, cancel, resume, and recovery controls.
- Discord interaction deduplication.
- Security audit events and an append-only hash chain.
- Production startup guards that reject development authentication.
- Fake Discord transport and a browser/passkey-capable WebAuthn test harness.

### 2.2 Excluded

- Live Discord connection or credential installation.
- Live Tailscale Serve, VPS, K3s, DNS, PostgreSQL, or Temporal deployment.
- General policy-bundle activation.
- Transitive taint enforcement beyond preserving the existing command trust
  label.
- Spending authorization.
- Root broker operations.
- External integrations or side effects.
- Multi-user, organization, role, delegation, or enterprise IAM features.

These exclusions are later roadmap slices. They may be represented by typed
interfaces, but this slice cannot activate them.

## 3. Design Invariants

This slice preserves every invariant in Section 22 of the parent
specification. The directly exercised invariants are:

1. Discord supplies authenticated input but never authority by message
   content.
2. Internet-facing services and the orchestrator remain non-root.
3. Temporal remains the sole owner of workflow execution state.
4. Every job and control operation has a deadline, retry bound, and
   deduplication identity.
5. Identity, lease, freeze, and workflow state each have one canonical owner.
6. External and model-derived content cannot alter identity, authority scope,
   lease state, or recovery behavior.
7. Discord mutation authority requires a valid authority lease.
8. The system cannot autonomously expand its commander, guild, channel,
   credential, lease, or recovery scope.

This slice introduces no external-effect adapter, autonomous spending,
arbitrary root command, or high-autonomy activation path.

## 4. Architecture

### 4.1 Discord Adapter

The Discord adapter is a thin, stateless transport boundary. It:

1. Verifies Discord's interaction signature against the exact raw request
   body.
2. Rejects requests whose signed timestamp is outside the configured skew
   window.
3. Deduplicates by immutable Discord interaction ID.
4. Compares the user ID literally with `628053765181800448`.
5. Compares guild and channel IDs with explicit numeric allowlists.
6. Normalizes the accepted interaction into a typed command or control
   request.
7. Obtains an admission decision from the identity and control boundaries.
8. Starts the appropriate Temporal workflow and returns an acknowledgement.

Channel names and category names are display metadata only. Renaming a channel
cannot change its authority. Direct messages, threads, webhooks, other guilds,
and channels outside the allowlist are denied unless a later approved policy
explicitly adds their immutable IDs.

The adapter stores no credential, lease, freeze, job, or audit authority
state.

### 4.2 Identity Service

The identity service is the canonical owner of:

- WebAuthn credential records;
- registration and authentication challenges;
- authority epochs;
- lease metadata;
- lease expiry and revocation;
- anomaly records; and
- identity security audit events.

It exposes typed operations for credential registration, lease issuance,
lease validation, lease revocation, and anomaly reporting. It never accepts
authority instructions from natural-language content.

### 4.3 Private WebAuthn Application

The WebAuthn application is served only over stable private HTTPS. Its
configured origin is exact, and its relying-party ID is the stable Tailscale
DNS name described by the parent specification. Production startup rejects
localhost origins, HTTP origins, wildcard origins, an empty relying-party ID,
or an origin whose effective domain is incompatible with the relying-party
ID.

Registration and authentication require:

- an unexpired, single-use server-generated challenge;
- an exact expected origin and relying-party ID;
- user presence;
- user verification;
- an allowed credential and algorithm;
- a signature valid for the stored public key; and
- clone or counter checks supported by the authenticator.

Raw assertions, challenges, credential secrets, and session material are
never sent to Discord or written to ordinary application logs.

### 4.4 Control Workflows

Temporal workflows are the canonical owners of job execution and job-control
state. They accept typed signals for:

- freeze observation;
- pause;
- cancel;
- resume; and
- status inspection.

The workflow records control transitions durably and reaches a declared safe
checkpoint before pausing or cancelling. Slice 1 executes only the existing
non-side-effecting graph, so it has no compensation behavior.

The global freeze record is canonically stored by the control store and
mirrored into workflows through durable signals. Mutation-capable admission
checks the freeze before workflow start, and future mutation-capable
activities must check it again immediately before an effect.

### 4.5 Control Store

PostgreSQL is the canonical owner of credential, challenge, lease, authority
epoch, global freeze, anomaly, interaction-deduplication, and audit records.
Temporal is the canonical owner of workflow execution state. No Redis cache,
process memory, Discord message, or Temporal search attribute becomes
canonical authority state.

Transactions enforce:

- single-use challenges;
- one active authority epoch;
- atomic revocation and replacement;
- freeze-before-admission ordering;
- interaction uniqueness; and
- append-only audit sequencing.

### 4.6 Emergency Freeze Latch

The service maintains a host-local, integrity-protected emergency latch whose
only transition is from unfrozen to frozen. It exists so a verified `/freeze`
request can reduce authority when PostgreSQL is unavailable.

The latch cannot unfreeze, issue a lease, change scope, or authorize a
command. On recovery, the service reconciles a set latch into PostgreSQL
before accepting any mutation. Clearing the latch requires the normal
Face-ID-bound recovery flow and successful persistence in the canonical
store.

## 5. Authority Model

### 5.1 Lease Scope

A lease is bound to:

- Jerry's exact Discord user ID;
- the configured Discord guild ID;
- the configured `AGENT OPS` channel ID allowlist;
- the authenticating WebAuthn credential ID;
- the current authority epoch;
- issuance and absolute expiry timestamps; and
- the exact approved capability class.

The lease is stored server-side and is never represented as a bearer token in
Discord. Discord commands refer internally to the active lease record.

### 5.2 Single Active Lease

Only one mutation lease may be active. Successful Face ID authentication:

1. consumes the challenge;
2. increments the authority epoch;
3. revokes every lease from an earlier epoch;
4. creates one lease expiring no later than 24 hours after issuance; and
5. appends the corresponding audit events;

all in one database transaction.

Multiple passkeys may be registered for recovery, but they cannot create
overlapping active leases.

### 5.3 Control Authorization

| Control | Required authority |
| --- | --- |
| `/freeze` | Exact authorized Discord identity and scope; no active lease required |
| `/inspect` | Exact authorized Discord identity and scope; no active lease required |
| New ordinary command | Exact identity and scope plus active lease |
| `/pause` | Active lease |
| `/cancel` | Active lease |
| `/resume` | Active lease and system not frozen |
| `/unfreeze` | Fresh WebAuthn user verification bound to the literal recovery request and freeze epoch |

Reducing authority never depends on possessing mutation authority. Increasing
or restoring authority always requires fresh Face ID.

### 5.4 Credential Lifecycle

The first credential is enrolled only when the credential store is empty and
an operator starts a bounded bootstrap ceremony from the local host console.
Bootstrap creates a single-use, short-lived enrollment session bound to the
configured commander, origin, relying-party ID, and initial credential action.
It does not accept a credential or public key from a command-line argument.

After bootstrap, registering or revoking a credential requires an existing
credential with fresh user verification bound to the exact credential-change
payload. Losing every credential invokes a separate offline recovery ceremony;
editing credential rows or enabling bootstrap again is not recovery.

Bootstrap and recovery sessions are disabled during ordinary production
operation, cannot be initiated from Discord, and emit audit events.

## 6. Core Flows

### 6.1 Lease Issuance

1. Jerry opens the private approval URL.
2. The server creates a cryptographically random, single-use challenge with a
   short absolute expiry.
3. The phone passkey signs the challenge with user verification.
4. The identity service verifies the complete WebAuthn assertion.
5. A transaction consumes the challenge, advances the authority epoch,
   revokes earlier leases, creates the 24-hour lease, and appends audit
   events.
6. The application displays success without exposing lease material.

### 6.2 Discord Command Admission

1. Verify signature and signed timestamp before parsing trusted fields.
2. Deduplicate the Discord interaction.
3. Verify exact user, guild, and channel IDs.
4. Classify the typed request as inspection, freeze, recovery, job control, or
   ordinary command.
5. Check the emergency latch and canonical freeze state.
6. Require and validate the active lease where the control table requires it.
7. Construct an immutable command envelope containing identity evidence and
   the current authority epoch.
8. Start the Temporal workflow using a deterministic workflow ID derived from
   the Discord interaction ID.
9. Record admission and return the Discord acknowledgement.

The natural-language command text cannot affect steps 1 through 6.

### 6.3 Freeze

1. Verify the signed Discord request and exact authorized scope.
2. Set the emergency latch.
3. Atomically freeze mutation admission, revoke the active lease, advance the
   authority epoch, and append audit events when PostgreSQL is available.
4. Signal active Temporal workflows.
5. Confirm that the system is frozen without revealing security internals.

Repeated freeze commands are idempotent.

### 6.4 Anomaly Freeze

The following high-confidence conditions trigger lease revocation and a
global mutation freeze:

- Discord signature replay or interaction identity inconsistency;
- WebAuthn challenge replay or assertion alteration;
- WebAuthn credential counter regression or clone indication;
- repeated failed WebAuthn verification beyond a fixed bounded threshold;
- authority epoch or lease-state inconsistency;
- attempted production use of development authentication; or
- failure to prove consistent canonical authority state.

Wrong-user, wrong-guild, wrong-channel, malformed, and unauthenticated traffic
is rejected, rate-limited, and audited but does not independently freeze the
system. Rejected traffic cannot become a trivial denial-of-service path.

### 6.5 Recovery and Unfreeze

1. Create a recovery request containing a unique ID, the literal `unfreeze`
   action, current freeze epoch, commander ID, guild ID, channel scope digest,
   issue time, and expiry.
2. Hash the canonical recovery payload.
3. Bind the WebAuthn challenge to that digest.
4. Require fresh user verification.
5. Verify that the freeze epoch and scope have not changed.
6. In one transaction, consume the challenge, advance the authority epoch,
   issue a fresh lease, clear the canonical freeze, and append audit events.
7. Reconcile and clear the emergency latch only after the canonical
   transaction succeeds.

Old assertions, old recovery links, database edits, Discord messages, and
model output cannot unfreeze the system.

## 7. Audit Model

Every security-relevant decision produces a structured audit event containing:

- event ID and version;
- UTC timestamp;
- actor and authenticated transport identity;
- Discord interaction ID where applicable;
- credential ID digest where applicable;
- authority and freeze epochs;
- action and decision;
- stable reason code;
- related workflow ID;
- canonical payload digest;
- previous event hash; and
- current event hash.

The event body is canonicalized before hashing. Secret or assertion material
is excluded. PostgreSQL provides the initial append-only chain. The interface
anticipates signed off-VPS export in the observability and security slices,
but this slice cannot falsely claim off-host immutability.

## 8. Failure Handling

- Identity, lease, freeze, audit, clock, database, and signature uncertainty
  fails closed for authority-bearing commands.
- PostgreSQL failure blocks lease issuance, unfreeze, and mutations.
- Temporal failure blocks new workflow-backed commands without changing
  identity or freeze state.
- Duplicate Discord interactions map to the same workflow and response
  outcome.
- Duplicate WebAuthn submissions consume no additional lease or authority
  epoch.
- Discord receives generic safe failures; detailed reason codes remain in the
  audit trail.
- Lease expiry uses server-side UTC and an absolute timestamp. No sliding
  renewal exists.
- Clock movement beyond the configured tolerance freezes mutations.
- Freeze wins races with command admission through transaction ordering and a
  final pre-start freeze check.
- Restarted services reconstruct authority from PostgreSQL and the emergency
  latch, never from memory.

Every retry, challenge, interaction, lease, and workflow control has a fixed
maximum count or absolute deadline.

## 9. Development and Production Profiles

The existing development token and authority headers remain available only in
an explicit development profile bound to loopback. Production startup rejects:

- a configured development command token;
- development authority headers;
- loopback WebAuthn origins;
- non-HTTPS WebAuthn origins;
- missing Discord public keys or scope allowlists; and
- an empty or default commander ID.

No environment may silently fall back from production authentication to the
development path.

## 10. Testing Strategy

### 10.1 Unit and Property Tests

- Lease expiry, epoch monotonicity, and atomic replacement.
- Challenge single use and absolute expiry.
- Freeze monotonicity outside approved recovery.
- Discord interaction and workflow deduplication.
- Literal ID and scope comparison.
- Canonical recovery and audit payload hashing.
- Bounded failure counters, retries, and time windows.

### 10.2 WebAuthn Security Tests

- Wrong origin or relying-party ID.
- Missing user presence or user verification.
- Altered, expired, or replayed challenge.
- Disallowed credential or algorithm.
- Invalid signature.
- Counter regression or clone indication.
- Revoked credential.
- Recovery payload or freeze-epoch alteration.

### 10.3 Discord Security Tests

- Forged signature.
- Stale or future timestamp.
- Wrong commander, guild, or channel ID.
- Renamed allowed channel.
- Same name with a different ID.
- Direct message, thread, webhook, and duplicate interaction.
- Message content attempting to alter authority or scope.

### 10.4 Concurrency and Reliability Tests

- Freeze racing command admission.
- Freeze while PostgreSQL is unavailable.
- Lease replacement under concurrent assertions.
- Worker and service restart during pause, cancel, and recovery.
- Temporal unavailable before and after command admission.
- Emergency-latch reconciliation after database recovery.
- Audit append failure.

### 10.5 Production-boundary Tests

- Production rejects development authentication and unsafe origins.
- Services run non-root.
- No raw assertion, challenge, credential, or lease material reaches logs,
  Discord responses, or workflow inputs.
- Fake Discord transport and a real browser/passkey-capable WebAuthn harness
  exercise the complete local ceremony.

## 11. Acceptance Gate

Slice 1 is accepted only when:

1. Only Discord user `628053765181800448` in the exact configured guild and
   `AGENT OPS` channel IDs can submit commands or controls.
2. Production WebAuthn registration and authentication pass the complete
   local security harness.
3. Exactly one 24-hour mutation lease can be active.
4. Expired, revoked, replayed, altered, anomalous, or scope-mismatched
   authority is rejected.
5. `/freeze` and `/inspect` remain available without a lease.
6. Unfreeze succeeds only with fresh Face ID bound to the exact recovery
   payload and current freeze epoch.
7. Freeze, pause, cancel, resume, inspection, and workflow deduplication remain
   correct across process and worker restarts.
8. Freeze wins every tested race against mutation admission.
9. Production cannot start with development authentication.
10. No external effect, live Discord connection, live infrastructure
    mutation, or privileged operation occurs during the gate.

Passing this gate authorizes planning of the immutable governance kernel. It
does not authorize live deployment, credential installation, Discord
connectivity, or any external mutation.
