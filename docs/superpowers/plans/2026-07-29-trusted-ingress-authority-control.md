# Trusted Ingress and Authority Control Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the production-shaped, single-commander Discord and WebAuthn authority boundary defined by Slice 1 without connecting live Discord, installing credentials, deploying, or enabling an external effect.

**Architecture:** A thin Discord adapter authenticates immutable transport identity and delegates admission to a PostgreSQL-backed identity/control service. Production WebAuthn issues one server-side 24-hour authority lease; Temporal owns durable job-control state; a one-way signed local latch preserves emergency freeze when PostgreSQL is unavailable.

**Tech Stack:** Python 3.13, FastAPI, Pydantic, Temporal Python SDK, SQLAlchemy 2, asyncpg, Alembic, py_webauthn, PyNaCl, PostgreSQL, pytest, Hypothesis.

---

## Scope Boundary

This plan implements code, migrations, local fakes, and automated tests only.
It does not authorize a live Discord connection, Tailscale Serve change,
passkey enrollment, PostgreSQL deployment, VPS mutation, Kubernetes apply,
root operation, policy activation, or external side effect.

The literal authorized commander is `628053765181800448`. Guild and `AGENT
OPS` channel IDs remain required production configuration because their
immutable values are not yet recorded.

## Initial File Map

- `src/olympus/authority/models.py`: immutable authority, freeze, challenge,
  credential, and audit domain types.
- `src/olympus/authority/repository.py`: transactional authority repository
  protocol and domain errors.
- `src/olympus/authority/sqlalchemy.py`: PostgreSQL implementation and
  transaction ordering.
- `src/olympus/authority/service.py`: lease, credential, freeze, recovery, and
  anomaly orchestration.
- `src/olympus/authority/latch.py`: atomic one-way signed emergency latch.
- `src/olympus/discord/contracts.py`: strict Discord interaction contracts.
- `src/olympus/discord/verify.py`: raw-body Ed25519 verification and timestamp
  freshness.
- `src/olympus/discord/service.py`: scope checks, typed classification,
  dedupe, admission, and acknowledgement.
- `src/olympus/webauthn/service.py`: registration and authentication ceremony
  verification behind a narrow backend protocol.
- `src/olympus/control/models.py`: typed job-control requests and statuses.
- `src/olympus/control/workflow.py`: durable Temporal pause, cancel, resume,
  freeze, and inspect behavior.
- `src/olympus/gateway/production.py`: production Discord and private WebAuthn
  HTTP routes.
- `src/olympus/gateway/production_settings.py`: fail-closed production
  configuration.
- `src/olympus/persistence/models.py`: SQLAlchemy tables and constraints.
- `migrations/`: pinned Alembic environment and initial authority schema.
- `tests/authority/`: authority state-machine, transaction, latch, and audit
  tests.
- `tests/discord/`: signature, scope, classification, dedupe, and admission
  tests.
- `tests/webauthn/`: ceremony and recovery binding tests.
- `tests/control/`: Temporal control and restart tests.
- `tests/gateway/test_production_app.py`: HTTP boundary and profile-isolation
  tests.

### Task 1: Pin Security and Persistence Dependencies

**Files:**
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Modify: `build-constraints.txt`
- Test: `tests/build/test_verify_distribution.py`

- [ ] **Step 1: Extend the distribution test**

Assert that installed metadata includes bounded requirements for
`sqlalchemy`, `asyncpg`, `alembic`, `webauthn`, and `pynacl`, and that
`hypothesis` is a development-only dependency.

- [ ] **Step 2: Run the test and verify failure**

Run:

```bash
uv run pytest tests/build/test_verify_distribution.py -q
```

Expected: FAIL because the new requirements are absent.

- [ ] **Step 3: Add bounded dependencies**

Add these project requirements:

```toml
"alembic>=1.16,<2",
"asyncpg>=0.30,<1",
"pynacl>=1.5,<2",
"sqlalchemy[asyncio]>=2.0,<3",
"webauthn>=2.5,<3",
```

Add `"hypothesis>=6.135,<7"` to the development group. Regenerate `uv.lock`
and add every newly introduced build dependency to `build-constraints.txt`
with the exact version and SHA-256 hashes emitted by `uv export`.

- [ ] **Step 4: Verify the dependency gate**

Run:

```bash
uv lock --check
uv sync --locked --all-groups
uv run pytest tests/build/test_verify_distribution.py -q
```

Expected: all commands exit `0`.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml uv.lock build-constraints.txt tests/build/test_verify_distribution.py
git commit -m "build: pin authority boundary dependencies"
```

### Task 2: Define Strict Authority and Control Contracts

**Files:**
- Create: `src/olympus/authority/__init__.py`
- Create: `src/olympus/authority/models.py`
- Create: `src/olympus/control/__init__.py`
- Create: `src/olympus/control/models.py`
- Modify: `src/olympus/contracts/commands.py`
- Create: `tests/authority/test_models.py`
- Create: `tests/control/test_models.py`
- Modify: `tests/contracts/test_commands.py`

- [ ] **Step 1: Write failing contract tests**

Cover:

```python
def test_lease_expiry_cannot_exceed_24_hours() -> None: ...
def test_authority_epoch_is_strictly_positive() -> None: ...
def test_recovery_payload_is_literal_and_canonical() -> None: ...
def test_freeze_epoch_is_monotonic() -> None: ...
def test_command_envelope_requires_discord_identity_evidence() -> None: ...
def test_control_request_rejects_unknown_fields() -> None: ...
```

Use exact boundary values, timezone-aware canonical ISO-8601 timestamps, and
Pydantic `extra="forbid"` for transport models.

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
uv run pytest tests/authority/test_models.py tests/control/test_models.py tests/contracts/test_commands.py -q
```

Expected: collection or import failure for the missing types.

- [ ] **Step 3: Implement the domain types**

Define:

```python
class AuthorityDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    FREEZE = "freeze"

class ControlAction(StrEnum):
    FREEZE = "freeze"
    INSPECT = "inspect"
    PAUSE = "pause"
    CANCEL = "cancel"
    RESUME = "resume"
    UNFREEZE = "unfreeze"

@dataclass(frozen=True)
class AuthorityContext:
    commander_id: str
    guild_id: str
    channel_id: str
    interaction_id: str
    authority_epoch: int | None
    lease_id: str | None

@dataclass(frozen=True)
class RecoveryPayload:
    request_id: str
    action: Literal["unfreeze"]
    freeze_epoch: int
    commander_id: str
    guild_id: str
    channel_scope_digest: str
    issued_at: str
    expires_at: str

@dataclass(frozen=True)
class ControlRequest:
    action: ControlAction
    target_workflow_id: str | None
    authority: AuthorityContext
```

Extend `CommandEnvelope` with immutable `guild_id`, `channel_id`,
`interaction_id`, and `authority_epoch`. Preserve the existing trust label and
execution bounds.

- [ ] **Step 4: Run focused tests**

Expected: all focused tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/olympus/authority src/olympus/control src/olympus/contracts tests/authority tests/control tests/contracts
git commit -m "feat: define literal authority contracts"
```

### Task 3: Enforce Production Configuration

**Files:**
- Create: `src/olympus/gateway/production_settings.py`
- Create: `tests/gateway/test_production_settings.py`
- Modify: `.env.example`

- [ ] **Step 1: Write failing settings tests**

Test exact rejection of:

- commander IDs other than `628053765181800448`;
- empty guild or channel allowlists;
- duplicate or nonnumeric Discord snowflakes;
- HTTP, localhost, wildcard, or mismatched WebAuthn origins;
- missing Discord public key;
- lease durations above 24 hours;
- development tokens or development headers in production; and
- non-absolute latch or database configuration.

- [ ] **Step 2: Run and verify failure**

```bash
uv run pytest tests/gateway/test_production_settings.py -q
```

Expected: import failure.

- [ ] **Step 3: Implement fail-closed settings**

Create `ProductionGatewaySettings(BaseSettings)` with:

```python
commander_id: Literal["628053765181800448"]
discord_application_public_key: SecretStr
discord_guild_id: str
discord_channel_ids: frozenset[str]
webauthn_origin: AnyHttpUrl
webauthn_rp_id: str
webauthn_rp_name: str = "Olympus"
lease_ttl: timedelta = timedelta(hours=24)
discord_timestamp_tolerance: timedelta = timedelta(minutes=5)
database_dsn: SecretStr
emergency_latch_path: Path
emergency_latch_verification_key: SecretStr
```

Use model validators for origin/RP compatibility and literal production
constraints. Do not include development defaults.

- [ ] **Step 4: Document placeholders safely**

Add variable names with nonfunctional placeholders to `.env.example`; never
add real IDs other than the approved non-secret commander ID, credentials, or
keys.

- [ ] **Step 5: Verify and commit**

```bash
uv run pytest tests/gateway/test_production_settings.py -q
git add .env.example src/olympus/gateway/production_settings.py tests/gateway/test_production_settings.py
git commit -m "feat: fail closed on production authority settings"
```

### Task 4: Verify and Normalize Discord Interactions

**Files:**
- Create: `src/olympus/discord/__init__.py`
- Create: `src/olympus/discord/contracts.py`
- Create: `src/olympus/discord/verify.py`
- Create: `tests/discord/test_verify.py`
- Create: `tests/discord/test_contracts.py`

- [ ] **Step 1: Write failing raw-body verification tests**

Cover valid Ed25519 signatures, forged signatures, altered bodies, malformed
hex, duplicate signature headers, stale/future timestamps, and signed bodies
whose parsed identity is outside scope.

- [ ] **Step 2: Run and verify failure**

```bash
uv run pytest tests/discord/test_verify.py tests/discord/test_contracts.py -q
```

Expected: import failure.

- [ ] **Step 3: Implement verification before parsing**

Expose:

```python
@dataclass(frozen=True)
class VerifiedDiscordRequest:
    raw_body: bytes
    signed_at: datetime

def verify_discord_request(
    *,
    raw_body: bytes,
    signature_values: Sequence[str],
    timestamp_values: Sequence[str],
    public_key: bytes,
    now: datetime,
    tolerance: timedelta,
) -> VerifiedDiscordRequest: ...
```

Require exactly one value for each signed header, use
`nacl.signing.VerifyKey.verify(timestamp_bytes + raw_body, signature)`, and
reject timestamps outside the symmetric tolerance.

After verification, parse strict contracts that retain interaction, user,
guild, and channel snowflakes literally.

- [ ] **Step 4: Add property tests**

Use Hypothesis to prove any one-byte body, timestamp, or signature mutation is
rejected.

- [ ] **Step 5: Verify and commit**

```bash
uv run pytest tests/discord -q
git add src/olympus/discord tests/discord
git commit -m "feat: authenticate literal Discord interactions"
```

### Task 5: Create the Canonical PostgreSQL Schema

**Files:**
- Create: `alembic.ini`
- Create: `migrations/env.py`
- Create: `migrations/script.py.mako`
- Create: `migrations/versions/20260729_01_authority_control.py`
- Create: `src/olympus/persistence/__init__.py`
- Create: `src/olympus/persistence/models.py`
- Create: `tests/persistence/test_schema.py`

- [ ] **Step 1: Write failing schema tests**

Assert exact tables and constraints for:

```text
webauthn_credentials
webauthn_challenges
authority_state
authority_leases
global_freeze
discord_interactions
authority_anomalies
security_audit_events
```

Require unique interaction IDs, one singleton authority row, one singleton
freeze row, positive epochs, challenge consumption timestamps, lease expiry,
revocation metadata, and unique audit sequence/hash fields.

- [ ] **Step 2: Run and verify failure**

```bash
uv run pytest tests/persistence/test_schema.py -q
```

Expected: import failure.

- [ ] **Step 3: Implement SQLAlchemy metadata and migration**

Use named constraints, UTC timestamps, binary credential public keys, SHA-256
digests, and `CHECK` constraints for positive epochs and fixed digest lengths.
The migration must create and downgrade exactly the Slice 1 schema.

- [ ] **Step 4: Verify migration shape**

Run the metadata tests and Alembic offline SQL generation:

```bash
uv run pytest tests/persistence/test_schema.py -q
uv run alembic upgrade head --sql
uv run alembic downgrade base --sql
```

Expected: exit `0`; generated SQL contains no destructive statement outside
the downgrade stream.

- [ ] **Step 5: Commit**

```bash
git add alembic.ini migrations src/olympus/persistence tests/persistence
git commit -m "feat: establish canonical authority schema"
```

### Task 6: Implement Atomic Authority Transactions and Audit Chain

**Files:**
- Create: `src/olympus/authority/repository.py`
- Create: `src/olympus/authority/sqlalchemy.py`
- Create: `tests/authority/test_repository_contract.py`
- Create: `tests/authority/test_sqlalchemy_repository.py`

- [ ] **Step 1: Write a reusable repository contract suite**

The suite must prove:

```python
async def test_challenge_is_consumed_once(repository: AuthorityRepository) -> None: ...
async def test_new_lease_revokes_prior_epoch_atomically(repository: AuthorityRepository) -> None: ...
async def test_freeze_revokes_lease_and_advances_epochs(repository: AuthorityRepository) -> None: ...
async def test_duplicate_interaction_returns_original_outcome(repository: AuthorityRepository) -> None: ...
async def test_audit_chain_rejects_missing_predecessor(repository: AuthorityRepository) -> None: ...
async def test_freeze_wins_concurrent_admission(repository: AuthorityRepository) -> None: ...
```

Run the contract against a deterministic in-memory fake and the SQLAlchemy
implementation against an isolated PostgreSQL database supplied by the test
environment. Skip only the PostgreSQL fixture when no explicit test DSN is
provided; CI must provide it before Slice 1 acceptance.

- [ ] **Step 2: Define the narrow repository protocol**

Include explicit methods for challenge creation/consumption, credential
changes, lease issuance/validation, freeze/recovery, anomaly recording,
interaction reservation/completion, and audit lookup. Do not expose generic
SQL execution.

- [ ] **Step 3: Implement serializable transactions**

Lock singleton authority and freeze rows in a stable order. Admission reads
and reserves interaction identity in the same transaction that checks the
current freeze and lease epochs. Hash audit events over canonical JSON and the
previous hash while holding the audit-head lock.

- [ ] **Step 4: Run concurrency tests repeatedly**

```bash
uv run pytest tests/authority/test_repository_contract.py tests/authority/test_sqlalchemy_repository.py -q
uv run pytest tests/authority/test_sqlalchemy_repository.py -q --count=20
```

If `pytest-repeat` is not introduced, use a shell loop with twenty explicit
pytest invocations instead of adding another dependency.

- [ ] **Step 5: Commit**

```bash
git add src/olympus/authority/repository.py src/olympus/authority/sqlalchemy.py tests/authority
git commit -m "feat: serialize lease freeze and audit state"
```

### Task 7: Implement the One-way Emergency Freeze Latch

**Files:**
- Create: `src/olympus/authority/latch.py`
- Create: `tests/authority/test_latch.py`

- [ ] **Step 1: Write failing latch tests**

Prove atomic creation, idempotent set, signature verification, rejection of
truncated or altered payloads, restrictive file mode, startup failure on an
invalid latch, and the absence of a public clear-without-proof operation.

- [ ] **Step 2: Implement the latch**

Persist canonical JSON containing version, set timestamp, freeze request ID,
and reason code. Sign the canonical bytes with an Ed25519 signing key exposed
only through a `LatchSigner` protocol. Write to a same-directory temporary
file, `fsync`, atomically replace, and `fsync` the directory.

Expose:

```python
class EmergencyFreezeLatch:
    def is_set(self) -> bool: ...
    def set(self, request_id: str, reason: FreezeReason, now: datetime) -> None: ...
    def reconcile_and_clear(self, proof: CanonicalRecoveryProof) -> None: ...
```

`reconcile_and_clear` must require a repository-issued proof containing the
new authority and freeze epochs. No boolean or caller assertion is accepted.

- [ ] **Step 3: Run failure-injection tests**

Mock write, fsync, replace, and directory-fsync failures and prove that no
failure yields an apparently valid cleared state.

- [ ] **Step 4: Verify and commit**

```bash
uv run pytest tests/authority/test_latch.py -q
git add src/olympus/authority/latch.py tests/authority/test_latch.py
git commit -m "feat: preserve one-way emergency freeze"
```

### Task 8: Implement Production WebAuthn Ceremonies

**Files:**
- Create: `src/olympus/webauthn/__init__.py`
- Create: `src/olympus/webauthn/backend.py`
- Create: `src/olympus/webauthn/service.py`
- Create: `tests/webauthn/test_service.py`
- Create: `tests/webauthn/test_recovery.py`

- [ ] **Step 1: Write failing ceremony tests**

Cover bootstrap-only-when-empty, single-use challenges, correct RP/origin,
required user verification, valid algorithms, invalid signatures, revoked
credentials, counter regression, duplicate assertion, additional credential
authorization, and exact recovery-payload binding.

- [ ] **Step 2: Define a backend adapter**

Wrap `py_webauthn` behind:

```python
class WebAuthnBackend(Protocol):
    def registration_options(self, request: RegistrationRequest) -> PublicKeyOptions: ...
    def verify_registration(self, request: RegistrationVerification) -> VerifiedRegistration: ...
    def authentication_options(self, request: AuthenticationRequest) -> PublicKeyOptions: ...
    def verify_authentication(self, request: AuthenticationVerification) -> VerifiedAuthentication: ...
```

Tests use a deterministic fake for state-machine coverage and focused
contract tests against the real library for serialization and verification
mapping.

- [ ] **Step 3: Implement ceremony orchestration**

Bind every stored challenge to a purpose, commander, RP ID, origin, payload
digest, issue time, and absolute expiry. Consume it transactionally before
committing credential, lease, or recovery changes. Counter regression records
an anomaly and invokes freeze.

- [ ] **Step 4: Verify and commit**

```bash
uv run pytest tests/webauthn tests/authority -q
git add src/olympus/webauthn tests/webauthn
git commit -m "feat: bind Face ID ceremonies to authority"
```

### Task 9: Add Durable Temporal Job Controls

**Files:**
- Create: `src/olympus/control/workflow.py`
- Modify: `src/olympus/workflows/command.py`
- Modify: `src/olympus/runtime/worker.py`
- Create: `tests/control/test_workflow.py`
- Modify: `tests/workflows/test_command_workflow.py`

- [ ] **Step 1: Write failing workflow tests**

Prove inspect, pause, resume, cancel, and freeze signals survive worker
restart; cancelled work stops at a safe checkpoint; resume is rejected while
frozen; duplicate signals are idempotent; and all waits have absolute
deadlines.

- [ ] **Step 2: Implement typed workflow state**

Use Temporal signal and query definitions. Keep only workflow execution state
inside the workflow. Pass authority decisions into the workflow as immutable
admission evidence; never query PostgreSQL from deterministic workflow code.

- [ ] **Step 3: Add checkpoint behavior**

Before scheduling each activity, wait while paused, stop when cancelled or
frozen, and record a stable terminal receipt. Continue using bounded activity
timeouts and retry counts.

- [ ] **Step 4: Verify histories**

Assert the Temporal histories contain signals and bounded activity options,
and replay the histories with the worker replayer.

- [ ] **Step 5: Commit**

```bash
git add src/olympus/control src/olympus/workflows src/olympus/runtime tests/control tests/workflows
git commit -m "feat: make emergency job controls durable"
```

### Task 10: Build Discord Admission and Control Routing

**Files:**
- Create: `src/olympus/discord/service.py`
- Create: `tests/discord/test_service.py`
- Modify: `src/olympus/gateway/app.py`
- Modify: `tests/gateway/test_app.py`

- [ ] **Step 1: Write failing admission tests**

Cover literal scope, `/freeze` and `/inspect` without a lease, authority
requirements for ordinary commands and other controls, deterministic workflow
IDs, duplicate interactions, freeze races, generic denial responses, and
natural-language attempts to alter authority.

- [ ] **Step 2: Implement classification**

Classification recognizes only registered Discord application command IDs and
typed option fields. It never infers a control action from arbitrary message
text. Ordinary natural-language input remains a command payload.

- [ ] **Step 3: Implement admission orchestration**

Reserve the interaction and obtain an atomic `AdmissionReceipt` from the
repository. Set the emergency latch before canonical freeze. Start workflows
with ID `discord-{interaction_id}`. Complete the interaction record with the
accepted workflow ID or stable denial reason.

- [ ] **Step 4: Preserve the development path**

Keep the existing development gateway behavior and tests unchanged behind its
explicit settings type. Do not share production routes or authentication
dependencies with it.

- [ ] **Step 5: Verify and commit**

```bash
uv run pytest tests/discord tests/gateway/test_app.py -q
git add src/olympus/discord src/olympus/gateway/app.py tests/discord tests/gateway/test_app.py
git commit -m "feat: admit commands through server-side authority"
```

### Task 11: Expose Private WebAuthn and Discord HTTP Boundaries

**Files:**
- Create: `src/olympus/gateway/production.py`
- Create: `src/olympus/runtime/production_gateway.py`
- Create: `tests/gateway/test_production_app.py`
- Modify: `tests/runtime/test_entrypoints.py`

- [ ] **Step 1: Write failing route tests**

Test:

```text
POST /v1/discord/interactions
POST /v1/webauthn/register/options
POST /v1/webauthn/register/verify
POST /v1/webauthn/lease/options
POST /v1/webauthn/lease/verify
POST /v1/webauthn/recovery/options
POST /v1/webauthn/recovery/verify
GET  /health/live
GET  /health/ready
```

Assert strict media types, body-size limits, no permissive CORS, generic
security failures, no secret response fields, and readiness failure when
canonical authority state is unavailable or inconsistent.

- [ ] **Step 2: Build explicit dependency wiring**

`create_production_app` receives constructed Discord, WebAuthn, authority,
latch, audit, and Temporal dependencies. No route constructs repositories or
reads ambient global state.

- [ ] **Step 3: Enforce private WebAuthn host/origin**

Reject mismatched `Host`, `Origin`, and forwarded host/proto data unless they
match an explicit trusted-proxy configuration. Do not trust forwarding
headers from arbitrary peers.

- [ ] **Step 4: Add the production entrypoint**

Bind according to explicit private-listener configuration, refuse root
execution, load no development token, and fail before opening a socket when
configuration or authority state is unsafe.

- [ ] **Step 5: Verify and commit**

```bash
uv run pytest tests/gateway/test_production_app.py tests/runtime/test_entrypoints.py -q
git add src/olympus/gateway/production.py src/olympus/runtime/production_gateway.py tests/gateway/test_production_app.py tests/runtime/test_entrypoints.py
git commit -m "feat: expose private production authority boundary"
```

### Task 12: Run Adversarial and Recovery Gates

**Files:**
- Create: `tests/security/test_authority_gauntlet.py`
- Create: `tests/security/test_no_authority_leaks.py`
- Create: `tests/integration/test_authority_recovery.py`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Add the literal policy-miss corpus**

Create parameterized cases for unauthorized user, guild, channel, expired
lease, old epoch, replayed interaction, altered WebAuthn payload, old freeze
epoch, missing audit append, latch tampering, production development-token
use, and natural-language self-authorization.

- [ ] **Step 2: Add recovery integration**

Against PostgreSQL and the Temporal test server:

1. issue a lease;
2. admit a command;
3. freeze during execution;
4. kill and restart the worker;
5. prove the command remains stopped;
6. attempt stale recovery and prove denial;
7. complete fresh Face-ID-backed recovery;
8. prove a new epoch and lease are required to resume.

- [ ] **Step 3: Add leakage tests**

Capture HTTP responses, structured logs, workflow inputs, exceptions, and
audit events. Assert absence of raw challenges, assertions, credential public
keys, database DSNs, signing keys, and lease material.

- [ ] **Step 4: Extend CI**

Add a pinned PostgreSQL service container with explicit health checks and a
non-production test DSN. Run migrations up and down before the Python test
suite. Preserve all existing Python and Helm gates.

- [ ] **Step 5: Run the complete gate**

```bash
uv lock --check
uv sync --locked --all-groups
uv run ruff format --check src tests migrations
uv run ruff check src tests migrations
uv run mypy
uv run alembic upgrade head
uv run pytest -W error
uv run alembic downgrade base
git diff --check
```

Expected: every command exits `0`.

- [ ] **Step 6: Commit**

```bash
git add tests/security tests/integration .github/workflows/ci.yml
git commit -m "test: enforce trusted authority recovery gate"
```

### Task 13: Record Slice 1 Acceptance

**Files:**
- Create: `docs/implementation/slice-1-trusted-ingress-acceptance.md`
- Modify: `README.md`

- [ ] **Step 1: Write the acceptance record**

Record exact local commands, test counts, migration results, Temporal replay
evidence, PostgreSQL version, unresolved live activation prerequisites, and
the explicit statement that no Discord credential, passkey, live
infrastructure, or external effect was used.

- [ ] **Step 2: Update project status**

Describe the production-shaped authority boundary and retain the clear
distinction between implemented code and live activation.

- [ ] **Step 3: Run the documentation gate**

```bash
git diff --check
rg -n 'TBD|TODO|Pending: add|development-only-token-change-before-use' docs/implementation/slice-1-trusted-ingress-acceptance.md
```

Expected: `git diff --check` exits `0`; the placeholder scan returns no match.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/implementation/slice-1-trusted-ingress-acceptance.md
git commit -m "docs: define trusted ingress acceptance gate"
```

## Plan Self-review Checklist

- Every affected Section 22 invariant is mapped in the approved Slice 1 design.
- Temporal retains sole ownership of workflow execution state.
- PostgreSQL owns authority records; caches and process memory do not.
- The commander ID is literal; guild and channel IDs fail closed until
  configured.
- Production WebAuthn is implemented, but live enrollment and deployment are
  excluded.
- No task enables an external effect or root operation.
- Freeze can reduce authority during database failure; only canonical
  Face-ID-bound recovery can restore it.
- All retries, challenges, leases, controls, and workflows are bounded.
