# Graph Report - olympus  (2026-08-02)

## Corpus Check
- 192 files · ~132,886 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 3104 nodes · 8195 edges · 148 communities (119 shown, 29 thin omitted)
- Extraction: 86% EXTRACTED · 14% INFERRED · 0% AMBIGUOUS · INFERRED: 1130 edges (avg confidence: 0.51)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `d076de6d`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_registry.py
- AuditDraft
- NodeMeshError
- authorization.py
- NodeAgent
- test_node_approvals.py
- Mesh
- SqlAlchemyAuthorityRepository
- ProductionGatewaySettings
- crypto.py
- postgres_store.py
- node_edge.py
- NodeRegistry
- test_file_read.py
- test_nodes_cli.py
- NodeRecord
- test_file_write.py
- AuthorityLease
- signing.py
- Credential
- test_vps4_capacity.py
- test_protocol_primitives.py
- test_production_app.py
- CommandWorkflow
- DiscordInteraction
- LocalEd25519Signer
- S3ObjectLockStore
- AuditExporter
- FakeBurstProvider
- EffectExecutor
- Olympus Trusted Ingress and Authority Control Design
- AuthorityRepository
- __main__.py
- ExportSegment
- latch.py
- InMemoryAuthorityRepository
- test_signing.py
- policy.py
- root.py
- CommandEnvelope
- Olympus — Agentic VPS God Agent Design Specification
- .handshake
- admission.py
- scopes.py
- file_read.py
- CapabilityRequest
- commands.py
- InMemoryArtifactPlane
- node_mesh.py
- Olympus Distributed Execution Node Mesh Design
- Challenge
- control_plane.py
- LocalTask
- test_app.py
- Node Capability `fs.read@1` — Scoped File Read
- 3. Slice Roadmap
- authority/models.py
- test_governed_mvp_path_reaches_fake_effects_with_complete_boundaries
- Any
- FileReadScope
- ScopeError
- FakeWorkflowGateway
- .dispatch_job
- Initial File Map
- test_agent_runtime.py
- .redeem_enrollment_token
- .run_job
- Install-OlympusNode.ps1
- Initial File Map
- Olympus Node-Mesh Persistence Design
- test_node_mesh_end_to_end.py
- TrustedSigner
- encode_frame
- Olympus Execution Node Mesh — Operator Runbook
- NodeJobWorkflow
- Olympus Signed Audit Export — Operator Runbook
- Olympus Node Mesh — Security Model
- Olympus Production Gateway — Deployment Runbook
- 19. Representative Workload Corpus
- .dispatch_node_job
- test_node_job_workflow.py
- channel.py
- open_session_channel
- properties
- properties
- Olympus Windows Node Agent
- README.md
- Olympus VPS Development Migration Design
- NodeAuditLog
- _exercises
- required
- VPS Development Migration Implementation Plan
- 20. Rollout
- FakeProbe
- values.schema.json
- workerQuota
- Execution Node Mesh Foundation Acceptance
- Discord Credential Recovery and Authority Bootstrap Readiness
- Olympus
- test_serve_loop.py
- 12. K3s Deployment
- SegmentSigner
- Phase 0 Foundation Walking Skeleton Acceptance
- 7. Worker Protocol `olympus-node/1`
- test_contracts.py
- Olympus Foundation Helm Chart
- 4. Architecture
- .validate_dev_command_token
- test_package.py
- test_gateway_runtime_wires_temporal_starter_and_loopback_uvicorn
- Olympus Repository Instructions
- 10. Permission and Approval Model
- 6. Discord Experience
- env.py
- data
- requestsCpuMillicores
- .validate_node_mesh_bounds
- .__init__
- systemd/README.md
- restart-gateway-if-cert-changed.sh
- activities/__init__.py
- authority/__init__.py
- broker/__init__.py
- capacity/__init__.py
- contracts/__init__.py
- control/__init__.py
- demo/__init__.py
- discord/__init__.py
- effects/__init__.py
- gateway/__init__.py
- governance/__init__.py
- graphs/__init__.py
- integrations/__init__.py
- nodes/__init__.py
- olympus/operations/__init__.py
- persistence/__init__.py
- runtime/__init__.py
- webauthn/__init__.py
- workers/__init__.py
- workflows/__init__.py
- authentication/__init__.py
- olympus

## God Nodes (most connected - your core abstractions)
1. `NodeMeshError` - 130 edges
2. `NodeRegistry` - 124 edges
3. `NodeReason` - 93 edges
4. `NodeSession` - 75 edges
5. `AuditDraft` - 72 edges
6. `NodeDispatchService` - 70 edges
7. `Mesh` - 67 edges
8. `GatewaySettings` - 65 edges
9. `NodeAgent` - 65 edges
10. `NodeJobRequest` - 64 edges

## Surprising Connections (you probably didn't know these)
- `main()` --calls--> `call()`  [INFERRED]
  scripts/audit_export_live_proof.py → tests/integration/test_node_mesh_end_to_end.py
- `_ReExportingStore` --uses--> `ObjectAlreadyExists`  [INFERRED]
  tests/audit_export/test_audit_export.py → src/olympus/audit_export/store.py
- `_ReExportingStore` --uses--> `ObjectStoreError`  [INFERRED]
  tests/audit_export/test_audit_export.py → src/olympus/audit_export/store.py
- `_ReExportingStore` --uses--> `S3ObjectLockStore`  [INFERRED]
  tests/audit_export/test_audit_export.py → src/olympus/audit_export/store.py
- `Ed25519TestSigner` --uses--> `FreezeReason`  [INFERRED]
  tests/authority/test_latch.py → src/olympus/authority/latch.py

## Import Cycles
- None detected.

## Communities (148 total, 29 thin omitted)

### Community 0 - "test_registry.py"
Cohesion: 0.06
Nodes (90): generate_node_keypair(), Generate an Ed25519 identity. The private half never leaves its machine., build_client(), enroll(), FakeJobStarter, issue(), Any, parametrize (+82 more)

### Community 1 - "AuditDraft"
Cohesion: 0.04
Nodes (46): AuditDraft, compute_event_hash(), link_event(), NodeAuditEvent, Any, datetime, Seal one draft into the chain at a sequence the caller already holds. Every…, Recompute every link and confirm the sequence, linkage, and digests. (+38 more)

### Community 2 - "NodeMeshError"
Cohesion: 0.12
Nodes (60): AuditEventResponse, AuditResponse, CapabilityResponse, ControlResponse, EnrollRequest, EnrollResponse, FreezeRequest, HealthResponse (+52 more)

### Community 3 - "authorization.py"
Cohesion: 0.07
Nodes (44): Action, ActionClass, _audit_hash(), AuthorizationAudit, AuthorizationAuditEvent, AuthorizationDecision, AuthorizationDenied, AuthorizationEngine (+36 more)

### Community 4 - "NodeAgent"
Cohesion: 0.09
Nodes (46): AgentIdentity, _artifact_frame(), NodeAgent, ClientFrame, ServerFrame, Node end of ``olympus-node/1``. The agent dials out, verifies the control plane…, What this agent is *able* to serve — not what it may do. Scoped capabilities…, Queue a frame without blocking; report whether it will actually be sent. (+38 more)

### Community 5 - "test_node_approvals.py"
Cohesion: 0.06
Nodes (57): ApprovalDenied, IssuedApproval, node_write_action_digest_from_content(), NodeApprovalIssuer, NodeApprovalVerifier, Any, datetime, Exception (+49 more)

### Community 6 - "Mesh"
Cohesion: 0.13
Nodes (60): FakeCapabilityProvider, Deterministic provider used by tests and by the built-in demo. It can succeed,…, create_channel_pair(), Return two connected in-memory channel halves., Task, connect(), hostile_connection(), job() (+52 more)

### Community 7 - "SqlAlchemyAuthorityRepository"
Cohesion: 0.10
Nodes (35): async_sessionmaker, AsyncSession, DeclarativeBase, AdmissionDenied, AdmissionReceipt, _audit_hash(), AuditEvent, AuthorityRepositoryError (+27 more)

### Community 8 - "ProductionGatewaySettings"
Cohesion: 0.06
Nodes (45): _is_ip_address(), ProductionGatewaySettings, BaseSettings, field_validator, model_validator, Path, SecretStr, Self (+37 more)

### Community 9 - "crypto.py"
Cohesion: 0.07
Nodes (37): Ed25519PrivateKey, Ed25519PublicKey, TrustLabel, CapabilityDescriptor, CapabilityRisk, CapabilityStatus, describe_capability(), _descriptor() (+29 more)

### Community 10 - "postgres_store.py"
Cohesion: 0.07
Nodes (27): Jsonb, EnrollmentTokenRecord, NodeHealthSnapshot, NodeKind, NodePlatform, StrEnum, One single-use enrollment grant. The secret itself is never stored., Last self-reported health. Node-reported, therefore untrusted. (+19 more)

### Community 11 - "node_edge.py"
Cohesion: 0.06
Nodes (43): HTTPException, NodeDispatchActivities, Activities that reach live node sessions. They are hosted by the process that…, create_app(), Client, FastAPI, TemporalCommandStarter, matches_development_token() (+35 more)

### Community 12 - "NodeRegistry"
Cohesion: 0.07
Nodes (36): AsyncConnectionPool, requires_postgres, datetime, NodeRegistry, Canonical owner of node identity, capability grants, and dispatch admission., Append a standalone audit event that changes no other state., Revoke an unconsumed enrollment token so it can never be redeemed., Detach sessions whose heartbeats stopped arriving; return affected nodes. (+28 more)

### Community 13 - "test_file_read.py"
Cohesion: 0.10
Nodes (51): Read a file, or refuse. Never leaves the granted root., read_within_scope(), fixture, Path, skipif, Adversarial tests for the node half of ``fs.read@1``, against a real…, Refused on being a link, not on where it points. Deciding by destination would…, A FIFO with no writer blocks `open()` indefinitely. This is a real denial of… (+43 more)

### Community 14 - "test_nodes_cli.py"
Cohesion: 0.08
Nodes (47): build_parser(), _call(), command_audit(), command_freeze(), command_grant(), command_list(), command_quarantine(), command_revoke() (+39 more)

### Community 15 - "NodeRecord"
Cohesion: 0.06
Nodes (27): _decode_scopes(), Any, Render stored scopes for an operator to read. Stored as canonical JSON text per…, NodeRecord, NodeState, NodeView, Canonical registry record for one enrolled machine., Derived, presentation-safe projection of a node at one instant. (+19 more)

### Community 16 - "test_file_write.py"
Cohesion: 0.12
Nodes (46): _atomic_write(), _existing_kind(), FileWriteProvider, _open_parent_directory(), Path, Write a file atomically inside the granted root, or refuse., What is already at ``name``, without following a link to find out., Write to a sibling temporary file, flush it, then rename into place. The rename… (+38 more)

### Community 17 - "AuthorityLease"
Cohesion: 0.08
Nodes (38): given, AuthorityLease, DiscordVerificationError, datetime, timedelta, ValueError, Raised when a Discord transport request cannot be authenticated., VerifiedDiscordRequest (+30 more)

### Community 18 - "signing.py"
Cohesion: 0.09
Nodes (41): chain(), main(), ok(), Live proof of the signed audit export against real AWS. Run this after any…, Gather exactly what an offline verifier needs, and nothing else. Everything…, Ask the key-backed question, which ``verify`` deliberately does not. ``verify``…, Whether what is off-host is a complete, unbroken chain., VerificationResult (+33 more)

### Community 19 - "Credential"
Cohesion: 0.12
Nodes (24): Credential, AuthenticationRequest, _json_options(), Protocol, PyWebAuthnBackend, RegistrationRequest, VerifiedAuthentication, VerifiedRegistration (+16 more)

### Community 20 - "test_vps4_capacity.py"
Cohesion: 0.08
Nodes (33): CapacityPlan, _construct_unique_mapping(), load_capacity_plan(), Any, BaseModel, field_validator, model_validator, Path (+25 more)

### Community 21 - "test_protocol_primitives.py"
Cohesion: 0.06
Nodes (35): bound_output(), bound_text(), Any, Mask credential-shaped substrings before text is logged, audited, or returned., Recursively redact strings inside JSON-shaped data, keys included. Keys are…, Truncate ``value`` to ``max_bytes`` UTF-8 bytes, reporting whether it was cut., Redact first, then bound, so truncation can never split a secret open., Redact then bound a structured result, reporting whether it was truncated. The… (+27 more)

### Community 22 - "test_production_app.py"
Cohesion: 0.11
Nodes (32): CanonicalRecoveryProof, Ceremony, AnomalousWebAuthn, client(), closed_page(), FakeDiscord, FakeWebAuthn, datetime (+24 more)

### Community 23 - "CommandWorkflow"
Cohesion: 0.08
Nodes (23): RetryPolicy, compile_graph_activity(), defn, CompiledJobReceipt, JobStatus, StrEnum, WorkflowControlState, run() (+15 more)

### Community 24 - "DiscordInteraction"
Cohesion: 0.13
Nodes (25): FreezeReason, StrEnum, AdmissionRequest, ControlSnapshot, DiscordCommandData, DiscordCommandOption, DiscordInteraction, DiscordMember (+17 more)

### Community 25 - "LocalEd25519Signer"
Cohesion: 0.06
Nodes (28): build_attestation(), ChainLinkMismatch, InvalidSignature, KmsEd25519Signer, LocalEd25519Signer, MalformedAttestation, ObjectIdentityMismatch, _parse_timestamp() (+20 more)

### Community 26 - "S3ObjectLockStore"
Cohesion: 0.09
Nodes (23): _error_code(), _identity_from_response(), _is_not_found(), _is_precondition_failure(), ObjectAlreadyExists, ObjectStoreError, Any, Exception (+15 more)

### Community 27 - "AuditExporter"
Cohesion: 0.11
Nodes (25): AuditExporter, Read the high-water mark from storage rather than from local state. Storage is…, Re-read every exported segment and confirm the chain is unbroken. This is the…, Copies a hash-chained audit log into write-once object storage. The on-host…, Every segment key under this chain, excluding signature sidecars. Sidecars…, InMemoryWriteOnceStore, A fake with Object Lock's one property that matters: no overwrite. Tests need…, _chain() (+17 more)

### Community 28 - "FakeBurstProvider"
Cohesion: 0.10
Nodes (16): BurstDenied, BurstManager, BurstProvider, BurstRequest, BurstResult, CapacityPressure, FakeBurstProvider, Decimal (+8 more)

### Community 29 - "EffectExecutor"
Cohesion: 0.14
Nodes (16): EffectExecutor, EffectIntent, EffectLedger, EffectProvider, EffectReceipt, EffectState, FakeEffectProvider, Protocol (+8 more)

### Community 30 - "Olympus Trusted Ingress and Authority Control Design"
Cohesion: 0.06
Nodes (34): 10.1 Unit and Property Tests, 10.2 WebAuthn Security Tests, 10.3 Discord Security Tests, 10.4 Concurrency and Reliability Tests, 10.5 Production-boundary Tests, 10. Testing Strategy, 11. Acceptance Gate, 1. Objective (+26 more)

### Community 31 - "AuthorityRepository"
Cohesion: 0.10
Nodes (8): AuthorityRepository, LeaseRequest, datetime, Protocol, _require_aware(), _require_digest(), _secret_fingerprint(), test_audit_events_do_not_contain_raw_lease_material()

### Community 32 - "__main__.py"
Cohesion: 0.11
Nodes (30): load_config(), NodeAgentConfig, NodeAgentConfigError, Path, ValueError, Raised when on-disk agent configuration is missing or unusable., On-disk agent identity and connection settings. The private key lives only in…, Return the outbound WebSocket URL this agent dials. (+22 more)

### Community 33 - "ExportSegment"
Cohesion: 0.08
Nodes (22): ExportResult, Any, Append every not-yet-exported event, skipping ranges already stored., Sign the segment that was just sealed and store the attestation beside it. This…, Return every exported event in order, for rebuilding after a loss., Rebuild a segment from its stored bytes, for offline inspection., What one export run put off-host., segment_from_bytes() (+14 more)

### Community 34 - "latch.py"
Cohesion: 0.12
Nodes (18): _canonical_json(), EmergencyFreezeLatch, InvalidEmergencyLatch, LatchSigner, LatchVerifier, datetime, Path, Protocol (+10 more)

### Community 35 - "InMemoryAuthorityRepository"
Cohesion: 0.11
Nodes (21): InMemoryAuthorityRepository, Deterministic transactional model used by the repository contract suite., bootstrap_challenge(), challenge(), enroll(), lease_request(), Enrollment creates authority from nothing; the chain must show it. Only…, test_audit_chain_verifies_after_authority_transitions() (+13 more)

### Community 36 - "test_signing.py"
Cohesion: 0.18
Nodes (31): An attestation together with the signature over it., Establish that these exact bytes, at this exact object, were signed. Purely…, SignedSegment, verify_signed_segment(), _chain(), _keyring(), parametrize, Hostile tests for key-backed authenticity of exported audit segments. Every… (+23 more)

### Community 37 - "policy.py"
Cohesion: 0.13
Nodes (24): _freeze_mapping(), _freeze_value(), _json_value(), PolicyActivationDenied, PolicyBundle, PolicyKernel, PolicyVerificationError, datetime (+16 more)

### Community 38 - "root.py"
Cohesion: 0.12
Nodes (20): BrokerDenied, BrokerReceipt, BrokerRequest, FakeHostExecutor, HostExecutor, literal_command_digest(), datetime, PermissionError (+12 more)

### Community 39 - "CommandEnvelope"
Cohesion: 0.13
Nodes (24): CommandAccepted, CommandEnvelope, CommandRequest, BaseModel, CommandStarter, Protocol, parametrize, test_command_envelope_requires_discord_identity_evidence() (+16 more)

### Community 40 - "Olympus — Agentic VPS God Agent Design Specification"
Cohesion: 0.07
Nodes (30): 11. Root Broker, 13. Adaptive Polyglot Data Layer, 14.1 Trust Labels and Taint Propagation, 14. Browser and Google Workspace Operations, 15.1 External-effect Dedupe and Reconciliation, 15. Bounded Cycles and Failure Handling, 16.1 Immutable Policy Supply Chain, 16. Security Controls (+22 more)

### Community 41 - ".handshake"
Cohesion: 0.12
Nodes (25): Verify the control plane, prove node identity, and read the session terms., canonical_json(), dedupe_key_for(), digest_of(), encode_bytes(), Any, random_nonce(), Verify an Ed25519 signature over a canonical payload or raise ``reason``. (+17 more)

### Community 42 - "admission.py"
Cohesion: 0.15
Nodes (17): IntEnum, AdmissionController, AdmissionDenied, RuntimeError, StrEnum, ResourceEnvelope, SystemMode, WorkerClass (+9 more)

### Community 43 - "scopes.py"
Cohesion: 0.12
Nodes (26): assert_scoped_dispatch(), parse_scopes(), Capability scopes: the constraints a grant carries beyond its name.…, Build the typed scopes for one node from its stored grant., Whether dispatching this capability is meaningless without a scope. Fail closed…, Refuse a dispatch whose parameters fall outside the node's grant. This is the…, requires_scope(), parametrize (+18 more)

### Community 44 - "file_read.py"
Cohesion: 0.11
Nodes (26): DirEntry, _containing_root(), _describe(), DirectoryListing, FileReadOutcome, FileReadRefused, _is_symlink_at(), list_within_scope() (+18 more)

### Community 45 - "CapabilityRequest"
Cohesion: 0.13
Nodes (16): Build the scoped providers from what the session actually granted. These are…, CapabilityRequest, CapabilityResult, _forever(), ProgressReporter, One bounded unit of work handed to a provider., Terminal provider outcome before bounding and redaction., FileListProvider (+8 more)

### Community 46 - "commands.py"
Cohesion: 0.20
Nodes (17): _canonical_node(), compile_execution_graph(), compile_noop_graph(), GraphCompilationError, ValueError, _topological_order(), CompiledGraph, GraphNode (+9 more)

### Community 47 - "InMemoryArtifactPlane"
Cohesion: 0.13
Nodes (13): ArtifactManifest, CanonicalOwner, DataOwnershipError, DataOwnershipRegistry, DatumKind, InMemoryArtifactPlane, RuntimeError, StrEnum (+5 more)

### Community 48 - "node_mesh.py"
Cohesion: 0.14
Nodes (21): Server, _expect_refusal(), _free_loopback_port(), _headline(), main(), Prove the full command path end to end without touching anything external.…, _wait_until_serving(), The one capability enabled in this slice: bounded, read-only inspection. (+13 more)

### Community 49 - "Olympus Distributed Execution Node Mesh Design"
Cohesion: 0.09
Nodes (23): 10. Audit, 11.1 Residual risks, 11. Threat Model Summary, 12. Testing Strategy, 13. Acceptance Gate, 14. Next Slices, 1. Objective, 2.1 Included (+15 more)

### Community 50 - "Challenge"
Cohesion: 0.19
Nodes (9): Challenge, _challenge_from_row(), AuthenticationAnomaly, BootstrapDenied, CeremonyPurpose, datetime, RuntimeError, StrEnum (+1 more)

### Community 51 - "control_plane.py"
Cohesion: 0.16
Nodes (17): BackupCorrupt, ControlPlaneMode, ControlPlaneSample, _decode_snapshot(), _encode_snapshot(), EncryptedBackup, EncryptedBackupStore, evaluate_control_plane() (+9 more)

### Community 52 - "LocalTask"
Cohesion: 0.18
Nodes (13): LocalAutonomyDenied, LocalAutonomyRunner, LocalBackend, LocalTask, LocalTaskResult, Path, Protocol, RuntimeError (+5 more)

### Community 53 - "test_app.py"
Cohesion: 0.19
Nodes (21): FakeStarter, make_client(), parametrize, TestClient, RaisingStarter, test_command_rejects_duplicate_authority_headers(), test_command_rejects_duplicate_authorization_headers_without_starting_workflow(), test_command_rejects_extra_json_fields() (+13 more)

### Community 54 - "Node Capability `fs.read@1` — Scoped File Read"
Cohesion: 0.09
Nodes (21): 10. The line this crosses, 11. Approval is bound to the literal action, 12. What a write refuses, 13. Status, 14. Closing the loop: the agent can now actually run these, 1. Why this needed a new concept first, 2. What this boundary is, and what it is not, 3. Enforcement happens twice, on purpose (+13 more)

### Community 55 - "3. Slice Roadmap"
Cohesion: 0.09
Nodes (21): 1. Objective, 2. Sequencing Principle, 3. Slice Roadmap, 4. Per-slice Delivery Protocol, 5. Immediate Next Step, Olympus Implementation Roadmap Design, Slice 0 — Foundation Acceptance Closure, Slice 10 — Typed Root Broker (+13 more)

### Community 56 - "authority/models.py"
Cohesion: 0.14
Nodes (14): AuthorityContext, AuthorityDecision, _canonical_datetime(), datetime, StrEnum, RecoveryPayload, ControlAction, ControlRequest (+6 more)

### Community 57 - "test_governed_mvp_path_reaches_fake_effects_with_complete_boundaries"
Cohesion: 0.16
Nodes (13): FakeReadOnlyAdapter, IntegrationRequest, Protocol, RuntimeError, ReadOnlyAdapter, ShadowModeRunner, ShadowModeViolation, ShadowProjection (+5 more)

### Community 58 - "Any"
Cohesion: 0.16
Nodes (10): LocalSystemProbe, Any, Path, Protocol, Host measurement seam so inspection is deterministic under test., Reads a fixed set of non-sensitive counters using only the standard library. It…, _read_memory_mib(), _read_uptime_seconds() (+2 more)

### Community 59 - "FileReadScope"
Cohesion: 0.10
Nodes (11): FileReadProvider, ProgressReporter, Serves ``fs.read@1`` for one node, bounded by the grant it was given., expected_action_digest(), FileReadScope, Any, datetime, The bound on one node's ``fs.read@1`` grant. (+3 more)

### Community 60 - "ScopeError"
Cohesion: 0.14
Nodes (16): is_within(), normalize_path(), _pure(), PurePath, Whether ``candidate`` is ``root`` or lies beneath it. Compared component-wise…, Return the normalized path, or refuse it as outside every root., Raised when a scope is malformed or a request falls outside it., Resolve ``.`` and ``..`` lexically and reject anything unsafe to compare.… (+8 more)

### Community 61 - "FakeWorkflowGateway"
Cohesion: 0.26
Nodes (15): active_lease(), FakeLatch, FakeWorkflowGateway, interaction(), datetime, parametrize, service(), test_duplicate_interaction_does_not_start_duplicate_workflow() (+7 more)

### Community 62 - ".dispatch_job"
Cohesion: 0.11
Nodes (10): Any, ClientFrame, ProgressCallback, ServerFrame, Close on a protocol violation with the same teardown as a lost socket. Latching…, Route inbound frames until the channel closes or a bound is violated., Accept an artifact only within what its capability declared. The catalog states…, Send one job to this node and await its terminal frame. (+2 more)

### Community 63 - "Initial File Map"
Cohesion: 0.11
Nodes (17): Initial File Map, Plan Self-review Checklist, Scope Boundary, Task 10: Build Discord Admission and Control Routing, Task 11: Expose Private WebAuthn and Discord HTTP Boundaries, Task 12: Run Adversarial and Recovery Gates, Task 13: Record Slice 1 Acceptance, Task 1: Pin Security and Persistence Dependencies (+9 more)

### Community 64 - "test_agent_runtime.py"
Cohesion: 0.30
Nodes (17): build_config(), build_provider(), collect(), parametrize, Path, test_configuration_round_trips_with_owner_only_permissions(), test_missing_or_corrupt_configuration_is_reported(), test_status_prints_a_redacted_configuration() (+9 more)

### Community 65 - ".redeem_enrollment_token"
Cohesion: 0.14
Nodes (14): normalize_capability_names(), Return a sorted, de-duplicated tuple of known capability names. Unknown names…, enrollment_secret_matches(), hash_enrollment_secret(), IssuedEnrollmentSecret, new_enrollment_secret(), One-time enrollment material. Only ``presented`` reaches the operator., Mint a single-use enrollment token and the hash the registry stores. (+6 more)

### Community 66 - ".run_job"
Cohesion: 0.13
Nodes (6): ProgressCallback, Admit, dispatch, and await one node job, recording the audit trail., Signal cancellation to whichever session currently holds the job., Freeze the mesh and stop every job already in flight., Revoke a node and stop it doing anything it is already doing. Revoking only the…, Quarantine a node and stop its in-flight work, same as revocation. Quarantine…

### Community 67 - "Install-OlympusNode.ps1"
Cohesion: 0.26
Nodes (14): Assert-ElevationIfNeeded(), Assert-Prerequisites(), ConvertTo-PlainText(), Find-Python313(), Initialize-Venv(), Install-Dependencies(), Invoke-Enrollment(), Invoke-UninstallFlow() (+6 more)

### Community 68 - "Initial File Map"
Cohesion: 0.13
Nodes (14): Follow-on Plan Order, Initial File Map, Olympus Foundation Walking Skeleton Implementation Plan, Scope Boundary, Task 10: Document the First Execution Gate, Task 1: Bootstrap the Python Toolchain, Task 2: Define Trust-Aware Command Contracts, Task 3: Compile a Bounded, Side-Effect-Free Graph (+6 more)

### Community 69 - "Olympus Node-Mesh Persistence Design"
Cohesion: 0.13
Nodes (15): 10. Acceptance Gate, 1. Objective, 2.1 Included, 2.2 Excluded, 2.3 Non-goals, 2. Scope, 3. Invariants Preserved, 4.1 Audit sequencing (+7 more)

### Community 70 - "test_node_mesh_end_to_end.py"
Cohesion: 0.30
Nodes (13): call(), enrolled_node(), free_port(), Harness, Any, Reconnect a previously enrolled node using the key material it already holds., Run the real gateway, the real edge worker, and a real Temporal server., Enroll a node over HTTP, then connect it outbound over a real WebSocket. (+5 more)

### Community 71 - "TrustedSigner"
Cohesion: 0.18
Nodes (12): A pinned public identity and the window in which it was trusted., The attestation names a key that is not in the pinned trust store., TrustedSigner, UnknownSigner, keyring_from_mapping(), Any, Exception, Raised when the pinned trust store cannot be used as written. (+4 more)

### Community 72 - "encode_frame"
Cohesion: 0.20
Nodes (14): encode_frame(), _parse(), parse_client_frame(), parse_server_frame(), Any, ClientFrame, ServerFrame, Serialize a frame and enforce the wire size bound before it is sent. (+6 more)

### Community 73 - "Olympus Execution Node Mesh — Operator Runbook"
Cohesion: 0.15
Nodes (13): 1. Purpose and scope, 2. Architecture at a glance, 3. Installation, 4. Enrollment, 5. Day-two operation, 6. Emergency controls, 7. Threat model, 8. Revocation and recovery (+5 more)

### Community 74 - "NodeJobWorkflow"
Cohesion: 0.17
Nodes (8): NodeJobWorkflow, defn, query, run, signal, Ask the node to stop. Reducing work never requires more authority., The node this job was pinned to, or empty before selection completes., Durable owner of one node job. The workflow is the only durable record of the…

### Community 75 - "Olympus Signed Audit Export — Operator Runbook"
Cohesion: 0.17
Nodes (11): 10. The export actually runs now, 1. Two different claims, deliberately kept apart, 2. What a signature commits to, 3. Live inventory, 4. Exporter permissions, 5. GOVERNANCE mode: what it does and does not protect against, 6. Verifying offline, 7. What was proven live (+3 more)

### Community 76 - "Olympus Node Mesh — Security Model"
Cohesion: 0.17
Nodes (11): 10. The failure mode this codebase actually has, 1. What this boundary is not, 2. The five things that must all hold, 3. Grants carry bounds, not just names, 4. Enforcement happens twice because neither side can do the other's job, 5. Mutation requires a receipt, not a permission, 6. Revocation reaches the present, not just the future, 7. What comes back is bounded, masked, and counted (+3 more)

### Community 77 - "Olympus Production Gateway — Deployment Runbook"
Cohesion: 0.17
Nodes (11): 1. Listener inventory taken before deploying, 2. Binding and reachability, 3. TLS, 4. Origin, RP ID, and the port, 5. Validated end to end, 6. Supervision, 7. Enrollment ceremony — completed, 7a. Enrollment is now in the signed audit chain (+3 more)

### Community 78 - "19. Representative Workload Corpus"
Cohesion: 0.17
Nodes (12): 19.1 Policy-miss Definitions, 19. Representative Workload Corpus, Job 10 — Meeting Autopilot, Job 1 — Parallel Vibe Development and Research, Job 2 — Daily Chief of Staff, Job 3 — Inbox Autopilot, Job 4 — Feature Delivery, Job 5 — Temporary Benchmark Fleet (+4 more)

### Community 79 - ".dispatch_node_job"
Cohesion: 0.20
Nodes (9): Any, defn, Queue, Choose the node once, so every later attempt reaches the same machine., Place one attempt of a node job and relay its progress as heartbeats., Heartbeat steadily so a cancellation request reaches this attempt promptly., is_permanent_refusal(), Refusals that retrying cannot turn into an allowance. (+1 more)

### Community 80 - "test_node_job_workflow.py"
Cohesion: 0.41
Nodes (10): defn, request(), run_workflow(), test_a_failed_job_does_not_keep_reporting_itself_as_dispatched(), test_a_permanent_refusal_is_not_retried(), test_a_transient_failure_is_retried_within_the_worker_recovery_bound(), test_cancellation_returns_a_cancelled_outcome_rather_than_a_lost_job(), test_the_job_is_pinned_to_one_node_so_a_retry_cannot_run_it_elsewhere() (+2 more)

### Community 81 - "channel.py"
Cohesion: 0.18
Nodes (3): MemoryChannel, Queue, In-memory channel half backed by a bounded queue.

### Community 82 - "open_session_channel"
Cohesion: 0.20
Nodes (6): ClientConnection, open_session_channel(), SSLContext, Node-side channel over an outbound WebSocket connection., Dial the control plane. Nodes only ever connect outbound; they never listen., WebSocketClientChannel

### Community 83 - "properties"
Cohesion: 0.20
Nodes (10): const, type, properties, const, type, control, platform, workersLocal (+2 more)

### Community 84 - "properties"
Cohesion: 0.20
Nodes (10): const, type, const, type, limitsMemoryMib, pods, requestsMemoryMib, const (+2 more)

### Community 85 - "Olympus Windows Node Agent"
Cohesion: 0.20
Nodes (9): 1. Build the wheel on the VPS, 2. Copy the wheel and this deploy folder to the Windows machine, 3. Enroll and install, 4. Verify, Olympus Windows Node Agent, Prerequisites, Security notes, SYSTEM-scoped alternative (+1 more)

### Community 86 - "README.md"
Cohesion: 0.20
Nodes (4): Capability map, Deliberate production gaps, Olympus MVP Slices 2–13, Verification evidence

### Community 87 - "Olympus VPS Development Migration Design"
Cohesion: 0.20
Nodes (9): 1. Objective, 2. Scope, 3. Explicit Exclusions, 4. Transfer Design, 5. Toolchain Installation, 6. Verification, 7. Failure and Rollback, 8. Invariants (+1 more)

### Community 88 - "NodeAuditLog"
Cohesion: 0.20
Nodes (5): NodeAuditLog, In-process hash-chained audit log. PostgreSQL is the canonical owner once a…, Adopt already-linked events, used when a transaction commits., Return whether the recorded chain is internally consistent., test_audit_payloads_are_redacted_before_they_are_hashed()

### Community 89 - "_exercises"
Cohesion: 0.24
Nodes (9): _exercises(), Any, parametrize, Path, Grant it, connect a real agent, dispatch it, and require a real result. Run…, How each enabled capability is granted and invoked. Scope and parameters…, Enabling a capability without saying how it is reached fails here. That…, test_capability_is_reachable_end_to_end() (+1 more)

### Community 90 - "required"
Cohesion: 0.22
Nodes (9): additionalProperties, required, type, properties, namespaces, control, data, platform (+1 more)

### Community 91 - "VPS Development Migration Implementation Plan"
Cohesion: 0.22
Nodes (8): Task 1: Publish the Approved Repository State, Task 2: Create the VPS Working Checkout, Task 3: Install the Pinned Python Toolchain, Task 4: Install the Pinned Kubernetes Validation Tools, Task 5: Verify the Complete Repository on the VPS, Task 6: Install and Authenticate Codex on the VPS, Task 7: Connect Codex Desktop to the VPS Workspace, VPS Development Migration Implementation Plan

### Community 92 - "20. Rollout"
Cohesion: 0.22
Nodes (9): 20.1 VPS-4 Activation Runbook, 20. Rollout, Phase 0A — VPS-4 Activation, Phase 0B — Foundation, Phase 1 — Shadow Mode, Phase 2 — Safe Autonomous Pilot, Phase 3 — Connected Operations, Phase 4 — High Autonomy (+1 more)

### Community 93 - "FakeProbe"
Cohesion: 0.31
Nodes (3): FakeProbe, Any, Deterministic host measurements so inspection output is assertable.

### Community 94 - "values.schema.json"
Cohesion: 0.25
Nodes (7): additionalProperties, required, $schema, title, type, namespaces, workerQuota

### Community 95 - "workerQuota"
Cohesion: 0.25
Nodes (8): workerQuota, additionalProperties, required, type, limitsMemoryMib, pods, requestsCpuMillicores, requestsMemoryMib

### Community 96 - "Execution Node Mesh Foundation Acceptance"
Cohesion: 0.25
Nodes (7): Adversarial review, Decision status: locally verified, not deployed, Execution Node Mesh Foundation Acceptance, Known limitations recorded rather than hidden, Local evidence, Required acceptance checklist, Scope and authorization boundary

### Community 97 - "Discord Credential Recovery and Authority Bootstrap Readiness"
Cohesion: 0.25
Nodes (7): 1. What is already proven, 2. Value one — bot token, 3. Value two — application public key, 4. What is ready and waiting, 5. Face ID enrollment ceremony, 6. Explicitly not done, Discord Credential Recovery and Authority Bootstrap Readiness

### Community 98 - "Olympus"
Cohesion: 0.25
Nodes (8): Delivery sequence, Development verification, Execution node mesh, Foundation walking skeleton, Manual local demo (operator procedure), Olympus, Run the end-to-end demonstration, Status

### Community 99 - "test_serve_loop.py"
Cohesion: 0.29
Nodes (6): Portable execution-node agent; dials out to the control plane and never listens., build_config(), MonkeyPatch, Path, Rebuilding the agent per attempt would silently discard replay safety., test_the_serve_loop_keeps_one_agent_so_its_dedupe_ledger_survives()

### Community 100 - "12. K3s Deployment"
Cohesion: 0.29
Nodes (7): 12.1 Base VPS Sizing, 12.2 Production Version-one Control Plane, 12.3 Target Always-on Topology, 12.4 Temporary Cloud Workers, 12.5 Admission, Degradation, and Overload, 12.6 Expansion Thresholds, 12. K3s Deployment

### Community 101 - "SegmentSigner"
Cohesion: 0.29
Nodes (4): datetime, Protocol, The narrow signing surface. Deliberately cannot verify or read a key., SegmentSigner

### Community 102 - "Phase 0 Foundation Walking Skeleton Acceptance"
Cohesion: 0.33
Nodes (5): Current local evidence, Decision status: accepted, Phase 0 Foundation Walking Skeleton Acceptance, Required acceptance checklist, Scope and authorization boundary

### Community 103 - "7. Worker Protocol `olympus-node/1`"
Cohesion: 0.33
Nodes (6): 7.1 Mutual authentication, 7.2 Frames, 7.3 Bounds, 7.4 Deduplication and replay-safe recovery, 7.5 Reconnect, 7. Worker Protocol `olympus-node/1`

### Community 104 - "test_contracts.py"
Cohesion: 0.53
Nodes (5): parametrize, test_parses_literal_discord_scope(), test_rejects_nonliteral_discord_identity(), test_rejects_unknown_interaction_fields(), valid_interaction()

### Community 105 - "Olympus Foundation Helm Chart"
Cohesion: 0.40
Nodes (4): Capacity and override policy, Network-policy boundary, Olympus Foundation Helm Chart, Singleton lifecycle

### Community 106 - "4. Architecture"
Cohesion: 0.40
Nodes (5): 4.1 Control plane, 4.2 Execution nodes, 4.3 Command and observation surfaces, 4.4 Where dispatch lives, 4. Architecture

### Community 109 - "test_gateway_runtime_wires_temporal_starter_and_loopback_uvicorn"
Cohesion: 0.60
Nodes (4): asyncio, MonkeyPatch, test_gateway_runtime_wires_temporal_starter_and_loopback_uvicorn(), test_worker_runtime_registers_command_workflow_and_graph_activity()

### Community 110 - "Olympus Repository Instructions"
Cohesion: 0.50
Nodes (3): Engineering workflow, Non-negotiable rules, Olympus Repository Instructions

### Community 111 - "10. Permission and Approval Model"
Cohesion: 0.50
Nodes (4): 10.1 Autonomous Actions, 10.2 Face ID Required, 10.3 Never Autonomous, 10. Permission and Approval Model

### Community 112 - "6. Discord Experience"
Cohesion: 0.50
Nodes (4): 6.1 Channel Layout, 6.2 Job Controls, 6.3 Discord Authority Lease, 6. Discord Experience

### Community 116 - "data"
Cohesion: 0.67
Nodes (3): const, type, data

### Community 117 - "requestsCpuMillicores"
Cohesion: 0.67
Nodes (3): requestsCpuMillicores, const, type

## Knowledge Gaps
- **312 isolated node(s):** `$schema`, `title`, `type`, `additionalProperties`, `namespaces` (+307 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **29 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `NodeMeshError` connect `NodeMeshError` to `test_registry.py`, `AuditDraft`, `NodeAgent`, `test_node_approvals.py`, `Mesh`, `crypto.py`, `postgres_store.py`, `node_edge.py`, `NodeRegistry`, `NodeRecord`, `test_file_write.py`, `__main__.py`, `.handshake`, `scopes.py`, `file_read.py`, `CapabilityRequest`, `FileReadScope`, `ScopeError`, `.dispatch_job`, `.redeem_enrollment_token`, `.run_job`, `encode_frame`?**
  _High betweenness centrality (0.058) - this node is a cross-community bridge._
- **Why does `test_governed_mvp_path_reaches_fake_effects_with_complete_boundaries()` connect `test_governed_mvp_path_reaches_fake_effects_with_complete_boundaries` to `authorization.py`, `policy.py`, `root.py`, `admission.py`, `commands.py`, `InMemoryArtifactPlane`, `LocalTask`, `EffectExecutor`?**
  _High betweenness centrality (0.047) - this node is a cross-community bridge._
- **Why does `WriteMode` connect `test_node_approvals.py` to `test_registry.py`, `NodeMeshError`, `scopes.py`, `CapabilityRequest`, `test_file_write.py`, `FileReadScope`?**
  _High betweenness centrality (0.047) - this node is a cross-community bridge._
- **Are the 76 inferred relationships involving `NodeMeshError` (e.g. with `NodeDispatchActivities` and `AuditEventResponse`) actually correct?**
  _`NodeMeshError` has 76 INFERRED edges - model-reasoned connections that need verification._
- **Are the 46 inferred relationships involving `NodeRegistry` (e.g. with `AuditEventResponse` and `AuditResponse`) actually correct?**
  _`NodeRegistry` has 46 INFERRED edges - model-reasoned connections that need verification._
- **Are the 69 inferred relationships involving `NodeReason` (e.g. with `AuditEventResponse` and `AuditResponse`) actually correct?**
  _`NodeReason` has 69 INFERRED edges - model-reasoned connections that need verification._
- **Are the 44 inferred relationships involving `NodeSession` (e.g. with `AuditEventResponse` and `AuditResponse`) actually correct?**
  _`NodeSession` has 44 INFERRED edges - model-reasoned connections that need verification._