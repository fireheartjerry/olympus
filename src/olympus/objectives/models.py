"""Canonical, side-effect-free objective and execution-graph contracts."""

from __future__ import annotations

from decimal import Decimal
from enum import StrEnum

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class ObjectiveMode(StrEnum):
    BOUNDED = "bounded"
    STANDING = "standing"
    TAKEOVER = "takeover"


class EffectClass(StrEnum):
    OBSERVE = "observe"
    LOCAL_REVERSIBLE = "local-reversible"
    LOCAL_IRREVERSIBLE = "local-irreversible"
    EXTERNAL_REVERSIBLE = "external-reversible"
    EXTERNAL_IRREVERSIBLE = "external-irreversible"
    PRIVILEGED = "privileged"


class NotificationPolicy(StrEnum):
    SILENT_UNTIL_COMPLETE = "silent-until-complete"
    MILESTONES = "milestones"
    BEFORE_CONSEQUENTIAL = "before-consequential"
    CONTINUOUS = "continuous"


class EvidenceKind(StrEnum):
    TYPED_RESULT = "typed-result"
    TEST_RECEIPT = "test-receipt"
    CONTENT_DIGEST = "content-digest"
    SCREENSHOT = "screenshot"
    EXTERNAL_RECEIPT = "external-receipt"
    HUMAN_CONFIRMATION = "human-confirmation"
    AUDIT_CHAIN_EVENT = "audit-chain-event"


class SuccessCriterion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    criterion_id: str = Field(min_length=1, max_length=128)
    statement: str = Field(min_length=1, max_length=2000)
    required_evidence: tuple[EvidenceKind, ...]


class BudgetEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    variable_cost_usd: Decimal = Field(default=Decimal("0.00"), ge=Decimal("0.00"))
    wall_clock_seconds: int = Field(ge=1, le=31_536_000)
    max_parallel_branches: int = Field(default=1, ge=1, le=64)
    max_external_mutations: int = Field(default=0, ge=0, le=10_000)
    max_revisions: int = Field(default=1, ge=0, le=64)


class AuthorityExpectation(StrEnum):
    CURRENT_LEASE = "current-lease"
    STANDING_CAPABILITY = "standing-capability"
    PER_ACTION_APPROVAL = "per-action-approval"
    OWNER_ONLY = "owner-only"
    EMERGENCY_DELEGATE = "emergency-delegate"


class ObjectiveDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    objective_id: str = Field(min_length=1, max_length=128)
    owner_id: str = Field(min_length=1, max_length=128)
    statement: str = Field(min_length=1, max_length=8000)
    mode: ObjectiveMode
    created_at: AwareDatetime
    context_refs: tuple[str, ...] = ()
    success_criteria: tuple[SuccessCriterion, ...]
    non_goals: tuple[str, ...] = ()
    allowed_domains: tuple[str, ...]
    prohibited_domains: tuple[str, ...] = ()
    budget: BudgetEnvelope
    authority: AuthorityExpectation
    notification_policy: NotificationPolicy = NotificationPolicy.MILESTONES
    termination_conditions: tuple[str, ...]

    @model_validator(mode="after")
    def validate_draft(self) -> ObjectiveDraft:
        if not self.success_criteria:
            raise ValueError("an objective requires at least one success criterion")
        if not self.allowed_domains:
            raise ValueError("an objective requires at least one allowed domain")
        if not self.termination_conditions:
            raise ValueError("an objective requires at least one termination condition")
        if set(self.allowed_domains) & set(self.prohibited_domains):
            raise ValueError("a domain cannot be both allowed and prohibited")
        if self.mode is ObjectiveMode.TAKEOVER and not self.context_refs:
            raise ValueError("takeover objectives require context references")
        return self


class ObjectiveContract(BaseModel):
    """Durable objective boundary compiled before planning begins."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1)
    objective_id: str
    owner_id: str
    statement: str
    mode: ObjectiveMode
    created_at: AwareDatetime
    context_refs: tuple[str, ...]
    success_criteria: tuple[SuccessCriterion, ...]
    non_goals: tuple[str, ...]
    allowed_domains: tuple[str, ...]
    prohibited_domains: tuple[str, ...]
    budget: BudgetEnvelope
    authority: AuthorityExpectation
    notification_policy: NotificationPolicy
    termination_conditions: tuple[str, ...]
    canonical_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class ObjectiveAuthorization(BaseModel):
    """Authority and policy binding established outside model reasoning.

    Constructing this object does not prove authority. The production binding
    workflow must first verify the referenced lease/capability and policy
    release through the existing Fire authority subsystem.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    authority_subject_id: str = Field(min_length=1, max_length=128)
    authority_basis_ref: str = Field(min_length=1, max_length=512)
    authority_epoch: int = Field(ge=1)
    policy_release_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    bound_at: AwareDatetime
    expires_at: AwareDatetime | None = None
    max_effect_class: EffectClass
    allowed_capabilities: tuple[str, ...]
    prohibited_capabilities: tuple[str, ...] = ()
    approval_refs: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_authorization(self) -> ObjectiveAuthorization:
        if not self.allowed_capabilities:
            raise ValueError("authorized objectives require at least one allowed capability")
        if set(self.allowed_capabilities) & set(self.prohibited_capabilities):
            raise ValueError("a capability cannot be both allowed and prohibited")
        if self.expires_at is not None and self.expires_at <= self.bound_at:
            raise ValueError("authorization expiry must be after its binding time")
        return self


class AuthorizedObjective(BaseModel):
    """Digest-bound production envelope over intent, authority, and policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1)
    contract: ObjectiveContract
    authorization: ObjectiveAuthorization
    envelope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class ExecutorClass(StrEnum):
    CONTROL_PLANE = "control-plane"
    WINDOWS_NODE = "windows-node"
    MACOS_NODE = "macos-node"
    LINUX_NODE = "linux-node"
    BROWSER_WORKER = "browser-worker"
    CODEX_WORKER = "codex-worker"
    CLAUDE_WORKER = "claude-worker"
    GPU_WORKER = "gpu-worker"
    DETERMINISTIC = "deterministic"


class ExecutionStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    step_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=300)
    capability_id: str = Field(min_length=1, max_length=256)
    executor_class: ExecutorClass
    dependencies: tuple[str, ...] = ()
    effect_class: EffectClass
    parameters_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    timeout_seconds: int = Field(ge=1, le=86_400)
    retry_limit: int = Field(default=0, ge=0, le=16)
    reversible: bool
    compensation_step_id: str | None = Field(default=None, max_length=128)
    required_evidence: tuple[EvidenceKind, ...]
    projected_variable_cost_usd: Decimal = Field(default=Decimal("0.00"), ge=Decimal("0.00"))


class ExecutionGraph(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    graph_id: str = Field(min_length=1, max_length=128)
    objective_id: str = Field(min_length=1, max_length=128)
    objective_contract_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_envelope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_release_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    compiler_version: str = Field(min_length=1, max_length=128)
    compiled_at: AwareDatetime
    steps: tuple[ExecutionStep, ...]
    graph_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_dag(self) -> ExecutionGraph:
        by_id = {step.step_id: step for step in self.steps}
        if len(by_id) != len(self.steps):
            raise ValueError("step_id values must be unique")
        for step in self.steps:
            missing = sorted(set(step.dependencies) - by_id.keys())
            if missing:
                raise ValueError(f"step {step.step_id!r} has missing dependencies: {missing}")
            if step.step_id in step.dependencies:
                raise ValueError(f"step {step.step_id!r} cannot depend on itself")
            if step.compensation_step_id is not None and step.compensation_step_id not in by_id:
                raise ValueError(
                    f"step {step.step_id!r} references missing compensation step "
                    f"{step.compensation_step_id!r}"
                )

        temporary: set[str] = set()
        permanent: set[str] = set()

        def visit(step_id: str) -> None:
            if step_id in permanent:
                return
            if step_id in temporary:
                raise ValueError("execution graph must be acyclic")
            temporary.add(step_id)
            for dependency in by_id[step_id].dependencies:
                visit(dependency)
            temporary.remove(step_id)
            permanent.add(step_id)

        for step_id in sorted(by_id):
            visit(step_id)
        return self
