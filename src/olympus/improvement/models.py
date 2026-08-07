"""Self-improvement proposal and promotion-gate contracts."""

from __future__ import annotations

from enum import StrEnum

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class ChangeClass(StrEnum):
    INTERNAL_OPTIMIZATION = "internal-optimization"
    TOOL_OR_SKILL = "tool-or-skill"
    PLANNER = "planner"
    MEMORY = "memory"
    INFRASTRUCTURE = "infrastructure"
    PERSONA = "persona"
    AUTHORITY = "authority"
    CONSTITUTION = "constitution"
    IDENTITY_SUCCESSION = "identity-succession"


class PromotionTier(StrEnum):
    AUTOMATED = "automated"
    VERIFIED_NOTIFY = "verified-notify"
    OWNER_APPROVAL = "owner-approval"
    OWNER_APPROVAL_AND_COOLING_OFF = "owner-approval-and-cooling-off"


class VerificationKind(StrEnum):
    UNIT_TESTS = "unit-tests"
    INTEGRATION_TESTS = "integration-tests"
    PROPERTY_TESTS = "property-tests"
    SECURITY_REVIEW = "security-review"
    INDEPENDENT_VERIFIER = "independent-verifier"
    CANARY = "canary"
    ROLLBACK_DRILL = "rollback-drill"
    OWNER_REVIEW = "owner-review"


class VerificationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: VerificationKind
    passed: bool
    evidence_ref: str = Field(min_length=1, max_length=1024)
    completed_at: AwareDatetime


class ImprovementProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    proposal_id: str = Field(min_length=1, max_length=128)
    change_class: ChangeClass
    title: str = Field(min_length=1, max_length=300)
    rationale: str = Field(min_length=1, max_length=8000)
    base_version: str = Field(min_length=1, max_length=128)
    candidate_version: str = Field(min_length=1, max_length=128)
    affected_invariants: tuple[str, ...] = ()
    rollback_ref: str = Field(min_length=1, max_length=1024)
    verification: tuple[VerificationRecord, ...]
    requested_at: AwareDatetime

    @model_validator(mode="after")
    def require_verification(self) -> ImprovementProposal:
        if not self.verification:
            raise ValueError("an improvement proposal requires verification evidence")
        return self


class PromotionDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    proposal_id: str
    tier: PromotionTier
    promotable: bool
    missing_verification: tuple[VerificationKind, ...]
    owner_approval_required: bool
    rationale: str = Field(min_length=1, max_length=4000)


def required_promotion_tier(change_class: ChangeClass) -> PromotionTier:
    if change_class in {
        ChangeClass.CONSTITUTION,
        ChangeClass.AUTHORITY,
        ChangeClass.IDENTITY_SUCCESSION,
    }:
        return PromotionTier.OWNER_APPROVAL_AND_COOLING_OFF
    if change_class is ChangeClass.PERSONA:
        return PromotionTier.OWNER_APPROVAL
    if change_class in {
        ChangeClass.PLANNER,
        ChangeClass.MEMORY,
        ChangeClass.INFRASTRUCTURE,
    }:
        return PromotionTier.VERIFIED_NOTIFY
    return PromotionTier.AUTOMATED


def evaluate_promotion(proposal: ImprovementProposal) -> PromotionDecision:
    tier = required_promotion_tier(proposal.change_class)
    required = {
        VerificationKind.UNIT_TESTS,
        VerificationKind.INDEPENDENT_VERIFIER,
        VerificationKind.ROLLBACK_DRILL,
    }
    if proposal.change_class in {
        ChangeClass.PLANNER,
        ChangeClass.MEMORY,
        ChangeClass.INFRASTRUCTURE,
        ChangeClass.PERSONA,
        ChangeClass.AUTHORITY,
        ChangeClass.CONSTITUTION,
        ChangeClass.IDENTITY_SUCCESSION,
    }:
        required.add(VerificationKind.INTEGRATION_TESTS)
    if proposal.change_class in {
        ChangeClass.AUTHORITY,
        ChangeClass.CONSTITUTION,
        ChangeClass.IDENTITY_SUCCESSION,
    }:
        required.add(VerificationKind.SECURITY_REVIEW)

    passed = {record.kind for record in proposal.verification if record.passed}
    missing = tuple(sorted(required - passed, key=str))
    owner_required = tier in {
        PromotionTier.OWNER_APPROVAL,
        PromotionTier.OWNER_APPROVAL_AND_COOLING_OFF,
    }
    return PromotionDecision(
        proposal_id=proposal.proposal_id,
        tier=tier,
        promotable=not missing,
        missing_verification=missing,
        owner_approval_required=owner_required,
        rationale="Promotion is based on change class and explicit verification receipts.",
    )
