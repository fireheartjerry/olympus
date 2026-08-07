from datetime import UTC, datetime

from olympus.improvement import (
    ChangeClass,
    ImprovementProposal,
    PromotionTier,
    VerificationKind,
    VerificationRecord,
    evaluate_promotion,
    required_promotion_tier,
)


def _record(kind: VerificationKind, *, passed: bool = True) -> VerificationRecord:
    return VerificationRecord(
        kind=kind,
        passed=passed,
        evidence_ref=f"evidence:{kind}",
        completed_at=datetime.now(UTC),
    )


def test_constitution_change_always_requires_owner_and_cooling_off() -> None:
    assert (
        required_promotion_tier(ChangeClass.CONSTITUTION)
        is PromotionTier.OWNER_APPROVAL_AND_COOLING_OFF
    )


def test_low_risk_change_needs_verifier_and_rollback() -> None:
    proposal = ImprovementProposal(
        proposal_id="p1",
        change_class=ChangeClass.TOOL_OR_SKILL,
        title="Improve deterministic parser",
        rationale="Reduces failures without changing authority.",
        base_version="1",
        candidate_version="2",
        rollback_ref="git:revert-1",
        verification=(
            _record(VerificationKind.UNIT_TESTS),
            _record(VerificationKind.INDEPENDENT_VERIFIER),
            _record(VerificationKind.ROLLBACK_DRILL),
        ),
        requested_at=datetime.now(UTC),
    )
    decision = evaluate_promotion(proposal)
    assert decision.promotable is True
    assert decision.owner_approval_required is False


def test_authority_change_without_security_review_is_not_promotable() -> None:
    proposal = ImprovementProposal(
        proposal_id="p1",
        change_class=ChangeClass.AUTHORITY,
        title="Change delegation policy",
        rationale="Test",
        base_version="1",
        candidate_version="2",
        rollback_ref="git:revert-1",
        verification=(
            _record(VerificationKind.UNIT_TESTS),
            _record(VerificationKind.INTEGRATION_TESTS),
            _record(VerificationKind.INDEPENDENT_VERIFIER),
            _record(VerificationKind.ROLLBACK_DRILL),
        ),
        requested_at=datetime.now(UTC),
    )
    decision = evaluate_promotion(proposal)
    assert decision.promotable is False
    assert VerificationKind.SECURITY_REVIEW in decision.missing_verification
    assert decision.owner_approval_required is True
