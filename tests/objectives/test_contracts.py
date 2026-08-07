from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from olympus.objectives import (
    AuthorityExpectation,
    BudgetEnvelope,
    EffectClass,
    EvidenceKind,
    NotificationPolicy,
    ObjectiveAuthorization,
    ObjectiveDraft,
    ObjectiveMode,
    SuccessCriterion,
    canonical_sha256,
    compile_objective,
    seal_authorized_objective,
)


def _criterion() -> SuccessCriterion:
    return SuccessCriterion(
        criterion_id="done",
        statement="The requested outcome is verified",
        required_evidence=(EvidenceKind.TYPED_RESULT, EvidenceKind.AUDIT_CHAIN_EVENT),
    )


def _draft() -> ObjectiveDraft:
    return ObjectiveDraft(
        objective_id="o1",
        owner_id="jerry",
        statement="  Finish the active task  ",
        mode=ObjectiveMode.BOUNDED,
        created_at=datetime(2026, 8, 6, tzinfo=UTC),
        context_refs=("screen:1", "screen:1", "repo:fire"),
        success_criteria=(_criterion(),),
        non_goals=("Do not publish", "Do not publish"),
        allowed_domains=("computer", "computer"),
        prohibited_domains=("finance",),
        budget=BudgetEnvelope(
            variable_cost_usd=Decimal("1.00"),
            wall_clock_seconds=600,
            max_parallel_branches=2,
        ),
        authority=AuthorityExpectation.CURRENT_LEASE,
        notification_policy=NotificationPolicy.MILESTONES,
        termination_conditions=("Success criteria pass",),
    )


def test_takeover_requires_context() -> None:
    with pytest.raises(ValueError, match="context"):
        ObjectiveDraft(
            objective_id="o1",
            owner_id="jerry",
            statement="Take over",
            mode=ObjectiveMode.TAKEOVER,
            created_at=datetime.now(UTC),
            success_criteria=(_criterion(),),
            allowed_domains=("computer",),
            budget=BudgetEnvelope(wall_clock_seconds=60),
            authority=AuthorityExpectation.CURRENT_LEASE,
            termination_conditions=("Owner stops the session",),
        )


def test_compilation_is_deterministic_and_does_not_expand_scope() -> None:
    draft = _draft()
    first = compile_objective(draft)
    second = compile_objective(draft)
    assert first == second
    assert first.context_refs == ("screen:1", "repo:fire")
    assert first.allowed_domains == ("computer",)
    assert first.prohibited_domains == ("finance",)
    assert first.canonical_digest == canonical_sha256(
        first.model_dump(mode="json", exclude={"canonical_digest"})
    )


def test_authorized_envelope_binds_contract_policy_and_capabilities() -> None:
    contract = compile_objective(_draft())
    authorization = ObjectiveAuthorization(
        authority_subject_id="jerry",
        authority_basis_ref="lease:abc",
        authority_epoch=4,
        policy_release_digest="b" * 64,
        bound_at=datetime(2026, 8, 6, tzinfo=UTC),
        expires_at=datetime(2026, 8, 6, tzinfo=UTC) + timedelta(minutes=15),
        max_effect_class=EffectClass.LOCAL_REVERSIBLE,
        allowed_capabilities=("system.inspect@1", "fs.read@1"),
    )
    envelope = seal_authorized_objective(contract, authorization)
    assert envelope.envelope_digest == canonical_sha256(
        envelope.model_dump(mode="json", exclude={"envelope_digest"})
    )


def test_authorization_refuses_empty_or_conflicting_capability_bounds() -> None:
    common = {
        "authority_subject_id": "jerry",
        "authority_basis_ref": "lease:abc",
        "authority_epoch": 1,
        "policy_release_digest": "b" * 64,
        "bound_at": datetime(2026, 8, 6, tzinfo=UTC),
        "max_effect_class": EffectClass.OBSERVE,
    }
    with pytest.raises(ValueError, match="at least one"):
        ObjectiveAuthorization(**common, allowed_capabilities=())
    with pytest.raises(ValueError, match="both allowed and prohibited"):
        ObjectiveAuthorization(
            **common,
            allowed_capabilities=("fs.read@1",),
            prohibited_capabilities=("fs.read@1",),
        )


def test_objective_timestamps_must_be_timezone_aware() -> None:
    with pytest.raises(ValueError, match="timezone"):
        ObjectiveDraft(
            objective_id="o-naive",
            owner_id="jerry",
            statement="Reject ambiguous time",
            mode=ObjectiveMode.BOUNDED,
            created_at=datetime(2026, 8, 6),
            success_criteria=(_criterion(),),
            allowed_domains=("computer",),
            budget=BudgetEnvelope(wall_clock_seconds=60),
            authority=AuthorityExpectation.CURRENT_LEASE,
            termination_conditions=("Complete",),
        )
