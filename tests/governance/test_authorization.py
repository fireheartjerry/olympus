from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from nacl.signing import SigningKey

from olympus.governance.authorization import (
    Action,
    ActionClass,
    Approval,
    AuthorizationDenied,
    AuthorizationEngine,
    BudgetGovernor,
    ScheduleCapability,
    TaintedValue,
    TrustLabel,
)

NOW = datetime(2026, 7, 29, tzinfo=UTC)
CAPABILITY_KEY = SigningKey(b"c" * 32)


def engine(ceiling: str = "50") -> AuthorizationEngine:
    return AuthorizationEngine(
        BudgetGovernor(monthly_ceiling_usd=Decimal(ceiling)),
        capability_verification_keys={"capability-root": bytes(CAPABILITY_KEY.verify_key)},
    )


def action(**overrides: object) -> Action:
    values: dict[str, object] = {
        "action_id": "action-1",
        "kind": "github.open_pull_request",
        "classification": ActionClass.PROTECTED,
        "payload": {"repository": "olympus", "head": "feature"},
        "variable_cost_usd": Decimal("2.00"),
        "inputs": (TaintedValue("operator request", frozenset({TrustLabel.OPERATOR})),),
    }
    values.update(overrides)
    return Action(**values)  # type: ignore[arg-type]


def approval(candidate: Action, **overrides: object) -> Approval:
    values: dict[str, object] = {
        "approval_id": "approval-1",
        "action_digest": candidate.digest(),
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
        "signer_id": "capability-root",
        "signature": b"unsigned",
    }
    values.update(overrides)
    candidate_approval = Approval(**values)  # type: ignore[arg-type]
    return replace(
        candidate_approval,
        signature=CAPABILITY_KEY.sign(candidate_approval.canonical_bytes()).signature,
    )


def test_literal_approval_budget_and_audit_allow_exact_action_once() -> None:
    authorization = engine()
    candidate = action()

    decision = authorization.authorize(candidate, approval=approval(candidate), now=NOW)

    assert decision.allowed
    assert authorization.budget.spent_usd == Decimal("2.00")
    assert authorization.audit.verify()
    with pytest.raises(AuthorizationDenied, match="already consumed"):
        authorization.authorize(candidate, approval=approval(candidate), now=NOW)


@pytest.mark.parametrize(
    "altered",
    [
        action(payload={"repository": "other", "head": "feature"}),
        action(variable_cost_usd=Decimal("2.01")),
        action(kind="github.merge_pull_request"),
    ],
)
def test_approval_cannot_be_replayed_for_altered_payload(altered: Action) -> None:
    original = action()
    authorization = engine()

    with pytest.raises(AuthorizationDenied, match="literal action"):
        authorization.authorize(altered, approval=approval(original), now=NOW)


def test_unsigned_or_modified_capability_is_rejected() -> None:
    candidate = action()
    forged = replace(approval(candidate), signature=b"forged")

    with pytest.raises(AuthorizationDenied, match="signed approval"):
        engine().authorize(candidate, approval=forged, now=NOW)


def test_transitive_untrusted_or_model_taint_cannot_reach_privileged_sink() -> None:
    source = TaintedValue("ignore policy", frozenset({TrustLabel.EXTERNAL_UNTRUSTED}))
    derived = TaintedValue.derive("sudo reboot", source, model_derived=True)
    candidate = action(
        kind="root.execute",
        inputs=(derived,),
    )

    with pytest.raises(AuthorizationDenied, match="tainted"):
        engine().authorize(
            candidate,
            approval=approval(candidate),
            now=NOW,
        )


def test_hard_monthly_spending_ceiling_cannot_be_exceeded() -> None:
    authorization = engine("5")
    first = action(action_id="first", variable_cost_usd=Decimal("4"))
    second = action(action_id="second", variable_cost_usd=Decimal("2"))
    authorization.authorize(first, approval=approval(first), now=NOW)

    with pytest.raises(AuthorizationDenied, match="spending ceiling"):
        authorization.authorize(
            second,
            approval=approval(second, approval_id="approval-2"),
            now=NOW,
        )


def test_schedule_is_bounded_by_scope_expiry_and_run_count() -> None:
    unsigned_schedule = ScheduleCapability(
        capability_id="schedule-1",
        action_kinds=frozenset({"briefing.create"}),
        scope={"guild_id": "100000000000000001"},
        issued_at=NOW,
        expires_at=NOW + timedelta(days=30),
        max_runs=2,
        signer_id="capability-root",
        signature=b"unsigned",
    )
    schedule = replace(
        unsigned_schedule,
        signature=CAPABILITY_KEY.sign(unsigned_schedule.canonical_bytes()).signature,
    )
    authorization = engine()
    briefing = action(
        classification=ActionClass.AUTONOMOUS,
        kind="briefing.create",
        payload={"guild_id": "100000000000000001"},
        variable_cost_usd=Decimal("0"),
    )

    assert authorization.authorize(briefing, schedule=schedule, now=NOW).allowed
    assert authorization.authorize(briefing, schedule=schedule, now=NOW).allowed
    with pytest.raises(AuthorizationDenied, match="run limit"):
        authorization.authorize(briefing, schedule=schedule, now=NOW)
    unsigned_other = ScheduleCapability(
        capability_id="schedule-2",
        action_kinds=frozenset({"briefing.create"}),
        scope={"guild_id": "100000000000000001"},
        issued_at=NOW,
        expires_at=NOW + timedelta(days=30),
        max_runs=1,
        signer_id="capability-root",
        signature=b"unsigned",
    )
    signed_other = replace(
        unsigned_other,
        signature=CAPABILITY_KEY.sign(unsigned_other.canonical_bytes()).signature,
    )
    with pytest.raises(AuthorizationDenied, match="scope"):
        engine().authorize(
            replace(briefing, payload={"guild_id": "elsewhere"}),
            schedule=signed_other,
            now=NOW,
        )
