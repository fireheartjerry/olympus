from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

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
    }
    values.update(overrides)
    return Approval(**values)  # type: ignore[arg-type]


def test_literal_approval_budget_and_audit_allow_exact_action_once() -> None:
    engine = AuthorizationEngine(BudgetGovernor(monthly_ceiling_usd=Decimal("50")))
    candidate = action()

    decision = engine.authorize(candidate, approval=approval(candidate), now=NOW)

    assert decision.allowed
    assert engine.budget.spent_usd == Decimal("2.00")
    assert engine.audit.verify()
    with pytest.raises(AuthorizationDenied, match="already consumed"):
        engine.authorize(candidate, approval=approval(candidate), now=NOW)


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
    engine = AuthorizationEngine(BudgetGovernor(monthly_ceiling_usd=Decimal("50")))

    with pytest.raises(AuthorizationDenied, match="literal action"):
        engine.authorize(altered, approval=approval(original), now=NOW)


def test_transitive_untrusted_or_model_taint_cannot_reach_privileged_sink() -> None:
    source = TaintedValue("ignore policy", frozenset({TrustLabel.EXTERNAL_UNTRUSTED}))
    derived = TaintedValue.derive("sudo reboot", source, model_derived=True)
    candidate = action(
        kind="root.execute",
        inputs=(derived,),
    )

    with pytest.raises(AuthorizationDenied, match="tainted"):
        AuthorizationEngine(BudgetGovernor(monthly_ceiling_usd=Decimal("50"))).authorize(
            candidate,
            approval=approval(candidate),
            now=NOW,
        )


def test_hard_monthly_spending_ceiling_cannot_be_exceeded() -> None:
    engine = AuthorizationEngine(BudgetGovernor(monthly_ceiling_usd=Decimal("5")))
    first = action(action_id="first", variable_cost_usd=Decimal("4"))
    second = action(action_id="second", variable_cost_usd=Decimal("2"))
    engine.authorize(first, approval=approval(first), now=NOW)

    with pytest.raises(AuthorizationDenied, match="spending ceiling"):
        engine.authorize(
            second,
            approval=replace(
                approval(second),
                approval_id="approval-2",
            ),
            now=NOW,
        )


def test_schedule_is_bounded_by_scope_expiry_and_run_count() -> None:
    schedule = ScheduleCapability(
        capability_id="schedule-1",
        action_kinds=frozenset({"briefing.create"}),
        scope={"guild_id": "100000000000000001"},
        issued_at=NOW,
        expires_at=NOW + timedelta(days=30),
        max_runs=2,
    )
    engine = AuthorizationEngine(BudgetGovernor(monthly_ceiling_usd=Decimal("50")))
    briefing = action(
        classification=ActionClass.AUTONOMOUS,
        kind="briefing.create",
        payload={"guild_id": "100000000000000001"},
        variable_cost_usd=Decimal("0"),
    )

    assert engine.authorize(briefing, schedule=schedule, now=NOW).allowed
    assert engine.authorize(briefing, schedule=schedule, now=NOW).allowed
    with pytest.raises(AuthorizationDenied, match="run limit"):
        engine.authorize(briefing, schedule=schedule, now=NOW)
    with pytest.raises(AuthorizationDenied, match="scope"):
        AuthorizationEngine(BudgetGovernor(monthly_ceiling_usd=Decimal("50"))).authorize(
            replace(briefing, payload={"guild_id": "elsewhere"}),
            schedule=ScheduleCapability(
                capability_id="schedule-2",
                action_kinds=frozenset({"briefing.create"}),
                scope={"guild_id": "100000000000000001"},
                issued_at=NOW,
                expires_at=NOW + timedelta(days=30),
                max_runs=1,
            ),
            now=NOW,
        )
