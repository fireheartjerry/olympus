from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from olympus.governance.authorization import (
    Action,
    ActionClass,
    AuthorizationDenied,
    AuthorizationEngine,
    BudgetGovernor,
    ScheduleCapability,
    TaintedValue,
    TrustLabel,
)
from olympus.operations.autonomy import (
    ActivationProof,
    AutonomyDenied,
    HighAutonomyController,
)

NOW = datetime(2026, 7, 29, tzinfo=UTC)


def schedule() -> ScheduleCapability:
    return ScheduleCapability(
        capability_id="chief-of-staff-30d",
        action_kinds=frozenset({"briefing.create", "repair.reversible"}),
        scope={"owner": "628053765181800448"},
        issued_at=NOW,
        expires_at=NOW + timedelta(days=30),
        max_runs=60,
    )


def action(kind: str = "briefing.create") -> Action:
    return Action(
        action_id=f"action-{kind}",
        kind=kind,
        classification=ActionClass.AUTONOMOUS,
        payload={"owner": "628053765181800448"},
        variable_cost_usd=Decimal("0"),
        inputs=(
            TaintedValue(
                "external inbox context",
                frozenset({TrustLabel.EXTERNAL_UNTRUSTED}),
            ),
        ),
    )


def controller() -> HighAutonomyController:
    return HighAutonomyController(
        authorization=AuthorizationEngine(BudgetGovernor(monthly_ceiling_usd=Decimal("50"))),
        activation_verifier=lambda proof: proof.proof_digest == "face-id-bound-digest",
        maximum_followups=10,
        maximum_followup_horizon=timedelta(days=30),
    )


def test_face_id_activation_enables_bounded_proactive_and_repair_actions() -> None:
    autonomy = controller()
    autonomy.activate(
        ActivationProof(2, NOW, NOW + timedelta(days=30), "face-id-bound-digest"),
        now=NOW,
    )

    briefing = autonomy.run(action(), schedule=schedule(), now=NOW)
    repair = autonomy.run(action("repair.reversible"), schedule=schedule(), now=NOW)

    assert briefing.allowed and repair.allowed


def test_inactive_expired_or_anomalous_autonomy_fails_closed() -> None:
    autonomy = controller()
    with pytest.raises(AutonomyDenied, match="not active"):
        autonomy.run(action(), schedule=schedule(), now=NOW)
    with pytest.raises(AutonomyDenied, match="proof"):
        autonomy.activate(
            ActivationProof(2, NOW, NOW + timedelta(days=30), "forged"),
            now=NOW,
        )
    autonomy.activate(
        ActivationProof(2, NOW, NOW + timedelta(days=1), "face-id-bound-digest"),
        now=NOW,
    )
    autonomy.record_anomaly("unexpected-protected-action")
    with pytest.raises(AutonomyDenied, match="not active"):
        autonomy.run(action(), schedule=schedule(), now=NOW)


def test_tainted_protected_action_still_cannot_become_autonomous() -> None:
    autonomy = controller()
    autonomy.activate(
        ActivationProof(2, NOW, NOW + timedelta(days=30), "face-id-bound-digest"),
        now=NOW,
    )
    protected = replace(action(), classification=ActionClass.PROTECTED)

    with pytest.raises(AuthorizationDenied, match="tainted"):
        autonomy.run(protected, schedule=schedule(), now=NOW)


def test_self_scheduled_followups_are_bounded() -> None:
    autonomy = controller()
    autonomy.activate(
        ActivationProof(2, NOW, NOW + timedelta(days=30), "face-id-bound-digest"),
        now=NOW,
    )

    for index in range(10):
        autonomy.schedule_followup(f"followup-{index}", NOW + timedelta(days=1), now=NOW)
    with pytest.raises(AutonomyDenied, match="limit"):
        autonomy.schedule_followup("followup-overflow", NOW + timedelta(days=1), now=NOW)
    far_future = controller()
    far_future.activate(
        ActivationProof(2, NOW, NOW + timedelta(days=30), "face-id-bound-digest"),
        now=NOW,
    )
    with pytest.raises(AutonomyDenied, match="horizon"):
        far_future.schedule_followup("too-far", NOW + timedelta(days=31), now=NOW)
