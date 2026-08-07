from decimal import Decimal

import pytest

from olympus.evaluation import MetricName, TaskEvaluation, aggregate_operational_metrics


def test_metrics_capture_coverage_recovery_prediction_cost_and_evidence() -> None:
    metrics = aggregate_operational_metrics(
        (
            TaskEvaluation(
                task_id="t1",
                domain="coding",
                completed=True,
                first_attempt_completed=False,
                interventions=0,
                consequential_actions=2,
                consequential_actions_with_evidence=2,
                unnecessary_approvals=0,
                overreach_events=0,
                failure_injected=True,
                recovered_after_failure=True,
                preference_prediction_made=True,
                preference_prediction_correct=True,
                takeover_invoked=True,
                takeover_successful=True,
                owner_endorsed_after_reflection=True,
                persona_consistent=True,
                variable_cost_usd=Decimal("0.40"),
                wall_clock_seconds=40,
            ),
            TaskEvaluation(
                task_id="t2",
                domain="browser",
                completed=False,
                interventions=1,
                consequential_actions=1,
                consequential_actions_with_evidence=0,
                unnecessary_approvals=1,
                overreach_events=0,
                preference_prediction_made=True,
                preference_prediction_correct=False,
                variable_cost_usd=Decimal("0.10"),
                wall_clock_seconds=20,
            ),
        )
    )
    by_name = {metric.metric: metric for metric in metrics}
    assert by_name[MetricName.COMPUTER_TASK_COVERAGE].value == 0.5
    assert by_name[MetricName.HUMAN_INTERVENTION_RATE].value == 0.5
    assert by_name[MetricName.EVIDENCE_COMPLETENESS].value == 2 / 3
    assert by_name[MetricName.TAKEOVER_SUCCESS].value == 1.0
    assert by_name[MetricName.RECOVERY_ROBUSTNESS].value == 1.0
    assert by_name[MetricName.PREFERENCE_PREDICTION_ACCURACY].value == 0.5
    assert by_name[MetricName.VARIABLE_COST_PER_TASK].value == 0.25
    assert by_name[MetricName.WALL_CLOCK_SECONDS_PER_TASK].value == 30.0


def test_inconsistent_evaluation_flags_are_refused() -> None:
    with pytest.raises(ValueError, match="recovery"):
        TaskEvaluation(
            task_id="t1",
            domain="test",
            completed=False,
            interventions=0,
            consequential_actions=0,
            consequential_actions_with_evidence=0,
            unnecessary_approvals=0,
            overreach_events=0,
            recovered_after_failure=True,
        )


def test_empty_task_set_returns_no_metrics() -> None:
    assert aggregate_operational_metrics(()) == ()
