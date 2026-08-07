from datetime import UTC, datetime

import pytest

from olympus.cognition import (
    CognitiveDomain,
    DecisionForensicTrace,
    DecisionOption,
    DecisionPrediction,
    EvidenceCitation,
    GoalImpact,
    JerryModelSnapshot,
    OptionAssessment,
    PreferenceHypothesis,
)


def _assessments() -> tuple[OptionAssessment, ...]:
    return (
        OptionAssessment(
            option_id="ship",
            immediate_probability=0.8,
            reflective_probability=0.3,
            recommendation_score=0.1,
            key_tradeoffs=("fast", "riskier"),
        ),
        OptionAssessment(
            option_id="refactor",
            immediate_probability=0.2,
            reflective_probability=0.7,
            recommendation_score=0.8,
            key_tradeoffs=("slower", "higher confidence"),
        ),
    )


def test_decision_prediction_distinguishes_jerry_and_fire_recommendation() -> None:
    prediction = DecisionPrediction(
        prediction_id="p1",
        snapshot_id="s1",
        question="Ship now or refactor first?",
        options=(
            DecisionOption(option_id="ship", summary="Ship now"),
            DecisionOption(option_id="refactor", summary="Refactor first"),
        ),
        assessments=_assessments(),
        predicted_immediate_option_id="ship",
        predicted_reflective_option_id="refactor",
        recommended_option_id="refactor",
        immediate_confidence=0.8,
        reflective_confidence=0.7,
        recommendation_confidence=0.85,
        evidence_signal_ids=("e1",),
        goal_ids=("quality",),
        uncertainty_sources=("deadline may change",),
        rationale="Immediate urgency differs from reflective quality preference.",
    )
    assert prediction.predicted_immediate_option_id != prediction.predicted_reflective_option_id
    assert prediction.recommended_option_id == "refactor"


def test_prediction_rejects_incomplete_assessment_coverage() -> None:
    with pytest.raises(ValueError, match="cover every option"):
        DecisionPrediction(
            prediction_id="p1",
            snapshot_id="s1",
            question="Question",
            options=(
                DecisionOption(option_id="a", summary="A"),
                DecisionOption(option_id="b", summary="B"),
            ),
            assessments=(
                OptionAssessment(
                    option_id="a",
                    immediate_probability=1.0,
                    reflective_probability=1.0,
                    recommendation_score=1.0,
                ),
            ),
            predicted_immediate_option_id="a",
            predicted_reflective_option_id="a",
            recommended_option_id="a",
            immediate_confidence=0.8,
            reflective_confidence=0.8,
            recommendation_confidence=0.8,
            evidence_signal_ids=(),
            goal_ids=(),
            rationale="Test",
        )


def test_snapshot_rejects_duplicate_preference_ids() -> None:
    preference = PreferenceHypothesis(
        preference_id="pref",
        domain=CognitiveDomain.ENGINEERING,
        proposition="Prefer tests before rollout",
        probability=0.9,
        last_updated_at=datetime.now(UTC),
    )
    with pytest.raises(ValueError, match="unique"):
        JerryModelSnapshot(
            snapshot_id="s1",
            owner_id="jerry",
            version=1,
            created_at=datetime.now(UTC),
            goal_graph_digest="a" * 64,
            preferences=(preference, preference),
        )


def test_forensic_trace_preserves_evidence_goal_impacts_and_uncertainty() -> None:
    trace = DecisionForensicTrace(
        trace_id="trace-1",
        prediction_id="p1",
        snapshot_id="s1",
        generated_at=datetime.now(UTC),
        evidence=(
            EvidenceCitation(
                signal_id="e1",
                role="supporting",
                effective_weight=0.8,
                interpretation="Repeated preference for verified releases.",
            ),
        ),
        goal_impacts=(
            GoalImpact(
                goal_id="quality",
                effect=0.7,
                confidence=0.8,
                explanation="Refactoring reduces deployment risk.",
            ),
        ),
        alternative_analyses=("Ship now if the deadline becomes hard.",),
        uncertainty_sources=("Deadline not independently confirmed.",),
        owner_question="Has the deadline become non-negotiable?",
        explanation="The reflective estimate favors quality while preserving the deadline caveat.",
    )
    assert trace.owner_question is not None
