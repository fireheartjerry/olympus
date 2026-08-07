from datetime import UTC, datetime

import pytest

from olympus.cognition import (
    AlignmentDisposition,
    CognitiveDomain,
    CognitiveSignal,
    EvidenceTrust,
    GoalGraph,
    GoalImpact,
    GoalKind,
    GoalNode,
    GoalState,
    LearningDirective,
    SignalKind,
    review_alignment,
    suggested_evidence_weight,
)


def _goal(goal_id: str, *, parent_ids: tuple[str, ...] = (), priority: float = 1.0) -> GoalNode:
    return GoalNode(
        goal_id=goal_id,
        statement=f"Advance {goal_id}",
        kind=GoalKind.LONG_HORIZON,
        state=GoalState.ACTIVE,
        priority=priority,
        parent_ids=parent_ids,
        rationale="Test goal",
        owner_confirmed=True,
    )


def test_explicit_owner_signal_outweighs_model_inference() -> None:
    common = {
        "signal_id": "signal-1",
        "subject_id": "jerry",
        "domain": CognitiveDomain.ENGINEERING,
        "summary": "Prefers reversible deployment steps",
        "source_ref": "conversation:1",
        "observed_at": datetime.now(UTC),
        "confidence": 0.9,
    }
    explicit = CognitiveSignal(
        **common,
        kind=SignalKind.EXPLICIT_STATEMENT,
        trust=EvidenceTrust.USER_AUTHORIZED,
    )
    inferred = CognitiveSignal(
        **{**common, "signal_id": "signal-2"},
        kind=SignalKind.MODEL_INFERENCE,
        trust=EvidenceTrust.MODEL_DERIVED,
    )
    assert suggested_evidence_weight(explicit) > suggested_evidence_weight(inferred)


def test_never_imitate_signal_has_zero_weight() -> None:
    signal = CognitiveSignal(
        signal_id="signal-1",
        subject_id="jerry",
        domain=CognitiveDomain.GENERAL,
        kind=SignalKind.DEMONSTRATED_ACTION,
        directive=LearningDirective.NEVER_IMITATE,
        summary="One-off behavior",
        source_ref="event:1",
        observed_at=datetime.now(UTC),
        confidence=1.0,
    )
    assert suggested_evidence_weight(signal) == 0.0


def test_goal_graph_rejects_cycle() -> None:
    with pytest.raises(ValueError, match="acyclic"):
        GoalGraph(
            version=1,
            goals=(
                _goal("a", parent_ids=("b",)),
                _goal("b", parent_ids=("a",)),
            ),
        )


def test_alignment_review_asks_why_when_high_priority_goal_conflicts() -> None:
    graph = GoalGraph(version=1, goals=(_goal("ship", priority=1.0), _goal("learn", priority=0.5)))
    review = review_alignment(
        graph=graph,
        impacts=(
            GoalImpact(
                goal_id="ship",
                effect=-0.8,
                confidence=0.9,
                explanation="Delays the release",
            ),
            GoalImpact(
                goal_id="learn",
                effect=0.3,
                confidence=0.7,
                explanation="Provides some learning",
            ),
        ),
        explanation="The proposed detour harms the active release objective.",
        recommended_alternative="Finish the release, then run the experiment.",
    )
    assert review.disposition is AlignmentDisposition.CONFLICTING
    assert review.ask_why is True
    assert review.conflicting_goal_ids == ("ship",)
