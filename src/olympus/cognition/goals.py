"""Typed goal graph and deterministic alignment-review primitives."""

from __future__ import annotations

from collections import deque
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class GoalKind(StrEnum):
    CONSTITUTIONAL = "constitutional"
    LONG_HORIZON = "long-horizon"
    ACTIVE = "active"
    TACTICAL = "tactical"


class GoalState(StrEnum):
    PROPOSED = "proposed"
    ACTIVE = "active"
    PAUSED = "paused"
    SATISFIED = "satisfied"
    RETIRED = "retired"


class GoalMetric(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=160)
    description: str = Field(min_length=1, max_length=1000)
    target: str = Field(min_length=1, max_length=500)


class GoalNode(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    goal_id: str = Field(min_length=1, max_length=128)
    statement: str = Field(min_length=1, max_length=2000)
    kind: GoalKind
    state: GoalState = GoalState.ACTIVE
    priority: float = Field(ge=0.0, le=1.0)
    parent_ids: tuple[str, ...] = ()
    metrics: tuple[GoalMetric, ...] = ()
    rationale: str = Field(min_length=1, max_length=4000)
    owner_confirmed: bool = False


class GoalGraph(BaseModel):
    """Acyclic hierarchy of explicit goals.

    This is not a reward function. It is inspectable state used by planners and
    reviewers, with uncertainty and owner confirmation kept visible.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(ge=1)
    goals: tuple[GoalNode, ...]

    @model_validator(mode="after")
    def validate_graph(self) -> GoalGraph:
        by_id = {goal.goal_id: goal for goal in self.goals}
        if len(by_id) != len(self.goals):
            raise ValueError("goal_id values must be unique")
        for goal in self.goals:
            if goal.goal_id in goal.parent_ids:
                raise ValueError(f"goal {goal.goal_id!r} cannot parent itself")
            missing = sorted(set(goal.parent_ids) - by_id.keys())
            if missing:
                raise ValueError(f"goal {goal.goal_id!r} has missing parents: {missing}")
        self.topological_order()
        return self

    def topological_order(self) -> tuple[str, ...]:
        by_id = {goal.goal_id: goal for goal in self.goals}
        indegree = {goal_id: 0 for goal_id in by_id}
        children: dict[str, list[str]] = {goal_id: [] for goal_id in by_id}
        for goal in self.goals:
            for parent_id in goal.parent_ids:
                indegree[goal.goal_id] += 1
                children[parent_id].append(goal.goal_id)

        ready = deque(sorted(goal_id for goal_id, degree in indegree.items() if degree == 0))
        order: list[str] = []
        while ready:
            goal_id = ready.popleft()
            order.append(goal_id)
            for child_id in sorted(children[goal_id]):
                indegree[child_id] -= 1
                if indegree[child_id] == 0:
                    ready.append(child_id)
        if len(order) != len(by_id):
            raise ValueError("goal graph must be acyclic")
        return tuple(order)

    def by_id(self) -> dict[str, GoalNode]:
        return {goal.goal_id: goal for goal in self.goals}


class GoalImpact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    goal_id: str = Field(min_length=1, max_length=128)
    effect: float = Field(ge=-1.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str = Field(min_length=1, max_length=2000)


class AlignmentDisposition(StrEnum):
    ALIGNED = "aligned"
    MIXED = "mixed"
    CONFLICTING = "conflicting"
    INSUFFICIENT_EVIDENCE = "insufficient-evidence"


class AlignmentReview(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    disposition: AlignmentDisposition
    weighted_score: float = Field(ge=-1.0, le=1.0)
    supporting_goal_ids: tuple[str, ...]
    conflicting_goal_ids: tuple[str, ...]
    ask_why: bool
    explanation: str = Field(min_length=1, max_length=4000)
    recommended_alternative: str | None = Field(default=None, max_length=4000)


def review_alignment(
    *,
    graph: GoalGraph,
    impacts: tuple[GoalImpact, ...],
    explanation: str,
    recommended_alternative: str | None = None,
) -> AlignmentReview:
    """Aggregate model-estimated impacts without pretending to estimate them here."""

    if not impacts:
        return AlignmentReview(
            disposition=AlignmentDisposition.INSUFFICIENT_EVIDENCE,
            weighted_score=0.0,
            supporting_goal_ids=(),
            conflicting_goal_ids=(),
            ask_why=True,
            explanation=explanation,
            recommended_alternative=recommended_alternative,
        )

    goals = graph.by_id()
    unknown = sorted({impact.goal_id for impact in impacts} - goals.keys())
    if unknown:
        raise ValueError(f"impacts reference unknown goals: {unknown}")

    numerator = 0.0
    denominator = 0.0
    supporting: list[str] = []
    conflicting: list[str] = []
    for impact in impacts:
        goal = goals[impact.goal_id]
        if goal.state is not GoalState.ACTIVE:
            continue
        weight = goal.priority * impact.confidence
        numerator += weight * impact.effect
        denominator += weight
        if impact.effect >= 0.2:
            supporting.append(impact.goal_id)
        elif impact.effect <= -0.2:
            conflicting.append(impact.goal_id)

    score = 0.0 if denominator == 0.0 else max(-1.0, min(1.0, numerator / denominator))
    if denominator == 0.0:
        disposition = AlignmentDisposition.INSUFFICIENT_EVIDENCE
    elif score <= -0.2 or any(
        goals[goal_id].kind is GoalKind.CONSTITUTIONAL for goal_id in conflicting
    ):
        disposition = AlignmentDisposition.CONFLICTING
    elif score >= 0.2 and not conflicting:
        disposition = AlignmentDisposition.ALIGNED
    else:
        disposition = AlignmentDisposition.MIXED

    return AlignmentReview(
        disposition=disposition,
        weighted_score=round(score, 6),
        supporting_goal_ids=tuple(sorted(set(supporting))),
        conflicting_goal_ids=tuple(sorted(set(conflicting))),
        ask_why=disposition
        in {
            AlignmentDisposition.CONFLICTING,
            AlignmentDisposition.MIXED,
            AlignmentDisposition.INSUFFICIENT_EVIDENCE,
        },
        explanation=explanation,
        recommended_alternative=recommended_alternative,
    )
