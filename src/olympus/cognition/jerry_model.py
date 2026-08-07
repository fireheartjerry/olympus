"""Versioned contracts for the Jerry cognitive model.

The models preserve distinctions that a prompt-only user profile tends to
collapse: observed behavior, predicted immediate choice, and reflective choice
under Jerry's declared long-horizon goals.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from olympus.cognition.goals import GoalImpact
from olympus.cognition.signals import CognitiveDomain


class PreferenceState(StrEnum):
    HYPOTHESIS = "hypothesis"
    OWNER_CONFIRMED = "owner-confirmed"
    DISPUTED = "disputed"
    RETIRED = "retired"


class PreferenceHypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    preference_id: str = Field(min_length=1, max_length=128)
    domain: CognitiveDomain
    proposition: str = Field(min_length=1, max_length=2000)
    probability: float = Field(ge=0.0, le=1.0)
    state: PreferenceState = PreferenceState.HYPOTHESIS
    supporting_signal_ids: tuple[str, ...] = ()
    contradicting_signal_ids: tuple[str, ...] = ()
    last_updated_at: AwareDatetime


class CommunicationProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_id: str = Field(min_length=1, max_length=128)
    audience_ref: str = Field(min_length=1, max_length=256)
    formality: float = Field(ge=0.0, le=1.0)
    directness: float = Field(ge=0.0, le=1.0)
    humor: float = Field(ge=0.0, le=1.0)
    vocabulary_notes: tuple[str, ...] = ()
    prohibited_patterns: tuple[str, ...] = ()
    evidence_signal_ids: tuple[str, ...] = ()


class ModelConflict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    conflict_id: str = Field(min_length=1, max_length=128)
    summary: str = Field(min_length=1, max_length=2000)
    evidence_signal_ids: tuple[str, ...]
    requires_owner_resolution: bool = True


class JerryModelSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot_id: str = Field(min_length=1, max_length=128)
    owner_id: str = Field(min_length=1, max_length=128)
    version: int = Field(ge=1)
    created_at: AwareDatetime
    goal_graph_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    preferences: tuple[PreferenceHypothesis, ...] = ()
    communication_profiles: tuple[CommunicationProfile, ...] = ()
    unresolved_conflicts: tuple[ModelConflict, ...] = ()
    predecessor_snapshot_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def require_unique_ids(self) -> JerryModelSnapshot:
        preference_ids = [item.preference_id for item in self.preferences]
        if len(preference_ids) != len(set(preference_ids)):
            raise ValueError("preference_id values must be unique")
        profile_ids = [item.profile_id for item in self.communication_profiles]
        if len(profile_ids) != len(set(profile_ids)):
            raise ValueError("profile_id values must be unique")
        conflict_ids = [item.conflict_id for item in self.unresolved_conflicts]
        if len(conflict_ids) != len(set(conflict_ids)):
            raise ValueError("conflict_id values must be unique")
        return self


class DecisionOption(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    option_id: str = Field(min_length=1, max_length=128)
    summary: str = Field(min_length=1, max_length=2000)


class OptionAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    option_id: str = Field(min_length=1, max_length=128)
    immediate_probability: float = Field(ge=0.0, le=1.0)
    reflective_probability: float = Field(ge=0.0, le=1.0)
    recommendation_score: float = Field(ge=-1.0, le=1.0)
    key_tradeoffs: tuple[str, ...] = ()


class EvidenceCitation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    signal_id: str = Field(min_length=1, max_length=128)
    role: str = Field(min_length=1, max_length=64)
    effective_weight: float = Field(ge=0.0, le=1.0)
    interpretation: str = Field(min_length=1, max_length=2000)


class DecisionForensicTrace(BaseModel):
    """Inspectable evidence for a prediction without exposing private model scratchpads."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    trace_id: str = Field(min_length=1, max_length=128)
    prediction_id: str = Field(min_length=1, max_length=128)
    snapshot_id: str = Field(min_length=1, max_length=128)
    generated_at: AwareDatetime
    evidence: tuple[EvidenceCitation, ...]
    goal_impacts: tuple[GoalImpact, ...]
    alternative_analyses: tuple[str, ...]
    uncertainty_sources: tuple[str, ...]
    owner_question: str | None = Field(default=None, max_length=4000)
    explanation: str = Field(min_length=1, max_length=12_000)


class DecisionPrediction(BaseModel):
    """Inspectable result from a future Jerry-simulation service."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    prediction_id: str = Field(min_length=1, max_length=128)
    snapshot_id: str = Field(min_length=1, max_length=128)
    question: str = Field(min_length=1, max_length=4000)
    options: tuple[DecisionOption, ...]
    assessments: tuple[OptionAssessment, ...]
    predicted_immediate_option_id: str
    predicted_reflective_option_id: str
    recommended_option_id: str
    immediate_confidence: float = Field(ge=0.0, le=1.0)
    reflective_confidence: float = Field(ge=0.0, le=1.0)
    recommendation_confidence: float = Field(ge=0.0, le=1.0)
    evidence_signal_ids: tuple[str, ...]
    goal_ids: tuple[str, ...]
    uncertainty_sources: tuple[str, ...] = ()
    rationale: str = Field(min_length=1, max_length=8000)

    @model_validator(mode="after")
    def require_known_choices(self) -> DecisionPrediction:
        option_ids = {option.option_id for option in self.options}
        if not option_ids:
            raise ValueError("a decision prediction requires at least one option")
        if len(option_ids) != len(self.options):
            raise ValueError("option_id values must be unique")
        assessment_ids = {assessment.option_id for assessment in self.assessments}
        if len(assessment_ids) != len(self.assessments):
            raise ValueError("assessment option_id values must be unique")
        if assessment_ids != option_ids:
            raise ValueError("assessments must cover every option exactly once")
        selected_ids = (
            self.predicted_immediate_option_id,
            self.predicted_reflective_option_id,
            self.recommended_option_id,
        )
        for selected in selected_ids:
            if selected not in option_ids:
                raise ValueError(f"prediction selects unknown option {selected!r}")
        return self


class ModelUpdateProposal(BaseModel):
    """A proposed model delta; never an automatic canonical mutation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    proposal_id: str = Field(min_length=1, max_length=128)
    base_snapshot_id: str = Field(min_length=1, max_length=128)
    signal_ids: tuple[str, ...]
    proposed_preference_updates: tuple[PreferenceHypothesis, ...] = ()
    conflict_updates: tuple[ModelConflict, ...] = ()
    owner_question: str | None = Field(default=None, max_length=4000)
    explanation: str = Field(min_length=1, max_length=8000)

    @model_validator(mode="after")
    def require_delta_evidence(self) -> ModelUpdateProposal:
        if not self.signal_ids:
            raise ValueError("a model update proposal requires source signals")
        if not self.proposed_preference_updates and not self.conflict_updates:
            raise ValueError("a model update proposal must change preferences or conflicts")
        return self
