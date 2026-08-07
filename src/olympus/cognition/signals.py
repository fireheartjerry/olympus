"""Side-effect-free contracts for evidence used by the Jerry cognitive model.

This module deliberately does not mutate a user model. It gives future model
workers a typed language for proposing evidence; persistence, authority, and
promotion remain separate governed operations.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator


class CognitiveDomain(StrEnum):
    GENERAL = "general"
    ENGINEERING = "engineering"
    RESEARCH = "research"
    BUSINESS = "business"
    FINANCE = "finance"
    COMMUNICATION = "communication"
    RELATIONSHIPS = "relationships"
    HEALTH = "health"
    OPERATIONS = "operations"
    PERSONAL_STYLE = "personal-style"


class SignalKind(StrEnum):
    EXPLICIT_STATEMENT = "explicit-statement"
    EXPLICIT_CORRECTION = "explicit-correction"
    DEMONSTRATED_ACTION = "demonstrated-action"
    REPEATED_BEHAVIOR = "repeated-behavior"
    OUTCOME_FEEDBACK = "outcome-feedback"
    EXTERNAL_EVIDENCE = "external-evidence"
    MODEL_INFERENCE = "model-inference"


class LearningDirective(StrEnum):
    AUTO = "auto"
    LEARN = "learn"
    EXCEPTION_ONLY = "exception-only"
    NEVER_IMITATE = "never-imitate"


class EvidenceTrust(StrEnum):
    """Mirrors the existing control-plane trust vocabulary without granting authority."""

    CONTROL = "control"
    USER_AUTHORIZED = "user-authorized"
    MODEL_DERIVED = "model-derived"
    EXTERNAL_UNTRUSTED = "external-untrusted"


class CognitiveSignal(BaseModel):
    """One immutable observation proposed as evidence about Jerry.

    A signal is not a fact and cannot update the canonical model by itself.
    The model-maintenance workflow must reconcile it with contradictions,
    provenance, recurrence, explicit directives, and owner confirmation.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    signal_id: str = Field(min_length=1, max_length=128)
    subject_id: str = Field(min_length=1, max_length=128)
    domain: CognitiveDomain
    kind: SignalKind
    directive: LearningDirective = LearningDirective.AUTO
    summary: str = Field(min_length=1, max_length=4000)
    source_ref: str = Field(min_length=1, max_length=1024)
    observed_at: AwareDatetime
    confidence: float = Field(ge=0.0, le=1.0)
    recurrence_key: str | None = Field(default=None, max_length=256)
    payload_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    trust: EvidenceTrust = EvidenceTrust.MODEL_DERIVED

    @field_validator("signal_id", "subject_id", "summary", "source_ref")
    @classmethod
    def reject_blank(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("value must not be blank")
        return stripped


def suggested_evidence_weight(signal: CognitiveSignal) -> float:
    """Return a conservative initial weight for review and calibration.

    These are defaults, not learned truth. They make the first model explicit
    and testable instead of hiding its assumptions inside prompts.
    """

    base = {
        SignalKind.EXPLICIT_CORRECTION: 1.00,
        SignalKind.EXPLICIT_STATEMENT: 0.90,
        SignalKind.OUTCOME_FEEDBACK: 0.75,
        SignalKind.DEMONSTRATED_ACTION: 0.65,
        SignalKind.REPEATED_BEHAVIOR: 0.60,
        SignalKind.EXTERNAL_EVIDENCE: 0.25,
        SignalKind.MODEL_INFERENCE: 0.20,
    }[signal.kind]

    if signal.directive is LearningDirective.LEARN:
        base = max(base, 0.95)
    elif signal.directive is LearningDirective.EXCEPTION_ONLY:
        base = min(base, 0.10)
    elif signal.directive is LearningDirective.NEVER_IMITATE:
        return 0.0

    trust_multiplier = {
        EvidenceTrust.CONTROL: 1.0,
        EvidenceTrust.USER_AUTHORIZED: 1.0,
        EvidenceTrust.MODEL_DERIVED: 0.7,
        EvidenceTrust.EXTERNAL_UNTRUSTED: 0.35,
    }[signal.trust]
    return round(min(1.0, base * signal.confidence * trust_multiplier), 6)
