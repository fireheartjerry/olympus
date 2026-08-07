"""Perception and memory contracts for continuous observation with selective retention."""

from __future__ import annotations

from enum import StrEnum

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class PerceptionSource(StrEnum):
    SCREEN = "screen"
    WINDOW_STATE = "window-state"
    FILESYSTEM = "filesystem"
    TERMINAL = "terminal"
    BROWSER = "browser"
    MESSAGE = "message"
    EMAIL = "email"
    CALENDAR = "calendar"
    MICROPHONE = "microphone"
    CAMERA = "camera"
    LOCATION = "location"
    DEVICE = "device"
    HEALTH = "health"
    CLOUD = "cloud"


class MediaKind(StrEnum):
    STRUCTURED = "structured"
    TEXT = "text"
    AUDIO = "audio"
    IMAGE = "image"
    VIDEO = "video"
    BINARY = "binary"


class Sensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    PERSONAL = "personal"
    SENSITIVE = "sensitive"
    HIGHLY_SENSITIVE = "highly-sensitive"


class MemoryKind(StrEnum):
    WORKING = "working"
    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    PROCEDURAL = "procedural"
    RELATIONAL = "relational"
    SELF_MODEL = "self-model"
    USER_MODEL = "user-model"


class RetentionClass(StrEnum):
    BUFFER_ONLY = "buffer-only"
    SHORT_TERM = "short-term"
    DURABLE_SUMMARY = "durable-summary"
    DURABLE_FACT = "durable-fact"
    ARCHIVAL = "archival"


class PerceptionEvent(BaseModel):
    """Digest-addressed event at the perception boundary.

    Raw media is referenced, never embedded. Any raw reference requires a
    finite expiry so continuous perception does not silently become permanent
    indiscriminate recording.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(min_length=1, max_length=128)
    source: PerceptionSource
    media_kind: MediaKind
    source_node_id: str = Field(min_length=1, max_length=128)
    observed_at: AwareDatetime
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    structured_summary: str = Field(min_length=1, max_length=8000)
    sensitivity: Sensitivity
    raw_buffer_ref: str | None = Field(default=None, max_length=1024)
    raw_expires_at: AwareDatetime | None = None
    contains_bystander_data: bool = False

    @model_validator(mode="after")
    def bound_raw_retention(self) -> PerceptionEvent:
        if (self.raw_buffer_ref is None) != (self.raw_expires_at is None):
            raise ValueError("raw_buffer_ref and raw_expires_at must be provided together")
        if self.raw_expires_at is not None and self.raw_expires_at <= self.observed_at:
            raise ValueError("raw buffer expiry must be after observation time")
        return self


class MemoryCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: str = Field(min_length=1, max_length=128)
    event_ids: tuple[str, ...]
    kind: MemoryKind
    summary: str = Field(min_length=1, max_length=12_000)
    entities: tuple[str, ...] = ()
    salience: float = Field(ge=0.0, le=1.0)
    goal_relevance: float = Field(ge=0.0, le=1.0)
    novelty: float = Field(ge=0.0, le=1.0)
    future_utility: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    sensitivity: Sensitivity
    proposed_retention: RetentionClass
    provenance_refs: tuple[str, ...]

    @model_validator(mode="after")
    def require_provenance(self) -> MemoryCandidate:
        if not self.event_ids:
            raise ValueError("memory candidate requires at least one source event")
        if not self.provenance_refs:
            raise ValueError("memory candidate requires provenance")
        return self


class RetentionDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: str
    retention: RetentionClass
    score: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(min_length=1, max_length=4000)
    owner_review_required: bool = False


class MemoryRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    memory_id: str = Field(min_length=1, max_length=128)
    kind: MemoryKind
    summary: str = Field(min_length=1, max_length=12_000)
    recorded_at: AwareDatetime
    source_event_ids: tuple[str, ...]
    provenance_refs: tuple[str, ...]
    sensitivity: Sensitivity
    confidence: float = Field(ge=0.0, le=1.0)
    supersedes_memory_ids: tuple[str, ...] = ()
    contradiction_memory_ids: tuple[str, ...] = ()
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def score_memory_candidate(candidate: MemoryCandidate) -> RetentionDecision:
    """Transparent v1 retention score; later calibration must remain versioned."""

    score = (
        0.24 * candidate.salience
        + 0.30 * candidate.goal_relevance
        + 0.16 * candidate.novelty
        + 0.20 * candidate.future_utility
        + 0.10 * candidate.confidence
    )
    score = max(0.0, min(1.0, score))

    if candidate.proposed_retention is RetentionClass.ARCHIVAL:
        owner_review = candidate.sensitivity in {
            Sensitivity.SENSITIVE,
            Sensitivity.HIGHLY_SENSITIVE,
        }
    else:
        owner_review = False

    if score >= 0.80:
        retention = candidate.proposed_retention
    elif score >= 0.58:
        retention = RetentionClass.DURABLE_SUMMARY
    elif score >= 0.30:
        retention = RetentionClass.SHORT_TERM
    else:
        retention = RetentionClass.BUFFER_ONLY

    return RetentionDecision(
        candidate_id=candidate.candidate_id,
        retention=retention,
        score=round(score, 6),
        rationale=(
            "Version-1 weighted retention decision over salience, goal relevance, "
            "novelty, future utility, and confidence."
        ),
        owner_review_required=owner_review,
    )
