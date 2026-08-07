from datetime import UTC, datetime, timedelta

import pytest

from olympus.memory import (
    MediaKind,
    MemoryCandidate,
    MemoryKind,
    PerceptionEvent,
    PerceptionSource,
    RetentionClass,
    Sensitivity,
    score_memory_candidate,
)


def test_raw_capture_requires_finite_expiry() -> None:
    with pytest.raises(ValueError, match="provided together"):
        PerceptionEvent(
            event_id="e1",
            source=PerceptionSource.SCREEN,
            media_kind=MediaKind.VIDEO,
            source_node_id="windows",
            observed_at=datetime.now(UTC),
            payload_sha256="a" * 64,
            structured_summary="Coding session",
            sensitivity=Sensitivity.SENSITIVE,
            raw_buffer_ref="buffer://1",
        )


def test_memory_scoring_prefers_goal_relevant_future_useful_events() -> None:
    candidate = MemoryCandidate(
        candidate_id="c1",
        event_ids=("e1",),
        kind=MemoryKind.PROCEDURAL,
        summary="A reliable recovery procedure",
        salience=0.8,
        goal_relevance=1.0,
        novelty=0.7,
        future_utility=1.0,
        confidence=0.9,
        sensitivity=Sensitivity.INTERNAL,
        proposed_retention=RetentionClass.DURABLE_FACT,
        provenance_refs=("audit:1",),
    )
    decision = score_memory_candidate(candidate)
    assert decision.retention is RetentionClass.DURABLE_FACT
    assert decision.score >= 0.8


def test_valid_raw_buffer_has_expiry_after_observation() -> None:
    observed = datetime.now(UTC)
    event = PerceptionEvent(
        event_id="e1",
        source=PerceptionSource.MICROPHONE,
        media_kind=MediaKind.AUDIO,
        source_node_id="phone",
        observed_at=observed,
        payload_sha256="b" * 64,
        structured_summary="Voice command",
        sensitivity=Sensitivity.PERSONAL,
        raw_buffer_ref="buffer://1",
        raw_expires_at=observed + timedelta(minutes=10),
    )
    assert event.raw_expires_at is not None
