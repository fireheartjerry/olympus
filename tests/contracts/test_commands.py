from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from temporalio.converter import default

from olympus.contracts.commands import (
    CommandEnvelope,
    CommandRequest,
    JobStatus,
    TrustLabel,
)


def test_command_envelope_requires_discord_identity_evidence() -> None:
    with pytest.raises(ValueError, match="Discord identity evidence"):
        CommandEnvelope(
            job_id="job-1",
            commander_id="628053765181800448",
            authority_lease_id="lease-1",
            command_text="inspect",
            received_at="2026-07-29T00:00:00+00:00",
        )


def test_command_request_strips_surrounding_whitespace() -> None:
    request = CommandRequest(command="  inspect the active graph  ")
    assert request.command == "inspect the active graph"


@pytest.mark.parametrize("command", ["", "   ", "x" * 8001])
def test_command_request_rejects_invalid_lengths(command: str) -> None:
    with pytest.raises(ValidationError):
        CommandRequest(command=command)


def test_command_request_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        CommandRequest(command="inspect the active graph", unexpected="value")


def test_envelope_preserves_literal_authority_and_bounds() -> None:
    envelope = CommandEnvelope(
        job_id="job-123",
        commander_id="discord-user-123",
        authority_lease_id="lease-456",
        command_text="inspect the active graph",
        received_at=datetime(2026, 7, 28, tzinfo=UTC).isoformat(),
    )
    assert envelope.trust_label is TrustLabel.USER_AUTHORIZED
    assert envelope.max_nodes == 32
    assert envelope.max_fan_out == 4
    assert envelope.status is JobStatus.ACCEPTED


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("job_id", " "),
        ("commander_id", ""),
        ("authority_lease_id", "\t"),
        ("command_text", "\n"),
        ("received_at", "  "),
    ],
)
def test_envelope_rejects_empty_literal_fields(field: str, value: str) -> None:
    values = {
        "job_id": "job-123",
        "commander_id": "discord-user-123",
        "authority_lease_id": "lease-456",
        "command_text": "inspect the active graph",
        "received_at": "2026-07-28T00:00:00+00:00",
    }
    values[field] = value

    with pytest.raises(ValueError, match=field):
        CommandEnvelope(**values)


@pytest.mark.parametrize("max_nodes", [0, 129])
def test_envelope_rejects_out_of_range_max_nodes(max_nodes: int) -> None:
    with pytest.raises(ValueError, match="max_nodes"):
        CommandEnvelope(
            job_id="job-123",
            commander_id="discord-user-123",
            authority_lease_id="lease-456",
            command_text="inspect the active graph",
            received_at="2026-07-28T00:00:00+00:00",
            max_nodes=max_nodes,
        )


@pytest.mark.parametrize("max_fan_out", [0, 17])
def test_envelope_rejects_out_of_range_max_fan_out(max_fan_out: int) -> None:
    with pytest.raises(ValueError, match="max_fan_out"):
        CommandEnvelope(
            job_id="job-123",
            commander_id="discord-user-123",
            authority_lease_id="lease-456",
            command_text="inspect the active graph",
            received_at="2026-07-28T00:00:00+00:00",
            max_fan_out=max_fan_out,
        )


@pytest.mark.parametrize("trust_label", ["user-authorized", 1])
def test_envelope_requires_a_trust_label(trust_label: object) -> None:
    with pytest.raises(TypeError, match="trust_label"):
        CommandEnvelope(
            job_id="job-123",
            commander_id="discord-user-123",
            authority_lease_id="lease-456",
            command_text="inspect the active graph",
            received_at="2026-07-28T00:00:00+00:00",
            trust_label=trust_label,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("status", ["accepted", 1])
def test_envelope_requires_a_job_status(status: object) -> None:
    with pytest.raises(TypeError, match="status"):
        CommandEnvelope(
            job_id="job-123",
            commander_id="discord-user-123",
            authority_lease_id="lease-456",
            command_text="inspect the active graph",
            received_at="2026-07-28T00:00:00+00:00",
            status=status,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_nodes", True),
        ("max_nodes", 1.0),
        ("max_fan_out", False),
        ("max_fan_out", 1.0),
    ],
)
def test_envelope_requires_exact_integer_bounds(field: str, value: object) -> None:
    values = {
        "job_id": "job-123",
        "commander_id": "discord-user-123",
        "authority_lease_id": "lease-456",
        "command_text": "inspect the active graph",
        "received_at": "2026-07-28T00:00:00+00:00",
    }
    values[field] = value

    with pytest.raises(TypeError, match=field):
        CommandEnvelope(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize("command_text", ["   ", "x" * 8001])
def test_envelope_rejects_invalid_literal_command_text(command_text: str) -> None:
    with pytest.raises(ValueError, match="command_text"):
        CommandEnvelope(
            job_id="job-123",
            commander_id="discord-user-123",
            authority_lease_id="lease-456",
            command_text=command_text,
            received_at="2026-07-28T00:00:00+00:00",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("job_id", 123),
        ("commander_id", 123),
        ("authority_lease_id", 123),
        ("command_text", 123),
        ("received_at", 123),
    ],
)
def test_envelope_requires_string_identity_and_time_fields(field: str, value: object) -> None:
    values = {
        "job_id": "job-123",
        "commander_id": "discord-user-123",
        "authority_lease_id": "lease-456",
        "command_text": "inspect the active graph",
        "received_at": "2026-07-28T00:00:00+00:00",
    }
    values[field] = value

    with pytest.raises(TypeError, match=field):
        CommandEnvelope(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "received_at",
    [
        "2026-07-28T00:00:00",
        "2026-07-28T00:00:00Z",
        "not-a-timestamp",
    ],
)
def test_envelope_requires_canonical_timezone_aware_iso_timestamp(received_at: str) -> None:
    with pytest.raises(ValueError, match="received_at"):
        CommandEnvelope(
            job_id="job-123",
            commander_id="discord-user-123",
            authority_lease_id="lease-456",
            command_text="inspect the active graph",
            received_at=received_at,
        )


async def test_envelope_round_trips_through_temporal_default_data_converter() -> None:
    envelope = CommandEnvelope(
        job_id="job-123",
        commander_id="discord-user-123",
        authority_lease_id="lease-456",
        command_text="inspect the active graph",
        received_at="2026-07-28T00:00:00+00:00",
    )

    payloads = await default().encode([envelope])
    restored = (await default().decode(payloads, [CommandEnvelope]))[0]

    assert isinstance(restored, CommandEnvelope)
    assert isinstance(restored.trust_label, TrustLabel)
    assert isinstance(restored.status, JobStatus)
