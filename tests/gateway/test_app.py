from typing import cast
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from temporalio.client import Client

from olympus.contracts.commands import (
    CommandAccepted,
    CommandEnvelope,
    TrustLabel,
)
from olympus.gateway.app import CommandStarter, TemporalCommandStarter, create_app
from olympus.gateway.settings import GatewaySettings
from olympus.workflows.command import CommandWorkflow

TEST_COMMAND_TOKEN = "test-token-with-at-least-32-bytes"
SHORT_TEST_COMMAND_TOKEN = "too-short"
VALID_HEADERS = {
    "Authorization": f"Bearer {TEST_COMMAND_TOKEN}",
    "X-Olympus-Commander": "discord-user-123",
    "X-Olympus-Authority-Lease": "lease-456",
}


class FakeStarter:
    def __init__(self) -> None:
        self.commands: list[CommandEnvelope] = []

    async def start(self, command: CommandEnvelope) -> CommandAccepted:
        self.commands.append(command)
        return CommandAccepted(job_id=command.job_id)


class RaisingStarter:
    async def start(self, command: CommandEnvelope) -> CommandAccepted:
        raise RuntimeError(f"failed to start {command.job_id}")


def make_client(
    starter: CommandStarter,
    *,
    raise_server_exceptions: bool = True,
) -> TestClient:
    settings = GatewaySettings(
        environment="test",
        dev_command_token=TEST_COMMAND_TOKEN,
    )
    return TestClient(
        create_app(settings=settings, starter=starter),
        raise_server_exceptions=raise_server_exceptions,
    )


def test_health_is_public() -> None:
    client = make_client(FakeStarter())

    assert client.get("/health/live").json() == {"status": "ok"}


def test_command_rejects_missing_token() -> None:
    client = make_client(FakeStarter())
    response = client.post(
        "/v1/commands",
        headers={
            "X-Olympus-Commander": "discord-user-123",
            "X-Olympus-Authority-Lease": "lease-456",
        },
        json={"command": "inspect the graph"},
    )

    assert response.status_code == 401


def test_command_rejects_invalid_bearer_token() -> None:
    client = make_client(FakeStarter())
    response = client.post(
        "/v1/commands",
        headers={
            "Authorization": "Bearer wrong-token-with-at-least-32-bytes",
            "X-Olympus-Commander": "discord-user-123",
            "X-Olympus-Authority-Lease": "lease-456",
        },
        json={"command": "inspect the graph"},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "invalid development command token"}


def test_command_rejects_non_ascii_authorization_as_unauthorized() -> None:
    client = make_client(FakeStarter(), raise_server_exceptions=False)
    response = client.post(
        "/v1/commands",
        headers=[
            (b"Authorization", "Bearer töken-with-at-least-32-bytes".encode()),
            (b"X-Olympus-Commander", b"discord-user-123"),
            (b"X-Olympus-Authority-Lease", b"lease-456"),
        ],
        json={"command": "inspect the graph"},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "invalid development command token"}


def test_command_requires_literal_authority_headers() -> None:
    client = make_client(FakeStarter())
    response = client.post(
        "/v1/commands",
        headers={"Authorization": "Bearer test-token-with-at-least-32-bytes"},
        json={"command": "inspect the graph"},
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    ("header_name", "header_value"),
    [
        ("X-Olympus-Commander", "   "),
        ("X-Olympus-Commander", "a" * 129),
        ("X-Olympus-Commander", "discord user"),
        ("X-Olympus-Commander", "discord/user"),
        ("X-Olympus-Commander", "discord\x01user"),
        ("X-Olympus-Authority-Lease", "   "),
        ("X-Olympus-Authority-Lease", "a" * 129),
        ("X-Olympus-Authority-Lease", "lease value"),
        ("X-Olympus-Authority-Lease", "lease/value"),
        ("X-Olympus-Authority-Lease", "lease\x01value"),
    ],
)
def test_command_rejects_malformed_authority_headers(
    header_name: str,
    header_value: str,
) -> None:
    client = make_client(FakeStarter(), raise_server_exceptions=False)
    headers = {**VALID_HEADERS, header_name: header_value}

    response = client.post(
        "/v1/commands",
        headers=headers,
        json={"command": "inspect the graph"},
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "duplicate_header",
    ["X-Olympus-Commander", "X-Olympus-Authority-Lease"],
)
def test_command_rejects_duplicate_authority_headers(duplicate_header: str) -> None:
    client = make_client(FakeStarter())
    headers = list(VALID_HEADERS.items())
    headers.append((duplicate_header, "second-value"))

    response = client.post(
        "/v1/commands",
        headers=headers,
        json={"command": "inspect the graph"},
    )

    assert response.status_code == 422


def test_command_rejects_extra_json_fields() -> None:
    client = make_client(FakeStarter())
    response = client.post(
        "/v1/commands",
        headers={
            "Authorization": "Bearer test-token-with-at-least-32-bytes",
            "X-Olympus-Commander": "discord-user-123",
            "X-Olympus-Authority-Lease": "lease-456",
        },
        json={"command": "inspect the graph", "authority": "self-approved"},
    )

    assert response.status_code == 422


def test_command_starts_workflow_with_user_authorized_taint() -> None:
    starter = FakeStarter()
    client = make_client(starter)
    response = client.post(
        "/v1/commands",
        headers={
            "Authorization": "Bearer test-token-with-at-least-32-bytes",
            "X-Olympus-Commander": "discord-user-123",
            "X-Olympus-Authority-Lease": "lease-456",
        },
        json={"command": "  inspect the graph  "},
    )

    assert response.status_code == 202
    assert response.json()["status"] == "accepted"
    assert starter.commands[0].commander_id == "discord-user-123"
    assert starter.commands[0].authority_lease_id == "lease-456"
    assert starter.commands[0].command_text == "inspect the graph"
    assert starter.commands[0].trust_label is TrustLabel.USER_AUTHORIZED


def test_command_returns_server_error_when_starter_fails() -> None:
    client = make_client(RaisingStarter(), raise_server_exceptions=False)

    response = client.post(
        "/v1/commands",
        headers=VALID_HEADERS,
        json={"command": "inspect the graph"},
    )

    assert response.status_code == 500


@pytest.mark.asyncio
async def test_temporal_starter_starts_the_command_workflow() -> None:
    client = AsyncMock(spec=Client)
    starter = TemporalCommandStarter(
        client=cast(Client, client),
        task_queue="test-command-queue",
    )
    command = CommandEnvelope(
        job_id="job-123",
        commander_id="discord-user-123",
        authority_lease_id="lease-456",
        command_text="inspect the graph",
        received_at="2026-07-28T00:00:00+00:00",
    )

    result = await starter.start(command)

    client.start_workflow.assert_awaited_once_with(
        CommandWorkflow.run,
        command,
        id="job-123",
        task_queue="test-command-queue",
    )
    assert result == CommandAccepted(job_id="job-123")


def test_production_environment_is_rejected() -> None:
    with pytest.raises(ValidationError):
        GatewaySettings(
            environment="production",
            dev_command_token=TEST_COMMAND_TOKEN,
        )


def test_token_shorter_than_32_characters_is_rejected() -> None:
    with pytest.raises(ValidationError):
        GatewaySettings(environment="test", dev_command_token=SHORT_TEST_COMMAND_TOKEN)


@pytest.mark.parametrize(
    "token",
    [
        "a" * 31 + "é",
        "a" * 16 + " " + "b" * 16,
        "a" * 16 + "\n" + "b" * 16,
        "a" * 32 + "\x7f",
        "a" * 257,
    ],
)
def test_unsafe_development_tokens_are_rejected(token: str) -> None:
    with pytest.raises(ValidationError):
        GatewaySettings(environment="test", dev_command_token=token)
