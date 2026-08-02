import hashlib
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import AsyncMock

import pytest
from temporalio.client import Client, WorkflowHandle

from olympus.authority.latch import FreezeReason
from olympus.authority.repository import InMemoryAuthorityRepository, LeaseRequest
from olympus.contracts.commands import CommandEnvelope
from olympus.control.workflow import ControlSnapshot
from olympus.discord.contracts import DiscordInteraction
from olympus.discord.service import (
    DiscordAdmissionDenied,
    DiscordCommandIds,
    DiscordCommandService,
    TemporalWorkflowGateway,
)

NOW = datetime(2026, 7, 29, tzinfo=UTC)
COMMAND_IDS = DiscordCommandIds(
    command="100000000000000010",
    freeze="100000000000000011",
    inspect="100000000000000012",
    pause="100000000000000013",
    cancel="100000000000000014",
    resume="100000000000000015",
)


class FakeLatch:
    def __init__(self) -> None:
        self.requests: list[tuple[str, FreezeReason]] = []

    def set(self, request_id: str, reason: FreezeReason, now: datetime) -> None:
        self.requests.append((request_id, reason))


class FakeWorkflowGateway:
    def __init__(self) -> None:
        self.commands: list[object] = []
        self.controls: list[tuple[str, str, str]] = []

    async def start_command(self, command: object, workflow_id: str) -> None:
        self.commands.append(command)

    async def signal_control(
        self,
        workflow_id: str,
        action: str,
        control_id: str,
    ) -> None:
        self.controls.append((workflow_id, action, control_id))

    async def inspect(self, workflow_id: str) -> dict[str, object]:
        return {"workflow_id": workflow_id, "status": "running"}


def interaction(
    command_id: str,
    *,
    option_name: str | None = None,
    option_value: str | None = None,
    user_id: str = "628053765181800448",
    guild_id: str = "100000000000000001",
    channel_id: str = "100000000000000002",
) -> DiscordInteraction:
    data: dict[str, object] = {
        "id": command_id,
        "name": "display-name-is-not-authority",
        "options": [],
    }
    if option_name is not None and option_value is not None:
        data["options"] = [{"name": option_name, "type": 3, "value": option_value}]
    return DiscordInteraction.model_validate(
        {
            "id": "100000000000000020",
            "application_id": "100000000000000021",
            "type": 2,
            "guild_id": guild_id,
            "channel_id": channel_id,
            "member": {"user": {"id": user_id}},
            "data": data,
        }
    )


def service(
    repository: InMemoryAuthorityRepository,
    latch: FakeLatch,
    workflows: FakeWorkflowGateway,
) -> DiscordCommandService:
    return DiscordCommandService(
        repository=repository,
        latch=latch,
        workflows=workflows,
        commander_id="628053765181800448",
        guild_id="100000000000000001",
        channel_ids=frozenset({"100000000000000002"}),
        command_ids=COMMAND_IDS,
    )


async def active_lease(repository: InMemoryAuthorityRepository) -> None:
    await repository.issue_lease(
        LeaseRequest(
            lease_id="lease-1",
            commander_id="628053765181800448",
            guild_id="100000000000000001",
            channel_scope_digest=hashlib.sha256(b'["100000000000000002"]').digest(),
            credential_id=b"credential-1",
            issued_at=NOW,
            expires_at=NOW + timedelta(hours=24),
        )
    )


@pytest.mark.parametrize(
    "interaction_request",
    [
        interaction(COMMAND_IDS.command, user_id="100000000000000099"),
        interaction(COMMAND_IDS.command, guild_id="100000000000000099"),
        interaction(COMMAND_IDS.command, channel_id="100000000000000099"),
    ],
)
async def test_rejects_any_literal_scope_mismatch(
    interaction_request: DiscordInteraction,
) -> None:
    repository = InMemoryAuthorityRepository()

    with pytest.raises(DiscordAdmissionDenied, match="scope"):
        await service(repository, FakeLatch(), FakeWorkflowGateway()).handle(
            interaction_request,
            raw_body=b"signed-body",
            now=NOW,
        )


async def test_freeze_needs_no_lease_and_sets_latch_before_repository() -> None:
    repository = InMemoryAuthorityRepository()
    latch = FakeLatch()

    response = await service(repository, latch, FakeWorkflowGateway()).handle(
        interaction(COMMAND_IDS.freeze),
        raw_body=b"signed-body",
        now=NOW,
    )

    assert response.status == "frozen"
    assert latch.requests == [("discord-100000000000000020", FreezeReason.OPERATOR_REQUEST)]
    assert await repository.is_frozen()


async def test_ordinary_command_uses_active_server_side_lease() -> None:
    repository = InMemoryAuthorityRepository()
    await active_lease(repository)
    workflows = FakeWorkflowGateway()

    response = await service(repository, FakeLatch(), workflows).handle(
        interaction(COMMAND_IDS.command, option_name="command", option_value="do research"),
        raw_body=b"signed-body",
        now=NOW,
    )

    assert response.status == "accepted"
    assert response.workflow_id == "discord-100000000000000020"
    assert len(workflows.commands) == 1


async def test_message_text_cannot_turn_an_ordinary_command_into_freeze() -> None:
    repository = InMemoryAuthorityRepository()
    await active_lease(repository)
    latch = FakeLatch()

    await service(repository, latch, FakeWorkflowGateway()).handle(
        interaction(COMMAND_IDS.command, option_name="command", option_value="/freeze"),
        raw_body=b"signed-body",
        now=NOW,
    )

    assert latch.requests == []


async def test_duplicate_interaction_does_not_start_duplicate_workflow() -> None:
    repository = InMemoryAuthorityRepository()
    await active_lease(repository)
    workflows = FakeWorkflowGateway()
    command_service = service(repository, FakeLatch(), workflows)
    request = interaction(
        COMMAND_IDS.command,
        option_name="command",
        option_value="do research",
    )

    first = await command_service.handle(request, raw_body=b"signed-body", now=NOW)
    second = await command_service.handle(request, raw_body=b"signed-body", now=NOW)

    assert first == second
    assert len(workflows.commands) == 1


async def test_pause_routes_by_registered_command_id_and_requires_lease() -> None:
    repository = InMemoryAuthorityRepository()
    workflows = FakeWorkflowGateway()
    command_service = service(repository, FakeLatch(), workflows)
    request = interaction(COMMAND_IDS.pause, option_name="job_id", option_value="job-7")

    with pytest.raises(DiscordAdmissionDenied, match="lease"):
        await command_service.handle(request, raw_body=b"signed-body", now=NOW)

    await active_lease(repository)
    response = await command_service.handle(request, raw_body=b"signed-body", now=NOW)

    assert response.status == "pause"
    assert workflows.controls == [("job-7", "pause", "discord-100000000000000020")]


async def test_unknown_command_id_cannot_reserve_interaction_identity() -> None:
    repository = InMemoryAuthorityRepository()
    await active_lease(repository)
    workflows = FakeWorkflowGateway()
    command_service = service(repository, FakeLatch(), workflows)

    with pytest.raises(DiscordAdmissionDenied, match="not registered"):
        await command_service.handle(
            interaction("100000000000000099"),
            raw_body=b"signed-body",
            now=NOW,
        )

    await command_service.handle(
        interaction(
            COMMAND_IDS.command,
            option_name="command",
            option_value="do research",
        ),
        raw_body=b"signed-body",
        now=NOW,
    )
    assert len(workflows.commands) == 1


async def test_temporal_gateway_uses_deterministic_workflow_and_typed_controls() -> None:
    client = AsyncMock(spec=Client)
    handle = AsyncMock(spec=WorkflowHandle)
    client.get_workflow_handle.return_value = handle
    handle.query.return_value = ControlSnapshot(
        paused=True,
        cancelled=False,
        frozen=False,
        processed_control_ids=("control-1",),
    )
    gateway = TemporalWorkflowGateway(cast(Client, client), "command-queue")
    command_envelope = cast(CommandEnvelope, object())

    await gateway.start_command(command_envelope, "discord-123")
    await gateway.signal_control("discord-123", "pause", "control-1")
    inspected = await gateway.inspect("discord-123")

    client.start_workflow.assert_awaited_once()
    assert client.start_workflow.await_args.kwargs["id"] == "discord-123"
    handle.signal.assert_awaited_once_with("pause", "control-1")
    assert inspected["paused"] is True
