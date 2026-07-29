import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Protocol

from temporalio.client import Client

from olympus.authority.latch import FreezeReason
from olympus.authority.repository import (
    AdmissionRequest,
    AuthorityRepository,
)
from olympus.contracts.commands import CommandEnvelope
from olympus.control.workflow import ControlSnapshot
from olympus.discord.contracts import DiscordCommandOption, DiscordInteraction
from olympus.workflows.command import COMMAND_WORKFLOW_EXECUTION_TIMEOUT, CommandWorkflow


class DiscordAdmissionDenied(RuntimeError):
    pass


@dataclass(frozen=True)
class DiscordCommandIds:
    command: str
    freeze: str
    inspect: str
    pause: str
    cancel: str
    resume: str

    def __post_init__(self) -> None:
        values = tuple(vars(self).values())
        if len(set(values)) != len(values):
            raise ValueError("Discord command IDs must be unique")


@dataclass(frozen=True)
class DiscordCommandResponse:
    status: str
    workflow_id: str | None = None
    detail: dict[str, object] | None = None


class EmergencyLatch(Protocol):
    def set(self, request_id: str, reason: FreezeReason, now: datetime) -> None: ...


class WorkflowGateway(Protocol):
    async def start_command(self, command: CommandEnvelope, workflow_id: str) -> None: ...

    async def signal_control(
        self,
        workflow_id: str,
        action: str,
        control_id: str,
    ) -> None: ...

    async def inspect(self, workflow_id: str) -> dict[str, object]: ...


class TemporalWorkflowGateway:
    def __init__(self, client: Client, task_queue: str) -> None:
        self._client = client
        self._task_queue = task_queue

    async def start_command(self, command: CommandEnvelope, workflow_id: str) -> None:
        await self._client.start_workflow(
            CommandWorkflow.run,
            command,
            id=workflow_id,
            task_queue=self._task_queue,
            execution_timeout=COMMAND_WORKFLOW_EXECUTION_TIMEOUT,
        )

    async def signal_control(
        self,
        workflow_id: str,
        action: str,
        control_id: str,
    ) -> None:
        handle = self._client.get_workflow_handle(workflow_id)
        await handle.signal(action, control_id)

    async def inspect(self, workflow_id: str) -> dict[str, object]:
        handle = self._client.get_workflow_handle(workflow_id)
        snapshot = await handle.query(CommandWorkflow.inspect)
        if not isinstance(snapshot, ControlSnapshot):
            raise TypeError("Temporal returned an invalid control snapshot")
        return asdict(snapshot)


class DiscordCommandService:
    def __init__(
        self,
        *,
        repository: AuthorityRepository,
        latch: EmergencyLatch,
        workflows: WorkflowGateway,
        commander_id: str,
        guild_id: str,
        channel_ids: frozenset[str],
        command_ids: DiscordCommandIds,
    ) -> None:
        self._repository = repository
        self._latch = latch
        self._workflows = workflows
        self._commander_id = commander_id
        self._guild_id = guild_id
        self._channel_ids = channel_ids
        self._command_ids = command_ids
        self._scope_digest = hashlib.sha256(
            json.dumps(sorted(channel_ids), separators=(",", ":")).encode()
        ).digest()

    async def handle(
        self,
        interaction: DiscordInteraction,
        *,
        raw_body: bytes,
        now: datetime,
    ) -> DiscordCommandResponse:
        self._require_scope(interaction)
        command_id = interaction.data.id
        control_id = f"discord-{interaction.id}"

        if command_id == self._command_ids.freeze:
            self._latch.set(control_id, FreezeReason.OPERATOR_REQUEST, now)
            await self._repository.freeze(control_id, "operator-request", now)
            return DiscordCommandResponse(status="frozen")

        if command_id == self._command_ids.inspect:
            workflow_id = _required_option(interaction.data.options, "job_id")
            detail = await self._workflows.inspect(workflow_id)
            return DiscordCommandResponse(
                status="inspected",
                workflow_id=workflow_id,
                detail=detail,
            )

        authority_command_ids = {
            self._command_ids.command,
            self._command_ids.pause,
            self._command_ids.cancel,
            self._command_ids.resume,
        }
        if command_id not in authority_command_ids:
            raise DiscordAdmissionDenied("Discord command ID is not registered")

        lease = await self._repository.active_lease()
        if lease is None or lease.expires_at <= now:
            raise DiscordAdmissionDenied("an active authority lease is required")
        admission = await self._repository.admit(
            AdmissionRequest(
                interaction_id=interaction.id,
                request_digest=hashlib.sha256(raw_body).digest(),
                commander_id=self._commander_id,
                guild_id=self._guild_id,
                channel_scope_digest=self._scope_digest,
                lease_id=lease.lease_id,
                authority_epoch=lease.authority_epoch,
                received_at=now,
            )
        )

        if command_id == self._command_ids.command:
            command_text = _required_option(interaction.data.options, "command").strip()
            if not command_text or len(command_text) > 8000:
                raise DiscordAdmissionDenied("command text is invalid")
            command = CommandEnvelope(
                job_id=admission.workflow_id,
                commander_id=self._commander_id,
                guild_id=self._guild_id,
                channel_id=interaction.channel_id,
                interaction_id=interaction.id,
                authority_lease_id=lease.lease_id,
                authority_epoch=lease.authority_epoch,
                command_text=command_text,
                received_at=now.isoformat(),
            )
            if not admission.duplicate:
                await self._workflows.start_command(command, admission.workflow_id)
            return DiscordCommandResponse(
                status="accepted",
                workflow_id=admission.workflow_id,
            )

        controls = {
            self._command_ids.pause: "pause",
            self._command_ids.cancel: "cancel",
            self._command_ids.resume: "resume",
        }
        action = controls.get(command_id)
        if action is None:
            raise DiscordAdmissionDenied("Discord command ID is not registered")
        workflow_id = _required_option(interaction.data.options, "job_id")
        await self._workflows.signal_control(workflow_id, action, control_id)
        return DiscordCommandResponse(status=action, workflow_id=workflow_id)

    def _require_scope(self, interaction: DiscordInteraction) -> None:
        if (
            interaction.member.user.id != self._commander_id
            or interaction.guild_id != self._guild_id
            or interaction.channel_id not in self._channel_ids
        ):
            raise DiscordAdmissionDenied("Discord identity is outside authorized scope")


def _required_option(
    options: tuple[DiscordCommandOption, ...],
    name: str,
) -> str:
    matching = [option.value for option in options if option.name == name]
    if len(matching) != 1:
        raise DiscordAdmissionDenied(f"exactly one {name} option is required")
    return matching[0]
