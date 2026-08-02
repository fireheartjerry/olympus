from datetime import UTC, datetime
from typing import Annotated, Protocol
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, status
from temporalio.client import Client

from olympus.contracts.commands import CommandAccepted, CommandEnvelope, CommandRequest
from olympus.gateway.auth import matches_development_token, require_single_authority_header
from olympus.gateway.nodes_api import NodeMeshRuntime, register_node_routes
from olympus.gateway.settings import GatewaySettings
from olympus.workflows.command import COMMAND_WORKFLOW_EXECUTION_TIMEOUT, CommandWorkflow


class CommandStarter(Protocol):
    async def start(self, command: CommandEnvelope) -> CommandAccepted: ...


class TemporalCommandStarter:
    def __init__(self, client: Client, task_queue: str) -> None:
        self._client = client
        self._task_queue = task_queue

    async def start(self, command: CommandEnvelope) -> CommandAccepted:
        await self._client.start_workflow(
            CommandWorkflow.run,
            command,
            id=command.job_id,
            task_queue=self._task_queue,
            execution_timeout=COMMAND_WORKFLOW_EXECUTION_TIMEOUT,
        )
        return CommandAccepted(job_id=command.job_id)


def create_app(
    settings: GatewaySettings,
    starter: CommandStarter,
    node_mesh: NodeMeshRuntime | None = None,
) -> FastAPI:
    app = FastAPI(title="Olympus Gateway", version="0.1.0")

    @app.get("/health/live")
    async def health_live() -> dict[str, str]:
        return {"status": "ok"}

    @app.post(
        "/v1/commands",
        response_model=CommandAccepted,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def start_command(
        request: CommandRequest,
        commander_ids: Annotated[
            list[str],
            Header(alias="X-Olympus-Commander"),
        ],
        authority_lease_ids: Annotated[
            list[str],
            Header(alias="X-Olympus-Authority-Lease"),
        ],
        authorization: Annotated[list[str] | None, Header()] = None,
    ) -> CommandAccepted:
        if not matches_development_token(
            authorization,
            settings.dev_command_token.get_secret_value(),
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid development command token",
            )

        commander_id = require_single_authority_header(commander_ids)
        authority_lease_id = require_single_authority_header(authority_lease_ids)
        command = CommandEnvelope(
            job_id=f"job-{uuid4()}",
            commander_id=commander_id,
            authority_lease_id=authority_lease_id,
            command_text=request.command.strip(),
            received_at=datetime.now(UTC).isoformat(),
        )
        return await starter.start(command)

    if node_mesh is not None:
        register_node_routes(app, settings=settings, runtime=node_mesh)

    return app
