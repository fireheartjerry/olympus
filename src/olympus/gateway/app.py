import hmac
import re
from datetime import UTC, datetime
from typing import Annotated, Protocol
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, status
from temporalio.client import Client

from olympus.contracts.commands import CommandAccepted, CommandEnvelope, CommandRequest
from olympus.gateway.settings import GatewaySettings
from olympus.workflows.command import CommandWorkflow

_AUTHORITY_HEADER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


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
        )
        return CommandAccepted(job_id=command.job_id)


def _require_single_authority_header(values: list[str]) -> str:
    if len(values) != 1 or _AUTHORITY_HEADER_PATTERN.fullmatch(values[0]) is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="invalid authority header",
        )
    return values[0]


def _matches_development_token(authorization: str | None, expected_token: str) -> bool:
    try:
        received = (authorization or "").encode("ascii")
        expected = f"Bearer {expected_token}".encode("ascii")
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(received, expected)


def create_app(settings: GatewaySettings, starter: CommandStarter) -> FastAPI:
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
        authorization: Annotated[str | None, Header()] = None,
    ) -> CommandAccepted:
        if not _matches_development_token(
            authorization,
            settings.dev_command_token.get_secret_value(),
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid development command token",
            )

        commander_id = _require_single_authority_header(commander_ids)
        authority_lease_id = _require_single_authority_header(authority_lease_ids)
        command = CommandEnvelope(
            job_id=f"job-{uuid4()}",
            commander_id=commander_id,
            authority_lease_id=authority_lease_id,
            command_text=request.command.strip(),
            received_at=datetime.now(UTC).isoformat(),
        )
        return await starter.start(command)

    return app
