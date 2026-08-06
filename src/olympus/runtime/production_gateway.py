"""The production authority gateway: TLS, PostgreSQL, and the enrollment page.

This is the process the Face ID enrollment ceremony runs against. It terminates
its own TLS on a dedicated private port rather than sitting behind a shared
proxy, because the production app refuses any request carrying ``X-Forwarded-*``
— an intermediary that could assert an origin on the browser's behalf would
dissolve the WebAuthn boundary this whole subsystem is built on.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
from datetime import datetime, timedelta
from typing import Any

import uvicorn
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from temporalio.client import Client
from temporalio.worker import Worker

from olympus.authority.sqlalchemy import SqlAlchemyAuthorityRepository
from olympus.discord.contracts import DiscordInteraction
from olympus.discord.service import DiscordCommandResponse
from olympus.gateway.auth import ProductionLeaseAuthorizer, issue_operator_grant
from olympus.gateway.nodes_api import NodeMeshRuntime
from olympus.gateway.production import create_production_app
from olympus.gateway.production_settings import ProductionGatewaySettings
from olympus.nodes.local_node import LocalNodeHandle, attach_local_node
from olympus.persistence.postgres_store import PostgresNodeMeshStore
from olympus.runtime.node_edge import (
    build_node_mesh_runtime,
    open_node_mesh_store_url,
    sweep_heartbeats_forever,
)
from olympus.webauthn.backend import PyWebAuthnBackend
from olympus.webauthn.service import SecureChallenges, WebAuthnAuthorityService
from olympus.workflows.node_job import NodeJobWorkflow

_log = logging.getLogger(__name__)


class DiscordAuthorityDisabled:
    """A Discord boundary that accepts nothing.

    Discord command authority is a separate surface from enrollment and is not
    enabled in this deployment: it would require a live bot credential and a
    Temporal workflow gateway, neither of which the enrollment ceremony needs.
    Refusing outright is the safe shape — an unwired boundary that silently
    accepted interactions would be a hole, and one that silently *looked*
    wired would be worse.
    """

    async def handle(
        self,
        interaction: DiscordInteraction,
        *,
        raw_body: bytes,
        now: datetime,
    ) -> DiscordCommandResponse:
        raise PermissionError("Discord command authority is not enabled on this gateway")


def _utc_now() -> datetime:
    from datetime import UTC

    return datetime.now(UTC)


def build_app(
    settings: ProductionGatewaySettings,
    *,
    sessions: Any,
    ready: Any,
    node_mesh: NodeMeshRuntime | None = None,
) -> FastAPI:
    repository = SqlAlchemyAuthorityRepository(sessions)
    operator_grant_issuer = None
    if node_mesh is not None:
        operator_private_key = node_mesh.control_plane_private_key

        def operator_grant_issuer(lease: Any) -> Any:
            return issue_operator_grant(operator_private_key, lease)

    webauthn = WebAuthnAuthorityService(
        repository=repository,
        backend=PyWebAuthnBackend(),
        challenges=SecureChallenges(),
        commander_id=settings.commander_id,
        guild_id=settings.discord_guild_id,
        channel_ids=settings.discord_channel_ids,
        # The RP ID is the bare hostname. The origin carries the port. Keeping
        # them separate here is the whole reason a non-default port is safe.
        rp_id=settings.webauthn_rp_id,
        rp_name=settings.webauthn_rp_name,
        origin=str(settings.webauthn_origin).rstrip("/"),
        challenge_ttl=timedelta(minutes=5),
        lease_ttl=settings.lease_ttl,
    )
    return create_production_app(
        webauthn=webauthn,
        discord=DiscordAuthorityDisabled(),
        discord_public_key=bytes.fromhex(
            settings.discord_application_public_key.get_secret_value()
        ),
        webauthn_origin=str(settings.webauthn_origin).rstrip("/"),
        webauthn_host=settings.public_host_header,
        bootstrap_enabled=settings.bootstrap_enabled,
        now=_utc_now,
        ready=ready,
        node_mesh=node_mesh,
        node_authorizer=(
            ProductionLeaseAuthorizer(
                repository=repository,
                commander_id=settings.commander_id,
                operator_public_key=node_mesh.control_plane_public_key,
                now=_utc_now,
            )
            if node_mesh is not None
            else None
        ),
        operator_grant_issuer=operator_grant_issuer,
        node_enrollment_ttl_seconds=settings.node_enrollment_ttl_seconds,
    )


def _tls_context(settings: ProductionGatewaySettings) -> ssl.SSLContext:
    if settings.tls_certificate_path is None or settings.tls_private_key_path is None:
        raise RuntimeError("the production gateway refuses to serve the enrollment page over TCP")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        certfile=str(settings.tls_certificate_path),
        keyfile=str(settings.tls_private_key_path),
    )
    return context


async def run() -> None:
    settings = ProductionGatewaySettings()

    engine = create_async_engine(settings.database_dsn.get_secret_value())
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    repository = SqlAlchemyAuthorityRepository(sessions)
    await repository.initialize(_utc_now())

    database_ready = True
    temporal_ready = not settings.node_mesh_enabled

    def ready() -> bool:
        return database_ready and temporal_ready

    temporal_client: Client | None = None
    node_store: PostgresNodeMeshStore | None = None
    node_runtime: NodeMeshRuntime | None = None
    node_activities: Any = None
    if settings.node_mesh_enabled:
        temporal_client = await Client.connect(settings.temporal_address)
        temporal_ready = True
        store, store_description = await open_node_mesh_store_url(settings.node_database_url)
        if not isinstance(store, PostgresNodeMeshStore):
            raise RuntimeError("production node mesh refuses volatile state")
        node_store = store
        _log.info("node-mesh canonical store: %s", store_description)
        node_runtime, node_activities = build_node_mesh_runtime(
            settings=settings,
            client=temporal_client,
            store=node_store,
        )
        recovery = await node_runtime.registry.recover_after_restart()
        if recovery.changed:
            _log.warning(
                "restart recovery cleared %d session(s) and reconciled %d job(s)",
                len(recovery.sessions_cleared),
                len(recovery.jobs_reconciled),
            )
        if recovery.frozen:
            _log.warning(
                "dispatch is frozen at epoch %d; it survived the restart",
                recovery.freeze_epoch,
            )

    app = build_app(settings, sessions=sessions, ready=ready, node_mesh=node_runtime)

    # Fail before binding rather than after: a certificate problem discovered
    # by the first browser is a failed ceremony, not a log line.
    _tls_context(settings)

    server = uvicorn.Server(
        uvicorn.Config(
            app=app,
            host=settings.http_host,
            port=settings.http_port,
            log_level="info",
            ssl_certfile=str(settings.tls_certificate_path),
            ssl_keyfile=str(settings.tls_private_key_path),
            # No proxy headers are honoured, matching the app's refusal to
            # accept X-Forwarded-*.
            proxy_headers=False,
            forwarded_allow_ips=[],
        )
    )
    sweeper: asyncio.Task[None] | None = None
    local_node: LocalNodeHandle | None = None
    try:
        if node_runtime is None or temporal_client is None:
            await server.serve()
            return
        edge_worker = Worker(
            temporal_client,
            task_queue=settings.node_task_queue,
            workflows=[NodeJobWorkflow],
            activities=[node_activities.select_node, node_activities.dispatch_node_job],
        )
        sweeper = asyncio.create_task(sweep_heartbeats_forever(node_runtime.registry))
        async with edge_worker:
            if settings.node_attach_control_plane_host:
                local_node = await attach_local_node(
                    registry=node_runtime.registry,
                    dispatch=node_runtime.dispatch,
                    control_plane_private_key=node_runtime.control_plane_private_key,
                    control_plane_public_key=node_runtime.control_plane_public_key,
                    control_plane_key_id=node_runtime.control_plane_key_id,
                    node_name=settings.node_control_plane_host_name,
                )
            await server.serve()
    finally:
        if local_node is not None:
            await local_node.aclose()
        if sweeper is not None:
            sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sweeper
        if node_store is not None:
            await node_store.close()
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(run())
