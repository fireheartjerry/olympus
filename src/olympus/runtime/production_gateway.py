"""The production authority gateway: TLS, PostgreSQL, and the enrollment page.

This is the process the Face ID enrollment ceremony runs against. It terminates
its own TLS on a dedicated private port rather than sitting behind a shared
proxy, because the production app refuses any request carrying ``X-Forwarded-*``
— an intermediary that could assert an origin on the browser's behalf would
dissolve the WebAuthn boundary this whole subsystem is built on.
"""

from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timedelta
from typing import Any

import uvicorn
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from olympus.authority.sqlalchemy import SqlAlchemyAuthorityRepository
from olympus.discord.contracts import DiscordInteraction
from olympus.discord.service import DiscordCommandResponse
from olympus.gateway.production import create_production_app
from olympus.gateway.production_settings import ProductionGatewaySettings
from olympus.webauthn.backend import PyWebAuthnBackend
from olympus.webauthn.service import SecureChallenges, WebAuthnAuthorityService


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


def build_app(settings: ProductionGatewaySettings, *, sessions: Any, ready: Any) -> FastAPI:
    repository = SqlAlchemyAuthorityRepository(sessions)
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

    def ready() -> bool:
        return database_ready

    app = build_app(settings, sessions=sessions, ready=ready)

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
    try:
        await server.serve()
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(run())
