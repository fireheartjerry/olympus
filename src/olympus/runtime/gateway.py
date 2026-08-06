import asyncio

import uvicorn
from temporalio.client import Client

from olympus.gateway.app import TemporalCommandStarter, create_app
from olympus.gateway.settings import GatewaySettings


async def run() -> None:
    settings = GatewaySettings()
    client = await Client.connect(settings.temporal_address)
    app = create_app(
        settings=settings,
        starter=TemporalCommandStarter(
            client=client,
            task_queue=settings.temporal_task_queue,
        ),
    )
    server = uvicorn.Server(
        uvicorn.Config(
            app=app,
            host=settings.http_host,
            port=settings.http_port,
            log_level="info",
        )
    )
    await server.serve()


if __name__ == "__main__":
    asyncio.run(run())
