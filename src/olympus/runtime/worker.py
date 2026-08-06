import asyncio

from temporalio.client import Client
from temporalio.worker import Worker

from olympus.activities.compile_graph import compile_graph_activity
from olympus.gateway.settings import GatewaySettings
from olympus.workflows.command import CommandWorkflow


async def run() -> None:
    settings = GatewaySettings()
    client = await Client.connect(settings.temporal_address)
    worker = Worker(
        client,
        task_queue=settings.temporal_task_queue,
        workflows=[CommandWorkflow],
        activities=[compile_graph_activity],
    )
    await worker.run()


if __name__ == "__main__":
    asyncio.run(run())
