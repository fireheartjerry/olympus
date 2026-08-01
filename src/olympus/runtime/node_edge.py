import asyncio
import contextlib

import uvicorn
from fastapi import FastAPI
from temporalio.client import Client
from temporalio.service import RPCError
from temporalio.worker import Worker

from olympus.activities.compile_graph import compile_graph_activity
from olympus.activities.node_dispatch import NodeDispatchActivities
from olympus.gateway.app import TemporalCommandStarter, create_app
from olympus.gateway.nodes_api import NodeMeshRuntime
from olympus.gateway.settings import GatewaySettings
from olympus.nodes.audit import NodeAuditLog
from olympus.nodes.crypto import generate_node_keypair, public_key_of
from olympus.nodes.dispatch import NodeDispatchService, NodeJobRequest
from olympus.nodes.errors import NodeMeshError, NodeReason
from olympus.nodes.registry import NodeRegistry
from olympus.workflows.command import CommandWorkflow
from olympus.workflows.node_job import NODE_JOB_WORKFLOW_EXECUTION_TIMEOUT, NodeJobWorkflow

HEARTBEAT_SWEEP_INTERVAL_SECONDS = 10


class TemporalNodeJobStarter:
    """Start and signal node-job workflows. Temporal keeps ownership of their state."""

    def __init__(self, *, client: Client, task_queue: str) -> None:
        self._client = client
        self._task_queue = task_queue

    async def start(self, request: NodeJobRequest) -> str:
        await self._client.start_workflow(
            NodeJobWorkflow.run,
            request,
            id=request.job_id,
            task_queue=self._task_queue,
            execution_timeout=NODE_JOB_WORKFLOW_EXECUTION_TIMEOUT,
        )
        return request.job_id

    async def cancel(self, job_id: str) -> None:
        handle = self._client.get_workflow_handle_for(NodeJobWorkflow.run, job_id)
        try:
            await handle.signal(NodeJobWorkflow.request_cancellation, "operator cancellation")
        except RPCError as exc:
            raise NodeMeshError(NodeReason.JOB_UNKNOWN, "unknown node job") from exc


def resolve_control_plane_keys(settings: GatewaySettings) -> tuple[str, str]:
    """Return the control-plane signing key pair, generating an ephemeral one if unset.

    An ephemeral key is a development convenience only: every already-enrolled
    node pinned the previous public key at enrollment and will refuse the new
    one, which is the intended failure rather than a silent downgrade.
    """
    configured = settings.node_control_plane_private_key
    if configured is not None:
        private_key = configured.get_secret_value()
        return private_key, public_key_of(private_key)
    generated = generate_node_keypair()
    return generated.private_key, generated.public_key


def build_node_mesh_runtime(
    *, settings: GatewaySettings, client: Client
) -> tuple[NodeMeshRuntime, NodeDispatchActivities]:
    """Assemble the mesh runtime and the activities that reach its live sessions."""
    private_key, public_key = resolve_control_plane_keys(settings)
    registry = NodeRegistry(
        audit=NodeAuditLog(),
        heartbeat_interval_seconds=settings.node_heartbeat_interval_seconds,
        heartbeat_expiry_seconds=settings.node_heartbeat_expiry_seconds,
        enrollment_ttl_seconds=settings.node_enrollment_ttl_seconds,
    )
    dispatch = NodeDispatchService(registry=registry)
    runtime = NodeMeshRuntime(
        registry=registry,
        dispatch=dispatch,
        control_plane_private_key=private_key,
        control_plane_public_key=public_key,
        control_plane_key_id=settings.node_control_plane_key_id,
        job_starter=TemporalNodeJobStarter(client=client, task_queue=settings.node_task_queue),
    )
    return runtime, NodeDispatchActivities(dispatch=dispatch)


async def sweep_heartbeats_forever(registry: NodeRegistry) -> None:
    """Mark nodes offline once their heartbeats stop arriving."""
    while True:
        await asyncio.sleep(HEARTBEAT_SWEEP_INTERVAL_SECONDS)
        await registry.sweep_expired_heartbeats()


def build_edge_app(
    settings: GatewaySettings, client: Client
) -> tuple[FastAPI, NodeMeshRuntime, NodeDispatchActivities]:
    """Build the gateway with the node mesh mounted on it.

    This entrypoint exists only to serve the mesh. When the mesh is switched off,
    the plain ``olympus.runtime.gateway`` entrypoint is the one to run, so the
    flag fails loudly here instead of silently mounting node routes anyway.
    """
    if not settings.node_mesh_enabled:
        raise RuntimeError(
            "the node-mesh runtime requires OLYMPUS_NODE_MESH_ENABLED=true; "
            "run olympus.runtime.gateway for the command-only gateway"
        )
    runtime, activities = build_node_mesh_runtime(settings=settings, client=client)
    app = create_app(
        settings=settings,
        starter=TemporalCommandStarter(client=client, task_queue=settings.temporal_task_queue),
        node_mesh=runtime,
    )
    return app, runtime, activities


async def run() -> None:
    """Run the gateway, the command worker, and the node-edge worker in one process.

    The edge worker is colocated with the gateway because the gateway owns the
    node connections. It is one Temporal worker on its own task queue, not a
    second orchestrator: every node job is still a Temporal workflow.
    """
    settings = GatewaySettings()  # type: ignore[call-arg]  # required values come from environment
    client = await Client.connect(settings.temporal_address)
    app, runtime, activities = build_edge_app(settings, client)

    command_worker = Worker(
        client,
        task_queue=settings.temporal_task_queue,
        workflows=[CommandWorkflow],
        activities=[compile_graph_activity],
    )
    edge_worker = Worker(
        client,
        task_queue=settings.node_task_queue,
        workflows=[NodeJobWorkflow],
        activities=[activities.dispatch_node_job],
    )
    server = uvicorn.Server(
        uvicorn.Config(
            app=app,
            host=settings.http_host,
            port=settings.http_port,
            log_level="info",
        )
    )
    sweeper = asyncio.create_task(sweep_heartbeats_forever(runtime.registry))
    try:
        async with command_worker, edge_worker:
            await server.serve()
    finally:
        sweeper.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await sweeper


if __name__ == "__main__":
    asyncio.run(run())
