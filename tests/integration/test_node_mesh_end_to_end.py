import asyncio
import contextlib
import secrets
import socket
from collections.abc import AsyncIterator
from typing import Any

import uvicorn
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from olympus.gateway.settings import GatewaySettings
from olympus.node_agent.agent import AGENT_VERSION, AgentIdentity, NodeAgent
from olympus.node_agent.capabilities import SystemInspectProvider
from olympus.node_agent.enroll import enroll, request_json
from olympus.node_agent.transport import open_session_channel
from olympus.nodes.capabilities import SYSTEM_INSPECT
from olympus.nodes.crypto import generate_node_keypair
from olympus.nodes.models import NodeJobStatus
from olympus.runtime.node_edge import build_edge_app
from olympus.workflows.node_job import NodeJobWorkflow

TEST_COMMAND_TOKEN = secrets.token_hex(32)
HEADERS = {
    "Authorization": f"Bearer {TEST_COMMAND_TOKEN}",
    "X-Olympus-Commander": "local-jerry",
    "X-Olympus-Authority-Lease": "development-lease",
}
NODE_NAME = "jerry-windows"
_KEYS: dict[str, str] = {}


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


async def call(base_url: str, path: str, **kwargs: Any) -> dict[str, Any]:
    return await asyncio.to_thread(request_json, base_url, path, headers=HEADERS, **kwargs)


class Harness:
    def __init__(self, base_url: str, client: Any, runtime: Any) -> None:
        self.base_url = base_url
        self.client = client
        self.runtime = runtime


@contextlib.asynccontextmanager
async def running_control_plane() -> AsyncIterator[Harness]:
    """Run the real gateway, the real edge worker, and a real Temporal server."""
    port = free_port()
    settings = GatewaySettings(
        environment="test",
        dev_command_token=TEST_COMMAND_TOKEN,  # type: ignore[arg-type]
        http_port=port,
        node_mesh_enabled=True,
        node_heartbeat_interval_seconds=2,
        node_heartbeat_expiry_seconds=30,
    )
    async with await WorkflowEnvironment.start_local() as environment:
        app, runtime, activities = build_edge_app(settings, environment.client)
        server = uvicorn.Server(
            uvicorn.Config(app=app, host="127.0.0.1", port=port, log_level="error")
        )
        serving = asyncio.create_task(server.serve())
        worker = Worker(
            environment.client,
            task_queue=settings.node_task_queue,
            workflows=[NodeJobWorkflow],
            activities=[activities.dispatch_node_job],
        )
        try:
            for _ in range(200):
                if server.started:
                    break
                await asyncio.sleep(0.05)
            async with worker:
                yield Harness(f"http://127.0.0.1:{port}", environment.client, runtime)
        finally:
            server.should_exit = True
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(serving, timeout=10)


@contextlib.asynccontextmanager
async def enrolled_node(harness: Harness) -> AsyncIterator[Any]:
    """Enroll a node over HTTP, then connect it outbound over a real WebSocket."""
    grant = await call(
        harness.base_url,
        "/v1/nodes/enrollments",
        payload={
            "node_name": NODE_NAME,
            "kind": "workstation",
            "platform": "linux",
            "capabilities": [SYSTEM_INSPECT.name],
        },
    )
    keys = generate_node_keypair()
    outcome = await asyncio.to_thread(
        enroll,
        control_plane_url=harness.base_url,
        enrollment_token=grant["enrollment_token"],
        public_key=keys.public_key,
        node_name=NODE_NAME,
        kind="workstation",
        node_platform="linux",
        architecture="x86_64",
        agent_version=AGENT_VERSION,
        declared_capabilities=(SYSTEM_INSPECT.name,),
    )
    _KEYS[outcome.node_id] = keys.private_key
    agent = NodeAgent(
        identity=AgentIdentity(
            node_id=outcome.node_id,
            node_name=outcome.node_name,
            private_key=keys.private_key,
            control_plane_public_key=outcome.control_plane_public_key,
            control_plane_key_id=outcome.control_plane_key_id,
        ),
        providers=[SystemInspectProvider(agent_version=AGENT_VERSION)],
        node_platform="linux",
        architecture="x86_64",
    )
    ready = asyncio.Event()
    port = harness.base_url.rsplit(":", 1)[1]

    async def serve() -> None:
        async with open_session_channel(f"ws://127.0.0.1:{port}{outcome.session_path}") as channel:
            await agent.run(channel, on_ready=lambda _frame: ready.set())

    task = asyncio.create_task(serve())
    try:
        await asyncio.wait_for(ready.wait(), timeout=30)
        yield outcome
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task


@contextlib.asynccontextmanager
async def reconnected_node(harness: Harness, node: Any) -> AsyncIterator[NodeAgent]:
    """Reconnect a previously enrolled node using the key material it already holds."""
    agent = NodeAgent(
        identity=AgentIdentity(
            node_id=node.node_id,
            node_name=node.node_name,
            private_key=_KEYS[node.node_id],
            control_plane_public_key=node.control_plane_public_key,
            control_plane_key_id=node.control_plane_key_id,
        ),
        providers=[SystemInspectProvider(agent_version=AGENT_VERSION)],
        node_platform="linux",
        architecture="x86_64",
    )
    ready = asyncio.Event()
    port = harness.base_url.rsplit(":", 1)[1]

    async def serve() -> None:
        async with open_session_channel(f"ws://127.0.0.1:{port}{node.session_path}") as channel:
            await agent.run(channel, on_ready=lambda _frame: ready.set())

    task = asyncio.create_task(serve())
    try:
        await asyncio.wait_for(ready.wait(), timeout=30)
        yield agent
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task


async def test_command_reaches_an_enrolled_node_and_returns_an_audited_result() -> None:
    async with running_control_plane() as harness, enrolled_node(harness) as node:
        listed = await call(harness.base_url, "/v1/nodes", method="GET")
        assert listed["nodes"][0]["state"] == "online"
        assert listed["nodes"][0]["effective_capabilities"] == [SYSTEM_INSPECT.name]
        assert listed["dispatch_frozen"] is False

        accepted = await call(
            harness.base_url,
            "/v1/nodes/jobs",
            payload={
                "capability": SYSTEM_INSPECT.name,
                "parameters": {"sections": ["os", "cpu", "agent"]},
                "node_id": node.node_id,
            },
        )
        assert accepted["status"] == "accepted"

        handle = harness.client.get_workflow_handle_for(NodeJobWorkflow.run, accepted["job_id"])
        result = await asyncio.wait_for(handle.result(), timeout=90)

        assert result.status is NodeJobStatus.SUCCEEDED
        assert result.node_id == node.node_id
        assert result.trust_label.value == "external-untrusted"
        assert sorted(result.output["sections"]) == ["agent", "cpu", "os"]
        assert result.output["sections"]["os"]["system"] == "Linux"

        jobs = await call(harness.base_url, "/v1/nodes/jobs", method="GET")
        record = jobs["jobs"][0]
        assert record["job_id"] == accepted["job_id"]
        assert record["status"] == "succeeded"
        assert record["progress_events"] >= 1
        assert record["commander_id"] == "local-jerry"

        audit = await call(harness.base_url, "/v1/nodes/audit", method="GET")
        actions = [event["action"] for event in audit["events"]]
        assert audit["chain_valid"] is True
        assert actions[:3] == [
            "enrollment-token-issued",
            "enrollment-redeemed",
            "session-opened",
        ]
        assert "dispatch-admitted" in actions
        assert "dispatch-completed" in actions
        assert TEST_COMMAND_TOKEN not in str(audit)


async def test_a_node_that_reconnects_keeps_serving_work() -> None:
    async with running_control_plane() as harness:
        async with enrolled_node(harness) as node:
            first = await call(harness.base_url, "/v1/nodes", method="GET")
            first_session = harness.runtime.dispatch.session_for(node.node_id)
            assert first["nodes"][0]["state"] == "online"
            assert first_session is not None

        # The session is gone with the connection; the registry stops reporting
        # the node as connected once its heartbeats stop arriving.
        assert harness.runtime.dispatch.session_for(node.node_id) is None

        async with reconnected_node(harness, node) as agent:
            assert agent.granted_capabilities == (SYSTEM_INSPECT.name,)
            second_session = harness.runtime.dispatch.session_for(node.node_id)
            assert second_session is not None
            assert second_session is not first_session

            accepted = await call(
                harness.base_url,
                "/v1/nodes/jobs",
                payload={
                    "capability": SYSTEM_INSPECT.name,
                    "parameters": {"sections": ["os"]},
                    "node_id": node.node_id,
                },
            )
            result = await asyncio.wait_for(
                harness.client.get_workflow_handle_for(
                    NodeJobWorkflow.run, accepted["job_id"]
                ).result(),
                timeout=90,
            )
            assert result.status is NodeJobStatus.SUCCEEDED


async def test_freezing_the_mesh_refuses_new_work_and_unfreezing_needs_the_epoch() -> None:
    async with running_control_plane() as harness, enrolled_node(harness) as node:
        frozen = await call(
            harness.base_url, "/v1/nodes/control/freeze", payload={"reason": "drill"}
        )
        assert frozen["frozen"] is True

        try:
            await call(
                harness.base_url,
                "/v1/nodes/jobs",
                payload={"capability": SYSTEM_INSPECT.name, "node_id": node.node_id},
            )
            raise AssertionError("a frozen mesh must not accept new work")
        except Exception as refusal:  # noqa: BLE001 - the stdlib client raises on 4xx
            assert "409" in str(refusal)

        thawed = await call(
            harness.base_url,
            "/v1/nodes/control/unfreeze",
            payload={"expected_freeze_epoch": frozen["freeze_epoch"], "reason": "drill over"},
        )
        assert thawed["frozen"] is False

        accepted = await call(
            harness.base_url,
            "/v1/nodes/jobs",
            payload={
                "capability": SYSTEM_INSPECT.name,
                "parameters": {"sections": ["uptime"]},
                "node_id": node.node_id,
            },
        )
        result = await asyncio.wait_for(
            harness.client.get_workflow_handle_for(
                NodeJobWorkflow.run, accepted["job_id"]
            ).result(),
            timeout=90,
        )
        assert result.status is NodeJobStatus.SUCCEEDED
