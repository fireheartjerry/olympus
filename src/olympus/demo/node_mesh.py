import asyncio
import contextlib
import secrets
import socket

import uvicorn
from pydantic import SecretStr
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from olympus.gateway.settings import GatewaySettings
from olympus.node_agent.agent import AGENT_VERSION, AgentIdentity, NodeAgent
from olympus.node_agent.capabilities import SystemInspectProvider
from olympus.node_agent.enroll import enroll, request_json
from olympus.node_agent.transport import open_session_channel
from olympus.nodes.capabilities import SYSTEM_INSPECT
from olympus.nodes.crypto import generate_node_keypair
from olympus.runtime.node_edge import build_edge_app
from olympus.workflows.node_job import NodeJobWorkflow

DEMO_COMMANDER = "local-jerry"
DEMO_LEASE = "development-lease"
DEMO_NODE_NAME = "demo-workstation"


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _headline(text: str) -> None:
    print(f"\n=== {text}")


async def _wait_until_serving(server: uvicorn.Server) -> None:
    for _ in range(200):
        if server.started:
            return
        await asyncio.sleep(0.05)
    raise RuntimeError("the demo gateway did not start")


async def main() -> int:
    """Prove the full command path end to end without touching anything external.

    phone/API command -> gateway -> Temporal workflow -> enrolled worker ->
    streamed progress -> result -> audit record -> response.

    Everything runs on loopback against an ephemeral Temporal dev server. No
    external service is contacted and no host state is mutated.
    """
    port = _free_loopback_port()
    base_url = f"http://127.0.0.1:{port}"
    operator_headers = {
        "Authorization": f"Bearer {secrets.token_hex(32)}",
        "X-Olympus-Commander": DEMO_COMMANDER,
        "X-Olympus-Authority-Lease": DEMO_LEASE,
    }
    settings = GatewaySettings(
        environment="development",
        dev_command_token=SecretStr(operator_headers["Authorization"].removeprefix("Bearer ")),
        http_port=port,
        node_mesh_enabled=True,
        node_allow_volatile_state=True,
        node_allow_ephemeral_control_plane_key=True,
        node_heartbeat_interval_seconds=2,
        node_heartbeat_expiry_seconds=10,
    )

    _headline("starting an ephemeral Temporal dev server")
    async with await WorkflowEnvironment.start_local() as environment:
        client = environment.client
        app, runtime, activities = build_edge_app(settings, client)
        server = uvicorn.Server(
            uvicorn.Config(app=app, host="127.0.0.1", port=port, log_level="warning")
        )
        serving = asyncio.create_task(server.serve())
        worker = Worker(
            client,
            task_queue=settings.node_task_queue,
            workflows=[NodeJobWorkflow],
            activities=[activities.select_node, activities.dispatch_node_job],
        )
        agent_task: asyncio.Task[None] | None = None
        try:
            await _wait_until_serving(server)
            print(f"gateway listening on {base_url} (loopback only)")

            async with worker:
                _headline("issuing a single-use enrollment token")
                issued = await asyncio.to_thread(
                    request_json,
                    base_url,
                    "/v1/nodes/enrollments",
                    payload={
                        "node_name": DEMO_NODE_NAME,
                        "kind": "workstation",
                        "platform": "linux",
                        "capabilities": [SYSTEM_INSPECT.name],
                    },
                    headers=operator_headers,
                )
                print(f"token id {issued['token_id']} expires {issued['expires_at']}")

                _headline("redeeming it from the node, which generates its own key")
                keys = generate_node_keypair()
                outcome = await asyncio.to_thread(
                    enroll,
                    control_plane_url=base_url,
                    enrollment_token=issued["enrollment_token"],
                    public_key=keys.public_key,
                    node_name=DEMO_NODE_NAME,
                    kind="workstation",
                    node_platform="linux",
                    architecture="x86_64",
                    agent_version=AGENT_VERSION,
                    declared_capabilities=(SYSTEM_INSPECT.name,),
                )
                print(f"enrolled {outcome.node_id} granted {outcome.granted_capabilities}")

                _headline("connecting the node outbound over a real WebSocket")
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
                session_url = f"ws://127.0.0.1:{port}{outcome.session_path}"
                ready = asyncio.Event()

                async def serve_node() -> None:
                    async with open_session_channel(session_url) as channel:
                        await agent.run(channel, on_ready=lambda _frame: ready.set())

                agent_task = asyncio.create_task(serve_node())
                await asyncio.wait_for(ready.wait(), timeout=20)
                print(f"session established; granted {agent.granted_capabilities}")

                listed = await asyncio.to_thread(
                    request_json,
                    base_url,
                    "/v1/nodes",
                    method="GET",
                    headers=operator_headers,
                )
                for node in listed["nodes"]:
                    print(
                        f"  {node['node_name']}: {node['state']} "
                        f"capabilities={node['effective_capabilities']}"
                    )

                _headline("dispatching a bounded system inspection through Temporal")
                accepted = await asyncio.to_thread(
                    request_json,
                    base_url,
                    "/v1/nodes/jobs",
                    payload={
                        "capability": SYSTEM_INSPECT.name,
                        "parameters": {"sections": ["os", "cpu", "memory", "agent"]},
                        "node_id": outcome.node_id,
                    },
                    headers=operator_headers,
                )
                job_id = accepted["job_id"]
                print(f"accepted {job_id} as workflow {accepted['workflow_id']}")

                handle = client.get_workflow_handle_for(NodeJobWorkflow.run, job_id)
                result = await asyncio.wait_for(handle.result(), timeout=60)
                print(f"workflow returned status={result.status} trust={result.trust_label}")
                sections = dict(result.output).get("sections", {})
                names = sorted(sections) if isinstance(sections, dict) else []
                print(f"sections: {names}")

                jobs = await asyncio.to_thread(
                    request_json,
                    base_url,
                    "/v1/nodes/jobs",
                    method="GET",
                    headers=operator_headers,
                )
                for job in jobs["jobs"][:1]:
                    print(f"progress events streamed: {job['progress_events']}")

                _headline("freezing dispatch and proving the kill switch holds")
                frozen = await asyncio.to_thread(
                    request_json,
                    base_url,
                    "/v1/nodes/control/freeze",
                    payload={"reason": "demo freeze"},
                    headers=operator_headers,
                )
                print(f"frozen at epoch {frozen['freeze_epoch']}")
                refused = await _expect_refusal(base_url, operator_headers)
                print(f"second dispatch refused: {refused}")
                thawed = await asyncio.to_thread(
                    request_json,
                    base_url,
                    "/v1/nodes/control/unfreeze",
                    payload={
                        "expected_freeze_epoch": frozen["freeze_epoch"],
                        "reason": "demo unfreeze",
                    },
                    headers=operator_headers,
                )
                print(f"unfrozen: frozen={thawed['frozen']}")

                _headline("audit record")
                audit = await asyncio.to_thread(
                    request_json,
                    base_url,
                    "/v1/nodes/audit",
                    method="GET",
                    headers=operator_headers,
                )
                print(f"chain valid: {audit['chain_valid']} events: {len(audit['events'])}")
                for event in audit["events"]:
                    print(f"  {event['sequence']:>3} {event['action']:<24} {event['decision']}")
                print(f"\nmobile console: {base_url}/ui/nodes")
        finally:
            if agent_task is not None:
                agent_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await agent_task
            server.should_exit = True
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(serving, timeout=10)
    return 0


async def _expect_refusal(base_url: str, headers: dict[str, str]) -> str:
    try:
        await asyncio.to_thread(
            request_json,
            base_url,
            "/v1/nodes/jobs",
            payload={"capability": SYSTEM_INSPECT.name, "parameters": {}},
            headers=headers,
        )
    except Exception as exc:  # noqa: BLE001 - the demo reports the refusal verbatim
        return str(exc)
    return "unexpectedly accepted"


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
