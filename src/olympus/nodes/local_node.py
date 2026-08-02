import asyncio
import contextlib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from olympus.node_agent.agent import AGENT_VERSION, AgentIdentity, NodeAgent
from olympus.node_agent.capabilities import CapabilityProvider, SystemInspectProvider
from olympus.nodes.capabilities import SYSTEM_INSPECT
from olympus.nodes.channel import create_channel_pair
from olympus.nodes.crypto import generate_node_keypair
from olympus.nodes.dispatch import NodeDispatchService
from olympus.nodes.models import NodeKind, NodePlatform
from olympus.nodes.registry import NodeDescription, NodeRegistry
from olympus.nodes.session import NodeSession


@dataclass
class LocalNodeHandle:
    """A running in-process node, used for the control-plane host and for tests."""

    node_id: str
    node_name: str
    agent: NodeAgent
    session: NodeSession
    _tasks: tuple[asyncio.Task[None], ...]

    async def aclose(self) -> None:
        await self.session.shutdown(reason="local-node-stopped")
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task


async def attach_local_node(
    *,
    registry: NodeRegistry,
    dispatch: NodeDispatchService,
    control_plane_private_key: str,
    control_plane_public_key: str,
    control_plane_key_id: str,
    node_name: str = "vps-primary",
    kind: NodeKind = NodeKind.CONTROL_PLANE_HOST,
    node_platform: NodePlatform = NodePlatform.LINUX,
    capabilities: Sequence[str] = (SYSTEM_INSPECT.name,),
    providers: Sequence[CapabilityProvider] | None = None,
    state_directory: Path | None = None,
    issued_by: str = "control-plane-bootstrap",
) -> LocalNodeHandle:
    """Enroll and connect the control-plane host as a first-class execution node.

    The host uses the same enrollment, the same protocol, and the same capability
    grants as a remote machine. Only the transport differs: an in-process channel
    instead of a WebSocket, so no loopback listener is added for it.
    """
    grants = tuple(capabilities)
    issued = await registry.issue_enrollment_token(
        node_name=node_name,
        kind=kind,
        platform=node_platform,
        granted_capabilities=grants,
        issued_by=issued_by,
    )
    keys = generate_node_keypair()
    record = await registry.redeem_enrollment_token(
        presented=issued.presented,
        description=NodeDescription(
            node_name=node_name,
            kind=kind,
            platform=node_platform,
            architecture="in-process",
            agent_version=AGENT_VERSION,
            declared_capabilities=grants,
        ),
        public_key=keys.public_key,
    )

    server_channel, client_channel = create_channel_pair()
    session = NodeSession(
        channel=server_channel,
        registry=registry,
        control_plane_private_key=control_plane_private_key,
        control_plane_key_id=control_plane_key_id,
    )
    agent = NodeAgent(
        identity=AgentIdentity(
            node_id=record.node_id,
            node_name=record.node_name,
            private_key=keys.private_key,
            control_plane_public_key=control_plane_public_key,
            control_plane_key_id=control_plane_key_id,
        ),
        providers=list(providers)
        if providers is not None
        else [
            SystemInspectProvider(
                state_directory=state_directory or Path.cwd(), agent_version=AGENT_VERSION
            )
        ],
        node_platform=node_platform.value,
        architecture="in-process",
    )

    agent_task = asyncio.create_task(agent.run(client_channel))
    await session.handshake()
    await dispatch.attach_session(session)
    pump_task = asyncio.create_task(session.pump())
    return LocalNodeHandle(
        node_id=record.node_id,
        node_name=record.node_name,
        agent=agent,
        session=session,
        _tasks=(agent_task, pump_task),
    )
