import asyncio

import pytest

from olympus.nodes.capabilities import SYSTEM_INSPECT
from olympus.nodes.crypto import generate_node_keypair
from olympus.nodes.dispatch import NodeDispatchService, NodeJobRequest
from olympus.nodes.errors import NodeMeshError, NodeReason
from olympus.nodes.local_node import attach_local_node
from olympus.nodes.models import DispatchAuthority, NodeJobStatus, NodeKind, NodeState
from olympus.nodes.registry import NodeRegistry

AUTHORITY = DispatchAuthority(commander_id="local-jerry", authority_lease_id="development-lease")


async def build_local_node() -> tuple[NodeRegistry, NodeDispatchService, object]:
    keys = generate_node_keypair()
    registry = NodeRegistry(heartbeat_interval_seconds=1, heartbeat_expiry_seconds=60)
    dispatch = NodeDispatchService(registry=registry)
    handle = await attach_local_node(
        registry=registry,
        dispatch=dispatch,
        control_plane_private_key=keys.private_key,
        control_plane_public_key=keys.public_key,
        control_plane_key_id="olympus-control-plane-test",
    )
    return registry, dispatch, handle


async def test_the_control_plane_host_enrolls_as_an_ordinary_execution_node() -> None:
    registry, dispatch, handle = await build_local_node()
    try:
        views = await registry.list_views()
        assert len(views) == 1
        view = views[0]
        assert view.node_name == "vps-primary"
        assert view.kind is NodeKind.CONTROL_PLANE_HOST
        assert view.state is NodeState.ONLINE
        assert view.effective_capabilities == (SYSTEM_INSPECT.name,)
        assert view.output_trust_label.value == "external-untrusted"
        assert dispatch.session_for(handle.node_id) is not None
    finally:
        await handle.aclose()


async def test_the_control_plane_host_serves_a_bounded_inspection() -> None:
    registry, dispatch, handle = await build_local_node()
    try:
        outcome = await asyncio.wait_for(
            dispatch.run_job(
                NodeJobRequest(
                    job_id="job-local-1",
                    capability=SYSTEM_INSPECT.name,
                    authority=AUTHORITY,
                    parameters={"sections": ["os", "agent"]},
                    node_id=handle.node_id,
                )
            ),
            timeout=10,
        )
    finally:
        await handle.aclose()

    assert outcome.status is NodeJobStatus.SUCCEEDED
    assert sorted(outcome.output["sections"]) == ["agent", "os"]
    assert await registry.verify_audit() is True


async def test_the_control_plane_host_holds_no_reserved_capability() -> None:
    registry, dispatch, handle = await build_local_node()
    try:
        with pytest.raises(NodeMeshError) as failure:
            await dispatch.run_job(
                NodeJobRequest(
                    job_id="job-local-2",
                    capability="shell.powershell@1",
                    authority=AUTHORITY,
                    node_id=handle.node_id,
                )
            )
    finally:
        await handle.aclose()
    assert failure.value.reason is NodeReason.CAPABILITY_RESERVED


async def test_closing_the_local_node_detaches_its_session() -> None:
    registry, dispatch, handle = await build_local_node()
    await handle.aclose()

    assert dispatch.session_for(handle.node_id) is None
    record = await registry.get_node(handle.node_id)
    assert record.session_id is None
