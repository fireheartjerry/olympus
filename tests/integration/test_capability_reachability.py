"""Every enabled capability must be reachable through the whole stack.

Three times now the same defect has shipped: a capability enabled in the
catalog, correct in isolation, and unable to be reached from some layer.

* ``fs.read`` and ``fs.write`` were enabled but the agent registered no
  provider for them.
* Dispatch never passed parameters to admission, so no scoped capability could
  be admitted at all.
* The enrollment API had no field for a scope, so the scoped capabilities could
  not be granted.

Each layer was individually complete and unit-tested. Nothing failed until
someone walked the whole path. This file walks the whole path, for every
enabled capability, so the fourth instance fails in CI instead of in
production.

The table below is deliberately mandatory: a new enabled capability with no
entry here fails ``test_every_enabled_capability_is_exercised``. Adding a
capability therefore forces the author to say how it is reached, which is
exactly the step that was skipped each time.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
from pathlib import Path
from typing import Any

import pytest

from olympus.nodes.capabilities import ENABLED_CAPABILITIES
from olympus.nodes.crypto import generate_node_keypair
from olympus.nodes.dispatch import NodeDispatchService, NodeJobRequest
from olympus.nodes.models import (
    DispatchAuthority,
    NodeJobStatus,
    NodeKind,
    NodePlatform,
)
from olympus.nodes.registry import NodeDescription, NodeRegistry

AUTHORITY = DispatchAuthority(commander_id="local-jerry", authority_lease_id="development-lease")
CONTROL_PLANE_KEY_ID = "olympus-control-plane-test"


class AcceptingApprovals:
    """Approval verification is exercised in its own suite; here it must not
    be the reason a capability appears unreachable."""

    def verify(self, *, action_digest: str, approval: Any, now: Any) -> None:
        return None


def _exercises(directory: Path) -> dict[str, dict[str, Any]]:
    """How each enabled capability is granted and invoked.

    Scope and parameters together, because for a scoped capability neither one
    alone demonstrates anything.
    """
    payload = b'{"reachable": true}'
    return {
        "system.inspect@1": {
            "scope": None,
            "parameters": {"sections": ["os"]},
        },
        "fs.read@1": {
            "scope": {"roots": [str(directory)], "max_bytes": 4096},
            "parameters": {"path": str(directory / "present.txt")},
        },
        "fs.list@1": {
            "scope": {"roots": [str(directory)], "max_bytes": 4096},
            "parameters": {"path": str(directory)},
        },
        "fs.write@1": {
            "scope": {"roots": [str(directory)], "max_bytes": 4096},
            "parameters": {
                "path": str(directory / "written.txt"),
                "content_base64": base64.b64encode(payload).decode(),
                "content_sha256": hashlib.sha256(payload).hexdigest(),
                "content_length": len(payload),
                "mode": "create",
            },
        },
    }


def test_every_enabled_capability_is_exercised(tmp_path: Path) -> None:
    """Enabling a capability without saying how it is reached fails here.

    That omission is precisely what shipped three unreachable capabilities.
    """
    missing = sorted(set(ENABLED_CAPABILITIES) - set(_exercises(tmp_path)))

    assert not missing, (
        f"{missing} are enabled but this file does not exercise them; add an entry "
        "showing how each is granted and invoked end to end"
    )


@pytest.mark.parametrize("capability", sorted(ENABLED_CAPABILITIES))
def test_capability_is_reachable_end_to_end(capability: str, tmp_path: Path) -> None:
    """Grant it, connect a real agent, dispatch it, and require a real result.

    Run through the actual registry, session handshake, agent, and dispatch
    service. A mock at any layer would reproduce the exact blindness this file
    exists to remove.
    """
    directory = tmp_path / "granted"
    directory.mkdir()
    (directory / "present.txt").write_text("reachable\n", encoding="utf-8")
    exercise = _exercises(directory)[capability]

    asyncio.run(_walk_the_stack(capability, exercise, directory))


async def _walk_the_stack(capability: str, exercise: dict[str, Any], directory: Path) -> None:
    from olympus.node_agent.agent import AgentIdentity, NodeAgent
    from olympus.node_agent.capabilities import SystemInspectProvider
    from olympus.nodes.channel import create_channel_pair
    from olympus.nodes.session import NodeSession

    control_keys = generate_node_keypair()
    node_keys = generate_node_keypair()
    registry = NodeRegistry(
        heartbeat_interval_seconds=1,
        heartbeat_expiry_seconds=60,
        approvals=AcceptingApprovals(),
    )
    dispatch = NodeDispatchService(registry=registry)

    scopes = {capability: exercise["scope"]} if exercise["scope"] else None
    issued = await registry.issue_enrollment_token(
        node_name="reachability-node",
        kind=NodeKind.WORKSTATION,
        platform=NodePlatform.LINUX,
        granted_capabilities=[capability],
        issued_by="local-jerry",
        capability_scopes=scopes,
    )
    record = await registry.redeem_enrollment_token(
        presented=issued.presented,
        description=NodeDescription(
            node_name="reachability-node",
            kind=NodeKind.WORKSTATION,
            platform=NodePlatform.LINUX,
            architecture="x86_64",
            agent_version="0.1.0",
            declared_capabilities=(capability,),
        ),
        public_key=node_keys.public_key,
    )

    server_channel, client_channel = create_channel_pair()
    session = NodeSession(
        channel=server_channel,
        registry=registry,
        control_plane_private_key=control_keys.private_key,
        control_plane_key_id=CONTROL_PLANE_KEY_ID,
    )
    agent = NodeAgent(
        identity=AgentIdentity(
            node_id=record.node_id,
            node_name="reachability-node",
            private_key=node_keys.private_key,
            control_plane_public_key=control_keys.public_key,
            control_plane_key_id=CONTROL_PLANE_KEY_ID,
        ),
        # Only the unscoped provider is constructed up front. The scoped ones
        # must be built by the agent from what the session delivers, which is
        # the step that was missing.
        providers=[SystemInspectProvider(agent_version="0.1.0")],
        serves=("fs.read@1", "fs.list@1", "fs.write@1"),
        node_platform="linux",
        architecture="x86_64",
    )

    ready = asyncio.Event()
    agent_task = asyncio.create_task(agent.run(client_channel, on_ready=lambda _f: ready.set()))
    await session.handshake()
    await dispatch.attach_session(session)
    pump_task = asyncio.create_task(session.pump())
    await asyncio.wait_for(ready.wait(), timeout=5)

    try:
        outcome = await asyncio.wait_for(
            dispatch.run_job(
                NodeJobRequest(
                    job_id=f"reach-{capability.replace('@', '-').replace('.', '-')}",
                    capability=capability,
                    authority=AUTHORITY,
                    parameters=exercise["parameters"],
                    approval=object() if capability == "fs.write@1" else None,
                )
            ),
            timeout=10,
        )
        assert outcome.status is NodeJobStatus.SUCCEEDED, (
            f"{capability} is enabled but did not complete end to end: {outcome}"
        )
    finally:
        await session.shutdown(reason="test-teardown")
        for task in (agent_task, pump_task):
            task.cancel()
        for task in (agent_task, pump_task):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    # And the capability actually did its job, rather than returning an empty
    # success that a reachability check alone would accept.
    if capability == "fs.write@1":
        assert (directory / "written.txt").read_bytes() == b'{"reachable": true}'
    elif capability == "fs.read@1":
        assert outcome.output["content"] == "reachable\n"
    elif capability == "fs.list@1":
        assert "present.txt" in {entry["name"] for entry in outcome.output["entries"]}
    else:
        assert outcome.output
