import asyncio
import contextlib
from dataclasses import replace

import pytest

from olympus.node_agent.agent import AgentIdentity, NodeAgent
from olympus.node_agent.capabilities import CapabilityArtifact, FakeCapabilityProvider
from olympus.nodes.capabilities import SYSTEM_INSPECT
from olympus.nodes.channel import create_channel_pair
from olympus.nodes.crypto import digest_of, generate_node_keypair, random_nonce, sign_payload
from olympus.nodes.dispatch import NodeDispatchService, NodeJobRequest
from olympus.nodes.errors import NodeMeshError, NodeReason
from olympus.nodes.models import (
    DispatchAuthority,
    NodeJobStatus,
    NodeKind,
    NodePlatform,
    NodeState,
)
from olympus.nodes.protocol import (
    PROTOCOL_ID,
    AttestFrame,
    HelloFrame,
    JobAckFrame,
    JobProgressFrame,
    JobResultFrame,
    encode_frame,
    node_proof_payload,
    parse_server_frame,
)
from olympus.nodes.registry import NodeDescription, NodeRegistry
from olympus.nodes.session import NodeSession

AUTHORITY = DispatchAuthority(commander_id="local-jerry", authority_lease_id="development-lease")
CONTROL_PLANE_KEY_ID = "olympus-control-plane-test"


class Mesh:
    """A registry, one enrolled node, and the key material both sides use."""

    def __init__(self, platform: NodePlatform = NodePlatform.WINDOWS) -> None:
        self.platform = platform
        self.control_keys = generate_node_keypair()
        self.node_keys = generate_node_keypair()
        self.registry = NodeRegistry(heartbeat_interval_seconds=1, heartbeat_expiry_seconds=60)
        self.dispatch = NodeDispatchService(registry=self.registry)
        self.node_id = ""

    async def enroll(
        self,
        capabilities: tuple[str, ...] = (SYSTEM_INSPECT.name,),
        capability_scopes: dict[str, dict[str, object]] | None = None,
    ) -> str:
        issued = await self.registry.issue_enrollment_token(
            node_name="jerry-windows",
            kind=NodeKind.WORKSTATION,
            platform=self.platform,
            granted_capabilities=list(capabilities),
            issued_by="local-jerry",
            capability_scopes=capability_scopes,
        )
        record = await self.registry.redeem_enrollment_token(
            presented=issued.presented,
            description=NodeDescription(
                node_name="jerry-windows",
                kind=NodeKind.WORKSTATION,
                platform=self.platform,
                architecture="AMD64",
                agent_version="0.1.0",
                declared_capabilities=capabilities,
            ),
            public_key=self.node_keys.public_key,
        )
        self.node_id = record.node_id
        return record.node_id

    def identity(self, **overrides: str) -> AgentIdentity:
        fields = {
            "node_id": self.node_id,
            "node_name": "jerry-windows",
            "private_key": self.node_keys.private_key,
            "control_plane_public_key": self.control_keys.public_key,
            "control_plane_key_id": CONTROL_PLANE_KEY_ID,
        }
        fields.update(overrides)
        return AgentIdentity(**fields)  # type: ignore[arg-type]

    def session(self, channel: object, **overrides: str) -> NodeSession:
        return NodeSession(
            channel=channel,  # type: ignore[arg-type]
            registry=self.registry,
            control_plane_private_key=overrides.get(
                "control_plane_private_key", self.control_keys.private_key
            ),
            control_plane_key_id=overrides.get("control_plane_key_id", CONTROL_PLANE_KEY_ID),
        )


class Connection:
    """A live agent and session pair over an in-memory channel."""

    def __init__(self, mesh: Mesh, agent: NodeAgent, session: NodeSession) -> None:
        self.mesh = mesh
        self.agent = agent
        self.session = session
        self.tasks: list[asyncio.Task[None]] = []

    async def aclose(self) -> None:
        await self.session.shutdown(reason="test-teardown")
        for task in self.tasks:
            task.cancel()
        for task in self.tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task


async def connect(
    mesh: Mesh,
    provider: FakeCapabilityProvider | None = None,
    *,
    providers: list[object] | None = None,
    serves: tuple[str, ...] = (),
) -> Connection:
    server_channel, client_channel = create_channel_pair()
    session = mesh.session(server_channel)
    agent = NodeAgent(
        identity=mesh.identity(),
        providers=providers  # type: ignore[arg-type]
        if providers is not None
        else [provider or FakeCapabilityProvider()],
        serves=serves,
        node_platform=mesh.platform.value,
        architecture="AMD64",
    )
    ready = asyncio.Event()
    agent_task = asyncio.create_task(agent.run(client_channel, on_ready=lambda _frame: ready.set()))
    await session.handshake()
    await mesh.dispatch.attach_session(session)
    pump_task = asyncio.create_task(session.pump())
    await asyncio.wait_for(ready.wait(), timeout=5)
    connection = Connection(mesh, agent, session)
    connection.tasks = [agent_task, pump_task]
    return connection


def job(job_id: str = "job-1", **overrides: object) -> NodeJobRequest:
    fields: dict[str, object] = {
        "job_id": job_id,
        "capability": SYSTEM_INSPECT.name,
        "authority": AUTHORITY,
        "parameters": {"sections": ["os"]},
    }
    fields.update(overrides)
    return NodeJobRequest(**fields)  # type: ignore[arg-type]


async def test_mutual_authentication_completes_and_grants_only_the_intersection() -> None:
    mesh = Mesh()
    await mesh.enroll()
    connection = await connect(mesh)
    try:
        assert connection.agent.granted_capabilities == (SYSTEM_INSPECT.name,)
        assert connection.session.node is not None
        record = await mesh.registry.get_node(mesh.node_id)
        assert record.session_id == connection.session.session_id
    finally:
        await connection.aclose()


async def test_a_node_rejects_a_control_plane_it_cannot_verify() -> None:
    mesh = Mesh()
    await mesh.enroll()
    impostor = generate_node_keypair()
    server_channel, client_channel = create_channel_pair()
    session = mesh.session(server_channel, control_plane_private_key=impostor.private_key)
    agent = NodeAgent(identity=mesh.identity(), providers=[FakeCapabilityProvider()])

    server_task = asyncio.create_task(session.handshake())
    with pytest.raises(NodeMeshError) as failure:
        await agent.run(client_channel)
    assert failure.value.reason is NodeReason.SERVER_PROOF_INVALID
    server_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await server_task


async def test_a_node_rejects_an_unexpected_control_plane_key_id() -> None:
    mesh = Mesh()
    await mesh.enroll()
    server_channel, client_channel = create_channel_pair()
    session = mesh.session(server_channel, control_plane_key_id="someone-elses-key")
    agent = NodeAgent(identity=mesh.identity(), providers=[FakeCapabilityProvider()])

    server_task = asyncio.create_task(session.handshake())
    with pytest.raises(NodeMeshError) as failure:
        await agent.run(client_channel)
    assert failure.value.reason is NodeReason.SERVER_PROOF_INVALID
    server_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await server_task


async def test_the_control_plane_rejects_a_node_that_cannot_sign() -> None:
    mesh = Mesh()
    await mesh.enroll()
    stolen_identity = mesh.identity(private_key=generate_node_keypair().private_key)
    server_channel, client_channel = create_channel_pair()
    session = mesh.session(server_channel)
    agent = NodeAgent(identity=stolen_identity, providers=[FakeCapabilityProvider()])

    agent_task = asyncio.create_task(agent.run(client_channel))
    with pytest.raises(NodeMeshError) as failure:
        await session.handshake()
    assert failure.value.reason is NodeReason.NODE_PROOF_INVALID
    agent_task.cancel()
    with pytest.raises((asyncio.CancelledError, NodeMeshError)):
        await agent_task


async def test_an_unsupported_protocol_version_is_refused() -> None:
    mesh = Mesh()
    await mesh.enroll()
    server_channel, client_channel = create_channel_pair()
    session = mesh.session(server_channel)

    await client_channel.send(
        encode_frame(
            HelloFrame(
                protocol="olympus-node/99",
                node_id=mesh.node_id,
                agent_version="0.1.0",
                platform="windows",
                architecture="AMD64",
                node_nonce="a" * 32,
            )
        )
    )
    with pytest.raises(NodeMeshError) as failure:
        await session.handshake()
    assert failure.value.reason is NodeReason.PROTOCOL_VERSION_UNSUPPORTED
    closing = parse_server_frame(await client_channel.receive())
    assert closing.type == "session-close"


async def test_a_revoked_node_cannot_open_a_session() -> None:
    mesh = Mesh()
    await mesh.enroll()
    await mesh.registry.revoke_node(mesh.node_id, actor="local-jerry", reason="stolen")
    server_channel, client_channel = create_channel_pair()
    session = mesh.session(server_channel)
    agent = NodeAgent(identity=mesh.identity(), providers=[FakeCapabilityProvider()])

    agent_task = asyncio.create_task(agent.run(client_channel))
    with pytest.raises(NodeMeshError) as failure:
        await session.handshake()
    assert failure.value.reason is NodeReason.NODE_REVOKED
    agent_task.cancel()
    with pytest.raises((asyncio.CancelledError, NodeMeshError)):
        await agent_task


async def test_dispatch_streams_progress_and_returns_untrusted_output() -> None:
    mesh = Mesh()
    await mesh.enroll()
    provider = FakeCapabilityProvider(output={"answer": 42})
    connection = await connect(mesh, provider)
    seen: list[str] = []

    async def on_progress(frame: object) -> None:
        seen.append(frame.message)  # type: ignore[attr-defined]

    try:
        outcome = await mesh.dispatch.run_job(job(), on_progress=on_progress)
    finally:
        await connection.aclose()

    assert outcome.status is NodeJobStatus.SUCCEEDED
    assert outcome.output == {"answer": 42}
    assert outcome.trust_label.value == "external-untrusted"
    assert seen == ["started", "halfway", "finishing"]
    assert provider.executions[0].parameters == {"sections": ["os"]}


async def test_a_re_dispatched_job_replays_instead_of_running_twice() -> None:
    mesh = Mesh()
    await mesh.enroll()
    provider = FakeCapabilityProvider(output={"answer": 42})
    connection = await connect(mesh, provider)
    try:
        first = await mesh.dispatch.run_job(job())
        second = await mesh.dispatch.run_job(job(attempt=2))
    finally:
        await connection.aclose()

    assert first.replayed is False
    assert second.replayed is True
    assert second.output == first.output
    assert len(provider.executions) == 1


async def test_the_dedupe_key_changes_when_the_parameters_change() -> None:
    assert job().dedupe_key != job(parameters={"sections": ["cpu"]}).dedupe_key
    assert job().dedupe_key == job().dedupe_key


async def test_a_reconnected_node_replays_the_recorded_result() -> None:
    mesh = Mesh()
    await mesh.enroll()
    provider = FakeCapabilityProvider(output={"answer": 42})

    first_connection = await connect(mesh, provider)
    original = await mesh.dispatch.run_job(job())
    agent = first_connection.agent
    await first_connection.aclose()

    # The same agent process reconnects, keeping its dedupe ledger.
    server_channel, client_channel = create_channel_pair()
    session = mesh.session(server_channel)
    agent_task = asyncio.create_task(agent.run(client_channel))
    await session.handshake()
    await mesh.dispatch.attach_session(session)
    pump_task = asyncio.create_task(session.pump())
    try:
        recovered = await mesh.dispatch.run_job(job(attempt=2))
    finally:
        await session.shutdown(reason="test-teardown")
        for task in (agent_task, pump_task):
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    assert recovered.replayed is True
    assert recovered.output == original.output
    assert len(provider.executions) == 1


async def test_a_job_lost_with_its_session_fails_so_temporal_can_retry() -> None:
    mesh = Mesh()
    await mesh.enroll()
    connection = await connect(mesh, FakeCapabilityProvider(stall=True, progress_messages=()))

    dispatching = asyncio.create_task(mesh.dispatch.run_job(job()))
    await asyncio.sleep(0.05)
    await connection.session.shutdown(reason="connection lost")

    with pytest.raises(NodeMeshError) as failure:
        await dispatching
    assert failure.value.reason is NodeReason.SESSION_CLOSED
    await connection.aclose()


async def test_cancellation_reaches_the_node_and_produces_a_cancelled_outcome() -> None:
    mesh = Mesh()
    await mesh.enroll()
    connection = await connect(mesh, FakeCapabilityProvider(stall=True, progress_messages=()))

    dispatching = asyncio.create_task(mesh.dispatch.run_job(job()))
    await asyncio.sleep(0.05)
    assert await mesh.dispatch.cancel_job("job-1", reason="operator", actor="local-jerry")

    try:
        outcome = await asyncio.wait_for(dispatching, timeout=5)
    finally:
        await connection.aclose()
    assert outcome.status is NodeJobStatus.CANCELLED
    assert outcome.reason == NodeReason.JOB_CANCELLED.value


async def test_a_cancelled_job_is_not_recorded_as_a_replayable_result() -> None:
    mesh = Mesh()
    await mesh.enroll()
    provider = FakeCapabilityProvider(stall=True, progress_messages=())
    connection = await connect(mesh, provider)

    dispatching = asyncio.create_task(mesh.dispatch.run_job(job()))
    await asyncio.sleep(0.05)
    await mesh.dispatch.cancel_job("job-1", reason="operator", actor="local-jerry")
    await asyncio.wait_for(dispatching, timeout=5)

    connection.agent._providers[SYSTEM_INSPECT.name] = FakeCapabilityProvider(  # noqa: SLF001
        output={"answer": 7}, progress_messages=()
    )
    try:
        retried = await asyncio.wait_for(mesh.dispatch.run_job(job(attempt=2)), timeout=5)
    finally:
        await connection.aclose()
    assert retried.replayed is False
    assert retried.status is NodeJobStatus.SUCCEEDED


async def test_a_node_that_declares_nothing_is_refused_before_dispatch() -> None:
    mesh = Mesh()
    await mesh.enroll()
    connection = await connect(mesh, FakeCapabilityProvider(capabilities=()))
    try:
        with pytest.raises(NodeMeshError) as targeted:
            await mesh.dispatch.run_job(job(node_id=mesh.node_id))
        with pytest.raises(NodeMeshError) as untargeted:
            await mesh.dispatch.run_job(job("job-2"))
    finally:
        await connection.aclose()
    assert targeted.value.reason is NodeReason.CAPABILITY_NOT_DECLARED
    assert untargeted.value.reason is NodeReason.DISPATCH_NO_ELIGIBLE_NODE


async def test_a_node_refuses_a_capability_outside_its_granted_set() -> None:
    mesh = Mesh()
    await mesh.enroll()
    connection = await connect(mesh)
    # Simulate a node whose grant was withdrawn after the session opened: the
    # node itself must still refuse the work rather than run it.
    connection.agent.granted_capabilities = ()
    try:
        outcome = await asyncio.wait_for(
            mesh.dispatch.run_job(job(node_id=mesh.node_id)), timeout=5
        )
    finally:
        await connection.aclose()
    assert outcome.status is NodeJobStatus.REJECTED
    assert outcome.reason == NodeReason.CAPABILITY_NOT_GRANTED.value


async def test_oversized_output_is_bounded_before_it_leaves_the_node() -> None:
    mesh = Mesh()
    await mesh.enroll()
    connection = await connect(
        mesh, FakeCapabilityProvider(oversized_bytes=200_000, progress_messages=())
    )
    try:
        outcome = await asyncio.wait_for(mesh.dispatch.run_job(job()), timeout=10)
    finally:
        await connection.aclose()

    assert outcome.output_truncated is True
    assert set(outcome.output) == {"preview"}
    assert len(str(outcome.output["preview"])) <= SYSTEM_INSPECT.max_output_bytes


async def test_secrets_in_node_output_are_redacted_before_the_control_plane_records_them() -> None:
    mesh = Mesh()
    await mesh.enroll()
    provider = FakeCapabilityProvider(
        output={"log": "connecting with password=hunter2 and Bearer abcdefghijklmnop"},
        progress_messages=("token=abcdefghij is live",),
    )
    connection = await connect(mesh, provider)
    messages: list[str] = []

    async def on_progress(frame: object) -> None:
        messages.append(frame.message)  # type: ignore[attr-defined]

    try:
        outcome = await mesh.dispatch.run_job(job(), on_progress=on_progress)
    finally:
        await connection.aclose()

    rendered = str(outcome.output)
    assert "hunter2" not in rendered
    assert "abcdefghijklmnop" not in rendered
    assert "[redacted]" in rendered
    assert "abcdefghij" not in messages[0]


async def test_artifacts_are_refused_for_a_capability_that_declares_none() -> None:
    """The catalog says system.inspect returns no artifacts. That has to bind.

    Artifacts were bounded only by a global ceiling, so a capability declaring
    zero could still stream up to it — and the result frame's own artifact list
    was trusted as a fallback, so even a refused artifact reappeared in the
    outcome. A declaration nothing enforces is not a bound.
    """
    mesh = Mesh()
    await mesh.enroll()
    provider = FakeCapabilityProvider(
        progress_messages=(),
        artifacts=(
            CapabilityArtifact(
                artifact_id="screenshot-1",
                kind="screenshot",
                media_type="image/png",
                data=b"\x89PNG\r\n\x1a\n-fake",
            ),
        ),
    )
    connection = await connect(mesh, provider)
    try:
        outcome = await asyncio.wait_for(mesh.dispatch.run_job(job()), timeout=5)
    finally:
        await connection.aclose()
    assert outcome.artifact_ids == ()


async def test_a_node_cannot_reference_artifacts_it_never_sent() -> None:
    """The result frame is a claim, not evidence.

    A node that lists artifact ids in its result without streaming them is
    describing files the control plane never received.
    """
    mesh = Mesh()
    await mesh.enroll()
    connection = await connect(mesh, FakeCapabilityProvider(progress_messages=()))
    try:
        outcome = await asyncio.wait_for(mesh.dispatch.run_job(job()), timeout=5)
    finally:
        await connection.aclose()

    assert outcome.artifact_ids == ()


async def test_freezing_refuses_new_dispatch_and_stops_work_in_flight() -> None:
    mesh = Mesh()
    await mesh.enroll()
    connection = await connect(mesh, FakeCapabilityProvider(stall=True, progress_messages=()))

    dispatching = asyncio.create_task(mesh.dispatch.run_job(job()))
    await asyncio.sleep(0.05)
    await mesh.dispatch.freeze(actor="local-jerry", reason="emergency")

    try:
        outcome = await asyncio.wait_for(dispatching, timeout=5)
        with pytest.raises(NodeMeshError) as failure:
            await mesh.dispatch.run_job(job("job-2"))
    finally:
        await connection.aclose()

    assert outcome.status is NodeJobStatus.CANCELLED
    assert failure.value.reason is NodeReason.DISPATCH_FROZEN


async def test_the_node_concurrency_bound_is_enforced() -> None:
    mesh = Mesh()
    await mesh.enroll()
    connection = await connect(mesh, FakeCapabilityProvider(stall=True, progress_messages=()))
    running = [
        asyncio.create_task(mesh.dispatch.run_job(job(f"job-{index}", parameters={"n": index})))
        for index in range(connection.session.limits.max_concurrent_jobs)
    ]
    await asyncio.sleep(0.1)
    try:
        with pytest.raises(NodeMeshError) as failure:
            await mesh.dispatch.run_job(job("job-overflow", parameters={"n": 99}))
    finally:
        for task in running:
            task.cancel()
        await connection.aclose()
    assert failure.value.reason is NodeReason.DISPATCH_CONCURRENCY_EXCEEDED


async def test_reconnecting_replaces_the_previous_session_for_that_node() -> None:
    mesh = Mesh()
    await mesh.enroll()
    first = await connect(mesh)
    second = await connect(mesh)
    try:
        assert first.session.closed is True
        assert mesh.dispatch.session_for(mesh.node_id) is second.session
    finally:
        await second.aclose()
        await first.aclose()


async def test_job_records_expose_progress_for_the_operator_console() -> None:
    mesh = Mesh()
    await mesh.enroll()
    connection = await connect(mesh)
    try:
        await mesh.dispatch.run_job(job())
    finally:
        await connection.aclose()

    records = mesh.dispatch.jobs()
    assert records[0].job_id == "job-1"
    assert records[0].status is NodeJobStatus.SUCCEEDED
    assert records[0].progress_events == 3
    assert mesh.dispatch.active_job_ids() == ()


async def test_dispatch_appends_an_unbroken_audit_chain() -> None:
    mesh = Mesh()
    await mesh.enroll()
    connection = await connect(mesh)
    try:
        await mesh.dispatch.run_job(job())
    finally:
        await connection.aclose()

    actions = [event.action.value for event in await mesh.registry.audit_events()]
    assert "dispatch-admitted" in actions
    assert "dispatch-completed" in actions
    assert await mesh.registry.verify_audit() is True


async def test_request_attempt_is_carried_into_the_dispatch_frame() -> None:
    original = job()
    assert replace(original, attempt=3).attempt == 3
    assert replace(original, attempt=3).dedupe_key == original.dedupe_key


async def hostile_connection(mesh: Mesh) -> tuple[NodeSession, object, asyncio.Task[None]]:
    """Complete a real handshake, then let the test drive the node side by hand."""
    server_channel, client_channel = create_channel_pair()
    session = mesh.session(server_channel)
    agent = NodeAgent(identity=mesh.identity(), providers=[FakeCapabilityProvider()])
    handshaking = asyncio.create_task(agent.handshake(client_channel))
    await session.handshake()
    await handshaking
    await mesh.dispatch.attach_session(session)
    pump = asyncio.create_task(session.pump())
    return session, client_channel, pump


async def test_a_result_naming_the_wrong_attempt_or_identity_is_discarded() -> None:
    mesh = Mesh()
    await mesh.enroll()
    session, client_channel, pump = await hostile_connection(mesh)

    dispatching = asyncio.create_task(mesh.dispatch.run_job(job()))
    dispatch_frame = parse_server_frame(await client_channel.receive())
    assert dispatch_frame.type == "job-dispatch"
    await client_channel.send(
        encode_frame(JobAckFrame(job_id=dispatch_frame.job_id, attempt=1, accepted=True))
    )

    forged = {
        "job_id": dispatch_frame.job_id,
        "dedupe_key": dispatch_frame.dedupe_key,
        "status": "succeeded",
        "output": {"stolen": True},
    }
    # Wrong attempt, then a dedupe key the control plane never issued.
    await client_channel.send(encode_frame(JobResultFrame(**{**forged, "attempt": 7})))
    await client_channel.send(
        encode_frame(JobResultFrame(**{**forged, "attempt": 1, "dedupe_key": "f" * 64}))
    )
    await asyncio.sleep(0.05)
    assert dispatching.done() is False

    await client_channel.send(encode_frame(JobResultFrame(**forged, attempt=1)))
    try:
        outcome = await asyncio.wait_for(dispatching, timeout=5)
    finally:
        await session.shutdown(reason="test-teardown")
        pump.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await pump

    assert outcome.status is NodeJobStatus.SUCCEEDED
    assert outcome.attempt == 1
    assert outcome.dedupe_key == job().dedupe_key


async def test_the_control_plane_enforces_the_progress_cap_a_node_ignores() -> None:
    mesh = Mesh()
    await mesh.enroll()
    session, client_channel, pump = await hostile_connection(mesh)
    delivered: list[str] = []

    async def on_progress(frame: object) -> None:
        delivered.append(frame.message)  # type: ignore[attr-defined]

    dispatching = asyncio.create_task(mesh.dispatch.run_job(job(), on_progress=on_progress))
    dispatch_frame = parse_server_frame(await client_channel.receive())
    await client_channel.send(
        encode_frame(JobAckFrame(job_id=dispatch_frame.job_id, attempt=1, accepted=True))
    )
    cap = dispatch_frame.max_progress_events
    for index in range(cap + 50):
        await client_channel.send(
            encode_frame(
                JobProgressFrame(
                    job_id=dispatch_frame.job_id, attempt=1, sequence=index % 200, message="flood"
                )
            )
        )
    await client_channel.send(
        encode_frame(
            JobResultFrame(
                job_id=dispatch_frame.job_id,
                attempt=1,
                dedupe_key=dispatch_frame.dedupe_key,
                status="succeeded",
            )
        )
    )
    try:
        await asyncio.wait_for(dispatching, timeout=10)
    finally:
        await session.shutdown(reason="test-teardown")
        pump.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await pump

    assert len(delivered) == cap
    assert mesh.dispatch.jobs()[0].progress_events == cap


async def test_the_control_plane_bounds_output_a_node_claims_is_untruncated() -> None:
    mesh = Mesh()
    await mesh.enroll()
    session, client_channel, pump = await hostile_connection(mesh)

    dispatching = asyncio.create_task(mesh.dispatch.run_job(job()))
    dispatch_frame = parse_server_frame(await client_channel.receive())
    await client_channel.send(
        encode_frame(JobAckFrame(job_id=dispatch_frame.job_id, attempt=1, accepted=True))
    )
    await client_channel.send(
        encode_frame(
            JobResultFrame(
                job_id=dispatch_frame.job_id,
                attempt=1,
                dedupe_key=dispatch_frame.dedupe_key,
                status="succeeded",
                output={"blob": "A" * 100_000},
                output_truncated=False,
            )
        )
    )
    try:
        outcome = await asyncio.wait_for(dispatching, timeout=10)
    finally:
        await session.shutdown(reason="test-teardown")
        pump.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await pump

    assert outcome.output_truncated is True
    assert set(outcome.output) == {"preview"}
    assert len(str(outcome.output["preview"])) <= SYSTEM_INSPECT.max_output_bytes


async def test_a_protocol_violation_tears_the_session_down_completely() -> None:
    mesh = Mesh()
    await mesh.enroll()
    session, client_channel, pump = await hostile_connection(mesh)

    dispatching = asyncio.create_task(mesh.dispatch.run_job(job()))
    dispatch_frame = parse_server_frame(await client_channel.receive())
    await client_channel.send(
        encode_frame(JobAckFrame(job_id=dispatch_frame.job_id, attempt=1, accepted=True))
    )
    # A well-formed frame that is illegal mid-session must fail the job promptly
    # and detach the node, not leave it orphaned until its deadline expires.
    await client_channel.send(
        encode_frame(
            HelloFrame(
                protocol=PROTOCOL_ID,
                node_id=mesh.node_id,
                agent_version="0.1.0",
                platform="windows",
                architecture="AMD64",
                node_nonce="a" * 32,
            )
        )
    )
    with pytest.raises(NodeMeshError) as failure:
        await asyncio.wait_for(dispatching, timeout=5)
    pump.cancel()
    with contextlib.suppress(asyncio.CancelledError, Exception):
        await pump

    assert failure.value.reason is NodeReason.SESSION_CLOSED
    record = await mesh.registry.get_node(mesh.node_id)
    assert record.session_id is None
    assert mesh.registry.state_of(record, mesh.registry.now()) is not NodeState.ONLINE


async def test_an_artifact_too_large_to_send_is_not_advertised() -> None:
    mesh = Mesh()
    await mesh.enroll()
    provider = FakeCapabilityProvider(
        progress_messages=(),
        artifacts=(
            CapabilityArtifact(
                artifact_id="oversized",
                kind="screenshot",
                media_type="image/png",
                data=b"\x00" * 400_000,
            ),
        ),
    )
    connection = await connect(mesh, provider)
    try:
        outcome = await asyncio.wait_for(mesh.dispatch.run_job(job()), timeout=10)
    finally:
        await connection.aclose()
    assert outcome.artifact_ids == ()


async def test_a_handshake_that_dies_before_ready_leaves_no_phantom_node() -> None:
    mesh = Mesh()
    await mesh.enroll()
    server_channel, client_channel = create_channel_pair()
    session = mesh.session(server_channel)
    handshaking = asyncio.create_task(session.handshake())

    await client_channel.send(
        encode_frame(
            HelloFrame(
                protocol=PROTOCOL_ID,
                node_id=mesh.node_id,
                agent_version="0.1.0",
                platform="windows",
                architecture="AMD64",
                declared_capabilities=(SYSTEM_INSPECT.name,),
                node_nonce=random_nonce(),
            )
        )
    )
    challenge = parse_server_frame(await client_channel.receive())
    await client_channel.send(
        encode_frame(
            AttestFrame(
                session_id=challenge.session_id,
                node_proof=sign_payload(
                    mesh.node_keys.private_key,
                    node_proof_payload(
                        protocol=PROTOCOL_ID,
                        session_id=challenge.session_id,
                        node_id=mesh.node_id,
                        server_nonce=challenge.server_nonce,
                        capabilities_digest=digest_of([SYSTEM_INSPECT.name]),
                    ),
                ),
            )
        )
    )
    # The node vanishes after attesting but before it ever reads the ready
    # frame: the window in which the session is already attached to its record.
    await client_channel.close()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(handshaking, timeout=5)

    record = await mesh.registry.get_node(mesh.node_id)
    assert record.session_id is None
    assert mesh.registry.state_of(record, mesh.registry.now()) is not NodeState.ONLINE
    with pytest.raises(NodeMeshError) as failure:
        await mesh.registry.assert_dispatchable(
            node_id=mesh.node_id, capability=SYSTEM_INSPECT.name
        )
    assert failure.value.reason is NodeReason.NODE_OFFLINE


# --- scoped capabilities end to end -------------------------------------------------
#
# fs.read and fs.write were implemented, enabled in the catalog, and unreachable:
# the agent registered only SystemInspectProvider, so a granted, scoped capability
# would have been refused as undeclared. These close that loop through the real
# handshake, the real session, and the real dispatch path.


async def test_a_scoped_capability_runs_end_to_end(tmp_path) -> None:
    directory = tmp_path / "granted"
    directory.mkdir()
    (directory / "report.txt").write_text("from the node\n", encoding="utf-8")

    mesh = Mesh(platform=NodePlatform.LINUX)
    await mesh.enroll(
        capabilities=(SYSTEM_INSPECT.name, "fs.read@1"),
        capability_scopes={"fs.read@1": {"roots": [str(directory)], "max_bytes": 4096}},
    )
    connection = await connect(mesh, providers=[], serves=("fs.read@1",))
    try:
        # The agent built the provider from the scope the session delivered.
        assert "fs.read@1" in connection.agent.capability_scopes
        outcome = await mesh.dispatch.run_job(
            job(
                job_id="read-1",
                capability="fs.read@1",
                parameters={"path": str(directory / "report.txt")},
            ),
        )
        assert outcome.status is NodeJobStatus.SUCCEEDED
        assert outcome.output["content"] == "from the node\n"
    finally:
        await connection.aclose()


async def test_the_node_builds_no_provider_when_the_scope_never_arrives() -> None:
    """Fail closed at the node, matching the control plane.

    A granted capability whose scope did not arrive must be refused as
    undeclared rather than run unbounded.
    """
    mesh = Mesh()
    await mesh.enroll(capabilities=(SYSTEM_INSPECT.name,))
    connection = await connect(mesh, providers=[], serves=("fs.read@1",))
    try:
        assert connection.agent.capability_scopes == {}
        # Declared as servable, but with no scope there is no provider, so a
        # dispatch would be refused rather than run unbounded.
        assert "fs.read@1" not in connection.agent._providers  # noqa: SLF001
    finally:
        await connection.aclose()


async def test_the_node_enforces_its_delivered_scope_not_the_request(tmp_path) -> None:
    """The node re-checks containment even though the control plane already did.

    Enforcement on one side only is enforcement that a bug on that side removes
    entirely.
    """
    directory = tmp_path / "granted"
    directory.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("private\n", encoding="utf-8")

    mesh = Mesh(platform=NodePlatform.LINUX)
    await mesh.enroll(
        capabilities=(SYSTEM_INSPECT.name, "fs.read@1"),
        capability_scopes={"fs.read@1": {"roots": [str(directory)], "max_bytes": 4096}},
    )
    connection = await connect(mesh, providers=[], serves=("fs.read@1",))
    try:
        provider = connection.agent._providers["fs.read@1"]  # noqa: SLF001 - asserting the bound
        assert provider.scope.roots == (str(directory),)

        from olympus.node_agent.capabilities import CapabilityRequest

        async def report(message: str, percent: int | None) -> None:
            return None

        result = await provider.execute(
            CapabilityRequest(
                job_id="direct",
                capability="fs.read@1",
                parameters={"path": str(secret)},
                deadline_seconds=15,
                max_output_bytes=4096,
            ),
            report,
        )
        assert result.status == "rejected"
        assert "private" not in result.message
    finally:
        await connection.aclose()


async def test_the_scope_the_node_receives_is_the_one_the_grant_states(tmp_path) -> None:
    # The node must not be able to widen what it was told, and the delivered
    # scope must match the grant rather than anything the node declared.
    directory = tmp_path / "granted"
    directory.mkdir()

    mesh = Mesh(platform=NodePlatform.LINUX)
    await mesh.enroll(
        capabilities=(SYSTEM_INSPECT.name, "fs.read@1"),
        capability_scopes={"fs.read@1": {"roots": [str(directory)], "max_bytes": 1024}},
    )
    connection = await connect(mesh, providers=[], serves=("fs.read@1",))
    try:
        delivered = connection.agent.capability_scopes["fs.read@1"]
        assert delivered["roots"] == [str(directory)]
        assert delivered["max_bytes"] == 1024
    finally:
        await connection.aclose()


# --- revocation must reach the live session ------------------------------------------


async def test_revoking_a_node_cancels_its_work_and_closes_its_session() -> None:
    """Revoking only the record marks the node untrusted for *future* dispatch.

    The channel stays open and whatever it is running keeps running — the
    opposite of what an operator revoking a compromised node is asking for.
    """
    mesh = Mesh()
    await mesh.enroll()
    connection = await connect(mesh, FakeCapabilityProvider(stall=True))
    try:
        running = asyncio.create_task(mesh.dispatch.run_job(job(job_id="stalled")))
        await asyncio.sleep(0.1)
        assert mesh.dispatch.active_job_ids() == ("stalled",)
        assert mesh.dispatch.session_for(mesh.node_id) is not None

        await mesh.dispatch.revoke_node(mesh.node_id, actor="jerry", reason="suspected-compromise")

        # The in-flight job does not complete; it fails because the channel it
        # was running over is gone. That is the point.
        with pytest.raises(NodeMeshError):
            await asyncio.wait_for(running, timeout=5)
        assert mesh.dispatch.active_job_ids() == ()
        assert mesh.dispatch.session_for(mesh.node_id) is None
    finally:
        await connection.aclose()


async def test_quarantining_a_node_also_stops_it_acting() -> None:
    # Reversible where revocation is not, but equally incapacitating while in
    # force.
    mesh = Mesh()
    await mesh.enroll()
    connection = await connect(mesh, FakeCapabilityProvider(stall=True))
    try:
        running = asyncio.create_task(mesh.dispatch.run_job(job(job_id="stalled")))
        await asyncio.sleep(0.1)

        await mesh.dispatch.quarantine_node(mesh.node_id, actor="jerry", reason="anomaly")

        with pytest.raises(NodeMeshError):
            await asyncio.wait_for(running, timeout=5)
        assert mesh.dispatch.active_job_ids() == ()
        assert mesh.dispatch.session_for(mesh.node_id) is None
    finally:
        await connection.aclose()


async def test_a_revoked_node_cannot_be_dispatched_to_afterwards() -> None:
    mesh = Mesh()
    await mesh.enroll()
    connection = await connect(mesh)
    try:
        await mesh.dispatch.revoke_node(mesh.node_id, actor="jerry", reason="rotation")

        with pytest.raises(NodeMeshError) as caught:
            await mesh.dispatch.run_job(job(job_id="after-revocation"))
        assert caught.value.reason in (
            NodeReason.NODE_REVOKED,
            NodeReason.DISPATCH_NO_ELIGIBLE_NODE,
        )
    finally:
        await connection.aclose()


async def test_revoking_an_unknown_node_refuses_and_touches_nothing() -> None:
    """Failing loudly beats silently tearing down whatever happens to be running."""
    mesh = Mesh()
    await mesh.enroll()
    connection = await connect(mesh, FakeCapabilityProvider(stall=True))
    try:
        running = asyncio.create_task(mesh.dispatch.run_job(job(job_id="mine")))
        await asyncio.sleep(0.1)

        with pytest.raises(NodeMeshError) as caught:
            await mesh.dispatch.revoke_node("node-that-does-not-exist", actor="jerry", reason="x")
        assert caught.value.reason is NodeReason.NODE_UNKNOWN

        assert mesh.dispatch.active_job_ids() == ("mine",)
        assert mesh.dispatch.session_for(mesh.node_id) is not None
        running.cancel()
    finally:
        await connection.aclose()


async def test_active_jobs_can_be_scoped_to_one_node() -> None:
    mesh = Mesh()
    await mesh.enroll()
    connection = await connect(mesh, FakeCapabilityProvider(stall=True))
    try:
        running = asyncio.create_task(mesh.dispatch.run_job(job(job_id="scoped")))
        await asyncio.sleep(0.1)

        assert mesh.dispatch.active_job_ids(node_id=mesh.node_id) == ("scoped",)
        assert mesh.dispatch.active_job_ids(node_id="someone-else") == ()
        running.cancel()
    finally:
        await connection.aclose()


async def test_fs_list_runs_end_to_end_under_the_read_scope(tmp_path) -> None:
    """Listing and reading share a scope: discovery reveals no more than reading.

    Wired through the agent in the same commit that enabled it, rather than
    shipping a third enabled-but-unreachable capability.
    """
    directory = tmp_path / "granted"
    directory.mkdir()
    (directory / "a.txt").write_text("a", encoding="utf-8")
    (directory / "sub").mkdir()

    mesh = Mesh(platform=NodePlatform.LINUX)
    await mesh.enroll(
        capabilities=(SYSTEM_INSPECT.name, "fs.list@1"),
        capability_scopes={"fs.list@1": {"roots": [str(directory)], "max_bytes": 4096}},
    )
    connection = await connect(mesh, providers=[], serves=("fs.list@1",))
    try:
        outcome = await mesh.dispatch.run_job(
            job(job_id="list-1", capability="fs.list@1", parameters={"path": str(directory)})
        )
        assert outcome.status is NodeJobStatus.SUCCEEDED
        names = {entry["name"] for entry in outcome.output["entries"]}
        assert names == {"a.txt", "sub"}
    finally:
        await connection.aclose()
