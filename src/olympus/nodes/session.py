import asyncio
import contextlib
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from olympus.contracts.commands import TrustLabel
from olympus.nodes.channel import (
    CLOSE_NORMAL,
    CLOSE_POLICY_VIOLATION,
    ChannelClosed,
    NodeChannel,
)
from olympus.nodes.crypto import digest_of, random_nonce, sign_payload, verify_payload
from olympus.nodes.errors import NodeMeshError, NodeReason
from olympus.nodes.models import (
    NodeHealthSnapshot,
    NodeJobOutcome,
    NodeJobStatus,
    NodeRecord,
    utc_now,
)
from olympus.nodes.protocol import (
    DEFAULT_HANDSHAKE_TIMEOUT_SECONDS,
    MAX_ARTIFACTS_PER_JOB,
    MAX_CONCURRENT_JOBS_PER_NODE,
    MAX_FRAME_BYTES,
    PROTOCOL_ID,
    SUPPORTED_PROTOCOL_IDS,
    ChallengeFrame,
    ClientFrame,
    HelloFrame,
    JobArtifactFrame,
    JobCancelFrame,
    JobDispatchFrame,
    JobProgressFrame,
    JobResultFrame,
    ServerFrame,
    SessionCloseFrame,
    SessionReadyFrame,
    encode_frame,
    node_proof_payload,
    parse_client_frame,
    server_proof_payload,
)
from olympus.nodes.redaction import bound_output, redact_text
from olympus.nodes.registry import NodeRegistry

ProgressCallback = Callable[[JobProgressFrame], Awaitable[None] | None]

_ACK_TIMEOUT_SECONDS = 10


@dataclass
class _PendingJob:
    job_id: str
    attempt: int
    dedupe_key: str
    capability: str
    deadline_seconds: int
    max_output_bytes: int
    max_progress_events: int
    acknowledged: asyncio.Event = field(default_factory=asyncio.Event)
    result: asyncio.Future[JobResultFrame] = field(default_factory=asyncio.Future)
    duplicate: bool = False
    progress_events: int = 0
    progress_events_dropped: int = 0
    progress_delivery_failures: int = 0
    artifact_ids: list[str] = field(default_factory=list)
    on_progress: ProgressCallback | None = None


@dataclass(frozen=True)
class SessionLimits:
    heartbeat_interval_seconds: int
    heartbeat_expiry_seconds: int
    max_frame_bytes: int = MAX_FRAME_BYTES
    max_concurrent_jobs: int = MAX_CONCURRENT_JOBS_PER_NODE


class NodeSession:
    """Control-plane end of one authenticated node connection.

    A session never dials out: the node connected here. The session owns frame
    routing for its channel, and hands terminal job outcomes back to whichever
    Temporal activity is awaiting them.
    """

    def __init__(
        self,
        *,
        channel: NodeChannel,
        registry: NodeRegistry,
        control_plane_private_key: str,
        control_plane_key_id: str,
        clock: Callable[[], datetime] = utc_now,
        handshake_timeout_seconds: int = DEFAULT_HANDSHAKE_TIMEOUT_SECONDS,
    ) -> None:
        self._channel = channel
        self._registry = registry
        self._private_key = control_plane_private_key
        self._key_id = control_plane_key_id
        self._clock = clock
        self._handshake_timeout_seconds = handshake_timeout_seconds
        self._pending: dict[str, _PendingJob] = {}
        self._closed = asyncio.Event()
        self.session_id = f"nsx-{uuid.uuid4()}"
        self.node: NodeRecord | None = None
        self.limits = SessionLimits(
            heartbeat_interval_seconds=registry.heartbeat_interval_seconds,
            heartbeat_expiry_seconds=registry.heartbeat_expiry_seconds,
        )
        self.heartbeats_received = 0

    @property
    def node_id(self) -> str:
        if self.node is None:
            raise NodeMeshError(NodeReason.SESSION_CLOSED, "session is not authenticated")
        return self.node.node_id

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    @property
    def active_job_count(self) -> int:
        return len(self._pending)

    async def _send(self, frame: ServerFrame) -> None:
        await self._channel.send(encode_frame(frame))

    async def _receive(self) -> ClientFrame:
        return parse_client_frame(await self._channel.receive())

    async def handshake(self) -> NodeRecord:
        """Authenticate both directions and bind the session to its node record."""
        try:
            async with asyncio.timeout(self._handshake_timeout_seconds):
                return await self._handshake()
        except TimeoutError as exc:
            await self._refuse(NodeReason.HANDSHAKE_TIMEOUT)
            raise NodeMeshError(NodeReason.HANDSHAKE_TIMEOUT, "handshake timed out") from exc
        except NodeMeshError as exc:
            await self._refuse(exc.reason)
            raise

    async def _handshake(self) -> NodeRecord:
        hello = await self._receive()
        if not isinstance(hello, HelloFrame):
            raise NodeMeshError(NodeReason.HANDSHAKE_FRAME_UNEXPECTED, "expected a hello frame")
        if hello.protocol not in SUPPORTED_PROTOCOL_IDS:
            raise NodeMeshError(
                NodeReason.PROTOCOL_VERSION_UNSUPPORTED, "unsupported protocol version"
            )

        record = await self._registry.get_node(hello.node_id)
        if record.revoked_at is not None:
            raise NodeMeshError(NodeReason.NODE_REVOKED, "node is revoked")

        server_nonce = random_nonce()
        proof = sign_payload(
            self._private_key,
            server_proof_payload(
                protocol=PROTOCOL_ID,
                session_id=self.session_id,
                node_id=record.node_id,
                node_nonce=hello.node_nonce,
            ),
        )
        await self._send(
            ChallengeFrame(
                protocol=PROTOCOL_ID,
                session_id=self.session_id,
                server_nonce=server_nonce,
                control_plane_key_id=self._key_id,
                server_proof=proof,
            )
        )

        attest = await self._receive()
        if attest.type != "attest":
            raise NodeMeshError(NodeReason.HANDSHAKE_FRAME_UNEXPECTED, "expected an attest frame")
        if attest.session_id != self.session_id:
            raise NodeMeshError(NodeReason.NONCE_INVALID, "attestation names another session")
        verify_payload(
            record.public_key,
            node_proof_payload(
                protocol=PROTOCOL_ID,
                session_id=self.session_id,
                node_id=record.node_id,
                server_nonce=server_nonce,
                capabilities_digest=digest_of(list(hello.declared_capabilities)),
            ),
            attest.node_proof,
            NodeReason.NODE_PROOF_INVALID,
        )

        attached = await self._registry.attach_session(
            node_id=record.node_id,
            session_id=self.session_id,
            declared_capabilities=hello.declared_capabilities,
            agent_version=hello.agent_version,
            architecture=hello.architecture,
        )
        self.node = attached
        await self._send(
            SessionReadyFrame(
                session_id=self.session_id,
                granted_capabilities=self._registry.effective_capabilities(attached),
                heartbeat_interval_seconds=self.limits.heartbeat_interval_seconds,
                heartbeat_expiry_seconds=self.limits.heartbeat_expiry_seconds,
                max_frame_bytes=self.limits.max_frame_bytes,
                max_concurrent_jobs=self.limits.max_concurrent_jobs,
                server_time=self._clock().isoformat(),
            )
        )
        return attached

    async def _refuse(self, reason: NodeReason) -> None:
        """Close on a protocol violation with the same teardown as a lost socket.

        Latching ``_closed`` here without the rest of the teardown would orphan
        every job waiting on this session and leave the registry believing the
        node is still connected, so the full shutdown runs on this path too.
        """
        with contextlib.suppress(ChannelClosed, NodeMeshError):
            await self._send(SessionCloseFrame(reason=reason.value))
        await self.shutdown(reason=reason.value, code=CLOSE_POLICY_VIOLATION)

    async def pump(self) -> None:
        """Route inbound frames until the channel closes or a bound is violated."""
        try:
            while not self._closed.is_set():
                frame = await self._receive()
                await self._handle(frame)
        except ChannelClosed:
            pass
        except NodeMeshError as exc:
            await self._refuse(exc.reason)
        finally:
            await self.shutdown(reason=NodeReason.SESSION_CLOSED.value)

    async def _handle(self, frame: ClientFrame) -> None:
        if frame.type == "heartbeat":
            self.heartbeats_received += 1
            await self._registry.record_heartbeat(
                node_id=self.node_id,
                session_id=self.session_id,
                health=NodeHealthSnapshot(
                    reported_at=self._clock(),
                    active_jobs=frame.health.active_jobs,
                    cpu_count=frame.health.cpu_count,
                    load_average_1m=frame.health.load_average_1m,
                    memory_total_mib=frame.health.memory_total_mib,
                    memory_available_mib=frame.health.memory_available_mib,
                    uptime_seconds=frame.health.uptime_seconds,
                    agent_uptime_seconds=frame.health.agent_uptime_seconds,
                ),
            )
            return
        if frame.type == "job-ack":
            pending = self._pending.get(frame.job_id)
            if pending is not None and pending.attempt == frame.attempt:
                pending.duplicate = frame.duplicate
                pending.acknowledged.set()
            return
        if frame.type == "job-progress":
            await self._handle_progress(frame)
            return
        if frame.type == "job-artifact":
            pending = self._pending.get(frame.job_id)
            if (
                pending is not None
                and pending.attempt == frame.attempt
                and len(pending.artifact_ids) < MAX_ARTIFACTS_PER_JOB
            ):
                pending.artifact_ids.append(frame.artifact_id)
            return
        if frame.type == "job-result":
            pending = self._pending.get(frame.job_id)
            # A node may only terminate the exact attempt and content identity it
            # was given. Anything else is discarded rather than trusted.
            if (
                pending is not None
                and pending.attempt == frame.attempt
                and pending.dedupe_key == frame.dedupe_key
                and not pending.result.done()
            ):
                pending.acknowledged.set()
                pending.result.set_result(frame)
            return
        raise NodeMeshError(NodeReason.FRAME_UNEXPECTED, "unexpected frame for an open session")

    async def _handle_progress(self, frame: JobProgressFrame) -> None:
        pending = self._pending.get(frame.job_id)
        if pending is None or pending.attempt != frame.attempt:
            return
        if pending.progress_events >= pending.max_progress_events:
            # The bound belongs on this end: a compromised node must not be able
            # to drive unbounded control-plane and Temporal work.
            pending.progress_events_dropped += 1
            return
        pending.progress_events += 1
        if pending.on_progress is None:
            return
        # Progress delivery is best effort. A failing consumer must never tear
        # down the connection that other jobs on this node depend on.
        try:
            outcome = pending.on_progress(frame)
            if outcome is not None:
                await outcome
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - consumer faults are isolated from the session
            pending.progress_delivery_failures += 1

    async def dispatch_job(
        self,
        *,
        job_id: str,
        attempt: int,
        dedupe_key: str,
        capability: str,
        parameters: dict[str, Any],
        deadline_seconds: int,
        max_output_bytes: int,
        max_progress_events: int,
        on_progress: ProgressCallback | None = None,
    ) -> NodeJobOutcome:
        """Send one job to this node and await its terminal frame."""
        if self.closed:
            raise NodeMeshError(NodeReason.SESSION_CLOSED, "session is closed")
        if job_id in self._pending:
            raise NodeMeshError(NodeReason.DISPATCH_DUPLICATE, "job is already in flight")
        if len(self._pending) >= self.limits.max_concurrent_jobs:
            raise NodeMeshError(
                NodeReason.DISPATCH_CONCURRENCY_EXCEEDED, "node concurrency bound reached"
            )

        pending = _PendingJob(
            job_id=job_id,
            attempt=attempt,
            dedupe_key=dedupe_key,
            capability=capability,
            deadline_seconds=deadline_seconds,
            max_output_bytes=max_output_bytes,
            max_progress_events=max_progress_events,
            on_progress=on_progress,
        )
        self._pending[job_id] = pending
        try:
            await self._send(
                JobDispatchFrame(
                    job_id=job_id,
                    attempt=attempt,
                    dedupe_key=dedupe_key,
                    capability=capability,
                    parameters=parameters,
                    deadline_seconds=deadline_seconds,
                    max_output_bytes=max_output_bytes,
                    max_progress_events=max_progress_events,
                    issued_at=self._clock().isoformat(),
                )
            )
            await self._await_ack(pending)
            return await self._await_result(pending)
        except ChannelClosed as exc:
            raise NodeMeshError(NodeReason.SESSION_CLOSED, "session closed mid-dispatch") from exc
        finally:
            self._pending.pop(job_id, None)

    async def _await_ack(self, pending: _PendingJob) -> None:
        try:
            async with asyncio.timeout(_ACK_TIMEOUT_SECONDS):
                await pending.acknowledged.wait()
        except TimeoutError as exc:
            raise NodeMeshError(
                NodeReason.NODE_OFFLINE, "node did not acknowledge dispatch"
            ) from exc

    async def _await_result(self, pending: _PendingJob) -> NodeJobOutcome:
        try:
            async with asyncio.timeout(pending.deadline_seconds):
                frame = await pending.result
        except TimeoutError as exc:
            with contextlib.suppress(ChannelClosed, NodeMeshError):
                await self._send(
                    JobCancelFrame(
                        job_id=pending.job_id,
                        attempt=pending.attempt,
                        reason=NodeReason.JOB_DEADLINE_EXCEEDED.value,
                    )
                )
            raise NodeMeshError(
                NodeReason.JOB_DEADLINE_EXCEEDED, "node job exceeded its deadline"
            ) from exc
        except asyncio.CancelledError:
            with contextlib.suppress(ChannelClosed, NodeMeshError):
                await self._send(
                    JobCancelFrame(
                        job_id=pending.job_id,
                        attempt=pending.attempt,
                        reason=NodeReason.JOB_CANCELLED.value,
                    )
                )
            raise
        return self._outcome_of(frame, pending)

    def _outcome_of(self, frame: JobResultFrame, pending: _PendingJob) -> NodeJobOutcome:
        output, truncated_here = bound_output(dict(frame.output), pending.max_output_bytes)
        return NodeJobOutcome(
            job_id=pending.job_id,
            node_id=self.node_id,
            capability=pending.capability,
            dedupe_key=pending.dedupe_key,
            status=NodeJobStatus(frame.status),
            attempt=pending.attempt,
            output=output,
            output_truncated=frame.output_truncated or truncated_here,
            artifact_ids=tuple(pending.artifact_ids) or frame.artifact_ids,
            reason=frame.reason,
            message=redact_text(frame.message),
            replayed=frame.replayed,
            trust_label=TrustLabel.EXTERNAL_UNTRUSTED,
        )

    async def cancel_job(self, job_id: str, *, reason: str) -> bool:
        """Ask the node to stop a job. The node still returns a terminal frame."""
        pending = self._pending.get(job_id)
        if pending is None:
            return False
        with contextlib.suppress(ChannelClosed, NodeMeshError):
            await self._send(JobCancelFrame(job_id=job_id, attempt=pending.attempt, reason=reason))
        return True

    async def shutdown(self, *, reason: str = "", code: int = CLOSE_NORMAL) -> None:
        """Close the channel and fail every job still waiting on this session."""
        if self._closed.is_set():
            return
        self._closed.set()
        for pending in list(self._pending.values()):
            if not pending.result.done():
                pending.result.set_exception(
                    NodeMeshError(NodeReason.SESSION_CLOSED, "session closed before completion")
                )
            pending.acknowledged.set()
        if self.node is not None:
            await self._registry.detach_session(
                node_id=self.node.node_id, session_id=self.session_id, reason=reason
            )
        with contextlib.suppress(ChannelClosed):
            await self._channel.close(code=code, reason=reason)


def artifact_digest_matches(frame: JobArtifactFrame, expected_sha256: str) -> bool:
    """Compare a streamed artifact against the digest the node declared."""
    return frame.sha256 == expected_sha256
