import asyncio
import base64
import contextlib
import hashlib
import platform
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from olympus.node_agent.capabilities import (
    CapabilityArtifact,
    CapabilityProvider,
    CapabilityRequest,
    CapabilityResult,
)
from olympus.nodes.channel import ChannelClosed, NodeChannel
from olympus.nodes.crypto import digest_of, random_nonce, sign_payload, verify_payload
from olympus.nodes.errors import NodeMeshError, NodeReason
from olympus.nodes.protocol import (
    MAX_ARTIFACT_BYTES,
    MAX_ARTIFACTS_PER_JOB,
    PROTOCOL_ID,
    AttestFrame,
    ChallengeFrame,
    ClientFrame,
    HeartbeatFrame,
    HelloFrame,
    JobAckFrame,
    JobArtifactFrame,
    JobDispatchFrame,
    JobProgressFrame,
    JobResultFrame,
    NodeHealthReport,
    ResumeState,
    ServerFrame,
    SessionReadyFrame,
    encode_frame,
    node_proof_payload,
    parse_server_frame,
    server_proof_payload,
)
from olympus.nodes.redaction import bound_output, redact_and_bound

AGENT_VERSION = "0.1.0"
LEDGER_CAPACITY = 64
_OUTBOX_CAPACITY = 256


@dataclass(frozen=True)
class AgentIdentity:
    """Enrolled node identity. The private key is generated and stays on the node."""

    node_id: str
    node_name: str
    private_key: str
    control_plane_public_key: str
    control_plane_key_id: str
    agent_version: str = AGENT_VERSION

    def __post_init__(self) -> None:
        for name, value in (
            ("node_id", self.node_id),
            ("private_key", self.private_key),
            ("control_plane_public_key", self.control_plane_public_key),
        ):
            if type(value) is not str or not value.strip():
                raise ValueError(f"agent identity requires {name}")


@dataclass
class _RunningJob:
    dedupe_key: str
    task: asyncio.Task[None] | None = None
    waiters: list[tuple[str, int]] = field(default_factory=list)


class _ResultLedger:
    """Bounded record of terminal results, keyed by dedupe key.

    This is what makes re-dispatch safe: a retried or replayed job returns the
    recorded outcome instead of running the work a second time.
    """

    def __init__(self, capacity: int = LEDGER_CAPACITY) -> None:
        self._capacity = capacity
        self._entries: OrderedDict[str, JobResultFrame] = OrderedDict()

    def get(self, dedupe_key: str) -> JobResultFrame | None:
        entry = self._entries.get(dedupe_key)
        if entry is not None:
            self._entries.move_to_end(dedupe_key)
        return entry

    def put(self, dedupe_key: str, frame: JobResultFrame) -> None:
        self._entries[dedupe_key] = frame
        self._entries.move_to_end(dedupe_key)
        while len(self._entries) > self._capacity:
            self._entries.popitem(last=False)

    def keys(self) -> tuple[str, ...]:
        return tuple(self._entries.keys())


class NodeAgent:
    """Node end of ``olympus-node/1``.

    The agent dials out, verifies the control plane before proving its own
    identity, then serves bounded capability jobs. It opens no listening socket
    and executes nothing outside its registered capability providers.
    """

    def __init__(
        self,
        *,
        identity: AgentIdentity,
        providers: Sequence[CapabilityProvider],
        node_platform: str | None = None,
        architecture: str | None = None,
        ledger_capacity: int = LEDGER_CAPACITY,
    ) -> None:
        self.identity = identity
        self._providers: dict[str, CapabilityProvider] = {}
        for provider in providers:
            for capability in provider.capabilities:
                self._providers[capability] = provider
        self.node_platform = node_platform or platform.system().lower()
        self.architecture = architecture or platform.machine() or "unknown"
        self._ledger = _ResultLedger(ledger_capacity)
        self._running: dict[str, _RunningJob] = {}
        self._jobs_by_id: dict[str, str] = {}
        self._outbox: asyncio.Queue[str | None] = asyncio.Queue(maxsize=_OUTBOX_CAPACITY)
        self._stop = asyncio.Event()
        self._started_at = time.monotonic()
        self._heartbeat_sequence = 0
        self.session: SessionReadyFrame | None = None
        self.granted_capabilities: tuple[str, ...] = ()

    @property
    def declared_capabilities(self) -> tuple[str, ...]:
        return tuple(sorted(self._providers))

    @property
    def active_jobs(self) -> int:
        return len(self._running)

    def _enqueue(self, frame: ClientFrame) -> bool:
        """Queue a frame without blocking; report whether it will actually be sent."""
        try:
            self._outbox.put_nowait(encode_frame(frame))
        except (asyncio.QueueFull, NodeMeshError):
            return False
        return True

    async def run(
        self, channel: NodeChannel, *, on_ready: Callable[[SessionReadyFrame], None] | None = None
    ) -> None:
        """Complete the handshake and serve jobs until the channel closes."""
        self._stop = asyncio.Event()
        ready = await self.handshake(channel)
        if on_ready is not None:
            on_ready(ready)
        sender = asyncio.create_task(self._sender_loop(channel))
        heartbeat = asyncio.create_task(self._heartbeat_loop())
        try:
            await self._receive_loop(channel)
        finally:
            self._stop.set()
            for job in list(self._running.values()):
                if job.task is not None:
                    job.task.cancel()
            heartbeat.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await heartbeat
            with contextlib.suppress(asyncio.QueueFull):
                self._outbox.put_nowait(None)
            with contextlib.suppress(asyncio.CancelledError, ChannelClosed):
                await sender

    async def handshake(self, channel: NodeChannel) -> SessionReadyFrame:
        """Verify the control plane, prove node identity, and read the session terms."""
        node_nonce = random_nonce()
        declared = self.declared_capabilities
        await channel.send(
            encode_frame(
                HelloFrame(
                    protocol=PROTOCOL_ID,
                    node_id=self.identity.node_id,
                    agent_version=self.identity.agent_version,
                    platform=self.node_platform,
                    architecture=self.architecture,
                    declared_capabilities=declared,
                    node_nonce=node_nonce,
                    resume=ResumeState(
                        completed_dedupe_keys=self._ledger.keys(),
                        running_dedupe_keys=tuple(self._running),
                    ),
                )
            )
        )
        challenge = parse_server_frame(await channel.receive())
        if not isinstance(challenge, ChallengeFrame):
            raise NodeMeshError(NodeReason.HANDSHAKE_FRAME_UNEXPECTED, "expected a challenge frame")
        if challenge.protocol != PROTOCOL_ID:
            raise NodeMeshError(
                NodeReason.PROTOCOL_VERSION_UNSUPPORTED, "unsupported protocol version"
            )
        if challenge.control_plane_key_id != self.identity.control_plane_key_id:
            raise NodeMeshError(NodeReason.SERVER_PROOF_INVALID, "unexpected control-plane key")
        verify_payload(
            self.identity.control_plane_public_key,
            server_proof_payload(
                protocol=PROTOCOL_ID,
                session_id=challenge.session_id,
                node_id=self.identity.node_id,
                node_nonce=node_nonce,
            ),
            challenge.server_proof,
            NodeReason.SERVER_PROOF_INVALID,
        )
        await channel.send(
            encode_frame(
                AttestFrame(
                    session_id=challenge.session_id,
                    node_proof=sign_payload(
                        self.identity.private_key,
                        node_proof_payload(
                            protocol=PROTOCOL_ID,
                            session_id=challenge.session_id,
                            node_id=self.identity.node_id,
                            server_nonce=challenge.server_nonce,
                            capabilities_digest=digest_of(list(declared)),
                        ),
                    ),
                )
            )
        )
        ready = parse_server_frame(await channel.receive())
        if not isinstance(ready, SessionReadyFrame):
            raise NodeMeshError(NodeReason.HANDSHAKE_FRAME_UNEXPECTED, "expected session-ready")
        self.session = ready
        self.granted_capabilities = ready.granted_capabilities
        return ready

    async def _sender_loop(self, channel: NodeChannel) -> None:
        while True:
            payload = await self._outbox.get()
            if payload is None:
                return
            try:
                await channel.send(payload)
            except ChannelClosed:
                return

    async def _heartbeat_loop(self) -> None:
        interval = self.session.heartbeat_interval_seconds if self.session else 15
        while not self._stop.is_set():
            self._heartbeat_sequence += 1
            self._enqueue(HeartbeatFrame(sequence=self._heartbeat_sequence, health=self._health()))
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(interval):
                    await self._stop.wait()

    def _health(self) -> NodeHealthReport:
        return NodeHealthReport(
            active_jobs=self.active_jobs,
            agent_uptime_seconds=int(time.monotonic() - self._started_at),
        )

    async def _receive_loop(self, channel: NodeChannel) -> None:
        while not self._stop.is_set():
            try:
                frame = parse_server_frame(await channel.receive())
            except ChannelClosed:
                return
            await self._handle(frame)

    async def _handle(self, frame: ServerFrame) -> None:
        if frame.type == "job-dispatch":
            await self._accept_job(frame)
            return
        if frame.type == "job-cancel":
            dedupe_key = self._jobs_by_id.get(frame.job_id)
            running = self._running.get(dedupe_key) if dedupe_key else None
            if running is not None and running.task is not None:
                running.task.cancel()
            return
        if frame.type == "session-close":
            self._stop.set()
            return

    async def _accept_job(self, frame: JobDispatchFrame) -> None:
        if frame.capability not in self._providers or frame.capability not in set(
            self.granted_capabilities
        ):
            self._enqueue(
                JobAckFrame(
                    job_id=frame.job_id,
                    attempt=frame.attempt,
                    accepted=False,
                    reason=NodeReason.CAPABILITY_NOT_GRANTED.value,
                )
            )
            self._enqueue(
                self._result_frame(
                    frame,
                    status="rejected",
                    reason=NodeReason.CAPABILITY_NOT_GRANTED.value,
                    message="capability is not available on this node",
                )
            )
            return

        cached = self._ledger.get(frame.dedupe_key)
        if cached is not None:
            self._enqueue(
                JobAckFrame(
                    job_id=frame.job_id, attempt=frame.attempt, accepted=True, duplicate=True
                )
            )
            self._enqueue(
                cached.model_copy(
                    update={"job_id": frame.job_id, "attempt": frame.attempt, "replayed": True}
                )
            )
            return

        running = self._running.get(frame.dedupe_key)
        if running is not None:
            running.waiters.append((frame.job_id, frame.attempt))
            self._jobs_by_id[frame.job_id] = frame.dedupe_key
            self._enqueue(
                JobAckFrame(
                    job_id=frame.job_id, attempt=frame.attempt, accepted=True, duplicate=True
                )
            )
            return

        self._enqueue(JobAckFrame(job_id=frame.job_id, attempt=frame.attempt, accepted=True))
        job = _RunningJob(dedupe_key=frame.dedupe_key, waiters=[(frame.job_id, frame.attempt)])
        self._running[frame.dedupe_key] = job
        self._jobs_by_id[frame.job_id] = frame.dedupe_key
        job.task = asyncio.create_task(self._run_job(frame, job))

    async def _run_job(self, frame: JobDispatchFrame, job: _RunningJob) -> None:
        provider = self._providers[frame.capability]
        emitted = 0
        started_at = datetime.now(UTC).isoformat()

        async def report(message: str, percent: int | None) -> None:
            nonlocal emitted
            if emitted >= frame.max_progress_events:
                return
            self._enqueue(
                JobProgressFrame(
                    job_id=frame.job_id,
                    attempt=frame.attempt,
                    sequence=emitted,
                    percent=percent,
                    message=redact_and_bound(message, 480)[0],
                )
            )
            emitted += 1

        request = CapabilityRequest(
            job_id=frame.job_id,
            capability=frame.capability,
            parameters=dict(frame.parameters),
            deadline_seconds=frame.deadline_seconds,
            max_output_bytes=frame.max_output_bytes,
        )
        status = "failed"
        reason = NodeReason.JOB_FAILED.value
        message = ""
        result: CapabilityResult | None = None
        try:
            async with asyncio.timeout(frame.deadline_seconds):
                result = await provider.execute(request, report)
            status, reason, message = result.status, result.reason, result.message
        except TimeoutError:
            reason = NodeReason.JOB_DEADLINE_EXCEEDED.value
            message = "capability exceeded its deadline"
        except asyncio.CancelledError:
            status = "cancelled"
            reason = NodeReason.JOB_CANCELLED.value
            message = "capability cancelled by the control plane"
        except Exception as exc:  # noqa: BLE001 - provider faults become typed failures
            reason = NodeReason.JOB_FAILED.value
            message = redact_and_bound(f"{type(exc).__name__}: {exc}", 480)[0]

        output, truncated = bound_output(
            dict(result.output) if result is not None else {}, frame.max_output_bytes
        )
        artifact_ids = self._emit_artifacts(frame, result)
        terminal = JobResultFrame(
            job_id=frame.job_id,
            attempt=frame.attempt,
            dedupe_key=frame.dedupe_key,
            status=status,  # type: ignore[arg-type]  # provider statuses match the literal union
            output=output,
            output_truncated=truncated,
            artifact_ids=artifact_ids,
            reason=reason if status != "succeeded" else "",
            message=redact_and_bound(message, 480)[0],
            started_at=started_at,
            finished_at=datetime.now(UTC).isoformat(),
        )
        if status != "cancelled":
            self._ledger.put(frame.dedupe_key, terminal)
        self._running.pop(frame.dedupe_key, None)
        for job_id, attempt in job.waiters:
            self._jobs_by_id.pop(job_id, None)
            self._enqueue(terminal.model_copy(update={"job_id": job_id, "attempt": attempt}))

    def _emit_artifacts(
        self, frame: JobDispatchFrame, result: CapabilityResult | None
    ) -> tuple[str, ...]:
        if result is None or not result.artifacts:
            return ()
        emitted: list[str] = []
        for artifact in result.artifacts[:MAX_ARTIFACTS_PER_JOB]:
            encoded = base64.b64encode(artifact.data).decode("ascii")
            if len(encoded) > MAX_ARTIFACT_BYTES:
                continue
            # Only advertise an artifact the control plane will actually receive.
            if self._enqueue(_artifact_frame(frame, artifact, encoded)):
                emitted.append(artifact.artifact_id)
        return tuple(emitted)

    def _result_frame(
        self, frame: JobDispatchFrame, *, status: str, reason: str, message: str
    ) -> JobResultFrame:
        now = datetime.now(UTC).isoformat()
        return JobResultFrame(
            job_id=frame.job_id,
            attempt=frame.attempt,
            dedupe_key=frame.dedupe_key,
            status=status,  # type: ignore[arg-type]  # callers pass literal union members
            reason=reason,
            message=message,
            started_at=now,
            finished_at=now,
        )


def _artifact_frame(
    frame: JobDispatchFrame, artifact: CapabilityArtifact, encoded: str
) -> JobArtifactFrame:
    return JobArtifactFrame(
        job_id=frame.job_id,
        attempt=frame.attempt,
        artifact_id=artifact.artifact_id,
        kind=artifact.kind,
        media_type=artifact.media_type,
        sha256=hashlib.sha256(artifact.data).hexdigest(),
        data=encoded,
    )
