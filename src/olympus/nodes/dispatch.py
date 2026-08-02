import asyncio
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any

from olympus.nodes.audit import AuditAction, AuditDecision, AuditDraft
from olympus.nodes.capabilities import require_dispatchable_capability
from olympus.nodes.crypto import dedupe_key_for
from olympus.nodes.errors import NodeMeshError, NodeReason
from olympus.nodes.models import (
    TERMINAL_JOB_STATUSES,
    DispatchAuthority,
    DispatchControlState,
    NodeJobOutcome,
    NodeJobRecord,
    NodeJobStatus,
    NodeRecord,
    utc_now,
)
from olympus.nodes.protocol import MAX_PROGRESS_EVENTS_PER_JOB, JobProgressFrame
from olympus.nodes.redaction import redact_text
from olympus.nodes.registry import NodeRegistry
from olympus.nodes.session import NodeSession, ProgressCallback

MAX_RETAINED_JOB_RECORDS = 200


@dataclass(frozen=True)
class NodeJobRequest:
    """Everything a workflow needs to place one capability job on one node."""

    job_id: str
    capability: str
    authority: DispatchAuthority
    parameters: dict[str, Any] = field(default_factory=dict)
    node_id: str | None = None
    # The approval for a mutating capability, verified by the registry against a
    # digest computed from this request's own parameters.
    approval: Any | None = None
    attempt: int = 1
    deadline_seconds: int | None = None
    max_output_bytes: int | None = None

    def __post_init__(self) -> None:
        if not self.job_id.strip():
            raise ValueError("job_id must not be empty")
        if self.attempt < 1:
            raise ValueError("attempt must be strictly positive")

    @property
    def dedupe_key(self) -> str:
        return dedupe_key_for(self.job_id, self.capability, self.parameters)


class NodeDispatchService:
    """Owns live node sessions and turns workflow requests into node jobs.

    This service holds connections, not durable state. Temporal remains the sole
    owner of workflow execution state: every job here exists because a Temporal
    activity is awaiting its outcome, and every retry re-enters through the same
    dedupe key.
    """

    def __init__(self, *, registry: NodeRegistry, clock: Callable[[], datetime] = utc_now) -> None:
        self._registry = registry
        self._clock = clock
        self._sessions: dict[str, NodeSession] = {}
        self._jobs: OrderedDict[str, NodeJobRecord] = OrderedDict()
        self._lock = asyncio.Lock()

    @property
    def registry(self) -> NodeRegistry:
        return self._registry

    # -- session ownership --------------------------------------------------

    async def attach_session(self, session: NodeSession) -> None:
        """Adopt an authenticated session, displacing any previous one for that node."""
        node_id = session.node_id
        async with self._lock:
            previous = self._sessions.get(node_id)
            self._sessions[node_id] = session
        if previous is not None and previous is not session:
            await previous.shutdown(reason=NodeReason.NODE_SESSION_REPLACED.value)

    async def detach_session(self, session: NodeSession) -> None:
        """Forget a session, provided it is still the current one for its node."""
        async with self._lock:
            if self._sessions.get(session.node_id) is session:
                del self._sessions[session.node_id]

    def session_for(self, node_id: str) -> NodeSession | None:
        session = self._sessions.get(node_id)
        if session is None or session.closed:
            return None
        return session

    def connected_node_ids(self) -> tuple[str, ...]:
        return tuple(sorted(node_id for node_id, s in self._sessions.items() if not s.closed))

    # -- dispatch -----------------------------------------------------------

    async def run_job(
        self, request: NodeJobRequest, *, on_progress: ProgressCallback | None = None
    ) -> NodeJobOutcome:
        """Admit, dispatch, and await one node job, recording the audit trail."""
        descriptor = require_dispatchable_capability(request.capability)
        # Parameters and approval travel with the admission decision. Without
        # them a scoped capability can never be admitted, and a mutating one
        # would be admitted without the approval that gates it.
        record = await self._registry.select_node(
            capability=request.capability,
            node_id=request.node_id,
            parameters=request.parameters,
            approval=request.approval,
        )

        # Re-check the kill switch immediately before the frame is written so a
        # freeze that lands during admission still wins the race.
        control = await self._registry.dispatch_control()
        if control.frozen:
            await self._refuse(request, NodeReason.DISPATCH_FROZEN, node_id=record.node_id)
            raise NodeMeshError(NodeReason.DISPATCH_FROZEN, "dispatch is frozen")

        session = self.session_for(record.node_id)
        if session is None:
            await self._refuse(request, NodeReason.NODE_OFFLINE, node_id=record.node_id)
            raise NodeMeshError(NodeReason.NODE_OFFLINE, "node has no live session")

        now = self._clock()
        job = NodeJobRecord(
            job_id=request.job_id,
            node_id=record.node_id,
            capability=request.capability,
            dedupe_key=request.dedupe_key,
            status=NodeJobStatus.DISPATCHED,
            attempt=request.attempt,
            authority=request.authority,
            created_at=now,
            updated_at=now,
        )
        await self._remember(job)
        await self._registry.record_audit(
            AuditDraft(
                actor=request.authority.commander_id,
                action=AuditAction.DISPATCH_ADMITTED,
                decision=AuditDecision.ALLOW,
                node_id=record.node_id,
                job_id=request.job_id,
                payload={
                    "capability": request.capability,
                    "dedupe_key": request.dedupe_key,
                    "attempt": request.attempt,
                    "authority_lease_id": request.authority.authority_lease_id,
                },
            )
        )

        try:
            outcome = await session.dispatch_job(
                job_id=request.job_id,
                attempt=request.attempt,
                dedupe_key=request.dedupe_key,
                capability=request.capability,
                parameters=dict(request.parameters),
                deadline_seconds=request.deadline_seconds or descriptor.max_runtime_seconds,
                max_output_bytes=request.max_output_bytes or descriptor.max_output_bytes,
                max_progress_events=MAX_PROGRESS_EVENTS_PER_JOB,
                on_progress=self._progress_recorder(request.job_id, on_progress),
            )
        except NodeMeshError as exc:
            await self._update(request.job_id, status=NodeJobStatus.FAILED, reason=exc.reason.value)
            await self._registry.record_audit(
                AuditDraft(
                    actor=request.authority.commander_id,
                    action=AuditAction.DISPATCH_COMPLETED,
                    decision=AuditDecision.DENY,
                    reason=exc.reason.value,
                    node_id=record.node_id,
                    job_id=request.job_id,
                )
            )
            raise
        except asyncio.CancelledError:
            await self._update(
                request.job_id,
                status=NodeJobStatus.CANCELLED,
                reason=NodeReason.JOB_CANCELLED.value,
            )
            await self._registry.record_audit(
                AuditDraft(
                    actor=request.authority.commander_id,
                    action=AuditAction.DISPATCH_CANCELLED,
                    decision=AuditDecision.OBSERVE,
                    node_id=record.node_id,
                    job_id=request.job_id,
                )
            )
            raise

        await self._update(request.job_id, status=outcome.status, reason=outcome.reason)
        await self._registry.record_audit(
            AuditDraft(
                actor=request.authority.commander_id,
                action=AuditAction.DISPATCH_COMPLETED,
                decision=AuditDecision.ALLOW
                if outcome.status is NodeJobStatus.SUCCEEDED
                else AuditDecision.OBSERVE,
                reason=outcome.reason,
                node_id=record.node_id,
                job_id=request.job_id,
                payload={
                    "status": outcome.status.value,
                    "replayed": outcome.replayed,
                    "output_truncated": outcome.output_truncated,
                    "trust_label": outcome.trust_label.value,
                },
            )
        )
        return outcome

    def _progress_recorder(
        self, job_id: str, on_progress: ProgressCallback | None
    ) -> ProgressCallback:
        async def record(frame: JobProgressFrame) -> None:
            await self._update(
                job_id,
                status=NodeJobStatus.RUNNING,
                message=redact_text(frame.message),
                bump_progress=True,
            )
            if on_progress is not None:
                outcome = on_progress(frame)
                if outcome is not None:
                    await outcome

        return record

    async def _refuse(self, request: NodeJobRequest, reason: NodeReason, *, node_id: str) -> None:
        await self._registry.record_audit(
            AuditDraft(
                actor=request.authority.commander_id,
                action=AuditAction.DISPATCH_REFUSED,
                decision=AuditDecision.DENY,
                reason=reason.value,
                node_id=node_id,
                job_id=request.job_id,
                payload={"capability": request.capability},
            )
        )

    async def cancel_job(self, job_id: str, *, reason: str, actor: str) -> bool:
        """Signal cancellation to whichever session currently holds the job."""
        cancelled = False
        for session in list(self._sessions.values()):
            if await session.cancel_job(job_id, reason=reason):
                cancelled = True
        if cancelled:
            await self._registry.record_audit(
                AuditDraft(
                    actor=actor,
                    action=AuditAction.DISPATCH_CANCELLED,
                    decision=AuditDecision.ALLOW,
                    reason=reason,
                    job_id=job_id,
                )
            )
        return cancelled

    # -- kill switch --------------------------------------------------------

    async def freeze(self, *, actor: str, reason: str) -> DispatchControlState:
        """Freeze the mesh and stop every job already in flight."""
        control = await self._registry.freeze_dispatch(actor=actor, reason=reason)
        for job_id in self.active_job_ids():
            await self.cancel_job(job_id, reason=NodeReason.DISPATCH_FROZEN.value, actor=actor)
        return control

    # -- lifecycle that must reach the live session -------------------------

    async def revoke_node(self, node_id: str, *, actor: str, reason: str) -> NodeRecord:
        """Revoke a node and stop it doing anything it is already doing.

        Revoking only the registry record marks the node untrusted for *future*
        dispatch and leaves the present alone: the channel stays open and
        whatever it is running keeps running. For a node revoked because it is
        believed compromised, that is the opposite of what the operator asked
        for.

        Order matters. The record is revoked first so nothing new can be
        admitted while in-flight work is being torn down; cancelling first would
        leave a window in which a fresh job could be accepted.
        """
        record = await self._registry.revoke_node(node_id, actor=actor, reason=reason)
        await self._terminate(node_id, actor=actor, reason=NodeReason.NODE_REVOKED.value)
        return record

    async def quarantine_node(self, node_id: str, *, actor: str, reason: str) -> NodeRecord:
        """Quarantine a node and stop its in-flight work, same as revocation.

        Quarantine is reversible where revocation is not, but while it is in
        force the node must be equally unable to act.
        """
        record = await self._registry.quarantine_node(node_id, actor=actor, reason=reason)
        await self._terminate(node_id, actor=actor, reason=NodeReason.NODE_QUARANTINED.value)
        return record

    async def _terminate(self, node_id: str, *, actor: str, reason: str) -> None:
        for job_id in self.active_job_ids(node_id=node_id):
            await self.cancel_job(job_id, reason=reason, actor=actor)
        session = self.session_for(node_id)
        if session is not None:
            # Closing the channel is what actually removes the node's ability to
            # act. Everything before this only changes what we would agree to.
            await session.shutdown(reason=reason)

    async def unfreeze(
        self, *, actor: str, expected_freeze_epoch: int, reason: str = ""
    ) -> DispatchControlState:
        return await self._registry.unfreeze_dispatch(
            actor=actor, expected_freeze_epoch=expected_freeze_epoch, reason=reason
        )

    # -- job bookkeeping ----------------------------------------------------

    async def _remember(self, job: NodeJobRecord) -> None:
        await self._registry.upsert_job(job)
        self._jobs[job.job_id] = job
        self._jobs.move_to_end(job.job_id)
        while len(self._jobs) > MAX_RETAINED_JOB_RECORDS:
            oldest, oldest_job = next(iter(self._jobs.items()))
            if oldest_job.status not in TERMINAL_JOB_STATUSES:
                break
            del self._jobs[oldest]

    async def _update(
        self,
        job_id: str,
        *,
        status: NodeJobStatus | None = None,
        reason: str = "",
        message: str | None = None,
        bump_progress: bool = False,
    ) -> None:
        job = self._jobs.get(job_id)
        if job is None:
            return
        updated = replace(
            job,
            status=status or job.status,
            reason=reason or job.reason,
            last_message=job.last_message if message is None else message,
            progress_events=job.progress_events + (1 if bump_progress else 0),
            updated_at=self._clock(),
        )
        self._jobs[job_id] = updated
        await self._registry.upsert_job(updated)

    def jobs(self) -> tuple[NodeJobRecord, ...]:
        return tuple(reversed(list(self._jobs.values())))

    def active_job_ids(self, *, node_id: str | None = None) -> tuple[str, ...]:
        return tuple(
            job.job_id
            for job in self._jobs.values()
            if job.status not in TERMINAL_JOB_STATUSES
            and (node_id is None or job.node_id == node_id)
        )
