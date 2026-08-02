import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any

from olympus.nodes.audit import (
    AuditAction,
    AuditDecision,
    AuditDraft,
    NodeAuditEvent,
)
from olympus.nodes.capabilities import (
    normalize_capability_names,
    require_dispatchable_capability,
)
from olympus.nodes.crypto import (
    enrollment_secret_matches,
    load_public_key,
    new_enrollment_secret,
    split_enrollment_token,
)
from olympus.nodes.errors import NodeMeshError, NodeReason
from olympus.nodes.models import (
    TERMINAL_JOB_STATUSES,
    DispatchControlState,
    EnrollmentTokenRecord,
    NodeHealthSnapshot,
    NodeJobRecord,
    NodeJobStatus,
    NodeKind,
    NodePlatform,
    NodeRecord,
    NodeState,
    NodeView,
    utc_now,
)
from olympus.nodes.protocol import (
    DEFAULT_HEARTBEAT_EXPIRY_SECONDS,
    DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
)
from olympus.nodes.scopes import (
    FILE_READ,
    FILE_WRITE,
    ApprovalVerifier,
    FileReadScope,
    FileWriteScope,
    assert_scoped_dispatch,
    expected_action_digest,
    parse_scopes,
    requires_approval,
    requires_scope,
)
from olympus.nodes.store import InMemoryNodeMeshStore, NodeMeshStore, NodeMeshTransaction

DEFAULT_ENROLLMENT_TTL_SECONDS = 900
MAX_ENROLLMENT_TTL_SECONDS = 3600
MIN_ENROLLMENT_TTL_SECONDS = 60
MAX_LABELS = 16

RESTART_REASON = "control-plane-restart"


@dataclass(frozen=True)
class NodeDescription:
    """Self-description a node presents at enrollment. Untrusted input."""

    node_name: str
    kind: NodeKind
    platform: NodePlatform
    architecture: str
    agent_version: str
    declared_capabilities: tuple[str, ...] = ()
    labels: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        for name, value in (
            ("node_name", self.node_name),
            ("architecture", self.architecture),
            ("agent_version", self.agent_version),
        ):
            if type(value) is not str or not value.strip():
                raise NodeMeshError(
                    NodeReason.ENROLLMENT_DESCRIPTION_INVALID, f"{name} must not be empty"
                )
        if len(self.labels) > MAX_LABELS:
            raise NodeMeshError(NodeReason.ENROLLMENT_DESCRIPTION_INVALID, "too many node labels")


@dataclass(frozen=True)
class IssuedEnrollment:
    """Enrollment material returned once to the operator and never stored."""

    token_id: str
    presented: str
    node_name: str
    kind: NodeKind
    platform: NodePlatform
    granted_capabilities: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class RecoveryReport:
    """What restart recovery changed, so an operator can see it in one line."""

    sessions_cleared: tuple[str, ...] = ()
    jobs_reconciled: tuple[str, ...] = ()
    frozen: bool = False
    freeze_epoch: int = 0

    @property
    def changed(self) -> bool:
        return bool(self.sessions_cleared or self.jobs_reconciled)


class NodeRegistry:
    """Canonical owner of node identity, capability grants, and dispatch admission."""

    def __init__(
        self,
        *,
        store: NodeMeshStore | None = None,
        approvals: ApprovalVerifier | None = None,
        clock: Callable[[], datetime] = utc_now,
        heartbeat_interval_seconds: int = DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
        heartbeat_expiry_seconds: int = DEFAULT_HEARTBEAT_EXPIRY_SECONDS,
        enrollment_ttl_seconds: int = DEFAULT_ENROLLMENT_TTL_SECONDS,
    ) -> None:
        if heartbeat_expiry_seconds <= heartbeat_interval_seconds:
            raise ValueError("heartbeat expiry must exceed the heartbeat interval")
        self._store: NodeMeshStore = store or InMemoryNodeMeshStore(clock=clock)
        # Absent by default. A mesh that never dispatches a mutating capability
        # needs no verifier, and one that does refuses until it is given one.
        self._approvals: ApprovalVerifier | None = approvals
        self._clock = clock
        self.heartbeat_interval_seconds = heartbeat_interval_seconds
        self.heartbeat_expiry_seconds = heartbeat_expiry_seconds
        self.enrollment_ttl_seconds = enrollment_ttl_seconds

    @property
    def store(self) -> NodeMeshStore:
        return self._store

    def now(self) -> datetime:
        """Read the registry clock so derived views share one instant."""
        return self._clock()

    # -- audit --------------------------------------------------------------

    async def audit_events(self) -> tuple[NodeAuditEvent, ...]:
        return await self._store.audit_events()

    async def audit_head(self) -> str:
        return await self._store.audit_head()

    async def verify_audit(self) -> bool:
        return await self._store.verify_audit_chain()

    async def record_audit(self, draft: AuditDraft) -> None:
        """Append a standalone audit event that changes no other state."""
        async with self._store.transaction() as tx:
            await tx.append_audit(draft)

    # -- enrollment ---------------------------------------------------------

    async def issue_enrollment_token(
        self,
        *,
        node_name: str,
        kind: NodeKind,
        platform: NodePlatform,
        granted_capabilities: Sequence[str],
        issued_by: str,
        ttl_seconds: int | None = None,
        capability_scopes: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> IssuedEnrollment:
        """Mint one single-use enrollment token bound to a node name and grant."""
        if not node_name.strip():
            raise NodeMeshError(NodeReason.ENROLLMENT_SCOPE_MISMATCH, "node_name must not be empty")
        ttl = self.enrollment_ttl_seconds if ttl_seconds is None else ttl_seconds
        if not MIN_ENROLLMENT_TTL_SECONDS <= ttl <= MAX_ENROLLMENT_TTL_SECONDS:
            raise NodeMeshError(
                NodeReason.ENROLLMENT_SCOPE_MISMATCH,
                "enrollment lifetime is outside the permitted range",
            )
        grants = tuple(sorted({name for name in granted_capabilities}))
        for name in grants:
            require_dispatchable_capability(name)

        # Validate scopes at mint time, not at dispatch time. A malformed scope
        # discovered when the operator is trying to run a job is a scope that
        # already shipped; discovered here, it is a refused token.
        scopes = _encode_scopes(capability_scopes or {}, platform=platform)
        for name in grants:
            if requires_scope(name) and name not in dict(scopes):
                raise NodeMeshError(
                    NodeReason.CAPABILITY_NOT_GRANTED,
                    f"{name} cannot be granted without a scope; "
                    "an unscoped grant of this capability would be unbounded",
                )

        issued_at = self._clock()
        secret = new_enrollment_secret()
        record = EnrollmentTokenRecord(
            token_id=secret.token_id,
            secret_hash=secret.secret_hash,
            node_name=node_name.strip(),
            kind=kind,
            platform=platform,
            granted_capabilities=grants,
            issued_at=issued_at,
            expires_at=issued_at + timedelta(seconds=ttl),
            issued_by=issued_by,
            capability_scopes=scopes,
        )
        async with self._store.transaction() as tx:
            control = await tx.get_dispatch_control()
            if control.frozen:
                await tx.append_audit(
                    AuditDraft(
                        actor=issued_by,
                        action=AuditAction.ENROLLMENT_ISSUED,
                        decision=AuditDecision.DENY,
                        reason=NodeReason.DISPATCH_FROZEN.value,
                        payload={"node_name": node_name},
                    )
                )
                # The deny event must survive, so it commits before the raise.
                frozen_error = NodeMeshError(NodeReason.DISPATCH_FROZEN, "dispatch is frozen")
            else:
                frozen_error = None
                await tx.put_enrollment_token(record)
                await tx.append_audit(
                    AuditDraft(
                        actor=issued_by,
                        action=AuditAction.ENROLLMENT_ISSUED,
                        decision=AuditDecision.ALLOW,
                        payload={
                            "token_id": record.token_id,
                            "node_name": record.node_name,
                            "granted_capabilities": list(grants),
                            "expires_at": record.expires_at.isoformat(),
                        },
                    )
                )
        if frozen_error is not None:
            raise frozen_error
        return IssuedEnrollment(
            token_id=record.token_id,
            presented=secret.presented,
            node_name=record.node_name,
            kind=record.kind,
            platform=record.platform,
            granted_capabilities=grants,
            issued_at=record.issued_at,
            expires_at=record.expires_at,
        )

    async def revoke_enrollment_token(self, token_id: str, *, actor: str, reason: str = "") -> None:
        """Revoke an unconsumed enrollment token so it can never be redeemed."""
        missing = False
        async with self._store.transaction() as tx:
            record = await tx.get_enrollment_token(token_id)
            if record is None:
                missing = True
            elif not record.revoked:
                await tx.put_enrollment_token(replace(record, revoked_at=self._clock()))
                await tx.append_audit(
                    AuditDraft(
                        actor=actor,
                        action=AuditAction.ENROLLMENT_GRANT_REVOKED,
                        decision=AuditDecision.ALLOW,
                        reason=reason,
                        payload={"token_id": token_id},
                    )
                )
        if missing:
            raise NodeMeshError(NodeReason.ENROLLMENT_UNKNOWN, "unknown enrollment token")

    async def redeem_enrollment_token(
        self, *, presented: str, description: NodeDescription, public_key: str
    ) -> NodeRecord:
        """Consume a single-use token and register the machine that presented it."""
        try:
            token_id, secret_value = split_enrollment_token(presented)
            load_public_key(public_key)
        except NodeMeshError as exc:
            await self._reject_enrollment(exc.reason, description.node_name)
            raise

        node: NodeRecord | None = None
        replayed: NodeRecord | None = None
        failure: NodeReason | None = None
        async with self._store.transaction() as tx:
            record = await tx.get_enrollment_token(token_id)
            if record is None or not enrollment_secret_matches(
                token_id, secret_value, record.secret_hash
            ):
                failure = NodeReason.ENROLLMENT_UNKNOWN
                await self._reject_in(tx, failure, description.node_name)
            else:
                now = self._clock()
                failure = self._enrollment_failure(record, description, now)
                if failure is not None:
                    if record.consumed and record.consumed_by_node_id is not None:
                        existing = await tx.get_node(record.consumed_by_node_id)
                        if existing is not None and existing.public_key == public_key:
                            # A retried enrollment from the same key is the same
                            # enrollment, not a replay. Return the original record.
                            replayed = existing
                            failure = None
                    if failure is not None:
                        await self._reject_in(tx, failure, description.node_name)
                else:
                    node = NodeRecord(
                        node_id=f"node-{uuid.uuid4()}",
                        node_name=record.node_name,
                        kind=record.kind,
                        platform=record.platform,
                        architecture=description.architecture,
                        agent_version=description.agent_version,
                        public_key=public_key,
                        granted_capabilities=record.granted_capabilities,
                        declared_capabilities=normalize_capability_names(
                            list(description.declared_capabilities)
                        ),
                        labels=description.labels,
                        enrolled_at=now,
                        enrollment_token_id=record.token_id,
                        capability_scopes=record.capability_scopes,
                    )
                    await tx.put_node(node)
                    await tx.put_enrollment_token(
                        replace(record, consumed_at=now, consumed_by_node_id=node.node_id)
                    )
                    await tx.append_audit(
                        AuditDraft(
                            actor=description.node_name,
                            action=AuditAction.ENROLLMENT_REDEEMED,
                            decision=AuditDecision.ALLOW,
                            node_id=node.node_id,
                            payload={
                                "token_id": token_id,
                                "platform": node.platform.value,
                                "granted_capabilities": list(node.granted_capabilities),
                                "declared_capabilities": list(node.declared_capabilities),
                            },
                        )
                    )
        if replayed is not None:
            return replayed
        if node is None:
            raise NodeMeshError(failure or NodeReason.ENROLLMENT_UNKNOWN, "enrollment refused")
        return node

    def _enrollment_failure(
        self, record: EnrollmentTokenRecord, description: NodeDescription, now: datetime
    ) -> NodeReason | None:
        if record.revoked:
            return NodeReason.ENROLLMENT_REVOKED
        if record.consumed:
            return NodeReason.ENROLLMENT_CONSUMED
        if now >= record.expires_at:
            return NodeReason.ENROLLMENT_EXPIRED
        if description.node_name.strip() != record.node_name:
            return NodeReason.ENROLLMENT_SCOPE_MISMATCH
        if description.platform is not record.platform or description.kind is not record.kind:
            return NodeReason.ENROLLMENT_SCOPE_MISMATCH
        return None

    @staticmethod
    async def _reject_in(tx: NodeMeshTransaction, reason: NodeReason, node_name: str) -> None:
        await tx.append_audit(
            AuditDraft(
                actor=node_name or "unknown",
                action=AuditAction.ENROLLMENT_REJECTED,
                decision=AuditDecision.DENY,
                reason=reason.value,
                payload={"node_name": node_name},
            )
        )

    async def _reject_enrollment(self, reason: NodeReason, node_name: str) -> None:
        async with self._store.transaction() as tx:
            await self._reject_in(tx, reason, node_name)

    # -- sessions and heartbeats -------------------------------------------

    async def get_node(self, node_id: str) -> NodeRecord:
        async with self._store.transaction() as tx:
            record = await tx.get_node(node_id)
        if record is None:
            raise NodeMeshError(NodeReason.NODE_UNKNOWN, "unknown node")
        return record

    async def attach_session(
        self,
        *,
        node_id: str,
        session_id: str,
        declared_capabilities: Sequence[str],
        agent_version: str,
        architecture: str,
    ) -> NodeRecord:
        """Bind a freshly authenticated session to its node record."""
        async with self._store.transaction() as tx:
            record = await tx.get_node(node_id)
            if record is None:
                raise NodeMeshError(NodeReason.NODE_UNKNOWN, "unknown node")
            if record.revoked_at is not None:
                raise NodeMeshError(NodeReason.NODE_REVOKED, "node is revoked")
            now = self._clock()
            attached = replace(
                record,
                session_id=session_id,
                session_started_at=now,
                last_heartbeat_at=now,
                agent_version=agent_version,
                architecture=architecture,
                declared_capabilities=normalize_capability_names(list(declared_capabilities)),
            )
            await tx.put_node(attached)
            await tx.append_audit(
                AuditDraft(
                    actor=record.node_name,
                    action=AuditAction.SESSION_OPENED,
                    decision=AuditDecision.ALLOW,
                    node_id=node_id,
                    payload={
                        "session_id": session_id,
                        "declared_capabilities": list(attached.declared_capabilities),
                        "effective_capabilities": list(self.effective_capabilities(attached)),
                    },
                )
            )
            return attached

    async def detach_session(self, *, node_id: str, session_id: str, reason: str = "") -> None:
        """Clear a session, ignoring stale detaches from a replaced connection."""
        async with self._store.transaction() as tx:
            record = await tx.get_node(node_id)
            if record is None or record.session_id != session_id:
                return
            await tx.put_node(replace(record, session_id=None, session_started_at=None))
            await tx.append_audit(
                AuditDraft(
                    actor=record.node_name,
                    action=AuditAction.SESSION_CLOSED,
                    decision=AuditDecision.OBSERVE,
                    reason=reason,
                    node_id=node_id,
                    payload={"session_id": session_id},
                )
            )

    async def record_heartbeat(
        self, *, node_id: str, session_id: str, health: NodeHealthSnapshot
    ) -> NodeRecord:
        """Record a heartbeat from the currently attached session."""
        async with self._store.transaction() as tx:
            record = await tx.get_node(node_id)
            if record is None:
                raise NodeMeshError(NodeReason.NODE_UNKNOWN, "unknown node")
            if record.session_id != session_id:
                raise NodeMeshError(
                    NodeReason.NODE_SESSION_REPLACED, "session is no longer current"
                )
            updated = replace(record, last_heartbeat_at=health.reported_at, last_health=health)
            await tx.put_node(updated)
            return updated

    async def sweep_expired_heartbeats(self) -> tuple[str, ...]:
        """Detach sessions whose heartbeats stopped arriving; return affected nodes."""
        now = self._clock()
        expired: list[NodeRecord] = []
        async with self._store.transaction() as tx:
            for record in await tx.list_nodes():
                if record.session_id is None or record.last_heartbeat_at is None:
                    continue
                if (
                    now - record.last_heartbeat_at
                ).total_seconds() <= self.heartbeat_expiry_seconds:
                    continue
                await tx.put_node(replace(record, session_id=None, session_started_at=None))
                await tx.append_audit(
                    AuditDraft(
                        actor="control-plane",
                        action=AuditAction.HEARTBEAT_EXPIRED,
                        decision=AuditDecision.OBSERVE,
                        node_id=record.node_id,
                        payload={"session_id": record.session_id},
                    )
                )
                expired.append(record)
        return tuple(record.node_id for record in expired)

    # -- restart recovery ---------------------------------------------------

    async def recover_after_restart(self) -> RecoveryReport:
        """Reconcile durable state with the fact that no session survived.

        A restart destroys every WebSocket the control plane held, so any node
        still carrying a session in storage is describing a connection that no
        longer exists. Heartbeat timestamps are preserved so state derivation
        ages those nodes to offline rather than erasing their history.

        Running this twice changes nothing the second time.
        """
        cleared: list[str] = []
        reconciled: list[str] = []
        async with self._store.transaction() as tx:
            for record in await tx.list_nodes():
                if record.session_id is None:
                    continue
                await tx.put_node(replace(record, session_id=None, session_started_at=None))
                await tx.append_audit(
                    AuditDraft(
                        actor="control-plane",
                        action=AuditAction.SESSION_CLOSED,
                        decision=AuditDecision.OBSERVE,
                        reason=RESTART_REASON,
                        node_id=record.node_id,
                        payload={"session_id": record.session_id},
                    )
                )
                cleared.append(record.node_id)

            now = self._clock()
            for job in await tx.list_jobs():
                if job.status in TERMINAL_JOB_STATUSES:
                    continue
                # Temporal decides retries. This only stops durable metadata
                # from claiming a job runs when nothing is running it.
                await tx.put_job(
                    replace(
                        job,
                        status=NodeJobStatus.TIMED_OUT,
                        updated_at=now,
                        reason=RESTART_REASON,
                    )
                )
                await tx.append_audit(
                    AuditDraft(
                        actor="control-plane",
                        action=AuditAction.JOB_RECONCILED,
                        decision=AuditDecision.OBSERVE,
                        reason=RESTART_REASON,
                        node_id=job.node_id,
                        job_id=job.job_id,
                        payload={"previous_status": job.status.value},
                    )
                )
                reconciled.append(job.job_id)

            control = await tx.get_dispatch_control()

        return RecoveryReport(
            sessions_cleared=tuple(cleared),
            jobs_reconciled=tuple(reconciled),
            frozen=control.frozen,
            freeze_epoch=control.freeze_epoch,
        )

    # -- job metadata -------------------------------------------------------

    async def upsert_job(self, record: NodeJobRecord) -> None:
        """Persist the durable metadata view of one dispatched job."""
        async with self._store.transaction() as tx:
            await tx.put_job(record)

    async def list_jobs(self) -> tuple[NodeJobRecord, ...]:
        async with self._store.transaction() as tx:
            return await tx.list_jobs()

    # -- lifecycle ----------------------------------------------------------

    async def quarantine_node(self, node_id: str, *, actor: str, reason: str) -> NodeRecord:
        """Stop dispatching to a node without severing observation."""
        return await self._lifecycle_change(
            node_id,
            actor=actor,
            reason=reason,
            action=AuditAction.NODE_QUARANTINED,
            mutate=lambda record: replace(
                record, quarantined_at=self._clock(), quarantine_reason=reason
            ),
        )

    async def restore_node(self, node_id: str, *, actor: str, reason: str = "") -> NodeRecord:
        """Return a quarantined node to normal dispatch eligibility."""
        return await self._lifecycle_change(
            node_id,
            actor=actor,
            reason=reason,
            action=AuditAction.NODE_RESTORED,
            mutate=lambda record: replace(record, quarantined_at=None, quarantine_reason=""),
            refuse_revoked="a revoked node cannot be restored",
        )

    async def revoke_node(self, node_id: str, *, actor: str, reason: str) -> NodeRecord:
        """Permanently retire a node identity. Revocation is irreversible."""
        return await self._lifecycle_change(
            node_id,
            actor=actor,
            reason=reason,
            action=AuditAction.NODE_REVOKED,
            mutate=lambda record: replace(
                record,
                revoked_at=record.revoked_at or self._clock(),
                revocation_reason=record.revocation_reason or reason,
                session_id=None,
                session_started_at=None,
            ),
        )

    async def _lifecycle_change(
        self,
        node_id: str,
        *,
        actor: str,
        reason: str,
        action: AuditAction,
        mutate: Callable[[NodeRecord], NodeRecord],
        refuse_revoked: str | None = None,
    ) -> NodeRecord:
        async with self._store.transaction() as tx:
            record = await tx.get_node(node_id)
            if record is None:
                raise NodeMeshError(NodeReason.NODE_UNKNOWN, "unknown node")
            if refuse_revoked is not None and record.revoked_at is not None:
                raise NodeMeshError(NodeReason.NODE_REVOKED, refuse_revoked)
            updated = mutate(record)
            await tx.put_node(updated)
            await tx.append_audit(
                AuditDraft(
                    actor=actor,
                    action=action,
                    decision=AuditDecision.ALLOW,
                    reason=reason,
                    node_id=node_id,
                )
            )
            return updated

    # -- dispatch kill switch ----------------------------------------------

    async def dispatch_control(self) -> DispatchControlState:
        async with self._store.transaction() as tx:
            return await tx.get_dispatch_control()

    async def freeze_dispatch(self, *, actor: str, reason: str) -> DispatchControlState:
        """Halt every new dispatch. Repeating a freeze is idempotent."""
        async with self._store.transaction() as tx:
            control = await tx.get_dispatch_control()
            if control.frozen:
                return control
            frozen = DispatchControlState(
                frozen=True,
                freeze_epoch=control.freeze_epoch + 1,
                changed_at=self._clock(),
                reason=reason,
            )
            await tx.put_dispatch_control(frozen)
            await tx.append_audit(
                AuditDraft(
                    actor=actor,
                    action=AuditAction.DISPATCH_FROZEN,
                    decision=AuditDecision.ALLOW,
                    reason=reason,
                    payload={"freeze_epoch": frozen.freeze_epoch},
                )
            )
        return frozen

    async def unfreeze_dispatch(
        self, *, actor: str, expected_freeze_epoch: int, reason: str = ""
    ) -> DispatchControlState:
        """Clear the kill switch only when the caller names the exact freeze epoch."""
        error: NodeMeshError | None = None
        thawed = DispatchControlState()
        async with self._store.transaction() as tx:
            control = await tx.get_dispatch_control()
            if not control.frozen:
                error = NodeMeshError(NodeReason.NOT_FROZEN, "dispatch is not frozen")
            elif expected_freeze_epoch != control.freeze_epoch:
                await tx.append_audit(
                    AuditDraft(
                        actor=actor,
                        action=AuditAction.DISPATCH_UNFROZEN,
                        decision=AuditDecision.DENY,
                        reason=NodeReason.FREEZE_EPOCH_MISMATCH.value,
                        payload={
                            "expected": expected_freeze_epoch,
                            "actual": control.freeze_epoch,
                        },
                    )
                )
                error = NodeMeshError(
                    NodeReason.FREEZE_EPOCH_MISMATCH, "freeze epoch does not match"
                )
            else:
                thawed = DispatchControlState(
                    frozen=False,
                    freeze_epoch=control.freeze_epoch,
                    changed_at=self._clock(),
                    reason=reason,
                )
                await tx.put_dispatch_control(thawed)
                await tx.append_audit(
                    AuditDraft(
                        actor=actor,
                        action=AuditAction.DISPATCH_UNFROZEN,
                        decision=AuditDecision.ALLOW,
                        reason=reason,
                        payload={"freeze_epoch": thawed.freeze_epoch},
                    )
                )
        if error is not None:
            raise error
        return thawed

    # -- admission ----------------------------------------------------------

    def effective_capabilities(self, record: NodeRecord) -> tuple[str, ...]:
        """Grant, declaration, and catalog intersected. Declarations never widen a grant."""
        return tuple(
            sorted(
                set(record.granted_capabilities)
                & set(record.declared_capabilities)
                & {name for name in record.granted_capabilities if _is_dispatchable(name)}
            )
        )

    def state_of(self, record: NodeRecord, now: datetime) -> NodeState:
        """Derive the observable node state without mutating storage."""
        if record.revoked_at is not None:
            return NodeState.REVOKED
        if record.quarantined_at is not None:
            return NodeState.QUARANTINED
        if record.session_id is None or record.last_heartbeat_at is None:
            return NodeState.OFFLINE if record.last_heartbeat_at else NodeState.PENDING
        age = (now - record.last_heartbeat_at).total_seconds()
        return NodeState.ONLINE if age <= self.heartbeat_expiry_seconds else NodeState.OFFLINE

    def view_of(self, record: NodeRecord, now: datetime) -> NodeView:
        age = (
            (now - record.last_heartbeat_at).total_seconds()
            if record.last_heartbeat_at is not None
            else None
        )
        return NodeView(
            node_id=record.node_id,
            node_name=record.node_name,
            kind=record.kind,
            platform=record.platform,
            architecture=record.architecture,
            agent_version=record.agent_version,
            state=self.state_of(record, now),
            connected=record.connected,
            granted_capabilities=record.granted_capabilities,
            declared_capabilities=record.declared_capabilities,
            effective_capabilities=self.effective_capabilities(record),
            enrolled_at=record.enrolled_at,
            last_heartbeat_at=record.last_heartbeat_at,
            heartbeat_age_seconds=age,
            labels=record.labels,
            health=record.last_health,
        )

    async def list_views(self) -> tuple[NodeView, ...]:
        now = self._clock()
        async with self._store.transaction() as tx:
            records = await tx.list_nodes()
        return tuple(
            self.view_of(record, now) for record in sorted(records, key=lambda item: item.node_name)
        )

    async def assert_dispatchable(
        self,
        *,
        node_id: str,
        capability: str,
        parameters: Mapping[str, Any] | None = None,
        approval: Any | None = None,
    ) -> NodeRecord:
        """Refuse dispatch unless mesh, node, grant, scope, and approval all permit it."""
        require_dispatchable_capability(capability)
        async with self._store.transaction() as tx:
            control = await tx.get_dispatch_control()
            record = await tx.get_node(node_id)
        if control.frozen:
            raise NodeMeshError(NodeReason.DISPATCH_FROZEN, "dispatch is frozen")
        if record is None:
            raise NodeMeshError(NodeReason.NODE_UNKNOWN, "unknown node")
        now = self._clock()
        state = self.state_of(record, now)
        if state is NodeState.REVOKED:
            raise NodeMeshError(NodeReason.NODE_REVOKED, "node is revoked")
        if state is NodeState.QUARANTINED:
            raise NodeMeshError(NodeReason.NODE_QUARANTINED, "node is quarantined")
        if capability not in record.granted_capabilities:
            raise NodeMeshError(NodeReason.CAPABILITY_NOT_GRANTED, "capability is not granted")
        if capability not in record.declared_capabilities:
            raise NodeMeshError(NodeReason.CAPABILITY_NOT_DECLARED, "capability is not declared")
        # The scope check comes before the liveness check on purpose: an
        # out-of-scope request is refused identically whether the node happens
        # to be online, so a caller cannot use timing or error codes to probe
        # which paths a node would have accepted.
        assert_scoped_dispatch(
            capability=capability,
            scopes=self.scopes_of(record),
            parameters=parameters or {},
        )
        # A mutating capability is gated on an approval bound to this literal
        # action -- this node, this path, these bytes, this mode. "Approved to
        # write files" would be reusable against any target; the digest is what
        # makes a captured approval useless for anything but the write it named.
        if requires_approval(capability):
            self._assert_approved(
                capability=capability,
                node_id=node_id,
                parameters=parameters or {},
                approval=approval,
            )
        if state is not NodeState.ONLINE:
            raise NodeMeshError(NodeReason.NODE_OFFLINE, "node is not online")
        return record

    def _assert_approved(
        self,
        *,
        capability: str,
        node_id: str,
        parameters: Mapping[str, Any],
        approval: Any | None,
    ) -> None:
        if approval is None:
            raise NodeMeshError(
                NodeReason.CAPABILITY_NOT_GRANTED,
                f"{capability} changes the node and requires an approval bound to this action",
            )
        if self._approvals is None:
            # Fail closed. A registry with no verifier cannot establish that an
            # approval is genuine, and accepting one on its own say-so would
            # make the whole gate decorative.
            raise NodeMeshError(
                NodeReason.CAPABILITY_NOT_GRANTED,
                "no approval verifier is configured; refusing to dispatch a mutating capability",
            )
        digest = expected_action_digest(
            capability=capability, node_id=node_id, parameters=parameters
        )
        self._approvals.verify(action_digest=digest, approval=approval, now=self._clock())

    def scopes_of(self, record: NodeRecord) -> dict[str, Any]:
        """Typed scopes for one node, parsed against that node's own platform."""
        return parse_scopes(_decode_scopes(record.capability_scopes), platform=record.platform)

    async def select_node(
        self,
        *,
        capability: str,
        node_id: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        approval: Any | None = None,
    ) -> NodeRecord:
        """Pick the eligible node for a capability, preferring the least loaded."""
        if node_id is not None:
            return await self.assert_dispatchable(
                node_id=node_id,
                capability=capability,
                parameters=parameters,
                approval=approval,
            )
        require_dispatchable_capability(capability)
        async with self._store.transaction() as tx:
            control = await tx.get_dispatch_control()
            records = await tx.list_nodes()
        if control.frozen:
            raise NodeMeshError(NodeReason.DISPATCH_FROZEN, "dispatch is frozen")
        now = self._clock()
        eligible = [
            record
            for record in records
            if self.state_of(record, now) is NodeState.ONLINE
            and capability in self.effective_capabilities(record)
        ]
        if not eligible:
            raise NodeMeshError(
                NodeReason.DISPATCH_NO_ELIGIBLE_NODE, "no online node offers this capability"
            )
        # Scope is part of eligibility, not a later check. A node granted a
        # different directory cannot serve this request at all, so selecting it
        # and refusing afterwards would report "no capacity" for what is really
        # "not granted" -- and on a mesh with several nodes it would pick the
        # wrong one while a correctly scoped node sat idle.
        if requires_scope(capability):
            scoped: list[NodeRecord] = []
            for record in eligible:
                try:
                    assert_scoped_dispatch(
                        capability=capability,
                        scopes=self.scopes_of(record),
                        parameters=parameters or {},
                    )
                except NodeMeshError:
                    continue
                scoped.append(record)
            if not scoped:
                raise NodeMeshError(
                    NodeReason.CAPABILITY_NOT_GRANTED,
                    "no online node is granted this capability for the requested parameters",
                )
            eligible = scoped
        eligible.sort(key=lambda record: (_active_jobs(record), record.node_id))
        chosen = eligible[0]
        # The approval gate is per-node, because the digest binds the node id.
        # It can only be checked once a node has been chosen.
        if requires_approval(capability):
            self._assert_approved(
                capability=capability,
                node_id=chosen.node_id,
                parameters=parameters or {},
                approval=approval,
            )
        return chosen

    async def enrollment_tokens(self) -> tuple[EnrollmentTokenRecord, ...]:
        async with self._store.transaction() as tx:
            return await tx.list_enrollment_tokens()


def _active_jobs(record: NodeRecord) -> int:
    return record.last_health.active_jobs if record.last_health is not None else 0


def _is_dispatchable(name: str) -> bool:
    try:
        require_dispatchable_capability(name)
    except NodeMeshError:
        return False
    return True


def labels_from_mapping(labels: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    """Normalize a label mapping into the deterministic tuple form records store."""
    return tuple(sorted((str(key), str(value)) for key, value in labels.items()))


def _encode_scopes(
    scopes: Mapping[str, Mapping[str, Any]], *, platform: NodePlatform
) -> tuple[tuple[str, str], ...]:
    """Validate and freeze scopes into the canonical form the record stores.

    Stored as sorted (capability, canonical JSON) pairs so the record hashes and
    compares deterministically, and so a scope cannot smuggle key ordering into
    anything downstream that signs or digests it.
    """
    import json

    encoded: list[tuple[str, str]] = []
    for capability, payload in scopes.items():
        if capability in (FILE_READ, FILE_WRITE):
            # Round-tripped through the typed scope so a malformed root, an
            # over-large ceiling, or "/" is rejected here rather than stored.
            builder = FileReadScope if capability == FILE_READ else FileWriteScope
            body = builder.from_mapping(payload, platform=platform).to_mapping()
        else:
            raise NodeMeshError(
                NodeReason.CAPABILITY_NOT_GRANTED,
                f"{capability} has no scope schema; refusing to store one it cannot enforce",
            )
        encoded.append((capability, json.dumps(body, sort_keys=True, separators=(",", ":"))))
    return tuple(sorted(encoded))


def _decode_scopes(pairs: tuple[tuple[str, str], ...]) -> dict[str, Any]:
    import json

    return {capability: json.loads(body) for capability, body in pairs}
