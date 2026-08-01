import asyncio
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Protocol

from olympus.nodes.audit import AuditAction, AuditDecision, NodeAuditLog
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
    DispatchControlState,
    EnrollmentTokenRecord,
    NodeHealthSnapshot,
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

DEFAULT_ENROLLMENT_TTL_SECONDS = 900
MAX_ENROLLMENT_TTL_SECONDS = 3600
MIN_ENROLLMENT_TTL_SECONDS = 60
MAX_LABELS = 16


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


class NodeRegistryStore(Protocol):
    """Persistence seam. PostgreSQL becomes the canonical owner in a later slice."""

    async def put_enrollment_token(self, record: EnrollmentTokenRecord) -> None: ...

    async def get_enrollment_token(self, token_id: str) -> EnrollmentTokenRecord | None: ...

    async def list_enrollment_tokens(self) -> tuple[EnrollmentTokenRecord, ...]: ...

    async def put_node(self, record: NodeRecord) -> None: ...

    async def get_node(self, node_id: str) -> NodeRecord | None: ...

    async def list_nodes(self) -> tuple[NodeRecord, ...]: ...

    async def get_dispatch_control(self) -> DispatchControlState: ...

    async def put_dispatch_control(self, state: DispatchControlState) -> None: ...


class InMemoryNodeRegistryStore:
    """Process-local registry storage used until the persistence slice lands."""

    def __init__(self) -> None:
        self._tokens: dict[str, EnrollmentTokenRecord] = {}
        self._nodes: dict[str, NodeRecord] = {}
        self._control = DispatchControlState()

    async def put_enrollment_token(self, record: EnrollmentTokenRecord) -> None:
        self._tokens[record.token_id] = record

    async def get_enrollment_token(self, token_id: str) -> EnrollmentTokenRecord | None:
        return self._tokens.get(token_id)

    async def list_enrollment_tokens(self) -> tuple[EnrollmentTokenRecord, ...]:
        return tuple(self._tokens.values())

    async def put_node(self, record: NodeRecord) -> None:
        self._nodes[record.node_id] = record

    async def get_node(self, node_id: str) -> NodeRecord | None:
        return self._nodes.get(node_id)

    async def list_nodes(self) -> tuple[NodeRecord, ...]:
        return tuple(self._nodes.values())

    async def get_dispatch_control(self) -> DispatchControlState:
        return self._control

    async def put_dispatch_control(self, state: DispatchControlState) -> None:
        self._control = state


class NodeRegistry:
    """Canonical owner of node identity, capability grants, and dispatch admission."""

    def __init__(
        self,
        *,
        store: NodeRegistryStore | None = None,
        audit: NodeAuditLog | None = None,
        clock: Callable[[], datetime] = utc_now,
        heartbeat_interval_seconds: int = DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
        heartbeat_expiry_seconds: int = DEFAULT_HEARTBEAT_EXPIRY_SECONDS,
        enrollment_ttl_seconds: int = DEFAULT_ENROLLMENT_TTL_SECONDS,
    ) -> None:
        if heartbeat_expiry_seconds <= heartbeat_interval_seconds:
            raise ValueError("heartbeat expiry must exceed the heartbeat interval")
        self._store: NodeRegistryStore = store or InMemoryNodeRegistryStore()
        self._audit = audit or NodeAuditLog(clock=clock)
        self._clock = clock
        self._lock = asyncio.Lock()
        self.heartbeat_interval_seconds = heartbeat_interval_seconds
        self.heartbeat_expiry_seconds = heartbeat_expiry_seconds
        self.enrollment_ttl_seconds = enrollment_ttl_seconds

    @property
    def audit(self) -> NodeAuditLog:
        return self._audit

    def now(self) -> datetime:
        """Read the registry clock so derived views share one instant."""
        return self._clock()

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

        control = await self._store.get_dispatch_control()
        if control.frozen:
            self._audit.append(
                actor=issued_by,
                action=AuditAction.ENROLLMENT_ISSUED,
                decision=AuditDecision.DENY,
                reason=NodeReason.DISPATCH_FROZEN.value,
                payload={"node_name": node_name},
            )
            raise NodeMeshError(NodeReason.DISPATCH_FROZEN, "dispatch is frozen")

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
        )
        async with self._lock:
            await self._store.put_enrollment_token(record)
        self._audit.append(
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
        async with self._lock:
            record = await self._store.get_enrollment_token(token_id)
            if record is None:
                raise NodeMeshError(NodeReason.ENROLLMENT_UNKNOWN, "unknown enrollment token")
            if record.revoked:
                return
            await self._store.put_enrollment_token(replace(record, revoked_at=self._clock()))
        self._audit.append(
            actor=actor,
            action=AuditAction.ENROLLMENT_GRANT_REVOKED,
            decision=AuditDecision.ALLOW,
            reason=reason,
            payload={"token_id": token_id},
        )

    async def redeem_enrollment_token(
        self, *, presented: str, description: NodeDescription, public_key: str
    ) -> NodeRecord:
        """Consume a single-use token and register the machine that presented it."""
        try:
            token_id, secret_value = split_enrollment_token(presented)
            load_public_key(public_key)
        except NodeMeshError as exc:
            self._reject_enrollment(exc.reason, description.node_name)
            raise

        async with self._lock:
            record = await self._store.get_enrollment_token(token_id)
            if record is None or not enrollment_secret_matches(
                token_id, secret_value, record.secret_hash
            ):
                self._reject_enrollment(NodeReason.ENROLLMENT_UNKNOWN, description.node_name)
                raise NodeMeshError(NodeReason.ENROLLMENT_UNKNOWN, "unknown enrollment token")
            now = self._clock()
            failure = self._enrollment_failure(record, description, now)
            if failure is not None:
                if record.consumed and record.consumed_by_node_id is not None:
                    existing = await self._store.get_node(record.consumed_by_node_id)
                    if existing is not None and existing.public_key == public_key:
                        # A retried enrollment from the same key is the same
                        # enrollment, not a replay. Return the original record.
                        return existing
                self._reject_enrollment(failure, description.node_name)
                raise NodeMeshError(failure, "enrollment refused")

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
            )
            await self._store.put_node(node)
            await self._store.put_enrollment_token(
                replace(record, consumed_at=now, consumed_by_node_id=node.node_id)
            )
        self._audit.append(
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

    def _reject_enrollment(self, reason: NodeReason, node_name: str) -> None:
        self._audit.append(
            actor=node_name or "unknown",
            action=AuditAction.ENROLLMENT_REJECTED,
            decision=AuditDecision.DENY,
            reason=reason.value,
            payload={"node_name": node_name},
        )

    # -- sessions and heartbeats -------------------------------------------

    async def get_node(self, node_id: str) -> NodeRecord:
        record = await self._store.get_node(node_id)
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
        async with self._lock:
            record = await self.get_node(node_id)
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
            await self._store.put_node(attached)
        self._audit.append(
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
        return attached

    async def detach_session(self, *, node_id: str, session_id: str, reason: str = "") -> None:
        """Clear a session, ignoring stale detaches from a replaced connection."""
        async with self._lock:
            record = await self._store.get_node(node_id)
            if record is None or record.session_id != session_id:
                return
            await self._store.put_node(replace(record, session_id=None, session_started_at=None))
        self._audit.append(
            actor=record.node_name,
            action=AuditAction.SESSION_CLOSED,
            decision=AuditDecision.OBSERVE,
            reason=reason,
            node_id=node_id,
            payload={"session_id": session_id},
        )

    async def record_heartbeat(
        self, *, node_id: str, session_id: str, health: NodeHealthSnapshot
    ) -> NodeRecord:
        """Record a heartbeat from the currently attached session."""
        async with self._lock:
            record = await self.get_node(node_id)
            if record.session_id != session_id:
                raise NodeMeshError(
                    NodeReason.NODE_SESSION_REPLACED, "session is no longer current"
                )
            updated = replace(record, last_heartbeat_at=health.reported_at, last_health=health)
            await self._store.put_node(updated)
        return updated

    async def sweep_expired_heartbeats(self) -> tuple[str, ...]:
        """Detach sessions whose heartbeats stopped arriving; return affected nodes."""
        now = self._clock()
        expired: list[NodeRecord] = []
        async with self._lock:
            for record in await self._store.list_nodes():
                if record.session_id is None or record.last_heartbeat_at is None:
                    continue
                if (
                    now - record.last_heartbeat_at
                ).total_seconds() <= self.heartbeat_expiry_seconds:
                    continue
                await self._store.put_node(
                    replace(record, session_id=None, session_started_at=None)
                )
                expired.append(record)
        for record in expired:
            self._audit.append(
                actor="control-plane",
                action=AuditAction.HEARTBEAT_EXPIRED,
                decision=AuditDecision.OBSERVE,
                node_id=record.node_id,
                payload={"session_id": record.session_id},
            )
        return tuple(record.node_id for record in expired)

    # -- lifecycle ----------------------------------------------------------

    async def quarantine_node(self, node_id: str, *, actor: str, reason: str) -> NodeRecord:
        """Stop dispatching to a node without severing observation."""
        async with self._lock:
            record = await self.get_node(node_id)
            updated = replace(record, quarantined_at=self._clock(), quarantine_reason=reason)
            await self._store.put_node(updated)
        self._audit.append(
            actor=actor,
            action=AuditAction.NODE_QUARANTINED,
            decision=AuditDecision.ALLOW,
            reason=reason,
            node_id=node_id,
        )
        return updated

    async def restore_node(self, node_id: str, *, actor: str, reason: str = "") -> NodeRecord:
        """Return a quarantined node to normal dispatch eligibility."""
        async with self._lock:
            record = await self.get_node(node_id)
            if record.revoked_at is not None:
                raise NodeMeshError(NodeReason.NODE_REVOKED, "a revoked node cannot be restored")
            updated = replace(record, quarantined_at=None, quarantine_reason="")
            await self._store.put_node(updated)
        self._audit.append(
            actor=actor,
            action=AuditAction.NODE_RESTORED,
            decision=AuditDecision.ALLOW,
            reason=reason,
            node_id=node_id,
        )
        return updated

    async def revoke_node(self, node_id: str, *, actor: str, reason: str) -> NodeRecord:
        """Permanently retire a node identity. Revocation is irreversible."""
        async with self._lock:
            record = await self.get_node(node_id)
            updated = replace(
                record,
                revoked_at=record.revoked_at or self._clock(),
                revocation_reason=record.revocation_reason or reason,
                session_id=None,
                session_started_at=None,
            )
            await self._store.put_node(updated)
        self._audit.append(
            actor=actor,
            action=AuditAction.NODE_REVOKED,
            decision=AuditDecision.ALLOW,
            reason=reason,
            node_id=node_id,
        )
        return updated

    # -- dispatch kill switch ----------------------------------------------

    async def dispatch_control(self) -> DispatchControlState:
        return await self._store.get_dispatch_control()

    async def freeze_dispatch(self, *, actor: str, reason: str) -> DispatchControlState:
        """Halt every new dispatch. Repeating a freeze is idempotent."""
        async with self._lock:
            control = await self._store.get_dispatch_control()
            if control.frozen:
                return control
            frozen = DispatchControlState(
                frozen=True,
                freeze_epoch=control.freeze_epoch + 1,
                changed_at=self._clock(),
                reason=reason,
            )
            await self._store.put_dispatch_control(frozen)
        self._audit.append(
            actor=actor,
            action=AuditAction.DISPATCH_FROZEN,
            decision=AuditDecision.ALLOW,
            reason=reason,
            payload={"freeze_epoch": frozen.freeze_epoch},
        )
        return frozen

    async def unfreeze_dispatch(
        self, *, actor: str, expected_freeze_epoch: int, reason: str = ""
    ) -> DispatchControlState:
        """Clear the kill switch only when the caller names the exact freeze epoch."""
        async with self._lock:
            control = await self._store.get_dispatch_control()
            if not control.frozen:
                raise NodeMeshError(NodeReason.NOT_FROZEN, "dispatch is not frozen")
            if expected_freeze_epoch != control.freeze_epoch:
                self._audit.append(
                    actor=actor,
                    action=AuditAction.DISPATCH_UNFROZEN,
                    decision=AuditDecision.DENY,
                    reason=NodeReason.FREEZE_EPOCH_MISMATCH.value,
                    payload={"expected": expected_freeze_epoch, "actual": control.freeze_epoch},
                )
                raise NodeMeshError(NodeReason.FREEZE_EPOCH_MISMATCH, "freeze epoch does not match")
            thawed = DispatchControlState(
                frozen=False,
                freeze_epoch=control.freeze_epoch,
                changed_at=self._clock(),
                reason=reason,
            )
            await self._store.put_dispatch_control(thawed)
        self._audit.append(
            actor=actor,
            action=AuditAction.DISPATCH_UNFROZEN,
            decision=AuditDecision.ALLOW,
            reason=reason,
            payload={"freeze_epoch": thawed.freeze_epoch},
        )
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
        records = await self._store.list_nodes()
        return tuple(
            self.view_of(record, now) for record in sorted(records, key=lambda item: item.node_name)
        )

    async def assert_dispatchable(self, *, node_id: str, capability: str) -> NodeRecord:
        """Refuse dispatch unless the mesh, the node, and the grant all permit it."""
        require_dispatchable_capability(capability)
        control = await self._store.get_dispatch_control()
        if control.frozen:
            raise NodeMeshError(NodeReason.DISPATCH_FROZEN, "dispatch is frozen")
        record = await self.get_node(node_id)
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
        if state is not NodeState.ONLINE:
            raise NodeMeshError(NodeReason.NODE_OFFLINE, "node is not online")
        return record

    async def select_node(self, *, capability: str, node_id: str | None = None) -> NodeRecord:
        """Pick the eligible node for a capability, preferring the least loaded."""
        if node_id is not None:
            return await self.assert_dispatchable(node_id=node_id, capability=capability)
        require_dispatchable_capability(capability)
        control = await self._store.get_dispatch_control()
        if control.frozen:
            raise NodeMeshError(NodeReason.DISPATCH_FROZEN, "dispatch is frozen")
        now = self._clock()
        eligible = [
            record
            for record in await self._store.list_nodes()
            if self.state_of(record, now) is NodeState.ONLINE
            and capability in self.effective_capabilities(record)
        ]
        if not eligible:
            raise NodeMeshError(
                NodeReason.DISPATCH_NO_ELIGIBLE_NODE, "no online node offers this capability"
            )
        eligible.sort(key=lambda record: (_active_jobs(record), record.node_id))
        return eligible[0]

    async def enrollment_tokens(self) -> tuple[EnrollmentTokenRecord, ...]:
        return await self._store.list_enrollment_tokens()


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
