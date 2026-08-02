import hashlib
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from typing import Any

from olympus.nodes.crypto import canonical_json, digest_of
from olympus.nodes.models import utc_now
from olympus.nodes.redaction import redact_value

AUDIT_EVENT_VERSION = 1
GENESIS_HASH = "0" * 64


class AuditDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    OBSERVE = "observe"


class AuditAction(StrEnum):
    ENROLLMENT_ISSUED = "enrollment-token-issued"
    ENROLLMENT_GRANT_REVOKED = "enrollment-token-revoked"
    ENROLLMENT_REDEEMED = "enrollment-redeemed"
    ENROLLMENT_REJECTED = "enrollment-rejected"
    SESSION_OPENED = "session-opened"
    SESSION_REJECTED = "session-rejected"
    SESSION_CLOSED = "session-closed"
    HEARTBEAT_EXPIRED = "heartbeat-expired"
    NODE_QUARANTINED = "node-quarantined"
    NODE_RESTORED = "node-restored"
    NODE_REVOKED = "node-revoked"
    DISPATCH_ADMITTED = "dispatch-admitted"
    DISPATCH_REFUSED = "dispatch-refused"
    DISPATCH_COMPLETED = "dispatch-completed"
    DISPATCH_CANCELLED = "dispatch-cancelled"
    DISPATCH_FROZEN = "dispatch-frozen"
    DISPATCH_UNFROZEN = "dispatch-unfrozen"
    JOB_RECONCILED = "job-reconciled"


@dataclass(frozen=True)
class AuditDraft:
    """An audit event before the chain assigns it a sequence and a hash.

    Callers describe *what happened*; only the store decides where the event
    lands in the chain, because only the store holds the chain head under a
    lock. The payload is redacted here so an unredacted value never reaches
    storage even if a store implementation is careless.
    """

    actor: str
    action: AuditAction
    decision: AuditDecision
    reason: str = ""
    node_id: str | None = None
    job_id: str | None = None
    payload: Mapping[str, Any] = field(default_factory=dict)

    def redacted_payload(self) -> dict[str, Any]:
        redacted: dict[str, Any] = redact_value(dict(self.payload))
        return redacted


@dataclass(frozen=True)
class NodeAuditEvent:
    """One tamper-evident link in the node-mesh audit chain."""

    sequence: int
    event_id: str
    version: int
    recorded_at: str
    actor: str
    action: AuditAction
    decision: AuditDecision
    reason: str
    node_id: str | None
    job_id: str | None
    payload: Mapping[str, Any]
    payload_digest: str
    previous_hash: str
    event_hash: str

    def body(self) -> dict[str, Any]:
        """Return the canonical hashed body, excluding the hash itself."""
        content = asdict(self)
        content.pop("event_hash")
        return content


def compute_event_hash(body: Mapping[str, Any]) -> str:
    """Hash one audit body over its canonical encoding."""
    return hashlib.sha256(canonical_json(dict(body))).hexdigest()


def link_event(
    draft: AuditDraft,
    *,
    sequence: int,
    previous_hash: str,
    recorded_at: datetime,
    event_id: str | None = None,
) -> NodeAuditEvent:
    """Seal one draft into the chain at a sequence the caller already holds.

    Every store links events the same way, so a chain written to PostgreSQL
    and a chain held in memory hash identically for identical inputs.
    """
    safe_payload = draft.redacted_payload()
    unlinked = NodeAuditEvent(
        sequence=sequence,
        event_id=event_id or f"nae-{uuid.uuid4()}",
        version=AUDIT_EVENT_VERSION,
        recorded_at=recorded_at.isoformat(),
        actor=draft.actor,
        action=draft.action,
        decision=draft.decision,
        reason=draft.reason,
        node_id=draft.node_id,
        job_id=draft.job_id,
        payload=safe_payload,
        payload_digest=digest_of(safe_payload),
        previous_hash=previous_hash,
        event_hash="",
    )
    return replace(unlinked, event_hash=compute_event_hash(unlinked.body()))


def verify_chain(events: Sequence[NodeAuditEvent]) -> bool:
    """Recompute every link and confirm the sequence, linkage, and digests."""
    previous_hash = GENESIS_HASH
    for index, event in enumerate(events, start=1):
        if event.sequence != index or event.previous_hash != previous_hash:
            return False
        if event.payload_digest != digest_of(dict(event.payload)):
            return False
        if compute_event_hash(event.body()) != event.event_hash:
            return False
        previous_hash = event.event_hash
    return True


class NodeAuditLog:
    """In-process hash-chained audit log.

    PostgreSQL is the canonical owner once a database is configured; this
    remains the store for tests and the offline demonstration. It provides the
    tamper-evidence property but makes no claim of off-host immutability.
    """

    def __init__(self, *, clock: Callable[[], datetime] = utc_now) -> None:
        self._clock = clock
        self._events: list[NodeAuditEvent] = []

    def append_draft(self, draft: AuditDraft) -> NodeAuditEvent:
        """Append one redacted, hash-chained event and return it."""
        event = link_event(
            draft,
            sequence=len(self._events) + 1,
            previous_hash=self.head(),
            recorded_at=self._clock(),
        )
        self._events.append(event)
        return event

    def append(
        self,
        *,
        actor: str,
        action: AuditAction,
        decision: AuditDecision,
        reason: str = "",
        node_id: str | None = None,
        job_id: str | None = None,
        payload: Mapping[str, Any] | None = None,
    ) -> NodeAuditEvent:
        """Append one event described by its individual fields."""
        return self.append_draft(
            AuditDraft(
                actor=actor,
                action=action,
                decision=decision,
                reason=reason,
                node_id=node_id,
                job_id=job_id,
                payload=dict(payload or {}),
            )
        )

    def extend(self, events: Sequence[NodeAuditEvent]) -> None:
        """Adopt already-linked events, used when a transaction commits."""
        self._events.extend(events)

    def events(self) -> tuple[NodeAuditEvent, ...]:
        return tuple(self._events)

    def head(self) -> str:
        return self._events[-1].event_hash if self._events else GENESIS_HASH

    def verify(self) -> bool:
        """Return whether the recorded chain is internally consistent."""
        return verify_chain(self._events)
