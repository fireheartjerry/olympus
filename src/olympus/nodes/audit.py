import hashlib
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
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


class NodeAuditLog:
    """Append-only, hash-chained audit log for node-mesh security decisions.

    PostgreSQL becomes the canonical owner in the persistence slice. Until then
    this in-process chain provides the interface and the tamper-evidence
    property, and makes no claim of off-host immutability.
    """

    def __init__(self, *, clock: Callable[[], datetime] = utc_now) -> None:
        self._clock = clock
        self._events: list[NodeAuditEvent] = []

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
        """Append one redacted, hash-chained event and return it."""
        safe_payload: dict[str, Any] = redact_value(dict(payload or {}))
        unlinked = NodeAuditEvent(
            sequence=len(self._events) + 1,
            event_id=f"nae-{uuid.uuid4()}",
            version=AUDIT_EVENT_VERSION,
            recorded_at=self._clock().isoformat(),
            actor=actor,
            action=action,
            decision=decision,
            reason=reason,
            node_id=node_id,
            job_id=job_id,
            payload=safe_payload,
            payload_digest=digest_of(safe_payload),
            previous_hash=self._events[-1].event_hash if self._events else GENESIS_HASH,
            event_hash="",
        )
        event = replace(unlinked, event_hash=compute_event_hash(unlinked.body()))
        self._events.append(event)
        return event

    def events(self) -> tuple[NodeAuditEvent, ...]:
        return tuple(self._events)

    def head(self) -> str:
        return self._events[-1].event_hash if self._events else GENESIS_HASH

    def verify(self) -> bool:
        """Return whether the recorded chain is internally consistent."""
        return verify_chain(self._events)


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
