import asyncio
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Protocol

from olympus.nodes.audit import AuditDraft, NodeAuditEvent, link_event, verify_chain
from olympus.nodes.models import (
    DispatchControlState,
    EnrollmentTokenRecord,
    NodeJobRecord,
    NodeRecord,
    utc_now,
)


class NodeMeshTransaction(Protocol):
    """One atomic unit of node-mesh state change.

    Every mutation and the audit events describing it commit together or not
    at all. A state change that survives without its audit event is
    indistinguishable from an unaudited change, which the audit chain exists
    to make impossible.
    """

    async def get_enrollment_token(self, token_id: str) -> EnrollmentTokenRecord | None: ...

    async def put_enrollment_token(self, record: EnrollmentTokenRecord) -> None: ...

    async def list_enrollment_tokens(self) -> tuple[EnrollmentTokenRecord, ...]: ...

    async def get_node(self, node_id: str) -> NodeRecord | None: ...

    async def put_node(self, record: NodeRecord) -> None: ...

    async def list_nodes(self) -> tuple[NodeRecord, ...]: ...

    async def get_dispatch_control(self) -> DispatchControlState: ...

    async def put_dispatch_control(self, state: DispatchControlState) -> None: ...

    async def get_job(self, job_id: str) -> NodeJobRecord | None: ...

    async def put_job(self, record: NodeJobRecord) -> None: ...

    async def list_jobs(self) -> tuple[NodeJobRecord, ...]: ...

    async def append_audit(self, draft: AuditDraft) -> None: ...


class NodeMeshStore(Protocol):
    """Canonical owner of node-mesh state behind a transactional seam."""

    def transaction(self) -> "_TransactionContext": ...

    async def audit_events(self) -> tuple[NodeAuditEvent, ...]: ...

    async def audit_head(self) -> str: ...

    async def verify_audit_chain(self) -> bool: ...


class _TransactionContext(Protocol):
    async def __aenter__(self) -> NodeMeshTransaction: ...

    async def __aexit__(self, *exc_info: object) -> bool | None: ...


class _InMemoryTransaction:
    """Buffers every write so a failed block leaves no partial state."""

    def __init__(self, store: "InMemoryNodeMeshStore") -> None:
        self._store = store
        self._tokens: dict[str, EnrollmentTokenRecord] = {}
        self._nodes: dict[str, NodeRecord] = {}
        self._jobs: dict[str, NodeJobRecord] = {}
        self._control: DispatchControlState | None = None
        self._drafts: list[AuditDraft] = []

    async def get_enrollment_token(self, token_id: str) -> EnrollmentTokenRecord | None:
        if token_id in self._tokens:
            return self._tokens[token_id]
        return self._store._tokens.get(token_id)

    async def put_enrollment_token(self, record: EnrollmentTokenRecord) -> None:
        self._tokens[record.token_id] = record

    async def list_enrollment_tokens(self) -> tuple[EnrollmentTokenRecord, ...]:
        merged = dict(self._store._tokens)
        merged.update(self._tokens)
        return tuple(merged.values())

    async def get_node(self, node_id: str) -> NodeRecord | None:
        if node_id in self._nodes:
            return self._nodes[node_id]
        return self._store._nodes.get(node_id)

    async def put_node(self, record: NodeRecord) -> None:
        self._nodes[record.node_id] = record

    async def list_nodes(self) -> tuple[NodeRecord, ...]:
        merged = dict(self._store._nodes)
        merged.update(self._nodes)
        return tuple(merged.values())

    async def get_dispatch_control(self) -> DispatchControlState:
        return self._control if self._control is not None else self._store._control

    async def put_dispatch_control(self, state: DispatchControlState) -> None:
        self._control = state

    async def get_job(self, job_id: str) -> NodeJobRecord | None:
        if job_id in self._jobs:
            return self._jobs[job_id]
        return self._store._jobs.get(job_id)

    async def put_job(self, record: NodeJobRecord) -> None:
        self._jobs[record.job_id] = record

    async def list_jobs(self) -> tuple[NodeJobRecord, ...]:
        merged = dict(self._store._jobs)
        merged.update(self._jobs)
        return tuple(merged.values())

    async def append_audit(self, draft: AuditDraft) -> None:
        self._drafts.append(draft)

    def commit(self) -> None:
        self._store._tokens.update(self._tokens)
        self._store._nodes.update(self._nodes)
        self._store._jobs.update(self._jobs)
        if self._control is not None:
            self._store._control = self._control
        for draft in self._drafts:
            self._store._events.append(
                link_event(
                    draft,
                    sequence=len(self._store._events) + 1,
                    previous_hash=(
                        self._store._events[-1].event_hash if self._store._events else "0" * 64
                    ),
                    recorded_at=self._store._clock(),
                )
            )


class InMemoryNodeMeshStore:
    """Process-local store used by tests and the offline demonstration.

    It is never canonical for a deployed control plane: a restart discards
    every node, grant, revocation, freeze, and audit event it holds.
    """

    def __init__(self, *, clock: Callable[[], datetime] = utc_now) -> None:
        self._clock = clock
        self._tokens: dict[str, EnrollmentTokenRecord] = {}
        self._nodes: dict[str, NodeRecord] = {}
        self._jobs: dict[str, NodeJobRecord] = {}
        self._control = DispatchControlState()
        self._events: list[NodeAuditEvent] = []
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def _transaction(self) -> AsyncIterator[NodeMeshTransaction]:
        async with self._lock:
            transaction = _InMemoryTransaction(self)
            yield transaction
            transaction.commit()

    def transaction(self) -> "_TransactionContext":
        return self._transaction()  # type: ignore[return-value]

    async def audit_events(self) -> tuple[NodeAuditEvent, ...]:
        return tuple(self._events)

    async def audit_head(self) -> str:
        return self._events[-1].event_hash if self._events else "0" * 64

    async def verify_audit_chain(self) -> bool:
        return verify_chain(self._events)

    def seed_audit(self, events: Sequence[NodeAuditEvent]) -> None:
        """Adopt an existing chain, used when rebuilding a store in tests."""
        self._events.extend(events)
