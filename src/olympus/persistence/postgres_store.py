from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import datetime
from typing import Any, Final

from psycopg import AsyncConnection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from olympus.nodes.audit import (
    GENESIS_HASH,
    AuditAction,
    AuditDecision,
    AuditDraft,
    NodeAuditEvent,
    link_event,
    verify_chain,
)
from olympus.nodes.models import (
    DispatchAuthority,
    DispatchControlState,
    EnrollmentTokenRecord,
    NodeHealthSnapshot,
    NodeJobRecord,
    NodeJobStatus,
    NodeKind,
    NodePlatform,
    NodeRecord,
    utc_now,
)
from olympus.persistence.migrator import apply_migrations

# Serializes audit appends so two transactions cannot claim one sequence.
AUDIT_LOCK_KEY: Final[int] = 0x0147_4D50_5553_0002


def _labels_to_json(labels: tuple[tuple[str, str], ...]) -> Jsonb:
    return Jsonb([[key, value] for key, value in labels])


def _labels_from_json(value: Any) -> tuple[tuple[str, str], ...]:
    if not value:
        return ()
    return tuple((str(pair[0]), str(pair[1])) for pair in value)


def _health_to_json(health: NodeHealthSnapshot | None) -> Jsonb | None:
    if health is None:
        return None
    body = asdict(health)
    body["reported_at"] = health.reported_at.isoformat()
    return Jsonb(body)


def _health_from_json(value: Any) -> NodeHealthSnapshot | None:
    if not value:
        return None
    body = dict(value)
    body["reported_at"] = datetime.fromisoformat(body["reported_at"])
    return NodeHealthSnapshot(**body)


def _token_from_row(row: Mapping[str, Any]) -> EnrollmentTokenRecord:
    return EnrollmentTokenRecord(
        token_id=row["token_id"],
        secret_hash=row["secret_hash"],
        node_name=row["node_name"],
        kind=NodeKind(row["kind"]),
        platform=NodePlatform(row["platform"]),
        granted_capabilities=tuple(row["granted_capabilities"]),
        issued_at=row["issued_at"],
        expires_at=row["expires_at"],
        issued_by=row["issued_by"],
        consumed_at=row["consumed_at"],
        consumed_by_node_id=row["consumed_by_node_id"],
        revoked_at=row["revoked_at"],
    )


def _node_from_row(row: Mapping[str, Any]) -> NodeRecord:
    return NodeRecord(
        node_id=row["node_id"],
        node_name=row["node_name"],
        kind=NodeKind(row["kind"]),
        platform=NodePlatform(row["platform"]),
        architecture=row["architecture"],
        agent_version=row["agent_version"],
        public_key=row["public_key"],
        granted_capabilities=tuple(row["granted_capabilities"]),
        declared_capabilities=tuple(row["declared_capabilities"]),
        labels=_labels_from_json(row["labels"]),
        enrolled_at=row["enrolled_at"],
        enrollment_token_id=row["enrollment_token_id"],
        session_id=row["session_id"],
        session_started_at=row["session_started_at"],
        last_heartbeat_at=row["last_heartbeat_at"],
        last_health=_health_from_json(row["last_health"]),
        quarantined_at=row["quarantined_at"],
        quarantine_reason=row["quarantine_reason"],
        revoked_at=row["revoked_at"],
        revocation_reason=row["revocation_reason"],
    )


def _job_from_row(row: Mapping[str, Any]) -> NodeJobRecord:
    return NodeJobRecord(
        job_id=row["job_id"],
        node_id=row["node_id"],
        capability=row["capability"],
        dedupe_key=row["dedupe_key"],
        status=NodeJobStatus(row["status"]),
        attempt=row["attempt"],
        authority=DispatchAuthority(
            commander_id=row["commander_id"],
            authority_lease_id=row["authority_lease_id"],
            authority_epoch=row["authority_epoch"],
        ),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        progress_events=row["progress_events"],
        last_message=row["last_message"],
        reason=row["reason"],
    )


def _event_from_row(row: Mapping[str, Any]) -> NodeAuditEvent:
    return NodeAuditEvent(
        sequence=row["sequence"],
        event_id=row["event_id"],
        version=row["version"],
        recorded_at=row["recorded_at"],
        actor=row["actor"],
        action=AuditAction(row["action"]),
        decision=AuditDecision(row["decision"]),
        reason=row["reason"],
        node_id=row["node_id"],
        job_id=row["job_id"],
        payload=row["payload"],
        payload_digest=row["payload_digest"],
        previous_hash=row["previous_hash"],
        event_hash=row["event_hash"],
    )


class PostgresNodeMeshTransaction:
    """Node-mesh writes bound to one PostgreSQL transaction."""

    def __init__(self, connection: AsyncConnection[Any], *, clock: Any) -> None:
        self._connection = connection
        self._clock = clock
        self._audit_locked = False

    async def _fetch_one(self, sql: str, params: Sequence[Any]) -> dict[str, Any] | None:
        async with self._connection.cursor(row_factory=dict_row) as cursor:
            await cursor.execute(sql, params)
            return await cursor.fetchone()

    async def _fetch_all(self, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        async with self._connection.cursor(row_factory=dict_row) as cursor:
            await cursor.execute(sql, params)
            return await cursor.fetchall()

    async def _execute(self, sql: str, params: Sequence[Any]) -> None:
        async with self._connection.cursor() as cursor:
            await cursor.execute(sql, params)

    # -- enrollment tokens --------------------------------------------------

    async def get_enrollment_token(self, token_id: str) -> EnrollmentTokenRecord | None:
        # FOR UPDATE so a single-use token cannot be redeemed twice
        # concurrently: the second redemption blocks until the first commits.
        row = await self._fetch_one(
            "SELECT * FROM enrollment_tokens WHERE token_id = %s FOR UPDATE", (token_id,)
        )
        return _token_from_row(row) if row else None

    async def put_enrollment_token(self, record: EnrollmentTokenRecord) -> None:
        await self._execute(
            """
            INSERT INTO enrollment_tokens (
                token_id, secret_hash, node_name, kind, platform,
                granted_capabilities, issued_at, expires_at, issued_by,
                consumed_at, consumed_by_node_id, revoked_at
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (token_id) DO UPDATE SET
                consumed_at = EXCLUDED.consumed_at,
                consumed_by_node_id = EXCLUDED.consumed_by_node_id,
                revoked_at = EXCLUDED.revoked_at
            """,
            (
                record.token_id,
                record.secret_hash,
                record.node_name,
                record.kind.value,
                record.platform.value,
                list(record.granted_capabilities),
                record.issued_at,
                record.expires_at,
                record.issued_by,
                record.consumed_at,
                record.consumed_by_node_id,
                record.revoked_at,
            ),
        )

    async def list_enrollment_tokens(self) -> tuple[EnrollmentTokenRecord, ...]:
        rows = await self._fetch_all("SELECT * FROM enrollment_tokens ORDER BY issued_at")
        return tuple(_token_from_row(row) for row in rows)

    # -- nodes --------------------------------------------------------------

    async def get_node(self, node_id: str) -> NodeRecord | None:
        row = await self._fetch_one("SELECT * FROM nodes WHERE node_id = %s", (node_id,))
        return _node_from_row(row) if row else None

    async def put_node(self, record: NodeRecord) -> None:
        await self._execute(
            """
            INSERT INTO nodes (
                node_id, node_name, kind, platform, architecture, agent_version,
                public_key, granted_capabilities, declared_capabilities, labels,
                enrolled_at, enrollment_token_id, session_id, session_started_at,
                last_heartbeat_at, last_health, quarantined_at, quarantine_reason,
                revoked_at, revocation_reason
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (node_id) DO UPDATE SET
                node_name = EXCLUDED.node_name,
                architecture = EXCLUDED.architecture,
                agent_version = EXCLUDED.agent_version,
                granted_capabilities = EXCLUDED.granted_capabilities,
                declared_capabilities = EXCLUDED.declared_capabilities,
                labels = EXCLUDED.labels,
                session_id = EXCLUDED.session_id,
                session_started_at = EXCLUDED.session_started_at,
                last_heartbeat_at = EXCLUDED.last_heartbeat_at,
                last_health = EXCLUDED.last_health,
                quarantined_at = EXCLUDED.quarantined_at,
                quarantine_reason = EXCLUDED.quarantine_reason,
                revoked_at = EXCLUDED.revoked_at,
                revocation_reason = EXCLUDED.revocation_reason
            """,
            (
                record.node_id,
                record.node_name,
                record.kind.value,
                record.platform.value,
                record.architecture,
                record.agent_version,
                record.public_key,
                list(record.granted_capabilities),
                list(record.declared_capabilities),
                _labels_to_json(record.labels),
                record.enrolled_at,
                record.enrollment_token_id,
                record.session_id,
                record.session_started_at,
                record.last_heartbeat_at,
                _health_to_json(record.last_health),
                record.quarantined_at,
                record.quarantine_reason,
                record.revoked_at,
                record.revocation_reason,
            ),
        )

    async def list_nodes(self) -> tuple[NodeRecord, ...]:
        rows = await self._fetch_all("SELECT * FROM nodes ORDER BY node_name")
        return tuple(_node_from_row(row) for row in rows)

    # -- dispatch control ---------------------------------------------------

    async def get_dispatch_control(self) -> DispatchControlState:
        row = await self._fetch_one("SELECT * FROM dispatch_control WHERE id = 1 FOR UPDATE", ())
        if row is None:
            return DispatchControlState()
        return DispatchControlState(
            frozen=row["frozen"],
            freeze_epoch=row["freeze_epoch"],
            changed_at=row["changed_at"],
            reason=row["reason"],
        )

    async def put_dispatch_control(self, state: DispatchControlState) -> None:
        await self._execute(
            """
            UPDATE dispatch_control
               SET frozen = %s, freeze_epoch = %s, changed_at = %s, reason = %s
             WHERE id = 1
            """,
            (state.frozen, state.freeze_epoch, state.changed_at, state.reason),
        )

    # -- jobs ---------------------------------------------------------------

    async def get_job(self, job_id: str) -> NodeJobRecord | None:
        row = await self._fetch_one("SELECT * FROM node_jobs WHERE job_id = %s", (job_id,))
        return _job_from_row(row) if row else None

    async def put_job(self, record: NodeJobRecord) -> None:
        await self._execute(
            """
            INSERT INTO node_jobs (
                job_id, node_id, capability, dedupe_key, status, attempt,
                commander_id, authority_lease_id, authority_epoch,
                created_at, updated_at, progress_events, last_message, reason
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (job_id) DO UPDATE SET
                status = EXCLUDED.status,
                attempt = EXCLUDED.attempt,
                updated_at = EXCLUDED.updated_at,
                progress_events = EXCLUDED.progress_events,
                last_message = EXCLUDED.last_message,
                reason = EXCLUDED.reason
            """,
            (
                record.job_id,
                record.node_id,
                record.capability,
                record.dedupe_key,
                record.status.value,
                record.attempt,
                record.authority.commander_id,
                record.authority.authority_lease_id,
                record.authority.authority_epoch,
                record.created_at,
                record.updated_at,
                record.progress_events,
                record.last_message,
                record.reason,
            ),
        )

    async def list_jobs(self) -> tuple[NodeJobRecord, ...]:
        rows = await self._fetch_all("SELECT * FROM node_jobs ORDER BY created_at")
        return tuple(_job_from_row(row) for row in rows)

    # -- audit --------------------------------------------------------------

    async def append_audit(self, draft: AuditDraft) -> None:
        """Insert one chained event inside the caller's transaction."""
        if not self._audit_locked:
            # Held until this transaction ends, so the sequence read below and
            # the insert that follows cannot interleave with another writer.
            await self._execute(f"SELECT pg_advisory_xact_lock({AUDIT_LOCK_KEY})", ())
            self._audit_locked = True
        head = await self._fetch_one(
            "SELECT sequence, event_hash FROM node_audit_events ORDER BY sequence DESC LIMIT 1",
            (),
        )
        sequence = (head["sequence"] + 1) if head else 1
        previous_hash = head["event_hash"] if head else GENESIS_HASH
        event = link_event(
            draft,
            sequence=sequence,
            previous_hash=previous_hash,
            recorded_at=self._clock(),
        )
        await self._execute(
            """
            INSERT INTO node_audit_events (
                sequence, event_id, version, recorded_at, actor, action,
                decision, reason, node_id, job_id, payload, payload_digest,
                previous_hash, event_hash
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                event.sequence,
                event.event_id,
                event.version,
                event.recorded_at,
                event.actor,
                event.action.value,
                event.decision.value,
                event.reason,
                event.node_id,
                event.job_id,
                Jsonb(dict(event.payload)),
                event.payload_digest,
                event.previous_hash,
                event.event_hash,
            ),
        )


class PostgresNodeMeshStore:
    """PostgreSQL as the canonical owner of node-mesh state."""

    def __init__(self, pool: AsyncConnectionPool[AsyncConnection[Any]], *, clock: Any = utc_now):
        self._pool = pool
        self._clock = clock

    @classmethod
    async def connect(
        cls, database_url: str, *, clock: Any = utc_now, min_size: int = 1, max_size: int = 8
    ) -> "PostgresNodeMeshStore":
        """Open a pool and bring the schema up to date."""
        pool: AsyncConnectionPool[AsyncConnection[Any]] = AsyncConnectionPool(
            database_url, min_size=min_size, max_size=max_size, open=False
        )
        await pool.open(wait=True, timeout=30)
        async with pool.connection() as connection:
            await connection.set_autocommit(True)
            await apply_migrations(connection)
        return cls(pool, clock=clock)

    async def close(self) -> None:
        await self._pool.close()

    @asynccontextmanager
    async def _transaction(self) -> AsyncIterator[PostgresNodeMeshTransaction]:
        async with self._pool.connection() as connection:
            async with connection.transaction():
                yield PostgresNodeMeshTransaction(connection, clock=self._clock)

    def transaction(self) -> Any:
        return self._transaction()

    async def audit_events(self) -> tuple[NodeAuditEvent, ...]:
        async with self._pool.connection() as connection:
            async with connection.cursor(row_factory=dict_row) as cursor:
                await cursor.execute("SELECT * FROM node_audit_events ORDER BY sequence")
                rows = await cursor.fetchall()
        return tuple(_event_from_row(row) for row in rows)

    async def audit_head(self) -> str:
        async with self._pool.connection() as connection:
            async with connection.cursor(row_factory=dict_row) as cursor:
                await cursor.execute(
                    "SELECT event_hash FROM node_audit_events ORDER BY sequence DESC LIMIT 1"
                )
                row = await cursor.fetchone()
        return row["event_hash"] if row else GENESIS_HASH

    async def verify_audit_chain(self) -> bool:
        return verify_chain(await self.audit_events())
