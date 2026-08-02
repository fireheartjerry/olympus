"""Durability tests for the PostgreSQL node-mesh store.

These require a real database because the properties under test — transaction
atomicity, single-use enforcement under concurrency, and survival across a
process restart — are exactly the ones an in-memory fake cannot demonstrate.
They skip when no test database is configured.
"""

import asyncio
import os
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from olympus.nodes.audit import AuditAction, AuditDecision, AuditDraft
from olympus.nodes.capabilities import SYSTEM_INSPECT
from olympus.nodes.crypto import generate_node_keypair
from olympus.nodes.errors import NodeMeshError, NodeReason
from olympus.nodes.models import (
    NodeHealthSnapshot,
    NodeJobStatus,
    NodeKind,
    NodePlatform,
)
from olympus.nodes.registry import NodeDescription, NodeRegistry
from olympus.persistence.migrator import apply_migrations, load_migrations
from olympus.persistence.postgres_store import PostgresNodeMeshStore

pytestmark = pytest.mark.asyncio

TEST_DATABASE_URL = os.environ.get("OLYMPUS_TEST_DATABASE_URL")

requires_postgres = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="set OLYMPUS_TEST_DATABASE_URL to run PostgreSQL persistence tests",
)


@pytest.fixture
async def store():
    """Give each test its own schema so tests never share audit sequences."""
    import psycopg

    schema = f"olympus_test_{uuid.uuid4().hex[:12]}"
    assert TEST_DATABASE_URL is not None
    async with await psycopg.AsyncConnection.connect(TEST_DATABASE_URL, autocommit=True) as setup:
        await setup.execute(f'CREATE SCHEMA "{schema}"')
    url = f"{TEST_DATABASE_URL}?options=-csearch_path%3D{schema}"
    opened = await PostgresNodeMeshStore.connect(url)
    try:
        yield opened
    finally:
        await opened.close()
        async with await psycopg.AsyncConnection.connect(
            TEST_DATABASE_URL, autocommit=True
        ) as teardown:
            await teardown.execute(f'DROP SCHEMA "{schema}" CASCADE')


def _description(name: str = "test-node") -> NodeDescription:
    return NodeDescription(
        node_name=name,
        kind=NodeKind.WORKSTATION,
        platform=NodePlatform.LINUX,
        architecture="x86_64",
        agent_version="0.1.0",
        declared_capabilities=(SYSTEM_INSPECT.name,),
    )


async def _enroll(registry: NodeRegistry, name: str = "test-node"):
    issued = await registry.issue_enrollment_token(
        node_name=name,
        kind=NodeKind.WORKSTATION,
        platform=NodePlatform.LINUX,
        granted_capabilities=[SYSTEM_INSPECT.name],
        issued_by="operator",
    )
    return await registry.redeem_enrollment_token(
        presented=issued.presented,
        description=_description(name),
        public_key=generate_node_keypair().public_key,
    )


@requires_postgres
async def test_migrations_are_idempotent(store: PostgresNodeMeshStore) -> None:
    import psycopg

    assert TEST_DATABASE_URL is not None
    # The fixture already migrated; applying again must change nothing.
    async with store._pool.connection() as connection:  # noqa: SLF001
        await connection.set_autocommit(True)
        assert await apply_migrations(connection) == ()
        async with connection.cursor() as cursor:
            await cursor.execute("SELECT count(*) FROM schema_migrations")
            row = await cursor.fetchone()
    assert row is not None
    assert row[0] == len(load_migrations())
    assert psycopg is not None


@requires_postgres
async def test_enrolled_state_survives_a_rebuilt_store(store: PostgresNodeMeshStore) -> None:
    registry = NodeRegistry(store=store)
    node = await _enroll(registry)

    # A new registry over the same database is what a restart looks like.
    restarted = NodeRegistry(store=store)
    recovered = await restarted.get_node(node.node_id)
    assert recovered.node_id == node.node_id
    assert recovered.granted_capabilities == (SYSTEM_INSPECT.name,)
    assert recovered.public_key == node.public_key


@requires_postgres
async def test_a_freeze_survives_a_restart(store: PostgresNodeMeshStore) -> None:
    registry = NodeRegistry(store=store)
    frozen = await registry.freeze_dispatch(actor="operator", reason="incident")
    assert frozen.frozen is True

    restarted = NodeRegistry(store=store)
    control = await restarted.dispatch_control()
    assert control.frozen is True
    assert control.freeze_epoch == frozen.freeze_epoch

    # And the mesh still refuses to mint enrollment while frozen.
    with pytest.raises(NodeMeshError) as failure:
        await restarted.issue_enrollment_token(
            node_name="another",
            kind=NodeKind.WORKSTATION,
            platform=NodePlatform.LINUX,
            granted_capabilities=[SYSTEM_INSPECT.name],
            issued_by="operator",
        )
    assert failure.value.reason is NodeReason.DISPATCH_FROZEN


@requires_postgres
async def test_a_revoked_node_stays_revoked_across_a_restart(
    store: PostgresNodeMeshStore,
) -> None:
    registry = NodeRegistry(store=store)
    node = await _enroll(registry)
    await registry.revoke_node(node.node_id, actor="operator", reason="lost laptop")

    restarted = NodeRegistry(store=store)
    recovered = await restarted.get_node(node.node_id)
    assert recovered.revoked_at is not None
    with pytest.raises(NodeMeshError) as failure:
        await restarted.restore_node(node.node_id, actor="operator")
    assert failure.value.reason is NodeReason.NODE_REVOKED


@requires_postgres
async def test_one_token_yields_one_node_under_concurrent_redemption(
    store: PostgresNodeMeshStore,
) -> None:
    registry = NodeRegistry(store=store)
    issued = await registry.issue_enrollment_token(
        node_name="racer",
        kind=NodeKind.WORKSTATION,
        platform=NodePlatform.LINUX,
        granted_capabilities=[SYSTEM_INSPECT.name],
        issued_by="operator",
    )

    async def redeem():
        return await registry.redeem_enrollment_token(
            presented=issued.presented,
            description=_description("racer"),
            public_key=generate_node_keypair().public_key,
        )

    results = await asyncio.gather(redeem(), redeem(), return_exceptions=True)
    succeeded = [item for item in results if not isinstance(item, BaseException)]
    refused = [item for item in results if isinstance(item, NodeMeshError)]
    assert len(succeeded) == 1
    assert len(refused) == 1

    async with store.transaction() as tx:
        nodes = await tx.list_nodes()
    assert len([node for node in nodes if node.node_name == "racer"]) == 1


@requires_postgres
async def test_the_audit_chain_verifies_and_detects_tampering(
    store: PostgresNodeMeshStore,
) -> None:
    registry = NodeRegistry(store=store)
    node = await _enroll(registry)
    await registry.quarantine_node(node.node_id, actor="operator", reason="suspicious")

    events = await store.audit_events()
    assert len(events) >= 3
    assert await store.verify_audit_chain() is True
    assert await store.audit_head() == events[-1].event_hash

    # Rewriting a stored payload must break verification.
    async with store._pool.connection() as connection:  # noqa: SLF001
        await connection.set_autocommit(True)
        async with connection.cursor() as cursor:
            await cursor.execute(
                "UPDATE node_audit_events SET reason = %s WHERE sequence = %s",
                ("rewritten", events[-1].sequence),
            )
    assert await store.verify_audit_chain() is False


@requires_postgres
async def test_deleting_an_audit_row_breaks_the_chain(store: PostgresNodeMeshStore) -> None:
    registry = NodeRegistry(store=store)
    for index in range(3):
        await registry.record_audit(
            AuditDraft(
                actor="operator",
                action=AuditAction.SESSION_OPENED,
                decision=AuditDecision.OBSERVE,
                payload={"index": index},
            )
        )
    assert await store.verify_audit_chain() is True

    async with store._pool.connection() as connection:  # noqa: SLF001
        await connection.set_autocommit(True)
        async with connection.cursor() as cursor:
            await cursor.execute("DELETE FROM node_audit_events WHERE sequence = 2")
    assert await store.verify_audit_chain() is False


@requires_postgres
async def test_a_failed_transaction_commits_neither_state_nor_audit(
    store: PostgresNodeMeshStore,
) -> None:
    registry = NodeRegistry(store=store)
    node = await _enroll(registry)
    before = await store.audit_events()

    class Boom(RuntimeError):
        pass

    with pytest.raises(Boom):
        async with store.transaction() as tx:
            await tx.put_node(replace(node, quarantine_reason="half-written"))
            await tx.append_audit(
                AuditDraft(
                    actor="operator",
                    action=AuditAction.NODE_QUARANTINED,
                    decision=AuditDecision.ALLOW,
                    node_id=node.node_id,
                )
            )
            raise Boom

    after = await store.audit_events()
    assert len(after) == len(before)
    recovered = await registry.get_node(node.node_id)
    assert recovered.quarantine_reason == ""
    assert await store.verify_audit_chain() is True


@requires_postgres
async def test_restart_recovery_clears_sessions_and_reconciles_jobs(
    store: PostgresNodeMeshStore,
) -> None:
    registry = NodeRegistry(store=store)
    node = await _enroll(registry)
    await registry.attach_session(
        node_id=node.node_id,
        session_id="session-1",
        declared_capabilities=[SYSTEM_INSPECT.name],
        agent_version="0.1.0",
        architecture="x86_64",
    )
    now = datetime.now(UTC)
    await registry.record_heartbeat(
        node_id=node.node_id,
        session_id="session-1",
        health=NodeHealthSnapshot(reported_at=now, active_jobs=1),
    )

    from olympus.nodes.models import DispatchAuthority, NodeJobRecord

    await registry.upsert_job(
        NodeJobRecord(
            job_id="job-1",
            node_id=node.node_id,
            capability=SYSTEM_INSPECT.name,
            dedupe_key="dedupe-1",
            status=NodeJobStatus.RUNNING,
            attempt=1,
            authority=DispatchAuthority(
                commander_id="jerry", authority_lease_id="development-lease"
            ),
            created_at=now,
            updated_at=now,
        )
    )

    restarted = NodeRegistry(store=store)
    report = await restarted.recover_after_restart()

    assert report.sessions_cleared == (node.node_id,)
    assert report.jobs_reconciled == ("job-1",)

    recovered = await restarted.get_node(node.node_id)
    assert recovered.session_id is None
    # Heartbeat history is preserved so the node ages to offline rather than
    # losing the fact that it was ever seen.
    assert recovered.last_heartbeat_at is not None

    jobs = await restarted.list_jobs()
    assert jobs[0].status is NodeJobStatus.TIMED_OUT
    assert jobs[0].reason == "control-plane-restart"

    # Recovery is idempotent.
    again = await restarted.recover_after_restart()
    assert again.changed is False
    assert await store.verify_audit_chain() is True


@requires_postgres
async def test_records_round_trip_with_labels_health_and_empty_grants(
    store: PostgresNodeMeshStore,
) -> None:
    registry = NodeRegistry(store=store)
    node = await _enroll(registry, name="round-trip")
    reported = datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=5)
    await registry.attach_session(
        node_id=node.node_id,
        session_id="session-x",
        declared_capabilities=[SYSTEM_INSPECT.name],
        agent_version="9.9.9",
        architecture="aarch64",
    )
    health = NodeHealthSnapshot(
        reported_at=reported,
        active_jobs=3,
        cpu_count=8,
        load_average_1m=0.5,
        memory_total_mib=1024,
        memory_available_mib=512,
        uptime_seconds=99,
        agent_uptime_seconds=42,
    )
    await registry.record_heartbeat(node_id=node.node_id, session_id="session-x", health=health)

    recovered = await NodeRegistry(store=store).get_node(node.node_id)
    assert recovered.last_health == health
    assert recovered.agent_version == "9.9.9"
    assert recovered.architecture == "aarch64"


@requires_postgres
async def test_a_consumed_token_cannot_be_replayed_after_a_restart(
    store: PostgresNodeMeshStore,
) -> None:
    registry = NodeRegistry(store=store)
    issued = await registry.issue_enrollment_token(
        node_name="once",
        kind=NodeKind.WORKSTATION,
        platform=NodePlatform.LINUX,
        granted_capabilities=[SYSTEM_INSPECT.name],
        issued_by="operator",
    )
    await registry.redeem_enrollment_token(
        presented=issued.presented,
        description=_description("once"),
        public_key=generate_node_keypair().public_key,
    )

    restarted = NodeRegistry(store=store)
    with pytest.raises(NodeMeshError) as failure:
        await restarted.redeem_enrollment_token(
            presented=issued.presented,
            description=_description("once"),
            public_key=generate_node_keypair().public_key,
        )
    assert failure.value.reason is NodeReason.ENROLLMENT_CONSUMED
