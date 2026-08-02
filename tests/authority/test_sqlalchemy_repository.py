import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from olympus.authority.repository import AdmissionRequest, LeaseRequest
from olympus.authority.sqlalchemy import SqlAlchemyAuthorityRepository
from olympus.persistence.models import Base, WebAuthnCredentialRow

TEST_DSN = os.environ.get("OLYMPUS_TEST_DATABASE_DSN")
pytestmark = pytest.mark.skipif(TEST_DSN is None, reason="explicit PostgreSQL test DSN required")


@pytest.fixture
async def repository() -> SqlAlchemyAuthorityRepository:
    assert TEST_DSN is not None
    assert "/olympus_test" in TEST_DSN, "refusing destructive setup outside olympus_test database"
    engine = create_async_engine(TEST_DSN)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    repo = SqlAlchemyAuthorityRepository(sessions)
    await repo.initialize(datetime(2026, 7, 29, tzinfo=UTC))
    async with sessions.begin() as session:
        session.add(
            WebAuthnCredentialRow(
                credential_id=b"credential-1",
                commander_id="628053765181800448",
                public_key=b"public-key",
                sign_count=0,
                created_at=datetime(2026, 7, 29, tzinfo=UTC),
            )
        )
    yield repo
    await engine.dispose()


async def test_postgres_lease_freeze_and_admission_are_serialized(
    repository: SqlAlchemyAuthorityRepository,
) -> None:
    now = datetime(2026, 7, 29, tzinfo=UTC)
    lease = await repository.issue_lease(
        LeaseRequest(
            lease_id="lease-1",
            commander_id="628053765181800448",
            guild_id="100000000000000001",
            channel_scope_digest=b"c" * 32,
            credential_id=b"credential-1",
            issued_at=now,
            expires_at=now + timedelta(hours=24),
        )
    )
    admitted = await repository.admit(
        AdmissionRequest(
            interaction_id="100000000000000002",
            request_digest=b"d" * 32,
            commander_id=lease.commander_id,
            guild_id=lease.guild_id,
            channel_scope_digest=lease.channel_scope_digest,
            lease_id=lease.lease_id,
            authority_epoch=lease.authority_epoch,
            received_at=now,
        )
    )
    frozen = await repository.freeze("freeze-1", "operator-request", now)

    assert admitted.authority_epoch == lease.authority_epoch
    assert frozen.authority_epoch == lease.authority_epoch + 1
    assert await repository.lease_is_revoked(lease.lease_id)
    assert repository.verify_audit_chain(await repository.audit_events())
