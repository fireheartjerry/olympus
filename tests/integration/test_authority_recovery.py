import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from olympus.authority.repository import (
    AdmissionDenied,
    AdmissionRequest,
    Challenge,
    LeaseRequest,
)
from olympus.authority.sqlalchemy import SqlAlchemyAuthorityRepository
from olympus.persistence.models import Base, WebAuthnCredentialRow

TEST_DSN = os.environ.get("OLYMPUS_TEST_DATABASE_DSN")
pytestmark = pytest.mark.skipif(TEST_DSN is None, reason="explicit PostgreSQL test DSN required")
NOW = datetime(2026, 7, 29, tzinfo=UTC)


def lease_request(lease_id: str) -> LeaseRequest:
    return LeaseRequest(
        lease_id=lease_id,
        commander_id="628053765181800448",
        guild_id="100000000000000001",
        channel_scope_digest=b"c" * 32,
        credential_id=b"credential-1",
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=24),
    )


def recovery_challenge(challenge_id: str) -> Challenge:
    digest = sha256(challenge_id.encode()).digest()
    return Challenge(
        challenge_id=challenge_id,
        challenge_value=digest,
        challenge_digest=digest,
        purpose="recovery",
        commander_id="628053765181800448",
        payload_digest=b"p" * 32,
        payload_json='{"action":"unfreeze"}',
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )


async def test_postgres_restart_preserves_freeze_and_requires_fresh_epoch() -> None:
    assert TEST_DSN is not None
    assert "/olympus_test" in TEST_DSN, "refusing destructive setup outside olympus_test database"
    engine = create_async_engine(TEST_DSN)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    repository = SqlAlchemyAuthorityRepository(sessions)
    await repository.initialize(NOW)
    async with sessions.begin() as session:
        session.add(
            WebAuthnCredentialRow(
                credential_id=b"credential-1",
                commander_id="628053765181800448",
                public_key=b"public-key",
                sign_count=0,
                created_at=NOW,
            )
        )

    old_lease = await repository.issue_lease(lease_request("lease-old"))
    old_admission = AdmissionRequest(
        interaction_id="interaction-old",
        request_digest=b"r" * 32,
        commander_id=old_lease.commander_id,
        guild_id=old_lease.guild_id,
        channel_scope_digest=old_lease.channel_scope_digest,
        lease_id=old_lease.lease_id,
        authority_epoch=old_lease.authority_epoch,
        received_at=NOW,
    )
    await repository.admit(old_admission)
    frozen = await repository.freeze("freeze-1", "operator-request", NOW)
    await engine.dispose()

    restarted_engine = create_async_engine(TEST_DSN)
    restarted_sessions = async_sessionmaker(restarted_engine, expire_on_commit=False)
    restarted = SqlAlchemyAuthorityRepository(restarted_sessions)
    assert (await restarted.freeze_state()).frozen
    with pytest.raises(AdmissionDenied):
        await restarted.admit(replace(old_admission, interaction_id="interaction-after-restart"))

    stale_challenge = recovery_challenge("recovery-stale")
    await restarted.create_challenge(stale_challenge)
    with pytest.raises(AdmissionDenied, match="freeze epoch changed"):
        await restarted.complete_recovery(
            challenge_id="recovery-stale",
            challenge_digest=stale_challenge.challenge_digest,
            expected_freeze_epoch=frozen.freeze_epoch - 1,
            credential_id=b"credential-1",
            new_sign_count=1,
            lease_request=lease_request("lease-stale"),
            recovery_id="recovery-stale",
            now=NOW,
        )

    fresh_challenge = recovery_challenge("recovery-fresh")
    await restarted.create_challenge(fresh_challenge)
    recovered = await restarted.complete_recovery(
        challenge_id="recovery-fresh",
        challenge_digest=fresh_challenge.challenge_digest,
        expected_freeze_epoch=frozen.freeze_epoch,
        credential_id=b"credential-1",
        new_sign_count=1,
        lease_request=lease_request("lease-fresh"),
        recovery_id="recovery-fresh",
        now=NOW,
    )

    assert recovered.lease.authority_epoch > frozen.authority_epoch
    assert not (await restarted.freeze_state()).frozen
    assert await restarted.lease_is_revoked(old_lease.lease_id)
    with pytest.raises(AdmissionDenied):
        await restarted.admit(replace(old_admission, interaction_id="interaction-old-epoch"))
    await restarted_engine.dispose()
