import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from olympus.authority.repository import (
    AdmissionDenied,
    AdmissionRequest,
    Challenge,
    ChallengeConsumed,
    InMemoryAuthorityRepository,
    LeaseRequest,
)

NOW = datetime(2026, 7, 29, tzinfo=UTC)


def challenge() -> Challenge:
    return Challenge(
        challenge_id="challenge-1",
        challenge_value=b"z" * 32,
        challenge_digest=b"a" * 32,
        purpose="lease",
        commander_id="628053765181800448",
        payload_digest=b"b" * 32,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )


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


async def test_challenge_is_consumed_once() -> None:
    repository = InMemoryAuthorityRepository()
    await repository.create_challenge(challenge())

    consumed = await repository.consume_challenge("challenge-1", b"a" * 32, NOW)

    assert consumed.consumed_at == NOW
    with pytest.raises(ChallengeConsumed):
        await repository.consume_challenge("challenge-1", b"a" * 32, NOW)


async def test_new_lease_revokes_prior_epoch_atomically() -> None:
    repository = InMemoryAuthorityRepository()
    first = await repository.issue_lease(lease_request("lease-1"))
    second = await repository.issue_lease(lease_request("lease-2"))

    assert first.authority_epoch == 2
    assert second.authority_epoch == 3
    assert await repository.active_lease() == second
    assert await repository.lease_is_revoked("lease-1")


async def test_freeze_revokes_lease_and_advances_epochs() -> None:
    repository = InMemoryAuthorityRepository()
    lease = await repository.issue_lease(lease_request("lease-1"))

    receipt = await repository.freeze("freeze-1", "operator-request", NOW)

    assert receipt.authority_epoch == lease.authority_epoch + 1
    assert receipt.freeze_epoch == 2
    assert await repository.lease_is_revoked("lease-1")


async def test_duplicate_interaction_returns_original_outcome() -> None:
    repository = InMemoryAuthorityRepository()
    lease = await repository.issue_lease(lease_request("lease-1"))
    request = AdmissionRequest(
        interaction_id="100000000000000002",
        request_digest=b"d" * 32,
        commander_id=lease.commander_id,
        guild_id=lease.guild_id,
        channel_scope_digest=lease.channel_scope_digest,
        lease_id=lease.lease_id,
        authority_epoch=lease.authority_epoch,
        received_at=NOW,
    )

    first = await repository.admit(request)
    second = await repository.admit(request)

    assert first.workflow_id == second.workflow_id
    assert first.duplicate is False
    assert second.duplicate is True


async def test_audit_chain_verifies_after_authority_transitions() -> None:
    repository = InMemoryAuthorityRepository()
    await repository.issue_lease(lease_request("lease-1"))
    await repository.freeze("freeze-1", "operator-request", NOW)

    events = await repository.audit_events()

    assert len(events) == 2
    assert repository.verify_audit_chain(events)


async def test_freeze_started_first_wins_concurrent_admission() -> None:
    repository = InMemoryAuthorityRepository()
    lease = await repository.issue_lease(lease_request("lease-1"))
    request = AdmissionRequest(
        interaction_id="100000000000000002",
        request_digest=b"d" * 32,
        commander_id=lease.commander_id,
        guild_id=lease.guild_id,
        channel_scope_digest=lease.channel_scope_digest,
        lease_id=lease.lease_id,
        authority_epoch=lease.authority_epoch,
        received_at=NOW,
    )

    freeze_task = asyncio.create_task(repository.freeze("freeze-1", "anomaly", NOW))
    await asyncio.sleep(0)

    with pytest.raises(AdmissionDenied, match="frozen"):
        await repository.admit(request)
    await freeze_task
