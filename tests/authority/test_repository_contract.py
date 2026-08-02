import asyncio
import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from olympus.authority.repository import (
    AdmissionDenied,
    AdmissionRequest,
    Challenge,
    ChallengeConsumed,
    Credential,
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
        payload_json=None,
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


def bootstrap_challenge() -> Challenge:
    return Challenge(
        challenge_id="challenge-bootstrap",
        challenge_value=b"y" * 32,
        challenge_digest=b"c" * 32,
        purpose="bootstrap-registration",
        commander_id="628053765181800448",
        payload_digest=b"d" * 32,
        payload_json=None,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )


async def enroll(repository: InMemoryAuthorityRepository) -> None:
    request = bootstrap_challenge()
    await repository.create_challenge(request)
    await repository.complete_registration(
        request.challenge_id,
        request.challenge_digest,
        Credential(
            credential_id=b"credential-identity",
            commander_id="628053765181800448",
            public_key=b"public-key-material",
            sign_count=0,
            created_at=NOW,
        ),
        NOW,
    )


async def test_enrollment_is_recorded_in_the_audit_chain() -> None:
    """Enrollment creates authority from nothing; the chain must show it.

    Only authority *use* was recorded before — leases, freezes, recovery — so a
    credential could appear with no chained, signable evidence that it ever
    did. That left the one event a forger would most want to fabricate outside
    the evidence the off-host export exists to protect.
    """
    repository = InMemoryAuthorityRepository()
    await enroll(repository)

    events = await repository.audit_events()

    assert [event.event_type for event in events] == ["credential-enrolled"]
    assert events[0].sequence == 1
    assert InMemoryAuthorityRepository.verify_audit_chain(events) is True


async def test_enrollment_audit_event_carries_no_credential_material() -> None:
    # The chain is exported off-host. A credential ID and public key are what a
    # forger needs; a fingerprint proves which credential without carrying it.
    repository = InMemoryAuthorityRepository()
    await enroll(repository)

    body = (await repository.audit_events())[0].body

    assert "credential-identity" not in body
    assert "public-key-material" not in body
    assert hashlib.sha256(b"credential-identity").hexdigest() in body
    assert hashlib.sha256(b"public-key-material").hexdigest() in body


async def test_enrollment_links_ahead_of_the_first_lease() -> None:
    # Enrollment must be sequence 1, so the chain shows authority being created
    # before it is ever exercised.
    repository = InMemoryAuthorityRepository()
    await enroll(repository)
    lease = challenge()
    await repository.create_challenge(lease)
    await repository.complete_authentication(
        lease.challenge_id,
        lease.challenge_digest,
        b"credential-identity",
        1,
        lease_request("lease-1"),
        NOW,
    )

    events = await repository.audit_events()

    assert [event.event_type for event in events] == ["credential-enrolled", "lease-issued"]
    assert InMemoryAuthorityRepository.verify_audit_chain(events) is True
