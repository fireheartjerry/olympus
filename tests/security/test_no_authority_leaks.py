from datetime import UTC, datetime, timedelta

from olympus.authority.repository import InMemoryAuthorityRepository, LeaseRequest

NOW = datetime(2026, 7, 29, tzinfo=UTC)


async def test_audit_events_do_not_contain_raw_lease_material() -> None:
    repository = InMemoryAuthorityRepository()
    secret_lease_id = "lease-do-not-disclose"
    await repository.issue_lease(
        LeaseRequest(
            lease_id=secret_lease_id,
            commander_id="628053765181800448",
            guild_id="100000000000000001",
            channel_scope_digest=b"c" * 32,
            credential_id=b"credential-1",
            issued_at=NOW,
            expires_at=NOW + timedelta(hours=24),
        )
    )

    serialized_audit = "\n".join(event.body for event in await repository.audit_events())

    assert secret_lease_id not in serialized_audit
    assert "credential-1" not in serialized_audit
    assert "public-key" not in serialized_audit
