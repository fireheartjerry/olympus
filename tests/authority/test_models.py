from datetime import UTC, datetime, timedelta

import pytest

from olympus.authority.models import AuthorityContext, RecoveryPayload


def test_authority_epoch_is_strictly_positive() -> None:
    with pytest.raises(ValueError, match="authority_epoch"):
        AuthorityContext(
            commander_id="628053765181800448",
            guild_id="123",
            channel_id="456",
            interaction_id="789",
            authority_epoch=0,
            lease_id="lease-1",
        )


def test_recovery_payload_rejects_more_than_five_minutes() -> None:
    issued_at = datetime(2026, 7, 29, tzinfo=UTC)

    with pytest.raises(ValueError, match="five minutes"):
        RecoveryPayload(
            request_id="recovery-1",
            action="unfreeze",
            freeze_epoch=1,
            commander_id="628053765181800448",
            guild_id="123",
            channel_scope_digest="a" * 64,
            issued_at=issued_at.isoformat(),
            expires_at=(issued_at + timedelta(minutes=5, microseconds=1)).isoformat(),
        )


def test_recovery_payload_canonical_bytes_are_stable() -> None:
    payload = RecoveryPayload(
        request_id="recovery-1",
        action="unfreeze",
        freeze_epoch=2,
        commander_id="628053765181800448",
        guild_id="123",
        channel_scope_digest="a" * 64,
        issued_at="2026-07-29T00:00:00+00:00",
        expires_at="2026-07-29T00:05:00+00:00",
    )

    assert payload.canonical_bytes() == (
        b'{"action":"unfreeze","channel_scope_digest":"'
        + (b"a" * 64)
        + b'","commander_id":"628053765181800448","expires_at":'
        b'"2026-07-29T00:05:00+00:00","freeze_epoch":2,"guild_id":"123",'
        b'"issued_at":"2026-07-29T00:00:00+00:00","request_id":"recovery-1"}'
    )
