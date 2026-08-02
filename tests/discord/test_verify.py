from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st
from nacl.signing import SigningKey

from olympus.discord.verify import DiscordVerificationError, verify_discord_request

NOW = datetime(2026, 7, 29, tzinfo=UTC)
BODY = b'{"id":"123","type":1}'


def signed_request() -> tuple[SigningKey, str, str]:
    signing_key = SigningKey.generate()
    timestamp = str(int(NOW.timestamp()))
    signature = signing_key.sign(timestamp.encode() + BODY).signature.hex()
    return signing_key, timestamp, signature


def test_verifies_exact_raw_body_and_timestamp() -> None:
    signing_key, timestamp, signature = signed_request()

    verified = verify_discord_request(
        raw_body=BODY,
        signature_values=[signature],
        timestamp_values=[timestamp],
        public_key=bytes(signing_key.verify_key),
        now=NOW,
        tolerance=timedelta(minutes=5),
    )

    assert verified.raw_body == BODY
    assert verified.signed_at == NOW


@pytest.mark.parametrize(
    ("signature_values", "timestamp_values"),
    [
        ([], ["1785312000"]),
        (["00" * 64, "11" * 64], ["1785312000"]),
        (["00" * 64], []),
        (["00" * 64], ["1785312000", "1785312001"]),
    ],
)
def test_rejects_missing_or_duplicate_signed_headers(
    signature_values: list[str],
    timestamp_values: list[str],
) -> None:
    with pytest.raises(DiscordVerificationError):
        verify_discord_request(
            raw_body=BODY,
            signature_values=signature_values,
            timestamp_values=timestamp_values,
            public_key=bytes(SigningKey.generate().verify_key),
            now=NOW,
            tolerance=timedelta(minutes=5),
        )


def test_rejects_stale_timestamp_even_with_valid_signature() -> None:
    signing_key = SigningKey.generate()
    timestamp = str(int((NOW - timedelta(minutes=5, microseconds=1)).timestamp()))
    signature = signing_key.sign(timestamp.encode() + BODY).signature.hex()

    with pytest.raises(DiscordVerificationError, match="timestamp"):
        verify_discord_request(
            raw_body=BODY,
            signature_values=[signature],
            timestamp_values=[timestamp],
            public_key=bytes(signing_key.verify_key),
            now=NOW,
            tolerance=timedelta(minutes=5),
        )


@given(st.integers(min_value=0, max_value=len(BODY) - 1))
def test_rejects_any_single_byte_body_mutation(index: int) -> None:
    signing_key, timestamp, signature = signed_request()
    altered = bytearray(BODY)
    altered[index] ^= 1

    with pytest.raises(DiscordVerificationError, match="signature"):
        verify_discord_request(
            raw_body=bytes(altered),
            signature_values=[signature],
            timestamp_values=[timestamp],
            public_key=bytes(signing_key.verify_key),
            now=NOW,
            tolerance=timedelta(minutes=5),
        )
