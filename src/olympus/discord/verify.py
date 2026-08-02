from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey


class DiscordVerificationError(ValueError):
    """Raised when a Discord transport request cannot be authenticated."""


@dataclass(frozen=True)
class VerifiedDiscordRequest:
    raw_body: bytes
    signed_at: datetime


def verify_discord_request(
    *,
    raw_body: bytes,
    signature_values: Sequence[str],
    timestamp_values: Sequence[str],
    public_key: bytes,
    now: datetime,
    tolerance: timedelta,
) -> VerifiedDiscordRequest:
    if len(signature_values) != 1 or len(timestamp_values) != 1:
        raise DiscordVerificationError("exactly one signature and timestamp are required")
    if now.tzinfo is None or now.utcoffset() is None:
        raise TypeError("now must be timezone-aware")
    if tolerance <= timedelta(0):
        raise ValueError("tolerance must be positive")

    timestamp = timestamp_values[0]
    try:
        signed_at = datetime.fromtimestamp(int(timestamp), tz=UTC)
    except (ValueError, OverflowError) as exc:
        raise DiscordVerificationError("invalid Discord timestamp") from exc
    if abs(now.astimezone(UTC) - signed_at) > tolerance:
        raise DiscordVerificationError("Discord timestamp is outside tolerance")

    try:
        signature = bytes.fromhex(signature_values[0])
        VerifyKey(public_key).verify(timestamp.encode("ascii") + raw_body, signature)
    except (ValueError, BadSignatureError, UnicodeEncodeError) as exc:
        raise DiscordVerificationError("invalid Discord signature") from exc

    return VerifiedDiscordRequest(raw_body=raw_body, signed_at=signed_at)
