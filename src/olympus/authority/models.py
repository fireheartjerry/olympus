import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal


class AuthorityDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    FREEZE = "freeze"


@dataclass(frozen=True)
class AuthorityContext:
    commander_id: str
    guild_id: str
    channel_id: str
    interaction_id: str
    authority_epoch: int | None
    lease_id: str | None

    def __post_init__(self) -> None:
        required = {
            "commander_id": self.commander_id,
            "guild_id": self.guild_id,
            "channel_id": self.channel_id,
            "interaction_id": self.interaction_id,
        }
        empty = [name for name, value in required.items() if not value.strip()]
        if empty:
            raise ValueError(f"authority context contains empty fields: {', '.join(empty)}")
        if self.authority_epoch is not None and self.authority_epoch < 1:
            raise ValueError("authority_epoch must be strictly positive")
        if (self.authority_epoch is None) != (self.lease_id is None):
            raise ValueError("authority_epoch and lease_id must both be present or absent")


@dataclass(frozen=True)
class RecoveryPayload:
    request_id: str
    action: Literal["unfreeze"]
    freeze_epoch: int
    commander_id: str
    guild_id: str
    channel_scope_digest: str
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        if self.action != "unfreeze":
            raise ValueError("recovery action must be literal unfreeze")
        if self.freeze_epoch < 1:
            raise ValueError("freeze_epoch must be strictly positive")
        if len(self.channel_scope_digest) != 64:
            raise ValueError("channel_scope_digest must be a SHA-256 hex digest")
        try:
            int(self.channel_scope_digest, 16)
        except ValueError as exc:
            raise ValueError("channel_scope_digest must be a SHA-256 hex digest") from exc
        issued_at = _canonical_datetime(self.issued_at, "issued_at")
        expires_at = _canonical_datetime(self.expires_at, "expires_at")
        if expires_at <= issued_at:
            raise ValueError("recovery payload must expire after issuance")
        if expires_at - issued_at > timedelta(minutes=5):
            raise ValueError("recovery payload lifetime cannot exceed five minutes")

    def canonical_bytes(self) -> bytes:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()


def _canonical_datetime(value: str, field_name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a canonical ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None or parsed.isoformat() != value:
        raise ValueError(f"{field_name} must be a canonical ISO-8601 timestamp")
    return parsed
